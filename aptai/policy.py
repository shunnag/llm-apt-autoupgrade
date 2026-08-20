"""The safety policy: what aptai will and will not do on this machine.

This module is the trust boundary.  It assumes the plan it is handed is
hostile -- crafted by a prompt-injected model, a compromised endpoint or a
man-in-the-middle -- and decides, using only local configuration and local
facts about the dpkg database, which typed actions may proceed.

Three properties hold regardless of what the model returns:

1. An action outside the current stage's vocabulary is refused.
2. Package names must match Debian policy's grammar, so no argument can ever
   look like an option or like shell syntax.
3. Essential packages, ``Priority: required`` packages, the configured
   protected list and the packages of the *running* kernel can never be
   removed, purged or marked automatic.

:mod:`aptai.executor` adds a second, independent layer on top of this one: it
simulates every destructive apt operation with ``-s`` and aborts when the
simulation removes more than the configured number of packages or touches a
protected package.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

from aptai.config import Config
from aptai.pkgfacts import PackageFacts, base_name
from aptai.plan import (
    KEY_ID_RE,
    KEYSERVER_RE,
    MAX_WAIT_SECONDS,
    PACKAGE_RE,
    RISK_LEVELS,
    STAGE_ACTIONS,
    VALID_MARKS,
    Action,
    ActionKind,
    Plan,
)

#: apt source files that belong to the distribution itself.  Disabling these
#: would stop the machine receiving security updates entirely, which is a far
#: worse outcome than the failure aptai is trying to repair.
PROTECTED_SOURCE_FILES = (
    "/etc/apt/sources.list",
    "/etc/apt/sources.list.d/ubuntu.sources",
    "/etc/apt/sources.list.d/debian.sources",
    "/etc/apt/sources.list.d/ubuntu.list",
    "/etc/apt/sources.list.d/debian.list",
    "/etc/apt/sources.list.d/official-package-repositories.list",
)

APT_ROOT = "/etc/apt"
SOURCE_SUFFIXES = (".list", ".sources")
MAX_PACKAGES_PER_ACTION = 30
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")
_URI_RE = re.compile(r"^(https?|ftp|mirror\+https?|tor\+https?)://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%\-]{3,300}$")


@dataclass
class Rejection:
    """One action that the policy refused, and why."""

    action: Action
    reason: str

    def to_dict(self) -> dict:
        return {"action": self.action.to_dict(), "rejected_because": self.reason}


@dataclass
class PolicyResult:
    accepted: list[Action] = field(default_factory=list)
    rejected: list[Rejection] = field(default_factory=list)
    escalate: bool = False
    escalation_reason: str = ""

    @property
    def has_work(self) -> bool:
        return bool(self.accepted)

    def to_dict(self) -> dict:
        return {
            "accepted": [a.to_dict() for a in self.accepted],
            "rejected": [r.to_dict() for r in self.rejected],
            "escalate": self.escalate,
            "escalation_reason": self.escalation_reason,
        }


def action_signature(action: Action) -> str:
    """Stable identity of an action, used to detect a model repeating itself."""
    return "|".join(
        [
            action.kind.value,
            ",".join(sorted(action.packages)),
            action.mark,
            "purge" if action.purge else "",
            action.source_file,
            action.source_uri,
            ",".join(sorted(k.lower() for k in action.key_ids)),
        ]
    )


class Policy:
    """Local gatekeeper for model-proposed actions."""

    def __init__(self, config: Config, facts: PackageFacts):
        self.config = config
        self.facts = facts
        self._protected = {p.strip().lower() for p in config.policy.protected_packages if p.strip()}
        self._kernel = {p.lower() for p in facts.running_kernel_packages()}

    # ---------------------------------------------------------------- public

    def review(
        self,
        plan: Plan,
        stage: str,
        *,
        previous_signatures: set[str] | None = None,
    ) -> PolicyResult:
        """Filter ``plan`` down to the actions that are safe to run for ``stage``."""
        result = PolicyResult(escalate=plan.escalate, escalation_reason=plan.escalation_reason)
        if plan.escalate:
            # An explicit escalation wins; nothing else in the plan is run.
            for action in plan.actions:
                result.rejected.append(Rejection(action, "plan requested escalation"))
            return result

        allowed_kinds = STAGE_ACTIONS.get(stage)
        if allowed_kinds is None:
            result.escalate = True
            result.escalation_reason = f"unknown stage {stage!r}"
            return result

        seen = set(previous_signatures or ())
        budget = self.config.policy.max_actions_per_round
        removal_budget = self.config.policy.max_removals

        for action in plan.actions:
            if len(result.accepted) >= budget:
                result.rejected.append(
                    Rejection(action, f"more than policy.max_actions_per_round ({budget}) actions proposed")
                )
                continue

            reason = self._check(action, stage, allowed_kinds)
            if reason is None and action.kind in (ActionKind.APT_REMOVE,):
                if len(action.packages) > removal_budget:
                    reason = (
                        f"removes {len(action.packages)} packages, over policy.max_removals "
                        f"({removal_budget})"
                    )
            if reason is None:
                signature = action_signature(action)
                if signature in seen:
                    reason = "identical action was already attempted in an earlier round"
                else:
                    seen.add(signature)

            if reason is None:
                result.accepted.append(action)
            else:
                result.rejected.append(Rejection(action, reason))

        if not result.accepted and result.rejected and not result.escalate:
            result.escalate = True
            result.escalation_reason = "every proposed action was refused by the local policy"
        return result

    # --------------------------------------------------------------- checks

    def _check(self, action: Action, stage: str, allowed_kinds) -> str | None:
        """Return ``None`` when the action is permitted, else the refusal reason."""
        if action.kind not in allowed_kinds:
            return f"action {action.kind.value!r} is not permitted during the {stage} stage"

        text_reason = self._check_text_fields(action)
        if text_reason:
            return text_reason

        risk_reason = self._check_risk(action)
        if risk_reason:
            return risk_reason

        handler = {
            ActionKind.APT_INSTALL: self._check_install,
            ActionKind.APT_REINSTALL: self._check_install,
            ActionKind.APT_REMOVE: self._check_remove,
            ActionKind.APT_MARK: self._check_mark,
            ActionKind.WAIT: self._check_wait,
            ActionKind.IMPORT_REPO_KEY: self._check_key_import,
            ActionKind.DISABLE_APT_SOURCE: self._check_disable_source,
            ActionKind.RESET_APT_LISTS: self._check_reset_lists,
            ActionKind.APT_AUTOREMOVE: self._check_no_params,
            ActionKind.APT_UPDATE: self._check_no_params,
            ActionKind.APT_UPGRADE: self._check_no_params,
            ActionKind.APT_FULL_UPGRADE: self._check_no_params,
            ActionKind.APT_FIX_BROKEN: self._check_no_params,
            ActionKind.APT_CLEAN: self._check_no_params,
            ActionKind.APT_AUTOCLEAN: self._check_no_params,
            ActionKind.DPKG_CONFIGURE_PENDING: self._check_no_params,
            ActionKind.DPKG_AUDIT: self._check_no_params,
            ActionKind.RETRY_STAGE: self._check_no_params,
            ActionKind.ESCALATE: lambda _a: None,
        }.get(action.kind)
        if handler is None:
            return f"no local implementation for action {action.kind.value!r}"
        return handler(action)

    def _check_text_fields(self, action: Action) -> str | None:
        for name in ("reason", "mark", "keyserver", "source_file", "source_uri"):
            value = getattr(action, name)
            if value and _CONTROL_CHARS.search(value):
                return f"{name} contains control characters"
        for package in action.packages + action.key_ids:
            if _CONTROL_CHARS.search(package):
                return "package or key id contains control characters"
        return None

    def _check_risk(self, action: Action) -> str | None:
        limit = self.config.policy.max_risk
        if RISK_LEVELS.index(action.risk) > RISK_LEVELS.index(limit):
            return f"risk {action.risk!r} exceeds policy.max_risk ({limit})"
        return None

    def _check_no_params(self, action: Action) -> str | None:
        if action.packages or action.mark or action.key_ids or action.source_file or action.source_uri:
            return f"{action.kind.value} takes no parameters but some were supplied"
        return None

    def _check_packages(self, action: Action) -> str | None:
        if not action.packages:
            return f"{action.kind.value} requires at least one package name"
        if len(action.packages) > MAX_PACKAGES_PER_ACTION:
            return f"{len(action.packages)} package names, limit is {MAX_PACKAGES_PER_ACTION}"
        for package in action.packages:
            if not PACKAGE_RE.match(package):
                return f"{package!r} is not a valid Debian package name"
            if "=" in package and not self.config.policy.allow_downgrade:
                # A pinned version may be older than what is installed.  Pins
                # are still allowed, but only when downgrades are permitted:
                # apt's own simulation is the second line of defence.
                return (
                    f"{package!r} pins an explicit version; enable policy.allow_downgrade "
                    "to permit version pinning"
                )
        return None

    def _check_install(self, action: Action) -> str | None:
        problem = self._check_packages(action)
        if problem:
            return problem
        if action.purge:
            return "purge is only meaningful for apt_remove"
        return None

    def _check_remove(self, action: Action) -> str | None:
        if not self.config.policy.allow_remove:
            return "package removal is disabled by policy.allow_remove"
        if action.purge and not self.config.policy.allow_purge:
            return "purging is disabled by policy.allow_purge"
        problem = self._check_packages(action)
        if problem:
            return problem
        for package in action.packages:
            protected = self.protected_reason(package)
            if protected:
                return f"refusing to remove {base_name(package)}: {protected}"
        return None

    def _check_mark(self, action: Action) -> str | None:
        if action.mark not in VALID_MARKS:
            return f"apt_mark requires mark to be one of {VALID_MARKS}"
        if action.mark in ("hold", "unhold") and not self.config.policy.allow_hold_changes:
            return "changing holds is disabled by policy.allow_hold_changes"
        problem = self._check_packages(action)
        if problem:
            return problem
        if action.mark == "auto":
            # 'apt-mark auto' makes a package a candidate for autoremove, so it
            # is a deferred removal and gets the same protection.
            for package in action.packages:
                protected = self.protected_reason(package)
                if protected:
                    return f"refusing to mark {base_name(package)} as automatic: {protected}"
        return None

    def _check_wait(self, action: Action) -> str | None:
        if action.seconds < 1:
            return "wait requires a positive number of seconds"
        if action.seconds > MAX_WAIT_SECONDS:
            return f"wait is limited to {MAX_WAIT_SECONDS} seconds"
        return None

    def _check_key_import(self, action: Action) -> str | None:
        if not self.config.policy.allow_key_import:
            return "importing repository keys is disabled by policy.allow_key_import"
        if not action.key_ids:
            return "import_repo_key requires at least one key id"
        if len(action.key_ids) > 5:
            return "import_repo_key is limited to 5 key ids"
        for key_id in action.key_ids:
            if not KEY_ID_RE.match(key_id):
                return f"{key_id!r} is not a hexadecimal OpenPGP key id"
        keyserver = action.keyserver or (self.config.policy.allowed_keyservers or [""])[0]
        if not KEYSERVER_RE.match(keyserver or ""):
            return f"{action.keyserver!r} is not a valid keyserver hostname"
        if keyserver not in self.config.policy.allowed_keyservers:
            return f"keyserver {keyserver!r} is not in policy.allowed_keyservers"
        return None

    def _check_disable_source(self, action: Action) -> str | None:
        if not self.config.policy.allow_sources_edit:
            return "editing apt sources is disabled by policy.allow_sources_edit"
        path = action.source_file
        if not path:
            return "disable_apt_source requires source_file"
        problem = validate_source_path(path)
        if problem:
            return problem
        if not action.source_uri:
            return "disable_apt_source requires source_uri"
        if not _URI_RE.match(action.source_uri):
            return f"{action.source_uri!r} is not a valid repository URI"
        return None

    def _check_reset_lists(self, action: Action) -> str | None:
        if not self.config.policy.allow_apt_lists_reset:
            return "resetting apt lists is disabled by policy.allow_apt_lists_reset"
        return self._check_no_params(action)

    # --------------------------------------------------------------- helpers

    def protected_reason(self, package: str) -> str | None:
        """Why ``package`` may never be removed, or ``None`` when it may be."""
        name = base_name(package).lower()
        if name in self._protected:
            return "it is in policy.protected_packages"
        if self.facts.is_essential(name):
            return "it is an Essential package"
        if self.config.policy.protect_required_priority and self.facts.is_required_priority(name):
            return "it has Priority: required/important"
        if name in self._kernel:
            return f"it belongs to the running kernel ({self.facts.kernel_release})"
        if name.startswith(("linux-image-", "linux-modules-")) and self.facts.kernel_release in name:
            return f"it belongs to the running kernel ({self.facts.kernel_release})"
        return None

    def protected_hits(self, packages) -> list[tuple[str, str]]:
        """Every ``(package, reason)`` pair among ``packages`` that is protected."""
        hits = []
        for package in packages:
            reason = self.protected_reason(package)
            if reason:
                hits.append((base_name(package), reason))
        return hits


def validate_source_path(path: str) -> str | None:
    """Confirm ``path`` is a real apt source file under ``/etc/apt``.

    Uses ``realpath`` so that a symlink cannot be used to redirect the edit to
    somewhere else on the filesystem.
    """
    if not path.startswith("/"):
        return "source_file must be an absolute path"
    if ".." in path.split("/"):
        return "source_file must not contain '..'"
    real = os.path.realpath(path)
    apt_root = os.path.realpath(APT_ROOT)
    if real != apt_root and not real.startswith(apt_root + os.sep):
        return f"source_file resolves outside {APT_ROOT}"
    if not real.endswith(SOURCE_SUFFIXES):
        return "source_file must be a .list or .sources file"
    if os.path.normpath(path) in PROTECTED_SOURCE_FILES or real in PROTECTED_SOURCE_FILES:
        return "that file holds the distribution's own repositories"
    if os.path.exists(real) and not os.path.isfile(real):
        return "source_file is not a regular file"
    return None
