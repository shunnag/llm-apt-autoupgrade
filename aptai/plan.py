"""The closed action vocabulary and the JSON schema handed to the model.

The model never returns a command line.  It returns a list of *typed actions*
drawn from :class:`ActionKind`, each of which is implemented by
:mod:`aptai.executor` as a fixed ``argv`` template with validated parameters.
Anything outside the vocabulary cannot be expressed, let alone executed.

Each upgrade stage exposes a different slice of the vocabulary
(:data:`STAGE_ACTIONS`).  A failing ``apt-get update`` is a repository/keyring
problem, so the update stage cannot reach dpkg state at all; a failing
``full-upgrade`` is a dpkg/dependency problem, so it cannot rewrite sources.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import StrEnum


class PlanParseError(Exception):
    """The model's answer could not be turned into a :class:`Plan`."""


class ActionKind(StrEnum):
    APT_UPDATE = "apt_update"
    APT_FULL_UPGRADE = "apt_full_upgrade"
    APT_UPGRADE = "apt_upgrade"
    APT_INSTALL = "apt_install"
    APT_REINSTALL = "apt_reinstall"
    APT_REMOVE = "apt_remove"
    APT_FIX_BROKEN = "apt_fix_broken"
    APT_AUTOREMOVE = "apt_autoremove"
    APT_CLEAN = "apt_clean"
    APT_AUTOCLEAN = "apt_autoclean"
    DPKG_CONFIGURE_PENDING = "dpkg_configure_pending"
    DPKG_AUDIT = "dpkg_audit"
    APT_MARK = "apt_mark"
    RESET_APT_LISTS = "reset_apt_lists"
    IMPORT_REPO_KEY = "import_repo_key"
    DISABLE_APT_SOURCE = "disable_apt_source"
    WAIT = "wait"
    RETRY_STAGE = "retry_stage"
    ESCALATE = "escalate"


#: Human-readable description of every action, sent to the model verbatim.
ACTION_DOCS: dict[ActionKind, str] = {
    ActionKind.APT_UPDATE: "Run `apt-get update` to refresh package indexes. No parameters.",
    ActionKind.APT_FULL_UPGRADE: "Run `apt-get -y full-upgrade` again. No parameters.",
    ActionKind.APT_UPGRADE: "Run `apt-get -y upgrade --with-new-pkgs`, which never removes packages. No parameters.",
    ActionKind.APT_INSTALL: "Run `apt-get -y install` for `packages`. Use it to satisfy a missing dependency. Names may carry an =version pin or a :arch suffix.",
    ActionKind.APT_REINSTALL: "Run `apt-get -y install --reinstall` for `packages`. Use it for a package with corrupted files.",
    ActionKind.APT_REMOVE: "Run `apt-get -y remove` for `packages` (set `purge` to also delete config files). Last resort; protected and Essential packages are refused.",
    ActionKind.APT_FIX_BROKEN: "Run `apt-get -y -f install` to let apt repair a broken dependency state. No parameters.",
    ActionKind.APT_AUTOREMOVE: "Run `apt-get -y autoremove` to drop no-longer-needed packages. Useful when /boot is full of old kernels.",
    ActionKind.APT_CLEAN: "Run `apt-get clean` to free the downloaded .deb cache in /var/cache/apt/archives. Use it when the disk is full.",
    ActionKind.APT_AUTOCLEAN: "Run `apt-get autoclean` to drop only obsolete .deb files from the cache.",
    ActionKind.DPKG_CONFIGURE_PENDING: "Run `dpkg --configure -a` to finish packages left half-configured by an interrupted run. No parameters.",
    ActionKind.DPKG_AUDIT: "Run `dpkg --audit` to list packages in a broken state. Read-only diagnostic. No parameters.",
    ActionKind.APT_MARK: "Run `apt-mark <mark>` for `packages`, where `mark` is hold, unhold, auto or manual. Hold a package to keep a broken upgrade from being retried.",
    ActionKind.RESET_APT_LISTS: "Delete the cached index files under /var/lib/apt/lists and run `apt-get update`. Use it for corrupted or hash-mismatched indexes. No parameters.",
    ActionKind.IMPORT_REPO_KEY: "Import the OpenPGP keys in `key_ids` from `keyserver` into /etc/apt/keyrings. Use it for NO_PUBKEY errors. Disabled by default in the local policy.",
    ActionKind.DISABLE_APT_SOURCE: "Comment out every apt source line in `source_file` that refers to `source_uri`, after backing the file up. Use it for a third-party repository that is permanently 404 or unsigned. Disabled by default in the local policy.",
    ActionKind.WAIT: "Sleep `seconds` (max 600) and then continue. Use it when another package manager holds the dpkg lock.",
    ActionKind.RETRY_STAGE: "Do nothing extra and simply retry the failed stage. Use it for a transient network error.",
    ActionKind.ESCALATE: "Stop and hand the problem to a human. Use it when the fix needs judgement, a reboot, hardware attention or anything outside this vocabulary.",
}

#: Which actions each stage may propose.
STAGE_ACTIONS: dict[str, tuple[ActionKind, ...]] = {
    "update": (
        ActionKind.APT_UPDATE,
        ActionKind.RESET_APT_LISTS,
        ActionKind.IMPORT_REPO_KEY,
        ActionKind.DISABLE_APT_SOURCE,
        ActionKind.APT_CLEAN,
        ActionKind.APT_AUTOCLEAN,
        ActionKind.WAIT,
        ActionKind.RETRY_STAGE,
        ActionKind.ESCALATE,
    ),
    "full_upgrade": (
        ActionKind.APT_FIX_BROKEN,
        ActionKind.DPKG_CONFIGURE_PENDING,
        ActionKind.DPKG_AUDIT,
        ActionKind.APT_INSTALL,
        ActionKind.APT_REINSTALL,
        ActionKind.APT_REMOVE,
        ActionKind.APT_MARK,
        ActionKind.APT_AUTOREMOVE,
        ActionKind.APT_CLEAN,
        ActionKind.APT_AUTOCLEAN,
        ActionKind.APT_UPDATE,
        ActionKind.APT_UPGRADE,
        ActionKind.WAIT,
        ActionKind.RETRY_STAGE,
        ActionKind.ESCALATE,
    ),
    "autoremove": (
        ActionKind.APT_FIX_BROKEN,
        ActionKind.DPKG_CONFIGURE_PENDING,
        ActionKind.DPKG_AUDIT,
        ActionKind.APT_MARK,
        ActionKind.APT_AUTOREMOVE,
        ActionKind.WAIT,
        ActionKind.RETRY_STAGE,
        ActionKind.ESCALATE,
    ),
    "autoclean": (
        ActionKind.APT_CLEAN,
        ActionKind.APT_AUTOCLEAN,
        ActionKind.WAIT,
        ActionKind.RETRY_STAGE,
        ActionKind.ESCALATE,
    ),
}

VALID_MARKS = ("hold", "unhold", "auto", "manual")
RISK_LEVELS = ("low", "medium", "high")
MAX_WAIT_SECONDS = 600

#: Debian policy 5.6.1 package names, optionally with a :arch qualifier and an
#: =version pin.  Deliberately strict: no whitespace, no slashes, no shell
#: metacharacters can survive this.
PACKAGE_RE = re.compile(r"^[a-z0-9][a-z0-9+.\-]{1,127}(:[a-zA-Z0-9][a-zA-Z0-9\-]{0,31})?(=[A-Za-z0-9][A-Za-z0-9.+:~\-]{0,63})?$")
KEY_ID_RE = re.compile(r"^(0x)?[0-9A-Fa-f]{8,40}$")
KEYSERVER_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9.\-]{0,253}[a-zA-Z0-9])?$")


@dataclass
class Action:
    """One typed remediation step proposed by the model."""

    kind: ActionKind
    reason: str = ""
    risk: str = "medium"
    packages: list[str] = field(default_factory=list)
    purge: bool = False
    mark: str = ""
    seconds: int = 0
    key_ids: list[str] = field(default_factory=list)
    keyserver: str = ""
    source_file: str = ""
    source_uri: str = ""

    def describe(self) -> str:
        bits = [self.kind.value]
        if self.packages:
            bits.append("packages=" + ",".join(self.packages))
        if self.mark:
            bits.append(f"mark={self.mark}")
        if self.purge:
            bits.append("purge=true")
        if self.seconds:
            bits.append(f"seconds={self.seconds}")
        if self.key_ids:
            bits.append("keys=" + ",".join(self.key_ids))
        if self.keyserver:
            bits.append(f"keyserver={self.keyserver}")
        if self.source_file:
            bits.append(f"file={self.source_file}")
        if self.source_uri:
            bits.append(f"uri={self.source_uri}")
        return " ".join(bits)

    def to_dict(self) -> dict:
        data = {"action": self.kind.value, "reason": self.reason, "risk": self.risk}
        for key in ("packages", "purge", "mark", "seconds", "key_ids", "keyserver",
                    "source_file", "source_uri"):
            value = getattr(self, key)
            if value:
                data[key] = value
        return data


@dataclass
class Plan:
    """What the model returned for one failed stage."""

    diagnosis: str = ""
    confidence: str = "medium"
    actions: list[Action] = field(default_factory=list)
    escalate: bool = False
    escalation_reason: str = ""
    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "diagnosis": self.diagnosis,
            "confidence": self.confidence,
            "escalate": self.escalate,
            "escalation_reason": self.escalation_reason,
            "actions": [a.to_dict() for a in self.actions],
        }


def plan_schema(allowed: tuple[ActionKind, ...]) -> dict:
    """JSON Schema for ``output_config.format`` restricted to ``allowed``."""
    return {
        "type": "object",
        "properties": {
            "diagnosis": {
                "type": "string",
                "description": "One paragraph: the most likely root cause of the failure.",
            },
            "confidence": {"type": "string", "enum": list(RISK_LEVELS)},
            "escalate": {
                "type": "boolean",
                "description": "True when no action in the vocabulary can fix this safely.",
            },
            "escalation_reason": {
                "type": "string",
                "description": "Required when escalate is true: what a human needs to do.",
            },
            "actions": {
                "type": "array",
                "maxItems": 8,
                "description": "Ordered remediation steps. Empty when escalate is true.",
                "items": {
                    "type": "object",
                    "properties": {
                        "action": {"type": "string", "enum": [a.value for a in allowed]},
                        "reason": {"type": "string", "description": "Why this step helps."},
                        "risk": {"type": "string", "enum": list(RISK_LEVELS)},
                        "packages": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Package names for install/reinstall/remove/apt_mark.",
                        },
                        "purge": {"type": "boolean", "description": "apt_remove only."},
                        "mark": {"type": "string", "enum": list(VALID_MARKS),
                                 "description": "apt_mark only."},
                        "seconds": {"type": "integer", "description": "wait only, 1-600."},
                        "key_ids": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "import_repo_key only: hex OpenPGP key ids.",
                        },
                        "keyserver": {"type": "string",
                                      "description": "import_repo_key only: keyserver hostname."},
                        "source_file": {"type": "string",
                                        "description": "disable_apt_source only: path under /etc/apt."},
                        "source_uri": {"type": "string",
                                       "description": "disable_apt_source only: repository URI to comment out."},
                    },
                    "required": ["action", "reason", "risk"],
                    "additionalProperties": False,
                },
            },
        },
        "required": ["diagnosis", "confidence", "escalate", "actions"],
        "additionalProperties": False,
    }


def parse_plan(payload: dict) -> Plan:
    """Turn the decoded JSON answer into a :class:`Plan`.

    Shape validation only -- whether an action is *permitted* is decided by
    :mod:`aptai.policy`, never here.
    """
    if not isinstance(payload, dict):
        raise PlanParseError(f"expected a JSON object, got {type(payload).__name__}")

    plan = Plan(
        diagnosis=_as_str(payload.get("diagnosis"), "diagnosis"),
        confidence=_as_str(payload.get("confidence") or "medium", "confidence").lower(),
        escalate=bool(payload.get("escalate", False)),
        escalation_reason=_as_str(payload.get("escalation_reason") or "", "escalation_reason"),
        raw=payload,
    )
    if plan.confidence not in RISK_LEVELS:
        plan.confidence = "medium"

    raw_actions = payload.get("actions") or []
    if not isinstance(raw_actions, list):
        raise PlanParseError("actions must be an array")
    for index, item in enumerate(raw_actions):
        plan.actions.append(_parse_action(item, index))
    return plan


def _parse_action(item, index: int) -> Action:
    where = f"actions[{index}]"
    if not isinstance(item, dict):
        raise PlanParseError(f"{where} must be an object")
    name = item.get("action")
    if not isinstance(name, str):
        raise PlanParseError(f"{where}.action is missing")
    try:
        kind = ActionKind(name.strip().lower())
    except ValueError as exc:
        raise PlanParseError(f"{where}.action is not a known action: {name!r}") from exc

    risk = _as_str(item.get("risk") or "medium", f"{where}.risk").lower()
    if risk not in RISK_LEVELS:
        risk = "high"  # an unparseable risk level is treated as the worst case
    return Action(
        kind=kind,
        reason=_as_str(item.get("reason") or "", f"{where}.reason")[:500],
        risk=risk,
        packages=_as_str_list(item.get("packages"), f"{where}.packages"),
        purge=bool(item.get("purge", False)),
        mark=_as_str(item.get("mark") or "", f"{where}.mark").lower(),
        seconds=_as_int(item.get("seconds"), f"{where}.seconds"),
        key_ids=_as_str_list(item.get("key_ids"), f"{where}.key_ids"),
        keyserver=_as_str(item.get("keyserver") or "", f"{where}.keyserver"),
        source_file=_as_str(item.get("source_file") or "", f"{where}.source_file"),
        source_uri=_as_str(item.get("source_uri") or "", f"{where}.source_uri"),
    )


def _as_str(value, where: str) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise PlanParseError(f"{where} must be a string")
    return value.strip()


def _as_str_list(value, where: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        raise PlanParseError(f"{where} must be an array of strings")
    out = []
    for item in value:
        if not isinstance(item, str):
            raise PlanParseError(f"{where} must contain only strings")
        item = item.strip()
        if item:
            out.append(item)
    if len(out) > 50:
        raise PlanParseError(f"{where} lists more than 50 entries")
    return out


def _as_int(value, where: str) -> int:
    if value is None or value == "":
        return 0
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PlanParseError(f"{where} must be a number")
    return int(value)


def extract_json_object(text: str) -> dict:
    """Recover a JSON object from a plain-text answer.

    Only used when structured output is disabled or the API rejected the
    schema; the model is asked for bare JSON, but may wrap it in a code fence.
    """
    if not text:
        raise PlanParseError("empty response")
    stripped = text.strip()
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", stripped, re.DOTALL)
    candidates = []
    if fenced:
        candidates.append(fenced.group(1))
    candidates.append(stripped)
    start = stripped.find("{")
    end = stripped.rfind("}")
    if start != -1 and end > start:
        candidates.append(stripped[start:end + 1])
    for candidate in candidates:
        try:
            decoded = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(decoded, dict):
            return decoded
    raise PlanParseError("no JSON object found in the response")
