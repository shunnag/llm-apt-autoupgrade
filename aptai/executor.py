"""Execution of apt stages and of policy-approved actions.

This is the second, independent safety layer.  Even after :mod:`aptai.policy`
has approved an action, every destructive apt operation is first run with
``-s`` (simulate) and the resulting plan is inspected:

* if apt would remove a protected, Essential or running-kernel package, the
  operation is abandoned;
* if it would remove more packages than the configured ceiling, the operation
  is abandoned (or degraded to a removal-free ``apt-get upgrade``);
* if it would downgrade packages and downgrades are not allowed, it is
  abandoned.

That check does not depend on the model having been honest about what its
action does -- it asks apt itself.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import time
import urllib.parse
from dataclasses import dataclass, field

from aptai import aptcmd
from aptai.config import Config
from aptai.plan import Action, ActionKind
from aptai.policy import Policy, validate_source_path
from aptai.sysexec import CommandResult, build_env, have, run_command

LOG = logging.getLogger("aptai.executor")

KEYRING_DIR = "/etc/apt/trusted.gpg.d"
BACKUP_SUBDIR = "backups"


@dataclass
class OperationResult:
    """Outcome of one apt/dpkg operation or one remediation action."""

    name: str
    success: bool = False
    message: str = ""
    aborted_by_policy: bool = False
    degraded: bool = False
    changed: bool = False
    simulation: aptcmd.Simulation | None = None
    commands: list[CommandResult] = field(default_factory=list)

    @property
    def error_text(self) -> str:
        """The text handed to the model when this operation failed."""
        if self.aborted_by_policy:
            return f"[aptai policy] {self.message}"
        parts = [self.message] if self.message else []
        for command in self.commands:
            output = command.combined_output()
            if output:
                parts.append(f"$ {command.display}\n(exit {command.returncode})\n{output}")
        return "\n\n".join(parts).strip()

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "success": self.success,
            "message": self.message,
            "aborted_by_policy": self.aborted_by_policy,
            "degraded": self.degraded,
            "changed": self.changed,
            "simulation": self.simulation.to_dict() if self.simulation else None,
            "commands": [c.to_dict() for c in self.commands],
        }


class Executor:
    """Runs apt stages and typed remediation actions."""

    def __init__(self, config: Config, policy: Policy, *, dry_run: bool = False):
        self.config = config
        self.policy = policy
        self.dry_run = dry_run or config.general.dry_run
        self.env = build_env(needrestart_mode=config.apt.needrestart_mode)
        self.timeout = float(config.apt.command_timeout)
        #: Output of the stage that failed; used to confirm that a key import
        #: or a source edit repairs something apt actually complained about.
        self.stage_error_text = ""

    # ------------------------------------------------------------ primitives

    def _run(self, argv: list[str], *, timeout: float | None = None) -> CommandResult:
        if not os.path.exists(argv[0]) and not have(os.path.basename(argv[0])):
            return CommandResult(argv=argv, returncode=127, not_found=True,
                                 stderr=f"[aptai] {argv[0]} is not installed")
        LOG.debug("running: %s", " ".join(argv))
        return run_command(argv, timeout=timeout or self.timeout, env=self.env)

    def _simulate(self, argv: list[str]) -> tuple[CommandResult, aptcmd.Simulation]:
        result = self._run(argv, timeout=min(self.timeout, 900.0))
        return result, aptcmd.parse_simulation(result.stdout + "\n" + result.stderr)

    def _review_simulation(
        self, sim: aptcmd.Simulation, *, removal_limit: int, install_limit: int = -1
    ) -> str | None:
        """Return a refusal message when apt's own plan is unacceptable."""
        if not sim.parsed_summary:
            # apt-get -s always ends with "N upgraded, N newly installed, ...".
            # Without it we did not understand the plan, and an unreadable plan
            # must not be executed.
            return "apt's simulation output could not be parsed, so its plan is unknown"
        hits = self.policy.protected_hits(sim.removals)
        if hits:
            listed = "; ".join(f"{name} ({why})" for name, why in hits[:6])
            return f"apt's plan removes protected packages: {listed}"
        if removal_limit >= 0 and sim.removal_count > removal_limit:
            return (
                f"apt's plan removes {sim.removal_count} packages "
                f"({', '.join(sim.removals[:10])}{'...' if sim.removal_count > 10 else ''}), "
                f"over the configured limit of {removal_limit}"
            )
        if install_limit >= 0 and len(sim.new_installs) > install_limit:
            return (
                f"apt's plan installs {len(sim.new_installs)} new packages, over the "
                f"configured limit of {install_limit}"
            )
        if sim.downgrades and not self.config.policy.allow_downgrade:
            return f"apt's plan downgrades {', '.join(sim.downgrades[:10])}"
        return None

    def _guarded(
        self,
        name: str,
        subcommand: str,
        packages: list[str] | None = None,
        *,
        removal_limit: int,
        install_limit: int = -1,
        extra: tuple[str, ...] = (),
    ) -> OperationResult:
        """Simulate, review, then run an apt-get subcommand."""
        out = OperationResult(name=name)
        sim_argv = aptcmd.apt_packages_argv(subcommand, packages, simulate=True, extra=extra)
        sim_result, sim = self._simulate(sim_argv)
        out.commands.append(sim_result)
        out.simulation = sim
        if not sim_result.ok:
            out.message = f"{name}: apt-get -s {subcommand} failed, nothing was executed"
            return out

        refusal = self._review_simulation(
            sim, removal_limit=removal_limit, install_limit=install_limit
        )
        if refusal:
            out.aborted_by_policy = True
            out.message = f"{name}: {refusal}"
            LOG.error("%s", out.message)
            return out

        if self.dry_run:
            out.success = True
            out.message = f"{name}: dry-run, simulation only ({sim.summary or 'no changes'})"
            return out

        real_argv = aptcmd.apt_packages_argv(subcommand, packages, simulate=False, extra=extra)
        real_result = self._run(real_argv)
        out.commands.append(real_result)
        out.success = real_result.ok
        out.changed = bool(sim.removals or sim.new_installs or sim.upgrades or sim.downgrades)
        out.message = f"{name}: {'ok' if out.success else 'failed'} ({sim.summary or 'no changes'})"
        return out

    # ---------------------------------------------------------------- stages

    def apt_update(self) -> OperationResult:
        out = OperationResult(name="apt-get update")
        if self.dry_run:
            out.success = True
            out.message = "apt-get update: skipped (dry-run)"
            return out
        result = self._run(aptcmd.apt_update_argv())
        out.commands.append(result)
        out.success = result.ok
        if out.success and self.config.apt.fail_on_partial_update:
            # apt-get update exits 0 even when individual repositories fail.
            # Scan the untruncated output: the acquisition progress on stdout
            # can be long enough that a tail would drop the summary lines.
            failures = partial_update_failures(result.stdout + "\n" + result.stderr)
            if failures:
                out.success = False
                out.message = (
                    "apt-get update: some repositories could not be refreshed ("
                    + "; ".join(failures[:4])
                    + ")"
                )
                return out
        out.message = "apt-get update: ok" if out.success else "apt-get update: failed"
        return out

    def apt_full_upgrade(self) -> OperationResult:
        limit = self.config.apt.max_upgrade_removals
        policy_on_excess = self.config.apt.on_excessive_removals
        effective_limit = -1 if policy_on_excess == "proceed" else limit
        out = self._guarded("full-upgrade", "full-upgrade", removal_limit=effective_limit)
        if out.aborted_by_policy and policy_on_excess == "fallback_upgrade" and not self._is_protected_abort(out):
            LOG.warning("%s -- falling back to a removal-free upgrade", out.message)
            fallback = self.apt_upgrade_safe()
            fallback.degraded = True
            fallback.message = (
                f"full-upgrade withheld ({out.message}); ran removal-free upgrade instead: "
                f"{fallback.message}"
            )
            fallback.commands = out.commands + fallback.commands
            return fallback
        return out

    @staticmethod
    def _is_protected_abort(result: OperationResult) -> bool:
        return "protected packages" in (result.message or "")

    def apt_upgrade_safe(self) -> OperationResult:
        """``apt-get upgrade --with-new-pkgs`` never removes an installed package."""
        return self._guarded(
            "upgrade", "upgrade", removal_limit=0, extra=("--with-new-pkgs",)
        )

    def apt_autoremove(self) -> OperationResult:
        extra = ("--purge",) if self.config.apt.autoremove_purge else ()
        return self._guarded(
            "autoremove", "autoremove",
            removal_limit=self.config.apt.max_autoremove_removals,
            extra=extra,
        )

    def apt_autoclean(self) -> OperationResult:
        out = OperationResult(name="autoclean")
        if self.dry_run:
            out.success = True
            out.message = "autoclean: skipped (dry-run)"
            return out
        result = self._run(aptcmd.base_apt_argv("autoclean"))
        out.commands.append(result)
        out.success = result.ok
        out.message = "autoclean: " + ("ok" if result.ok else "failed")
        return out

    def apt_clean(self) -> OperationResult:
        out = OperationResult(name="clean")
        if self.dry_run:
            out.success = True
            out.message = "clean: skipped (dry-run)"
            return out
        result = self._run(aptcmd.base_apt_argv("clean"))
        out.commands.append(result)
        out.success = result.ok
        out.message = "clean: " + ("ok" if result.ok else "failed")
        return out

    def apt_fix_broken(self) -> OperationResult:
        return self._guarded(
            "fix-broken", "install", removal_limit=self.config.policy.max_removals, extra=("-f",)
        )

    def dpkg_configure_pending(self) -> OperationResult:
        out = OperationResult(name="dpkg --configure -a")
        if self.dry_run:
            out.success = True
            out.message = "dpkg --configure -a: skipped (dry-run)"
            return out
        result = self._run([aptcmd.DPKG, "--configure", "-a", "--force-confdef", "--force-confold"])
        out.commands.append(result)
        out.success = result.ok
        out.changed = result.ok
        out.message = "dpkg --configure -a: " + ("ok" if result.ok else "failed")
        return out

    def dpkg_audit(self) -> OperationResult:
        out = OperationResult(name="dpkg --audit")
        result = self._run([aptcmd.DPKG, "--audit"], timeout=180)
        out.commands.append(result)
        out.success = True  # read-only diagnostic; never a failure by itself
        out.message = "dpkg --audit: " + (result.stdout.strip() or "no problems reported")
        return out

    # --------------------------------------------------------------- actions

    def execute(self, action: Action) -> OperationResult:
        """Run one action that :class:`~aptai.policy.Policy` has approved."""
        handlers = {
            ActionKind.APT_UPDATE: lambda a: self.apt_update(),
            ActionKind.APT_FULL_UPGRADE: lambda a: self.apt_full_upgrade(),
            ActionKind.APT_UPGRADE: lambda a: self.apt_upgrade_safe(),
            ActionKind.APT_FIX_BROKEN: lambda a: self.apt_fix_broken(),
            ActionKind.APT_AUTOREMOVE: lambda a: self.apt_autoremove(),
            ActionKind.APT_CLEAN: lambda a: self.apt_clean(),
            ActionKind.APT_AUTOCLEAN: lambda a: self.apt_autoclean(),
            ActionKind.DPKG_CONFIGURE_PENDING: lambda a: self.dpkg_configure_pending(),
            ActionKind.DPKG_AUDIT: lambda a: self.dpkg_audit(),
            ActionKind.APT_INSTALL: self._do_install,
            ActionKind.APT_REINSTALL: self._do_reinstall,
            ActionKind.APT_REMOVE: self._do_remove,
            ActionKind.APT_MARK: self._do_mark,
            ActionKind.RESET_APT_LISTS: self._do_reset_lists,
            ActionKind.IMPORT_REPO_KEY: self._do_import_key,
            ActionKind.DISABLE_APT_SOURCE: self._do_disable_source,
            ActionKind.WAIT: self._do_wait,
            ActionKind.RETRY_STAGE: self._do_retry,
            ActionKind.ESCALATE: self._do_escalate,
        }
        handler = handlers.get(action.kind)
        if handler is None:
            return OperationResult(name=action.kind.value, message="no implementation for this action")
        LOG.info("action: %s", action.describe())
        try:
            return handler(action)
        except ValueError as exc:
            # aptcmd re-validates every argument, so this only fires when the
            # policy let something through. Escalating is the correct outcome;
            # crashing mid-upgrade is not.
            LOG.error("refusing to run %s: %s", action.kind.value, exc)
            return OperationResult(
                name=action.kind.value, aborted_by_policy=True,
                message=f"{action.kind.value} was refused while building the command: {exc}",
            )

    def _do_install(self, action: Action) -> OperationResult:
        # removal_limit=0: an install that turns into a removal is either apt
        # resolving a conflict we did not ask it to resolve, or the trailing-'-'
        # selector trick. Neither may proceed unattended; both escalate.
        return self._guarded(
            f"install {' '.join(action.packages)}", "install", action.packages,
            removal_limit=0, install_limit=self.config.policy.max_new_installs,
        )

    def _do_reinstall(self, action: Action) -> OperationResult:
        return self._guarded(
            f"reinstall {' '.join(action.packages)}", "install", action.packages,
            removal_limit=0, install_limit=self.config.policy.max_new_installs,
            extra=("--reinstall",),
        )

    def _do_remove(self, action: Action) -> OperationResult:
        extra = ("--purge",) if action.purge else ()
        return self._guarded(
            f"remove {' '.join(action.packages)}", "remove", action.packages,
            removal_limit=self.config.policy.max_removals, extra=extra,
        )

    def _do_mark(self, action: Action) -> OperationResult:
        out = OperationResult(name=f"apt-mark {action.mark}")
        if self.dry_run:
            out.success = True
            out.message = f"apt-mark {action.mark} {' '.join(action.packages)}: skipped (dry-run)"
            return out
        result = self._run(aptcmd.apt_mark_argv(action.mark, action.packages), timeout=180)
        out.commands.append(result)
        out.success = result.ok
        out.changed = result.ok
        out.message = f"apt-mark {action.mark}: " + ("ok" if result.ok else "failed")
        return out

    def _do_reset_lists(self, action: Action) -> OperationResult:
        out = OperationResult(name="reset apt lists")
        removed, problem = _purge_directory(aptcmd.APT_LISTS_DIR, dry_run=self.dry_run)
        if problem:
            out.message = f"reset apt lists: {problem}"
            return out
        out.changed = bool(removed)
        out.message = f"reset apt lists: removed {removed} cached index file(s)"
        if self.dry_run:
            out.success = True
            out.message += " (dry-run, nothing deleted)"
            return out
        update = self.apt_update()
        out.commands.extend(update.commands)
        out.success = update.success
        out.message += "; " + update.message
        return out

    def _do_import_key(self, action: Action) -> OperationResult:
        out = OperationResult(name="import repository key")
        if not have("gpg"):
            out.message = "gpg is not installed; install the gnupg package to import repository keys"
            return out
        unseen = [k for k in action.key_ids if not _key_mentioned(k, self.stage_error_text)]
        if unseen:
            out.aborted_by_policy = True
            out.message = (
                "refusing to import key(s) " + ", ".join(unseen)
                + ": apt did not report them as missing in this failure"
            )
            return out
        if self.dry_run:
            out.success = True
            out.message = f"would import {', '.join(action.key_ids)} (dry-run)"
            return out
        allowed = self.config.policy.allowed_keyservers
        keyserver = action.keyserver or (allowed[0] if allowed else "")
        if not keyserver:
            out.aborted_by_policy = True
            out.message = "no keyserver given and policy.allowed_keyservers is empty"
            return out
        try:
            os.makedirs(KEYRING_DIR, mode=0o755, exist_ok=True)
        except OSError as exc:
            out.message = f"cannot create {KEYRING_DIR}: {exc}"
            return out
        for key_id in action.key_ids:
            safe_id = re.sub(r"[^0-9A-Fa-f]", "", key_id)[-16:]
            keyring = os.path.join(KEYRING_DIR, f"aptai-{safe_id}.gpg")
            result = self._run(
                [
                    "gpg", "--batch", "--no-default-keyring", "--no-tty",
                    "--keyring", keyring,
                    "--keyserver", keyserver,
                    "--recv-keys", key_id,
                ],
                timeout=180,
            )
            out.commands.append(result)
            if not result.ok:
                out.message = f"failed to fetch key {key_id} from {keyserver}"
                return out
            try:
                os.chmod(keyring, 0o644)
            except OSError:
                pass
        out.success = True
        out.changed = True
        out.message = f"imported {', '.join(action.key_ids)} from {keyserver} into {KEYRING_DIR}"
        return out

    def _do_disable_source(self, action: Action) -> OperationResult:
        out = OperationResult(name="disable apt source")
        problem = validate_source_path(action.source_file)
        if problem:
            out.aborted_by_policy = True
            out.message = problem
            return out
        host = _uri_host(action.source_uri)
        if not host:
            out.aborted_by_policy = True
            out.message = f"{action.source_uri!r} has no usable host"
            return out
        if host not in _hosts_in(self.stage_error_text):
            out.aborted_by_policy = True
            out.message = (
                f"refusing to disable {host}: apt did not report an error for that host "
                "in this failure"
            )
            return out
        try:
            with open(action.source_file, encoding="utf-8", errors="replace") as handle:
                original = handle.read()
        except OSError as exc:
            out.message = f"cannot read {action.source_file}: {exc}"
            return out

        updated, changed = _comment_out_uri(original, action.source_uri)
        if not changed:
            out.message = f"{action.source_file} contains no active entry for {action.source_uri}"
            return out
        if self.dry_run:
            out.success = True
            out.message = f"would comment out {action.source_uri} in {action.source_file} (dry-run)"
            return out
        backup_dir = os.path.join(self.config.general.state_dir, BACKUP_SUBDIR)
        try:
            os.makedirs(backup_dir, mode=0o750, exist_ok=True)
            stamp = time.strftime("%Y%m%dT%H%M%S", time.gmtime())
            backup = os.path.join(
                backup_dir, f"{os.path.basename(action.source_file)}.{stamp}.bak"
            )
            shutil.copy2(action.source_file, backup)
            _atomic_write(action.source_file, updated)
        except OSError as exc:
            out.message = f"cannot rewrite {action.source_file}: {exc}"
            return out
        out.success = True
        out.changed = True
        out.message = (
            f"commented out {action.source_uri} in {action.source_file} (backup: {backup})"
        )
        return out

    def _do_wait(self, action: Action) -> OperationResult:
        seconds = max(1, min(action.seconds, 600))
        out = OperationResult(name=f"wait {seconds}s", success=True)
        if self.dry_run:
            out.message = f"would wait {seconds}s (dry-run)"
            return out
        LOG.info("waiting %ss before retrying", seconds)
        time.sleep(seconds)
        out.message = f"waited {seconds}s"
        return out

    def _do_retry(self, action: Action) -> OperationResult:
        return OperationResult(name="retry stage", success=True, message="retrying the stage")

    def _do_escalate(self, action: Action) -> OperationResult:
        return OperationResult(
            name="escalate", success=False,
            message=action.reason or "the model asked for human intervention",
        )


# ------------------------------------------------------------------ helpers


def _purge_directory(path: str, *, dry_run: bool) -> tuple[int, str | None]:
    """Delete the regular files directly under ``path`` (and its ``partial`` dir)."""
    if os.path.islink(path):
        return 0, f"{path} is a symlink; refusing to touch it"
    if not os.path.isdir(path):
        return 0, f"{path} is not a directory"
    real_root = os.path.realpath(path)
    count = 0
    for directory in (path, os.path.join(path, "partial")):
        if not os.path.isdir(directory) or os.path.islink(directory):
            continue
        try:
            entries = list(os.scandir(directory))
        except OSError as exc:
            return count, f"cannot list {directory}: {exc}"
        for entry in entries:
            if entry.is_dir(follow_symlinks=False):
                continue
            target = os.path.realpath(entry.path)
            if not target.startswith(real_root + os.sep):
                continue
            if entry.name in ("lock", "auxfiles"):
                continue
            count += 1
            if dry_run:
                continue
            try:
                os.unlink(entry.path)
            except OSError:
                pass
    return count, None


def _key_mentioned(key_id: str, error_text: str) -> bool:
    """True when apt's own error names this key (NO_PUBKEY <id>)."""
    if not error_text:
        return False
    digits = re.sub(r"[^0-9A-Fa-f]", "", key_id).upper()
    if len(digits) < 8:
        return False
    haystack = re.sub(r"[^0-9A-Za-z]", "", error_text).upper()
    return digits[-8:] in haystack


def _uri_host(uri: str) -> str:
    """Host of a repository URI, or "" when there is not a usable one.

    Parsed rather than pattern-matched so that ``https://a.b@evil/`` cannot
    pass off ``evil`` as ``a.b``; userinfo is rejected outright because no
    legitimate plan needs it here.
    """
    parsed = urllib.parse.urlsplit(uri or "")
    if parsed.scheme not in ("http", "https", "ftp") or "@" in (parsed.netloc or ""):
        return ""
    host = (parsed.hostname or "").strip().lower()
    if "." not in host or len(host) < 4:
        return ""
    return host


_HOST_RE = re.compile(r"\b(?:https?|ftp)://([^/\s:@]+)", re.IGNORECASE)


def _hosts_in(text: str) -> set[str]:
    """Every repository host named in apt's own output."""
    return {match.group(1).lower() for match in _HOST_RE.finditer(text or "")}


_UPDATE_FAILURE_MARKERS = (
    "Err:",
    "E: ",
    "W: GPG error",
    "W: Failed to fetch",
    "W: Some index files failed to download",
    "W: The repository",
    "W: An error occurred during the signature verification",
)


def partial_update_failures(text: str) -> list[str]:
    """Lines showing that `apt-get update` did not refresh every repository.

    apt exits 0 in that case, so the exit status alone would report a stale
    index -- including a stale security index -- as a success.
    """
    seen: list[str] = []
    for line in (text or "").splitlines():
        stripped = line.strip()
        if stripped.startswith(_UPDATE_FAILURE_MARKERS) and stripped not in seen:
            seen.append(stripped[:300])
    return seen


def _comment_out_uri(content: str, uri: str) -> tuple[str, bool]:
    """Comment out one-line ``deb`` entries and deb822 stanzas that use ``uri``."""
    lines = content.splitlines(keepends=True)
    changed = False
    out: list[str] = []
    stanza: list[str] = []

    def flush_stanza() -> None:
        nonlocal changed
        if not stanza:
            return
        text = "".join(stanza)
        if uri in text and not all(line.lstrip().startswith("#") for line in stanza if line.strip()):
            changed = True
            out.extend(
                ("# " + line) if line.strip() and not line.lstrip().startswith("#") else line
                for line in stanza
            )
        else:
            out.extend(stanza)
        stanza.clear()

    is_deb822 = any(line.startswith(("Types:", "URIs:")) for line in lines)
    if is_deb822:
        for line in lines:
            if not line.strip():
                flush_stanza()
                out.append(line)
            else:
                stanza.append(line)
        flush_stanza()
        return "".join(out), changed

    for line in lines:
        stripped = line.lstrip()
        if stripped.startswith("#") or not stripped.strip():
            out.append(line)
            continue
        # apt's sources.list parser splits on arbitrary whitespace, so match on
        # the first token rather than on a "deb " prefix.
        first = stripped.split(None, 1)[0]
        is_entry = first in ("deb", "deb-src") or first.startswith(("deb[", "deb-src["))
        if is_entry and uri in line:
            out.append("# " + line)
            changed = True
        else:
            out.append(line)
    return "".join(out), changed


def _atomic_write(path: str, content: str) -> None:
    tmp = path + ".aptai.tmp"
    try:
        stat = os.stat(path)
        mode = stat.st_mode & 0o777
    except OSError:
        mode = 0o644
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, path)
