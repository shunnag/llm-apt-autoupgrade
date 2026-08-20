"""Central subprocess wrapper.

Every external program aptai runs goes through :func:`run_command`.  There is
exactly one rule, and it is enforced by the signature: ``argv`` is a list and
``shell=False`` is hard-coded.  No part of aptai ever builds a command string,
so a package name -- whether it came from a config file or from the language
model -- can never be interpreted as shell syntax.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field

#: Environment forced on every child process.  ``C.UTF-8`` keeps apt/dpkg
#: output parseable, and the frontend variables stop apt, debconf, needrestart
#: and apt-listchanges from trying to open an interactive prompt on a service
#: that has no terminal.
BASE_ENV: dict[str, str] = {
    "DEBIAN_FRONTEND": "noninteractive",
    "DEBIAN_PRIORITY": "critical",
    "APT_LISTCHANGES_FRONTEND": "none",
    "UCF_FORCE_CONFOLD": "1",
    "LC_ALL": "C.UTF-8",
    "LANG": "C.UTF-8",
    "LANGUAGE": "",
}

#: Environment variables that must never be inherited by apt/dpkg children --
#: the API key has no business being visible to maintainer scripts.
SCRUBBED_ENV_KEYS = ("ANTHROPIC_API_KEY", "APTAI_API_KEY", "ANTHROPIC_AUTH_TOKEN")

MAX_CAPTURE_BYTES = 512 * 1024


@dataclass
class CommandResult:
    """Outcome of a single child process."""

    argv: list[str]
    returncode: int
    stdout: str = ""
    stderr: str = ""
    duration: float = 0.0
    timed_out: bool = False
    not_found: bool = False
    extra: dict[str, str] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and not self.not_found

    @property
    def display(self) -> str:
        return " ".join(self.argv)

    def combined_output(self, limit: int = 8000) -> str:
        """stdout+stderr, tail-truncated -- what gets shown to a human or the model."""
        text = (self.stdout or "") + (("\n" + self.stderr) if self.stderr else "")
        text = text.strip()
        if len(text) > limit:
            text = "...[truncated]...\n" + text[-limit:]
        return text

    def to_dict(self) -> dict:
        return {
            "argv": self.argv,
            "returncode": self.returncode,
            "duration": round(self.duration, 3),
            "timed_out": self.timed_out,
            "not_found": self.not_found,
            "stdout": self.stdout,
            "stderr": self.stderr,
        }


def build_env(extra: dict[str, str] | None = None, needrestart_mode: str | None = None) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k not in SCRUBBED_ENV_KEYS}
    env.update(BASE_ENV)
    if needrestart_mode:
        # 'l' = only list services that need a restart, 'a' = restart them.
        env["NEEDRESTART_MODE"] = needrestart_mode
        env["NEEDRESTART_SUSPEND"] = "" if needrestart_mode != "off" else "1"
    if extra:
        env.update(extra)
    return env


def run_command(
    argv: list[str],
    *,
    timeout: float = 600.0,
    env: dict[str, str] | None = None,
    cwd: str | None = None,
    stdin_text: str | None = None,
) -> CommandResult:
    """Run ``argv`` without a shell and capture its output.

    Never raises for a non-zero exit status; inspect :attr:`CommandResult.ok`.
    """
    if not argv or not all(isinstance(a, str) for a in argv):
        raise ValueError("argv must be a non-empty list of strings")
    started = time.monotonic()
    try:
        proc = subprocess.run(  # noqa: S603 - shell=False, argv is a validated list
            argv,
            shell=False,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            env=env if env is not None else build_env(),
            cwd=cwd,
            input=stdin_text,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            argv=list(argv),
            returncode=124,
            stdout=_as_text(exc.stdout),
            stderr=_as_text(exc.stderr) + f"\n[aptai] timed out after {timeout:.0f}s",
            duration=time.monotonic() - started,
            timed_out=True,
        )
    except FileNotFoundError:
        return CommandResult(
            argv=list(argv),
            returncode=127,
            stderr=f"[aptai] executable not found: {argv[0]}",
            duration=time.monotonic() - started,
            not_found=True,
        )
    except OSError as exc:  # permission denied, ENOMEM, ...
        return CommandResult(
            argv=list(argv),
            returncode=126,
            stderr=f"[aptai] failed to execute {argv[0]}: {exc}",
            duration=time.monotonic() - started,
        )
    return CommandResult(
        argv=list(argv),
        returncode=proc.returncode,
        stdout=_truncate(proc.stdout),
        stderr=_truncate(proc.stderr),
        duration=time.monotonic() - started,
    )


def have(program: str) -> bool:
    """True when ``program`` exists on PATH."""
    return shutil.which(program) is not None


def _as_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def _truncate(text: str | None) -> str:
    text = text or ""
    if len(text) > MAX_CAPTURE_BYTES:
        return "...[truncated]...\n" + text[-MAX_CAPTURE_BYTES:]
    return text
