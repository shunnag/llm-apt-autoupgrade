"""apt/dpkg command construction, simulation parsing and lock probing.

Kept separate from :mod:`aptai.executor` so that the parsing of ``apt-get -s``
output -- which is what stops a "fix" from quietly removing half the system --
can be unit tested against captured fixtures without touching a real machine.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

APT_GET = "/usr/bin/apt-get"
APT_MARK = "/usr/bin/apt-mark"
APT_CACHE = "/usr/bin/apt-cache"
DPKG = "/usr/bin/dpkg"
DPKG_QUERY = "/usr/bin/dpkg-query"

DPKG_LOCK_FRONTEND = "/var/lib/dpkg/lock-frontend"
DPKG_LOCK = "/var/lib/dpkg/lock"
APT_LISTS_DIR = "/var/lib/apt/lists"

#: Options forced on every apt-get invocation that touches packages.
#:
#: ``--force-confold`` keeps the administrator's existing configuration file
#: when a package ships a changed one, and ``--force-confdef`` lets dpkg take
#: the package default where the admin never edited the file.  This pair is
#: the conservative choice: an unattended run must never overwrite local
#: configuration, and it must never stop to ask.
DPKG_OPTIONS = (
    "-o", "Dpkg::Options::=--force-confdef",
    "-o", "Dpkg::Options::=--force-confold",
    "-o", "Dpkg::Use-Pty=0",
    "-o", "APT::Get::Assume-Yes=true",
    "-o", "Acquire::Retries=3",
)

_SECTION_HEADERS = {
    "removed": re.compile(r"^The following packages will be REMOVED:"),
    "new": re.compile(r"^The following NEW packages will be installed:"),
    "upgraded": re.compile(r"^The following packages will be upgraded:"),
    "downgraded": re.compile(r"^The following packages will be DOWNGRADED:"),
    "held": re.compile(r"^The following packages have been kept back:"),
}
_SUMMARY_RE = re.compile(
    r"^(\d+) upgraded, (\d+) newly installed, (?:(\d+) reinstalled, )?(?:(\d+) downgraded, )?"
    r"(\d+) to remove and (\d+) not upgraded\.?"
)
_REMV_RE = re.compile(r"^Remv\s+(\S+)")
_INST_RE = re.compile(r"^Inst\s+(\S+)")


@dataclass
class Simulation:
    """What ``apt-get -s`` says a command would do."""

    removals: list[str] = field(default_factory=list)
    new_installs: list[str] = field(default_factory=list)
    upgrades: list[str] = field(default_factory=list)
    downgrades: list[str] = field(default_factory=list)
    held_back: list[str] = field(default_factory=list)
    summary: str = ""
    parsed_summary: bool = False

    @property
    def removal_count(self) -> int:
        return len(self.removals)

    def to_dict(self) -> dict:
        return {
            "removals": self.removals,
            "new_installs": self.new_installs,
            "upgrades": self.upgrades,
            "downgrades": self.downgrades,
            "held_back": self.held_back,
            "summary": self.summary,
        }


def base_apt_argv(subcommand: str, *, simulate: bool = False, extra: tuple[str, ...] = ()) -> list[str]:
    argv = [APT_GET]
    if simulate:
        argv.append("-s")
    else:
        argv.append("-y")
    argv.extend(DPKG_OPTIONS)
    argv.extend(extra)
    argv.append(subcommand)
    return argv


def apt_update_argv() -> list[str]:
    return [APT_GET, "-y", "-o", "Dpkg::Use-Pty=0", "-o", "Acquire::Retries=3", "update"]


def apt_packages_argv(
    subcommand: str,
    packages: list[str] | None = None,
    *,
    simulate: bool = False,
    extra: tuple[str, ...] = (),
) -> list[str]:
    """Build ``apt-get [-s|-y] <opts> <subcommand> [packages...]``.

    ``packages`` must already have passed :data:`aptai.plan.PACKAGE_RE`; the
    regex forbids a leading ``-`` so a name can never be read as an option.
    """
    argv = base_apt_argv(subcommand, simulate=simulate, extra=extra)
    for package in packages or []:
        if package.startswith("-"):
            raise ValueError(f"refusing to pass option-like package name {package!r}")
        argv.append(package)
    return argv


def apt_mark_argv(mark: str, packages: list[str]) -> list[str]:
    if mark not in ("hold", "unhold", "auto", "manual", "showhold"):
        raise ValueError(f"unsupported apt-mark subcommand {mark!r}")
    argv = [APT_MARK, mark]
    for package in packages:
        if package.startswith("-"):
            raise ValueError(f"refusing to pass option-like package name {package!r}")
        argv.append(package)
    return argv


def parse_simulation(output: str) -> Simulation:
    """Parse the plan section and the ``Remv``/``Inst`` lines of ``apt-get -s``."""
    sim = Simulation()
    current: list[str] | None = None
    targets = {
        "removed": sim.removals,
        "new": sim.new_installs,
        "upgraded": sim.upgrades,
        "downgraded": sim.downgrades,
        "held": sim.held_back,
    }
    for raw_line in (output or "").splitlines():
        line = raw_line.rstrip()
        if not line:
            current = None
            continue
        matched_header = False
        for key, pattern in _SECTION_HEADERS.items():
            if pattern.match(line):
                current = targets[key]
                matched_header = True
                break
        if matched_header:
            continue
        if line.startswith((" ", "\t")) and current is not None:
            current.extend(_split_packages(line))
            continue
        current = None
        summary = _SUMMARY_RE.match(line)
        if summary:
            sim.summary = line.strip()
            sim.parsed_summary = True
            continue
        remv = _REMV_RE.match(line)
        if remv:
            _add_unique(sim.removals, remv.group(1))
            continue
        inst = _INST_RE.match(line)
        if inst and inst.group(1) not in sim.upgrades:
            _add_unique(sim.new_installs, inst.group(1))
    # A package can appear both as an upgrade and in an Inst line; keep the
    # lists disjoint so that counts are not double reported.
    sim.new_installs = [p for p in sim.new_installs if p not in sim.upgrades and p not in sim.downgrades]
    return sim


def _split_packages(line: str) -> list[str]:
    out = []
    for token in line.split():
        token = token.strip().strip(",")
        # apt annotates some entries, e.g. "libfoo*" for purge or "(due to ...)".
        if not token or token.startswith("("):
            continue
        out.append(token.rstrip("*"))
    return out


def _add_unique(target: list[str], value: str) -> None:
    if value not in target:
        target.append(value)


@dataclass
class LockStatus:
    locked: bool
    path: str = ""
    holders: list[str] = field(default_factory=list)
    error: str = ""

    def describe(self) -> str:
        if not self.locked:
            return "dpkg lock is free"
        who = "; ".join(self.holders) if self.holders else "unknown process"
        return f"dpkg lock held ({self.path}) by {who}"


def probe_dpkg_lock() -> LockStatus:
    """Test whether another package manager holds the dpkg locks.

    apt and dpkg use POSIX record locks (``fcntl(F_SETLK)``), which
    :func:`fcntl.lockf` maps onto.  The lock is taken non-blocking and
    released immediately -- aptai only *probes*; it never holds the lock while
    apt-get runs, and it never deletes a lock file.
    """
    import fcntl

    for path in (DPKG_LOCK_FRONTEND, DPKG_LOCK):
        if not os.path.exists(path):
            continue
        try:
            fd = os.open(path, os.O_RDWR)
        except PermissionError:
            return LockStatus(locked=False, path=path, error="not enough privileges to probe the lock")
        except OSError as exc:
            return LockStatus(locked=False, path=path, error=str(exc))
        try:
            fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return LockStatus(locked=True, path=path, holders=find_package_manager_processes())
        else:
            try:
                fcntl.lockf(fd, fcntl.LOCK_UN)
            except OSError:
                pass
        finally:
            os.close(fd)
    return LockStatus(locked=False)


_PM_MARKERS = (
    "apt-get", "aptitude", "/usr/bin/apt", "unattended-upgrade", "dpkg",
    "synaptic", "packagekitd", "apt.systemd.daily", "apt-fast",
)


def find_package_manager_processes(exclude_pid: int | None = None) -> list[str]:
    """Best-effort list of other package managers currently running."""
    exclude_pid = exclude_pid if exclude_pid is not None else os.getpid()
    found: list[str] = []
    try:
        entries = os.listdir("/proc")
    except OSError:
        return found
    for entry in entries:
        if not entry.isdigit():
            continue
        pid = int(entry)
        if pid == exclude_pid:
            continue
        try:
            with open(f"/proc/{entry}/cmdline", "rb") as handle:
                raw = handle.read()
        except OSError:
            continue
        cmdline = raw.replace(b"\x00", b" ").decode("utf-8", "replace").strip()
        if not cmdline:
            continue
        lowered = cmdline.lower()
        if any(marker in lowered for marker in _PM_MARKERS):
            found.append(f"pid {pid}: {cmdline[:160]}")
        if len(found) >= 10:
            break
    return found


@dataclass
class DiskSpace:
    path: str
    total_mb: int
    free_mb: int
    exists: bool = True

    def to_dict(self) -> dict:
        return {"path": self.path, "total_mb": self.total_mb, "free_mb": self.free_mb}


def disk_space(path: str) -> DiskSpace:
    """Free space in MiB for the filesystem holding ``path``."""
    if not os.path.exists(path):
        return DiskSpace(path=path, total_mb=0, free_mb=0, exists=False)
    try:
        stat = os.statvfs(path)
    except OSError:
        return DiskSpace(path=path, total_mb=0, free_mb=0, exists=False)
    block = stat.f_frsize or stat.f_bsize
    return DiskSpace(
        path=path,
        total_mb=int(stat.f_blocks * block / (1024 * 1024)),
        free_mb=int(stat.f_bavail * block / (1024 * 1024)),
    )
