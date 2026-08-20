"""Collection of the host state that is shown to the model.

Everything gathered here is passed through :func:`aptai.redact.redact` before
it leaves the machine, and ``/etc/apt/auth.conf*`` is never opened at all.
``aptai diagnose`` prints exactly this payload so an administrator can see
what would be uploaded before enabling the LLM at all.
"""

from __future__ import annotations

import glob
import os
import platform
import socket
from dataclasses import dataclass, field

from aptai import aptcmd
from aptai.config import Config
from aptai.pkgfacts import PackageFacts, reboot_required
from aptai.redact import is_forbidden_path, redact
from aptai.sysexec import run_command

MAX_SOURCE_BYTES = 8000


@dataclass
class Diagnostics:
    hostname: str = ""
    os_pretty_name: str = ""
    os_id: str = ""
    os_version_id: str = ""
    kernel: str = ""
    architecture: str = ""
    python_version: str = ""
    apt_version: str = ""
    dpkg_version: str = ""
    disks: list[dict] = field(default_factory=list)
    reboot_required: bool = False
    reboot_packages: str = ""
    held_packages: list[str] = field(default_factory=list)
    dpkg_audit: str = ""
    fix_simulation: str = ""
    upgradable_count: int = -1
    sources: dict[str, str] = field(default_factory=dict)
    dpkg_log_tail: str = ""
    lock_status: str = ""

    def to_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "os": {
                "pretty_name": self.os_pretty_name,
                "id": self.os_id,
                "version_id": self.os_version_id,
            },
            "kernel": self.kernel,
            "architecture": self.architecture,
            "python_version": self.python_version,
            "apt_version": self.apt_version,
            "dpkg_version": self.dpkg_version,
            "disks": self.disks,
            "reboot_required": self.reboot_required,
            "reboot_packages": self.reboot_packages,
            "held_packages": self.held_packages,
            "dpkg_audit": self.dpkg_audit,
            "fix_simulation": self.fix_simulation,
            "upgradable_count": self.upgradable_count,
            "sources": self.sources,
            "dpkg_log_tail": self.dpkg_log_tail,
            "lock_status": self.lock_status,
        }

    def to_text(self) -> str:
        """Compact, human- and model-readable rendering."""
        lines = [
            f"host: {self.hostname}",
            f"os: {self.os_pretty_name} (id={self.os_id}, version_id={self.os_version_id})",
            f"kernel: {self.kernel}  arch: {self.architecture}  python: {self.python_version}",
            f"apt: {self.apt_version}  dpkg: {self.dpkg_version}",
        ]
        for disk in self.disks:
            lines.append(
                f"disk {disk['path']}: {disk['free_mb']} MiB free of {disk['total_mb']} MiB"
            )
        if self.lock_status:
            lines.append(f"lock: {self.lock_status}")
        lines.append(f"reboot required: {self.reboot_required} {self.reboot_packages}".rstrip())
        if self.upgradable_count >= 0:
            lines.append(f"upgradable packages: {self.upgradable_count}")
        if self.held_packages:
            lines.append("held packages: " + ", ".join(self.held_packages[:40]))
        if self.dpkg_audit:
            lines.append("dpkg --audit:\n" + _indent(self.dpkg_audit))
        if self.fix_simulation:
            lines.append("apt-get -s -f install:\n" + _indent(self.fix_simulation))
        if self.sources:
            lines.append("apt sources:")
            for path, content in self.sources.items():
                lines.append(f"  --- {path} ---\n" + _indent(content, "  "))
        if self.dpkg_log_tail:
            lines.append("tail of /var/log/dpkg.log:\n" + _indent(self.dpkg_log_tail))
        return "\n".join(lines)


def _indent(text: str, prefix: str = "  ") -> str:
    return "\n".join(prefix + line for line in (text or "").splitlines())


def read_os_release(path: str = "/etc/os-release") -> dict[str, str]:
    data: dict[str, str] = {}
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                data[key.strip()] = value.strip().strip('"').strip("'")
    except OSError:
        pass
    return data


def collect(config: Config, facts: PackageFacts | None = None, *, deep: bool = True) -> Diagnostics:
    """Gather host state.  ``deep=False`` skips the slower apt queries."""
    os_release = read_os_release()
    diag = Diagnostics(
        hostname=config.general.hostname or socket.gethostname(),
        os_pretty_name=os_release.get("PRETTY_NAME", ""),
        os_id=os_release.get("ID", ""),
        os_version_id=os_release.get("VERSION_ID", ""),
        kernel=platform.release(),
        architecture=platform.machine(),
        python_version=platform.python_version(),
    )
    for path in ("/", "/var", "/boot", "/boot/efi", "/var/cache/apt"):
        space = aptcmd.disk_space(path)
        if space.exists:
            diag.disks.append(space.to_dict())
    diag.reboot_required, diag.reboot_packages = reboot_required()
    lock = aptcmd.probe_dpkg_lock()
    diag.lock_status = lock.describe() if (lock.locked or lock.error) else ""

    version = run_command([aptcmd.APT_GET, "--version"], timeout=30)
    diag.apt_version = version.stdout.splitlines()[0].strip() if version.stdout else ""
    dpkg_version = run_command([aptcmd.DPKG, "--version"], timeout=30)
    diag.dpkg_version = dpkg_version.stdout.splitlines()[0].strip() if dpkg_version.stdout else ""

    if deep:
        audit = run_command([aptcmd.DPKG, "--audit"], timeout=180)
        diag.dpkg_audit = audit.combined_output(4000)
        fix = run_command(
            aptcmd.apt_packages_argv("install", None, simulate=True, extra=("-f",)), timeout=300
        )
        diag.fix_simulation = fix.combined_output(4000)
        upgradable = run_command([aptcmd.APT_GET, "-s", "upgrade"], timeout=300)
        sim = aptcmd.parse_simulation(upgradable.stdout)
        diag.upgradable_count = len(sim.upgrades) if upgradable.ok else -1
        diag.held_packages = facts.held_packages() if facts else []

    if config.privacy.send_sources_list:
        diag.sources = collect_sources()
    diag.dpkg_log_tail = tail_file("/var/log/dpkg.log", config.privacy.dpkg_log_lines)

    if config.privacy.redact:
        diag = _redact_diagnostics(diag)
    return diag


def collect_sources() -> dict[str, str]:
    """Read apt source definitions, minus anything that only holds credentials."""
    paths = ["/etc/apt/sources.list"]
    paths.extend(sorted(glob.glob("/etc/apt/sources.list.d/*.list")))
    paths.extend(sorted(glob.glob("/etc/apt/sources.list.d/*.sources")))
    out: dict[str, str] = {}
    for path in paths:
        if is_forbidden_path(path) or not os.path.isfile(path):
            continue
        try:
            with open(path, encoding="utf-8", errors="replace") as handle:
                content = handle.read(MAX_SOURCE_BYTES)
        except OSError:
            continue
        useful = "\n".join(
            line for line in content.splitlines()
            if line.strip() and not line.strip().startswith("#")
        )
        if useful:
            out[path] = useful
        if len(out) >= 30:
            break
    return out


def tail_file(path: str, lines: int) -> str:
    if lines <= 0 or not os.path.isfile(path) or is_forbidden_path(path):
        return ""
    try:
        with open(path, "rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            block = min(size, max(4096, lines * 200))
            handle.seek(size - block)
            data = handle.read().decode("utf-8", "replace")
    except OSError:
        return ""
    return "\n".join(data.splitlines()[-lines:])


def _redact_diagnostics(diag: Diagnostics) -> Diagnostics:
    diag.dpkg_audit = redact(diag.dpkg_audit)
    diag.fix_simulation = redact(diag.fix_simulation)
    diag.dpkg_log_tail = redact(diag.dpkg_log_tail)
    diag.lock_status = redact(diag.lock_status)
    diag.sources = {path: redact(content) for path, content in diag.sources.items()}
    return diag
