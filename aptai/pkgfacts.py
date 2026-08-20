"""Facts about installed packages, used by the safety policy.

Everything here is read-only.  The data is collected once per run with a
single ``dpkg-query`` call so that the policy can answer "is this package
essential?" without shelling out per package.
"""

from __future__ import annotations

import os
import platform
import re
from dataclasses import dataclass, field

from aptai.sysexec import run_command

_STRIP_RE = re.compile(r"^([^=:\s]+)")


def base_name(package: str) -> str:
    """``libfoo:amd64=1.2-3`` -> ``libfoo``."""
    match = _STRIP_RE.match(package.strip())
    return match.group(1) if match else package.strip()


@dataclass
class PackageInfo:
    name: str
    essential: bool = False
    priority: str = ""
    status: str = ""
    version: str = ""

    @property
    def installed(self) -> bool:
        # dpkg-query ${Status} is "<want> <error> <state>", e.g. "install ok installed".
        state = self.status.split()[-1] if self.status else ""
        return state in ("installed", "half-configured", "half-installed", "unpacked")


@dataclass
class PackageFacts:
    """Snapshot of the local dpkg database plus the running kernel."""

    packages: dict[str, PackageInfo] = field(default_factory=dict)
    kernel_release: str = ""
    collected: bool = False

    @classmethod
    def collect(cls, *, timeout: float = 120.0) -> "PackageFacts":
        facts = cls(kernel_release=platform.release())
        result = run_command(
            [
                "dpkg-query",
                "-W",
                "-f=${Package}\\t${Essential}\\t${Priority}\\t${Status}\\t${Version}\\n",
            ],
            timeout=timeout,
        )
        if not result.ok:
            # A partial or failed dpkg-query must not look like an empty but
            # healthy system: the policy fails closed on collected=False.
            return facts
        for line in result.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) < 4:
                continue
            name, essential, priority, status = parts[0], parts[1], parts[2], parts[3]
            version = parts[4] if len(parts) > 4 else ""
            facts.packages[name] = PackageInfo(
                name=name,
                essential=essential.strip().lower() == "yes",
                priority=priority.strip().lower(),
                status=status.strip(),
                version=version.strip(),
            )
        # A dpkg database with a handful of entries is a corrupt one, not a
        # minimal install: even debootstrap --variant=minbase gives ~100.
        facts.collected = len(facts.packages) >= 20
        return facts

    def info(self, package: str) -> PackageInfo | None:
        return self.packages.get(base_name(package))

    def is_essential(self, package: str) -> bool:
        info = self.info(package)
        return bool(info and info.essential)

    def is_required_priority(self, package: str) -> bool:
        info = self.info(package)
        return bool(info and info.priority in ("required", "important"))

    def is_installed(self, package: str) -> bool:
        info = self.info(package)
        return bool(info and info.installed)

    def running_kernel_packages(self) -> set[str]:
        """Package names that belong to the currently booted kernel.

        Removing any of these on a machine that has not rebooted yet is how an
        unattended upgrade turns into an unbootable server.
        """
        release = self.kernel_release
        if not release:
            return set()
        names = {
            f"linux-image-{release}",
            f"linux-image-unsigned-{release}",
            f"linux-modules-{release}",
            f"linux-modules-extra-{release}",
            f"linux-headers-{release}",
            f"linux-objects-nvidia-{release}",
        }
        # Anything whose name ends with the running release string, e.g.
        # linux-image-6.8.0-45-generic on Ubuntu or 6.12.0-1-amd64 on Debian.
        for name in self.packages:
            if name.endswith(release):
                names.add(name)
        return names

    def held_packages(self) -> list[str]:
        result = run_command(["apt-mark", "showhold"], timeout=60)
        if not result.ok:
            return []
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def running_kernel_release() -> str:
    return platform.release()


def reboot_required() -> tuple[bool, str]:
    """Ubuntu/Debian drop a marker file when a reboot is pending."""
    marker = "/var/run/reboot-required"
    if not os.path.exists(marker):
        marker = "/run/reboot-required"
    if not os.path.exists(marker):
        return False, ""
    detail = ""
    pkgs = marker + ".pkgs"
    try:
        if os.path.exists(pkgs):
            with open(pkgs, encoding="utf-8", errors="replace") as handle:
                detail = ", ".join(sorted({line.strip() for line in handle if line.strip()}))
    except OSError:
        detail = ""
    return True, detail
