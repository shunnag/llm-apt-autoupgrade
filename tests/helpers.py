"""Shared fixtures: a fake dpkg database so the tests never touch a real host."""

from __future__ import annotations

from aptai.config import Config
from aptai.pkgfacts import PackageFacts, PackageInfo
from aptai.plan import Action, ActionKind, Plan

KERNEL = "6.8.0-45-generic"

_DB = [
    # name, essential, priority
    ("libc6", True, "required"),
    ("bash", True, "required"),
    ("dpkg", True, "required"),
    ("apt", False, "important"),
    ("systemd", False, "important"),
    ("openssh-server", False, "optional"),
    ("nginx", False, "optional"),
    ("curl", False, "optional"),
    ("libfoo1", False, "optional"),
    ("libbar2", False, "optional"),
    ("python3-minimal", False, "important"),
    (f"linux-image-{KERNEL}", False, "optional"),
    (f"linux-modules-{KERNEL}", False, "optional"),
    ("linux-image-6.8.0-31-generic", False, "optional"),
    ("linux-modules-6.8.0-31-generic", False, "optional"),
]


def make_facts() -> PackageFacts:
    facts = PackageFacts(kernel_release=KERNEL, collected=True)
    for name, essential, priority in _DB:
        facts.packages[name] = PackageInfo(
            name=name, essential=essential, priority=priority, status="ii installed", version="1.0"
        )
    return facts


def make_config(**overrides) -> Config:
    config = Config()
    for dotted, value in overrides.items():
        section, _, key = dotted.partition(".")
        setattr(getattr(config, section), key, value)
    return config


def action(kind: ActionKind, **kwargs) -> Action:
    kwargs.setdefault("reason", "test")
    kwargs.setdefault("risk", "medium")
    return Action(kind=kind, **kwargs)


def plan(*actions: Action, escalate: bool = False, reason: str = "") -> Plan:
    return Plan(
        diagnosis="test diagnosis",
        confidence="medium",
        actions=list(actions),
        escalate=escalate,
        escalation_reason=reason,
    )
