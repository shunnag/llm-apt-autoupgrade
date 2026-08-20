"""The machine-readable record of a run.

Every run writes ``<log_dir>/run-<timestamp>.json``.  That file is the thing a
human reads after being paged: it holds each stage, each consultation with the
model, each action the policy accepted or refused, and every command that was
executed with its exit status.
"""

from __future__ import annotations

import glob
import json
import os
import socket
import time
from dataclasses import dataclass, field

from aptai.version import __version__


@dataclass
class RoundRecord:
    """One consult-then-remediate cycle inside a stage."""

    number: int
    consultation: dict = field(default_factory=dict)
    policy: dict = field(default_factory=dict)
    actions: list[dict] = field(default_factory=list)
    retry: dict | None = None

    def to_dict(self) -> dict:
        return {
            "round": self.number,
            "consultation": self.consultation,
            "policy": self.policy,
            "actions": self.actions,
            "retry": self.retry,
        }


@dataclass
class StageRecord:
    name: str
    success: bool = False
    skipped: bool = False
    escalated: bool = False
    message: str = ""
    degraded: bool = False
    initial: dict = field(default_factory=dict)
    rounds: list[RoundRecord] = field(default_factory=list)
    error_text: str = ""

    def to_dict(self) -> dict:
        return {
            "stage": self.name,
            "success": self.success,
            "skipped": self.skipped,
            "escalated": self.escalated,
            "degraded": self.degraded,
            "message": self.message,
            "initial": self.initial,
            "rounds": [r.to_dict() for r in self.rounds],
            "error_text": self.error_text,
        }


@dataclass
class RunReport:
    hostname: str = field(default_factory=socket.gethostname)
    version: str = __version__
    started_at: float = field(default_factory=time.time)
    finished_at: float = 0.0
    mode: str = "auto"
    dry_run: bool = False
    success: bool = False
    stages: list[StageRecord] = field(default_factory=list)
    diagnostics: dict = field(default_factory=dict)
    reboot_required: bool = False
    reboot_packages: str = ""
    notifications: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    path: str = ""

    @property
    def duration(self) -> float:
        return (self.finished_at or time.time()) - self.started_at

    @property
    def failed_stages(self) -> list[StageRecord]:
        return [s for s in self.stages if not s.success and not s.skipped]

    @property
    def llm_rounds(self) -> int:
        return sum(len(s.rounds) for s in self.stages)

    def stage(self, name: str) -> StageRecord:
        record = StageRecord(name=name)
        self.stages.append(record)
        return record

    def to_dict(self) -> dict:
        return {
            "aptai_version": self.version,
            "hostname": self.hostname,
            "started_at": _iso(self.started_at),
            "finished_at": _iso(self.finished_at or time.time()),
            "duration_seconds": round(self.duration, 1),
            "mode": self.mode,
            "dry_run": self.dry_run,
            "success": self.success,
            "reboot_required": self.reboot_required,
            "reboot_packages": self.reboot_packages,
            "llm_rounds": self.llm_rounds,
            "stages": [s.to_dict() for s in self.stages],
            "diagnostics": self.diagnostics,
            "notifications": self.notifications,
            "errors": self.errors,
        }

    def summary_text(self) -> str:
        lines = [
            f"aptai {self.version} on {self.hostname}",
            f"mode: {self.mode}{' (dry-run)' if self.dry_run else ''}, "
            f"duration: {self.duration:.0f}s, LLM rounds: {self.llm_rounds}",
        ]
        for stage in self.stages:
            if stage.skipped:
                status = "skipped"
            elif stage.success and stage.degraded:
                status = "ok (degraded)"
            elif stage.success:
                status = "ok"
            elif stage.escalated:
                status = "ESCALATED"
            else:
                status = "FAILED"
            lines.append(f"  [{status}] {stage.name}: {stage.message}")
        if self.reboot_required:
            lines.append(f"  reboot required: {self.reboot_packages or 'yes'}")
        if self.errors:
            lines.append("  errors: " + "; ".join(self.errors))
        return "\n".join(lines)

    def failure_excerpt(self, limit: int = 3000) -> str:
        parts = []
        for stage in self.failed_stages:
            parts.append(f"### stage {stage.name}\n{stage.error_text or stage.message}")
        text = "\n\n".join(parts).strip()
        if len(text) > limit:
            text = "...[truncated]...\n" + text[-limit:]
        return text

    def write(self, log_dir: str, *, keep: int = 30) -> str:
        if not log_dir:
            return ""
        try:
            os.makedirs(log_dir, mode=0o750, exist_ok=True)
            stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(self.started_at))
            path = os.path.join(log_dir, f"run-{stamp}.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(self.to_dict(), handle, indent=2, ensure_ascii=False)
            os.chmod(path, 0o640)
            self.path = path
            _prune(log_dir, keep)
            return path
        except OSError:
            return ""


def _prune(log_dir: str, keep: int) -> None:
    if keep <= 0:
        return
    reports = sorted(glob.glob(os.path.join(log_dir, "run-*.json")))
    for stale in reports[:-keep]:
        try:
            os.unlink(stale)
        except OSError:
            pass


def _iso(epoch: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))
