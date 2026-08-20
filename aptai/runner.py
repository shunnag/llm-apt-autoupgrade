"""The upgrade orchestrator.

Flow for every run:

    preflight -> apt-get update -> apt-get full-upgrade -> apt-get autoremove
              -> (optional autoclean) -> postflight

When a stage fails, aptai enters the consult loop for *that stage only*:

    capture output -> collect diagnostics -> ask Claude for a typed plan
                   -> local policy filters the plan -> execute what survived
                   -> re-run the stage

The loop runs at most ``general.max_rounds`` times (three by default).  If the
stage still fails, or the model escalates, or the policy refuses everything,
the run stops and a notification with the full history is sent to Slack and/or
Mattermost.
"""

from __future__ import annotations

import logging
import os
import re
import socket
import time
from dataclasses import dataclass

from aptai import aptcmd, diagnostics as diag_mod
from aptai.config import Config
from aptai.errors import LockBusyError, PreflightError
from aptai.executor import Executor, OperationResult
from aptai.llm import ClaudeClient
from aptai.notify import COLOR_FAIL, COLOR_OK, COLOR_WARN, Message, Notifier
from aptai.pkgfacts import PackageFacts, reboot_required
from aptai.policy import Policy, action_signature
from aptai.redact import redact
from aptai.report import RoundRecord, RunReport, StageRecord
from aptai.sysexec import run_command

LOG = logging.getLogger("aptai.runner")


@dataclass
class Stage:
    key: str          # matches a key of aptai.plan.STAGE_ACTIONS
    label: str
    enabled_attr: str


STAGES = (
    Stage("update", "apt-get update", "update"),
    Stage("full_upgrade", "apt-get full-upgrade", "full_upgrade"),
    Stage("autoremove", "apt-get autoremove", "autoremove"),
    Stage("autoclean", "apt-get autoclean", "autoclean"),
)


class Runner:
    def __init__(
        self,
        config: Config,
        *,
        dry_run: bool = False,
        mode: str | None = None,
        use_llm: bool = True,
        only_stages: list[str] | None = None,
    ):
        self.config = config
        self.dry_run = dry_run or config.general.dry_run
        self.mode = mode or config.general.mode
        self.use_llm = use_llm and config.llm.enabled
        self.only_stages = only_stages
        self.facts = PackageFacts()
        self.policy: Policy | None = None
        self.executor: Executor | None = None
        self.client = ClaudeClient(config)
        self.notifier = Notifier(config)

    # ------------------------------------------------------------------- run

    def run(self) -> RunReport:
        report = RunReport(
            hostname=self.config.general.hostname or socket.gethostname(),
            mode=self.mode,
            dry_run=self.dry_run,
        )
        try:
            self.preflight()
        except PreflightError as exc:
            report.errors.append(str(exc))
            report.success = False
            report.finished_at = time.time()
            report.write(self.config.general.log_dir, keep=self.config.general.keep_reports)
            self._notify(report, preflight_error=str(exc))
            return report

        self.facts = PackageFacts.collect()
        self.policy = Policy(self.config, self.facts)
        self.executor = Executor(self.config, self.policy, dry_run=self.dry_run)

        for stage in STAGES:
            if self.only_stages and stage.key not in self.only_stages:
                continue
            record = report.stage(stage.key)
            if not getattr(self.config.apt, stage.enabled_attr):
                record.skipped = True
                record.success = True
                record.message = f"{stage.label} is disabled in the configuration"
                LOG.info("%s", record.message)
                continue
            self._run_stage(stage, record)
            if not record.success:
                LOG.error("%s did not recover; stopping the run", stage.label)
                break

        report.success = all(s.success for s in report.stages) and bool(report.stages)
        report.reboot_required, report.reboot_packages = reboot_required()
        try:
            report.diagnostics = diag_mod.collect(self.config, self.facts, deep=False).to_dict()
        except Exception as exc:  # noqa: BLE001 - diagnostics must never break a run
            LOG.debug("post-run diagnostics failed: %s", exc)
        report.finished_at = time.time()
        path = report.write(self.config.general.log_dir, keep=self.config.general.keep_reports)
        if path:
            LOG.info("run report written to %s", path)
        self._notify(report)
        self._maybe_reboot(report)
        return report

    # ------------------------------------------------------------- preflight

    def preflight(self) -> None:
        """Refuse to start when the machine is in no state to be upgraded."""
        if os.geteuid() != 0:
            if not self.dry_run:
                raise PreflightError("aptai must run as root (try: sudo aptai run)")
            LOG.warning("not running as root; results will be incomplete")

        if not os.path.exists(aptcmd.APT_GET):
            raise PreflightError(f"{aptcmd.APT_GET} not found -- is this a Debian/Ubuntu system?")

        for path, floor in (
            ("/", self.config.apt.min_free_root_mb),
            ("/var", self.config.apt.min_free_var_mb),
            ("/boot", self.config.apt.min_free_boot_mb),
        ):
            space = aptcmd.disk_space(path)
            if not space.exists or floor <= 0:
                continue
            if space.free_mb < floor:
                raise PreflightError(
                    f"only {space.free_mb} MiB free on {path}, need at least {floor} MiB "
                    f"(a full /boot is the most common cause of a failed kernel upgrade)"
                )
            LOG.debug("%s: %d MiB free", path, space.free_mb)

        self._wait_for_lock()

    def _wait_for_lock(self) -> None:
        """Back off while another package manager is running.

        unattended-upgrades ships enabled on Ubuntu, so finding the dpkg lock
        held is normal rather than exceptional.  aptai waits; it never removes
        a lock file, because deleting a live lock corrupts the dpkg database.
        """
        deadline = time.monotonic() + max(0, self.config.apt.lock_wait_seconds)
        first = True
        while True:
            status = aptcmd.probe_dpkg_lock()
            if not status.locked:
                if not first:
                    LOG.info("dpkg lock released; continuing")
                return
            if time.monotonic() >= deadline:
                raise LockBusyError(
                    status.describe()
                    + f"; gave up after {self.config.apt.lock_wait_seconds}s"
                )
            if first:
                LOG.warning("%s -- waiting", status.describe())
                first = False
            time.sleep(max(1, self.config.apt.lock_poll_seconds))

    # ---------------------------------------------------------------- stages

    def _operation(self, stage_key: str) -> OperationResult:
        assert self.executor is not None
        return {
            "update": self.executor.apt_update,
            "full_upgrade": self.executor.apt_full_upgrade,
            "autoremove": self.executor.apt_autoremove,
            "autoclean": self.executor.apt_autoclean,
        }[stage_key]()

    def _run_stage(self, stage: Stage, record: StageRecord) -> None:
        LOG.info("=== %s ===", stage.label)
        result = self._operation(stage.key)
        record.initial = result.to_dict()
        record.degraded = result.degraded
        record.message = result.message
        if result.success:
            record.success = True
            LOG.info("%s succeeded", stage.label)
            return

        record.error_text = redact(result.error_text) if self.config.privacy.redact else result.error_text
        LOG.error("%s failed: %s", stage.label, result.message)

        if not self.use_llm:
            record.message = f"{result.message} (LLM advisor disabled)"
            return
        if not self.client.available:
            record.message = f"{result.message} (no Claude API key configured)"
            record.error_text += "\n[aptai] the LLM advisor could not be used: no API key"
            return

        self._consult_loop(stage, record, result)

    def _consult_loop(self, stage: Stage, record: StageRecord, failure: OperationResult) -> None:
        assert self.executor is not None and self.policy is not None
        history: list[dict] = []
        signatures: set[str] = set()
        last_error_signature = error_signature(failure.error_text)
        max_rounds = self.config.general.max_rounds

        for round_number in range(1, max_rounds + 1):
            LOG.info("consulting %s (round %d/%d)", self.config.llm.model, round_number, max_rounds)
            round_record = RoundRecord(number=round_number)
            record.rounds.append(round_record)

            diagnostics = diag_mod.collect(self.config, self.facts, deep=True)
            error_text = failure.error_text
            if self.config.privacy.redact:
                error_text = redact(error_text)
            self.executor.stage_error_text = failure.error_text

            consultation = self.client.consult(
                stage=stage.key,
                error_text=error_text,
                diagnostics_text=diagnostics.to_text(),
                history=history,
                round_number=round_number,
                max_rounds=max_rounds,
            )
            round_record.consultation = consultation.to_dict()
            if consultation.error or consultation.plan is None:
                record.message = f"{stage.label} failed; the advisor was unusable: {consultation.error}"
                record.escalated = True
                LOG.error("%s", record.message)
                return

            plan = consultation.plan
            LOG.info("diagnosis: %s", plan.diagnosis[:400])
            decision = self.policy.review(plan, stage.key, previous_signatures=signatures)
            round_record.policy = decision.to_dict()
            for rejection in decision.rejected:
                LOG.warning("policy refused %s: %s", rejection.action.kind.value, rejection.reason)

            if decision.escalate or not decision.accepted:
                record.escalated = True
                record.message = (
                    f"{stage.label} failed; escalating: "
                    f"{decision.escalation_reason or plan.escalation_reason or plan.diagnosis}"
                )
                LOG.error("%s", record.message)
                return

            for action in decision.accepted:
                signatures.add(action_signature(action))

            if self.mode == "suggest":
                record.message = (
                    f"{stage.label} failed; suggest mode, {len(decision.accepted)} action(s) "
                    "proposed but not executed: "
                    + "; ".join(a.describe() for a in decision.accepted)
                )
                record.escalated = True
                LOG.warning("%s", record.message)
                return

            outcomes = []
            for action in decision.accepted:
                outcome = self.executor.execute(action)
                round_record.actions.append(
                    {"action": action.to_dict(), "result": outcome.to_dict()}
                )
                outcomes.append(f"{action.kind.value}: {outcome.message}")
                LOG.info("%s", outcome.message)

            failure = self._operation(stage.key)
            round_record.retry = failure.to_dict()
            if failure.success:
                record.success = True
                record.degraded = failure.degraded
                record.message = (
                    f"{stage.label} recovered after {round_number} advisor round(s): {failure.message}"
                )
                LOG.info("%s", record.message)
                return

            record.error_text = (
                redact(failure.error_text) if self.config.privacy.redact else failure.error_text
            )
            history.append(
                {
                    "diagnosis": plan.diagnosis,
                    "actions": "; ".join(a.describe() for a in decision.accepted),
                    "outcome": "; ".join(outcomes)
                    + f" | stage retry still failing: {failure.message}",
                }
            )

            signature = error_signature(failure.error_text)
            if signature and signature == last_error_signature and round_number < max_rounds:
                LOG.warning("the failure is unchanged after remediation; not repeating the round")
                record.message = (
                    f"{stage.label} failed; the same error persisted after round {round_number}, "
                    "so aptai stopped early"
                )
                record.escalated = True
                return
            last_error_signature = signature

        record.message = (
            f"{stage.label} still failing after {max_rounds} advisor round(s)"
        )
        LOG.error("%s", record.message)

    # --------------------------------------------------------- notify/reboot

    def _notify(self, report: RunReport, *, preflight_error: str = "") -> None:
        notify = self.config.notify
        if not notify.enabled:
            return
        should = (
            (not report.success and notify.on_failure)
            or (report.success and notify.on_success)
            or (report.reboot_required and notify.on_reboot_required and report.success)
        )
        if not should:
            return

        if preflight_error:
            title = f":no_entry: aptai could not start on {report.hostname}"
            color = COLOR_FAIL
            body = preflight_error
        elif report.success:
            title = f":white_check_mark: aptai upgrade completed on {report.hostname}"
            color = COLOR_WARN if report.reboot_required else COLOR_OK
            body = report.summary_text()
        else:
            title = f":rotating_light: aptai upgrade failed on {report.hostname}"
            color = COLOR_FAIL
            body = report.summary_text() + "\n\n" + report.failure_excerpt(notify.max_log_chars)

        fields = [
            ("mode", f"{report.mode}{' (dry-run)' if report.dry_run else ''}"),
            ("duration", f"{report.duration:.0f}s"),
            ("advisor rounds", str(report.llm_rounds)),
        ]
        if report.reboot_required:
            fields.append(("reboot required", report.reboot_packages or "yes"))
        if report.path:
            fields.append(("report", report.path))
        failed = [s.name for s in report.failed_stages]
        if failed:
            fields.append(("failed stages", ", ".join(failed)))

        message = Message(
            title=title,
            color=color,
            host=report.hostname,
            fields=fields,
            body=redact(body) if self.config.privacy.redact else body,
        )
        results = self.notifier.send(message)
        report.notifications = [r.to_dict() for r in results]
        for result in results:
            if not result.ok:
                report.errors.append(f"notification to {result.target} failed: {result.message}")
        report.write(self.config.general.log_dir, keep=self.config.general.keep_reports)

    def _maybe_reboot(self, report: RunReport) -> None:
        if not (report.success and report.reboot_required and self.config.apt.reboot_if_required):
            return
        if self.dry_run:
            LOG.warning("a reboot is required (dry-run: not rebooting)")
            return
        LOG.warning("a reboot is required and apt.reboot_if_required is enabled; rebooting in 1 minute")
        run_command(["/sbin/shutdown", "-r", "+1", "aptai: rebooting after package upgrade"],
                    timeout=60)


_NUMBERS = re.compile(r"\d+")
_INTERESTING = re.compile(r"^(E:|W: GPG error|Err:|dpkg:|dpkg-deb:|Errors were encountered)")


def error_signature(text: str) -> str:
    """A stable fingerprint of a failure, used to detect "no progress".

    Digits are normalised away so that changing byte counts, PIDs and version
    numbers do not make two identical failures look different.
    """
    if not text:
        return ""
    lines = [line.strip() for line in text.splitlines() if _INTERESTING.match(line.strip())]
    if not lines:
        lines = [line.strip() for line in text.splitlines() if line.strip()][-8:]
    normalised = sorted({_NUMBERS.sub("N", line) for line in lines})
    return "\n".join(normalised)[:2000]
