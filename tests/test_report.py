"""The run report is written to disk and quoted into notifications."""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from aptai.redact import PLACEHOLDER
from aptai.report import RunReport, StageRecord


def _report(redact: bool = True) -> RunReport:
    report = RunReport(hostname="server1", redact_output=redact)
    stage = report.stage("full_upgrade")
    stage.success = False
    stage.message = "full-upgrade: failed"
    stage.error_text = "E: dpkg returned an error code (1)"
    stage.initial = {
        "name": "full-upgrade",
        "commands": [
            {
                "argv": ["/usr/bin/apt-get", "-y", "full-upgrade"],
                "returncode": 100,
                "stdout": "Err:1 https://alice:s3cr3t@repo.example.com/debian stable InRelease",
                "stderr": "E: Failed to fetch",
            }
        ],
    }
    return report


class TestRedactionOfTheReport(unittest.TestCase):
    def test_command_output_is_redacted(self):
        dumped = json.dumps(_report().to_dict())
        self.assertNotIn("s3cr3t", dumped)
        self.assertIn(PLACEHOLDER, dumped)
        self.assertIn("repo.example.com", dumped)

    def test_redaction_can_be_turned_off(self):
        dumped = json.dumps(_report(redact=False).to_dict())
        self.assertIn("s3cr3t", dumped)

    def test_written_file_is_redacted_and_not_world_readable(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _report().write(tmp)
            self.assertTrue(path)
            with open(path, encoding="utf-8") as handle:
                content = handle.read()
            self.assertNotIn("s3cr3t", content)
            self.assertEqual(0, os.stat(path).st_mode & 0o007)


class TestSummary(unittest.TestCase):
    def test_summary_marks_failed_stages(self):
        report = _report()
        self.assertIn("[FAILED] full_upgrade", report.summary_text())

    def test_summary_marks_escalation(self):
        report = RunReport(hostname="h")
        stage = report.stage("update")
        stage.escalated = True
        stage.message = "needs a human"
        self.assertIn("[ESCALATED] update", report.summary_text())

    def test_summary_marks_a_degraded_success(self):
        report = RunReport(hostname="h")
        stage = report.stage("full_upgrade")
        stage.success = True
        stage.degraded = True
        self.assertIn("ok (degraded)", report.summary_text())

    def test_failure_excerpt_is_bounded(self):
        report = RunReport(hostname="h")
        stage = report.stage("full_upgrade")
        stage.error_text = "x" * 50000
        self.assertLessEqual(len(report.failure_excerpt(2000)), 2100)


class TestPruning(unittest.TestCase):
    def test_old_reports_are_pruned(self):
        with tempfile.TemporaryDirectory() as tmp:
            for index in range(6):
                path = os.path.join(tmp, f"run-2026010{index}T000000Z.json")
                with open(path, "w", encoding="utf-8") as handle:
                    handle.write("{}")
            RunReport(hostname="h").write(tmp, keep=3)
            remaining = sorted(f for f in os.listdir(tmp) if f.startswith("run-"))
            self.assertEqual(3, len(remaining))


if __name__ == "__main__":
    unittest.main()
