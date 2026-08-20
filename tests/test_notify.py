"""Slack and Mattermost delivery."""

from __future__ import annotations

import io
import json
import unittest
import urllib.error
from unittest import mock

from aptai.notify import COLOR_FAIL, Message, Notifier
from tests.helpers import make_config


class FakeResponse(io.BytesIO):
    def __enter__(self):
        self.seek(0)
        return self

    def __exit__(self, *args):
        return False


def ok_response() -> FakeResponse:
    return FakeResponse(b"ok")


class TestNotifier(unittest.TestCase):
    def setUp(self):
        self.config = make_config()
        self.config.notify.slack.webhook_url = "https://hooks.slack.com/services/A/B/C"
        self.config.notify.mattermost.webhook_url = "https://mm.example.com/hooks/abc"
        self.config.notify.mattermost.channel = "ops"
        self.notifier = Notifier(self.config)
        self.message = Message(
            title="aptai failed",
            color=COLOR_FAIL,
            host="server1",
            fields=[("stage", "full_upgrade")],
            body="E: dpkg returned an error code (1)",
        )

    def _capture(self):
        captured = []

        def side_effect(request, *args, **kwargs):
            captured.append((request.full_url, json.loads(request.data.decode())))
            return ok_response()

        return captured, side_effect

    def test_sends_to_both_targets(self):
        captured, side_effect = self._capture()
        with mock.patch("urllib.request.urlopen", side_effect=side_effect):
            results = self.notifier.send(self.message)
        self.assertEqual(2, len(results))
        self.assertTrue(all(r.ok for r in results))
        self.assertEqual(
            ["https://hooks.slack.com/services/A/B/C", "https://mm.example.com/hooks/abc"],
            [url for url, _ in captured],
        )

    def test_slack_payload_shape(self):
        captured, side_effect = self._capture()
        with mock.patch("urllib.request.urlopen", side_effect=side_effect):
            self.notifier.send(self.message)
        _, payload = captured[0]
        self.assertEqual("aptai failed", payload["text"])
        self.assertEqual("aptai", payload["username"])
        attachment = payload["attachments"][0]
        self.assertEqual(COLOR_FAIL, attachment["color"])
        self.assertIn("dpkg returned an error", attachment["text"])
        titles = [f["title"] for f in attachment["fields"]]
        self.assertIn("host", titles)
        self.assertIn("stage", titles)

    def test_mattermost_payload_carries_the_channel(self):
        captured, side_effect = self._capture()
        with mock.patch("urllib.request.urlopen", side_effect=side_effect):
            self.notifier.send(self.message)
        _, payload = captured[1]
        self.assertEqual("ops", payload["channel"])

    def test_long_bodies_are_truncated(self):
        self.config.notify.max_log_chars = 200
        self.message.body = "x" * 10000
        captured, side_effect = self._capture()
        with mock.patch("urllib.request.urlopen", side_effect=side_effect):
            self.notifier.send(self.message)
        _, payload = captured[0]
        self.assertLess(len(payload["attachments"][0]["text"]), 400)
        self.assertIn("truncated", payload["attachments"][0]["text"])

    def test_delivery_failure_is_reported_not_raised(self):
        error = urllib.error.HTTPError("https://x", 404, "gone", {}, io.BytesIO(b"no such hook"))
        with mock.patch("urllib.request.urlopen", side_effect=error):
            results = self.notifier.send(self.message)
        self.assertTrue(all(not r.ok for r in results))
        self.assertIn("404", results[0].message)

    def test_network_failure_is_reported(self):
        with mock.patch("urllib.request.urlopen", side_effect=urllib.error.URLError("down")):
            results = self.notifier.send(self.message)
        self.assertIn("cannot reach", results[0].message)

    def test_no_target_configured(self):
        config = make_config()
        results = Notifier(config).send(self.message)
        self.assertFalse(results[0].ok)
        self.assertIn("no Slack or Mattermost webhook", results[0].message)

    def test_disabled_notifications_send_nothing(self):
        self.config.notify.enabled = False
        with mock.patch("urllib.request.urlopen") as urlopen:
            results = Notifier(self.config).send(self.message)
        urlopen.assert_not_called()
        self.assertTrue(results[0].ok)

    def test_targets_listing(self):
        self.assertEqual(["slack", "mattermost"], self.notifier.targets)


if __name__ == "__main__":
    unittest.main()
