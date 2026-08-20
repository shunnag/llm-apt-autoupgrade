"""Slack and Mattermost notifications.

Both products accept the same "incoming webhook" JSON shape, so one payload
builder serves both.  Delivery uses :mod:`urllib.request` for the same reason
as :mod:`aptai.llm`: no third-party dependency may stand between this tool and
a broken package manager.

Everything sent here has already been redacted, and the message body is
truncated to ``notify.max_log_chars`` so a 30 MB apt log cannot be pushed into
a chat channel.
"""

from __future__ import annotations

import http.client
import json
import logging
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from aptai.config import Config, resolve_secret
from aptai.redact import redact
from aptai.version import __version__

LOG = logging.getLogger("aptai.notify")

COLOR_OK = "#2eb886"
COLOR_WARN = "#daa038"
COLOR_FAIL = "#c0392b"


@dataclass
class DeliveryResult:
    target: str
    ok: bool
    message: str = ""

    def to_dict(self) -> dict:
        return {"target": self.target, "ok": self.ok, "message": self.message}


@dataclass
class Message:
    """A notification, independent of the chat product it is sent to."""

    title: str
    color: str = COLOR_FAIL
    host: str = ""
    fields: list[tuple[str, str]] = field(default_factory=list)
    body: str = ""

    def to_text(self) -> str:
        lines = [self.title]
        if self.host:
            lines.append(f"host: {self.host}")
        lines.extend(f"{name}: {value}" for name, value in self.fields)
        if self.body:
            lines.append("")
            lines.append(self.body)
        return "\n".join(lines)


class Notifier:
    def __init__(self, config: Config):
        self.config = config
        self.notify = config.notify
        self._ssl_context = ssl.create_default_context()

    # ---------------------------------------------------------------- public

    @property
    def targets(self) -> list[str]:
        out = []
        if self._slack_url():
            out.append("slack")
        if self._mattermost_url():
            out.append("mattermost")
        return out

    def send(self, message: Message) -> list[DeliveryResult]:
        if not self.notify.enabled:
            return [DeliveryResult("disabled", True, "notifications are disabled")]
        results: list[DeliveryResult] = []
        slack_url = self._slack_url()
        if slack_url:
            results.append(self._deliver("slack", slack_url, self._slack_payload(message)))
        mattermost_url = self._mattermost_url()
        if mattermost_url:
            results.append(
                self._deliver("mattermost", mattermost_url, self._mattermost_payload(message))
            )
        if not results:
            results.append(
                DeliveryResult("none", False, "no Slack or Mattermost webhook is configured")
            )
        return results

    def send_test(self) -> list[DeliveryResult]:
        return self.send(
            Message(
                title=f":package: aptai {__version__} test notification",
                color=COLOR_OK,
                host=self.config.general.hostname or socket.gethostname(),
                fields=[("status", "this is a test message from `aptai notify-test`")],
            )
        )

    # --------------------------------------------------------------- payloads

    def _slack_payload(self, message: Message) -> dict:
        payload: dict = {
            "text": message.title,
            "attachments": [
                {
                    "color": message.color,
                    "fallback": message.to_text()[: self.notify.max_log_chars],
                    "fields": [
                        {"title": name, "value": value[:1800], "short": len(value) < 40}
                        for name, value in ([("host", message.host)] if message.host else [])
                        + message.fields
                    ],
                    "text": _code_block(message.body, self.notify.max_log_chars),
                }
            ],
        }
        if self.notify.slack.username:
            payload["username"] = self.notify.slack.username
        if self.notify.slack.icon_emoji:
            payload["icon_emoji"] = self.notify.slack.icon_emoji
        return payload

    def _mattermost_payload(self, message: Message) -> dict:
        payload: dict = {
            "text": message.title,
            "attachments": [
                {
                    "color": message.color,
                    "fallback": message.to_text()[: self.notify.max_log_chars],
                    "fields": [
                        {"title": name, "value": value[:1800], "short": len(value) < 40}
                        for name, value in ([("host", message.host)] if message.host else [])
                        + message.fields
                    ],
                    "text": _code_block(message.body, self.notify.max_log_chars),
                }
            ],
        }
        if self.notify.mattermost.channel:
            payload["channel"] = self.notify.mattermost.channel
        if self.notify.mattermost.username:
            payload["username"] = self.notify.mattermost.username
        return payload

    # --------------------------------------------------------------- delivery

    def _deliver(self, target: str, url: str, payload: dict) -> DeliveryResult:
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(  # noqa: S310 - scheme validated in config
            url,
            data=data,
            headers={"content-type": "application/json", "user-agent": f"aptai/{__version__}"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(  # noqa: S310
                request, timeout=self.notify.timeout, context=self._ssl_context
            ) as response:
                body = response.read(2048).decode("utf-8", "replace").strip()
            LOG.info("notification delivered to %s", target)
            return DeliveryResult(target, True, body[:200])
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = exc.read(1024).decode("utf-8", "replace")
            except Exception:  # noqa: BLE001
                detail = ""
            problem = f"HTTP {exc.code}: {redact(detail)[:200]}"
        except urllib.error.URLError as exc:
            problem = f"cannot reach the webhook: {exc.reason}"
        except (TimeoutError, OSError, http.client.HTTPException) as exc:
            problem = f"network error: {exc}"
        LOG.error("notification to %s failed: %s", target, problem)
        return DeliveryResult(target, False, problem)

    # ---------------------------------------------------------------- secrets

    def _slack_url(self) -> str:
        return resolve_secret(
            self.notify.slack.webhook_url, self.notify.slack.webhook_url_file, "APTAI_SLACK_WEBHOOK"
        )

    def _mattermost_url(self) -> str:
        return resolve_secret(
            self.notify.mattermost.webhook_url,
            self.notify.mattermost.webhook_url_file,
            "APTAI_MATTERMOST_WEBHOOK",
        )


def _code_block(text: str, limit: int) -> str:
    if not text:
        return ""
    trimmed = text.strip()
    if len(trimmed) > limit:
        trimmed = "...[truncated]...\n" + trimmed[-limit:]
    return "```\n" + trimmed + "\n```"
