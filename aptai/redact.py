"""Redaction of secrets before anything leaves the machine.

Diagnostics are sent to the Claude API and, on failure, to a Slack or
Mattermost webhook.  APT configuration legitimately contains credentials --
``deb https://user:password@repo.example.com/...`` is a normal private-repo
line -- so every string that leaves the host passes through :func:`redact`.

aptai never reads ``/etc/apt/auth.conf`` or ``/etc/apt/auth.conf.d/*``: those
files exist only to hold passwords, so the safe handling is to not open them.
"""

from __future__ import annotations

import re

PLACEHOLDER = "[REDACTED]"

#: Paths that are never read, no matter who asks.
FORBIDDEN_PATHS = (
    "/etc/apt/auth.conf",
    "/etc/apt/auth.conf.d",
    "/root/.netrc",
    "/etc/aptai/env",
    "/etc/aptai/api_key",
)

_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # scheme://user:password@host -> scheme://[REDACTED]@host
    (re.compile(r"(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*://)(?P<userinfo>[^/\s@]+)@"),
     r"\g<scheme>" + PLACEHOLDER + "@"),
    # Anthropic keys.
    (re.compile(r"sk-ant-[A-Za-z0-9_\-]{8,}"), PLACEHOLDER),
    # Slack tokens and webhook paths.
    (re.compile(r"xox[abprs]-[A-Za-z0-9\-]{8,}"), PLACEHOLDER),
    (re.compile(r"(https://hooks\.slack\.com/services/)[A-Za-z0-9/_\-]+"), r"\1" + PLACEHOLDER),
    (re.compile(r"(https?://[^/\s]+/hooks/)[A-Za-z0-9_\-]{8,}"), r"\1" + PLACEHOLDER),
    # GitHub / GitLab style tokens.
    (re.compile(r"gh[pousr]_[A-Za-z0-9]{16,}"), PLACEHOLDER),
    (re.compile(r"glpat-[A-Za-z0-9_\-]{16,}"), PLACEHOLDER),
    # AWS access key ids and generic bearer tokens.
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), PLACEHOLDER),
    (re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._\-]{12,}"), r"\1 " + PLACEHOLDER),
    # key=value shaped secrets in config snippets, query strings and env dumps.
    (re.compile(
        r"(?i)\b(password|passwd|pass|secret|token|api[_-]?key|apikey|auth|credential)s?"
        r"(\s*[:=]\s*|\s+)"
        r"(\"[^\"\n]{3,}\"|'[^'\n]{3,}'|[^\s,;&\"']{3,})"),
     lambda m: f"{m.group(1)}{m.group(2)}{PLACEHOLDER}"),
)


def redact(text: str | None) -> str:
    """Return ``text`` with credentials replaced by :data:`PLACEHOLDER`."""
    if not text:
        return ""
    out = text
    for pattern, replacement in _PATTERNS:
        out = pattern.sub(replacement, out)
    return out


def redact_obj(obj):
    """Recursively redact every string inside a JSON-serialisable structure."""
    if isinstance(obj, str):
        return redact(obj)
    if isinstance(obj, dict):
        return {k: redact_obj(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [redact_obj(v) for v in obj]
    return obj


def is_forbidden_path(path: str) -> bool:
    """True for files aptai refuses to read because they only hold secrets."""
    normalised = path.rstrip("/")
    for forbidden in FORBIDDEN_PATHS:
        if normalised == forbidden or normalised.startswith(forbidden + "/"):
            return True
    return False
