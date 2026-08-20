"""Exception hierarchy and process exit codes."""

from __future__ import annotations


class AptaiError(Exception):
    """Base class for every error raised by aptai."""

    exit_code = 1


class ConfigError(AptaiError):
    """The configuration file is missing, malformed or invalid."""

    exit_code = 2


class PreflightError(AptaiError):
    """The host is not in a state where an upgrade may be attempted."""

    exit_code = 3


class LockBusyError(PreflightError):
    """Another package manager holds the dpkg/apt lock."""

    exit_code = 4


class PermissionError_(AptaiError):
    """aptai was not started as root."""

    exit_code = 77


class LLMError(AptaiError):
    """The Claude API could not be reached or returned an unusable answer."""

    exit_code = 5


class LLMRefusalError(LLMError):
    """The model declined to answer (``stop_reason == "refusal"``)."""


class NotifyError(AptaiError):
    """A Slack/Mattermost webhook delivery failed."""

    exit_code = 6


class PolicyViolation(AptaiError):
    """A proposed action was rejected by the local safety policy."""


EXIT_OK = 0
EXIT_UPGRADE_FAILED = 1
