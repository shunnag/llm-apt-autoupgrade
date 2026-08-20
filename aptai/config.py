"""Configuration loading and validation.

The on-disk format is TOML, parsed with :mod:`tomllib` from the standard
library (Python 3.11+).  Unknown keys are rejected rather than ignored: a
typo in a safety setting must not silently fall back to a permissive default.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import asdict, dataclass, field, fields

from aptai.errors import ConfigError

DEFAULT_CONFIG_PATH = "/etc/aptai/config.toml"

VALID_MODES = ("auto", "suggest")
VALID_EFFORTS = ("low", "medium", "high", "xhigh", "max")
VALID_RISKS = ("low", "medium", "high")
VALID_REMOVAL_POLICIES = ("abort", "fallback_upgrade", "proceed")
VALID_NEEDRESTART = ("l", "a", "i", "off")

#: Packages that aptai refuses to remove, hold or downgrade regardless of what
#: the model proposes.  This list is additive to the automatic guards
#: (``Essential: yes``, ``Priority: required`` and the running kernel).
DEFAULT_PROTECTED_PACKAGES = (
    "apt",
    "base-files",
    "bash",
    "coreutils",
    "dash",
    "dpkg",
    "grub-common",
    "grub-efi-amd64",
    "grub-pc",
    "init",
    "libc-bin",
    "libc6",
    "login",
    "openssh-server",
    "passwd",
    "perl-base",
    "python3",
    "python3-minimal",
    "shim-signed",
    "sudo",
    "systemd",
    "systemd-sysv",
    "udev",
)


@dataclass
class GeneralConfig:
    mode: str = "auto"
    max_rounds: int = 3
    dry_run: bool = False
    log_dir: str = "/var/log/aptai"
    state_dir: str = "/var/lib/aptai"
    log_level: str = "INFO"
    keep_reports: int = 30
    hostname: str = ""


@dataclass
class AptConfig:
    update: bool = True
    full_upgrade: bool = True
    autoremove: bool = True
    autoremove_purge: bool = False
    autoclean: bool = False
    command_timeout: int = 3600
    lock_wait_seconds: int = 900
    lock_poll_seconds: int = 20
    min_free_root_mb: int = 512
    min_free_var_mb: int = 1024
    min_free_boot_mb: int = 120
    needrestart_mode: str = "l"
    on_excessive_removals: str = "abort"
    fail_on_partial_update: bool = True
    max_upgrade_removals: int = 10
    max_autoremove_removals: int = 60
    reboot_if_required: bool = False


@dataclass
class LLMConfig:
    enabled: bool = True
    base_url: str = "https://api.anthropic.com"
    model: str = "claude-opus-5"
    api_version: str = "2023-06-01"
    api_key_env: str = "ANTHROPIC_API_KEY"
    api_key_file: str = "/etc/aptai/api_key"
    max_tokens: int = 16000
    effort: str = "high"
    timeout: int = 300
    max_retries: int = 4
    # Optional request features are individually switchable so that a future
    # API change turns into a config edit instead of a code change.
    use_effort: bool = True
    use_structured_output: bool = True
    use_refusal_fallbacks: bool = True
    fallback_beta: str = "server-side-fallback-2026-07-01"
    extra_instructions: str = ""


@dataclass
class PolicyConfig:
    max_actions_per_round: int = 6
    max_risk: str = "medium"
    max_removals: int = 5
    max_new_installs: int = 50
    require_known_packages: bool = True
    allow_remove: bool = True
    allow_purge: bool = False
    allow_hold_changes: bool = True
    allow_sources_edit: bool = False
    allow_key_import: bool = False
    allow_apt_lists_reset: bool = True
    allow_downgrade: bool = False
    protect_required_priority: bool = True
    protected_packages: list[str] = field(default_factory=lambda: list(DEFAULT_PROTECTED_PACKAGES))
    allowed_keyservers: list[str] = field(default_factory=lambda: ["keyserver.ubuntu.com"])


@dataclass
class PrivacyConfig:
    redact: bool = True
    send_sources_list: bool = True
    send_package_list: bool = False
    dpkg_log_lines: int = 120
    max_payload_chars: int = 60000


@dataclass
class SlackConfig:
    webhook_url: str = ""
    webhook_url_file: str = ""
    username: str = "aptai"
    icon_emoji: str = ":package:"


@dataclass
class MattermostConfig:
    webhook_url: str = ""
    webhook_url_file: str = ""
    channel: str = ""
    username: str = "aptai"


@dataclass
class NotifyConfig:
    enabled: bool = True
    on_success: bool = False
    on_failure: bool = True
    on_reboot_required: bool = True
    timeout: int = 30
    max_log_chars: int = 3000
    slack: SlackConfig = field(default_factory=SlackConfig)
    mattermost: MattermostConfig = field(default_factory=MattermostConfig)


@dataclass
class Config:
    general: GeneralConfig = field(default_factory=GeneralConfig)
    apt: AptConfig = field(default_factory=AptConfig)
    llm: LLMConfig = field(default_factory=LLMConfig)
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    privacy: PrivacyConfig = field(default_factory=PrivacyConfig)
    notify: NotifyConfig = field(default_factory=NotifyConfig)
    source_path: str = ""

    def to_dict(self) -> dict:
        data = asdict(self)
        # Never let webhook URLs or key paths end up in a report.
        data["notify"]["slack"]["webhook_url"] = _mask(self.notify.slack.webhook_url)
        data["notify"]["mattermost"]["webhook_url"] = _mask(self.notify.mattermost.webhook_url)
        return data


_SECTIONS = {
    "general": GeneralConfig,
    "apt": AptConfig,
    "llm": LLMConfig,
    "policy": PolicyConfig,
    "privacy": PrivacyConfig,
    "notify": NotifyConfig,
}
_NOTIFY_SUBSECTIONS = {"slack": SlackConfig, "mattermost": MattermostConfig}


def _mask(value: str) -> str:
    return "[set]" if value else ""


def _build_section(cls, data: dict, path: str):
    known = {f.name: f for f in fields(cls)}
    kwargs = {}
    for key, value in data.items():
        if key not in known:
            raise ConfigError(f"{path}: unknown option {key!r}")
        expected = known[key].type
        kwargs[key] = _coerce(value, expected, f"{path}.{key}")
    return cls(**kwargs)


def _coerce(value, expected, path: str):
    """Reject obviously wrong types early; TOML already gives us real types."""
    if expected in ("int", int):
        if isinstance(value, bool) or not isinstance(value, int):
            raise ConfigError(f"{path}: expected an integer, got {value!r}")
        return value
    if expected in ("bool", bool):
        if not isinstance(value, bool):
            raise ConfigError(f"{path}: expected true/false, got {value!r}")
        return value
    if expected in ("str", str):
        if not isinstance(value, str):
            raise ConfigError(f"{path}: expected a string, got {value!r}")
        return value
    if expected in ("list[str]", list):
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise ConfigError(f"{path}: expected a list of strings, got {value!r}")
        return list(value)
    return value


def load_config(path: str | None = None, *, required: bool = False) -> Config:
    """Load ``path`` (or the default) and validate it."""
    cfg_path = path or DEFAULT_CONFIG_PATH
    raw: dict = {}
    if os.path.exists(cfg_path):
        try:
            with open(cfg_path, "rb") as handle:
                raw = tomllib.load(handle)
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"{cfg_path}: invalid TOML: {exc}") from exc
        except OSError as exc:
            raise ConfigError(f"{cfg_path}: cannot be read: {exc}") from exc
    elif required or path:
        raise ConfigError(f"configuration file not found: {cfg_path}")

    config = Config(source_path=cfg_path if os.path.exists(cfg_path) else "")
    for section, data in raw.items():
        if section not in _SECTIONS:
            raise ConfigError(f"{cfg_path}: unknown section [{section}]")
        if not isinstance(data, dict):
            raise ConfigError(f"{cfg_path}: [{section}] must be a table")
        if section == "notify":
            sub = {k: v for k, v in data.items() if k in _NOTIFY_SUBSECTIONS}
            flat = {k: v for k, v in data.items() if k not in _NOTIFY_SUBSECTIONS}
            notify = _build_section(NotifyConfig, flat, "notify")
            for name, value in sub.items():
                if not isinstance(value, dict):
                    raise ConfigError(f"{cfg_path}: [notify.{name}] must be a table")
                setattr(notify, name, _build_section(_NOTIFY_SUBSECTIONS[name], value, f"notify.{name}"))
            config.notify = notify
        else:
            setattr(config, section, _build_section(_SECTIONS[section], data, section))

    validate(config)
    return config


def validate(config: Config) -> None:
    """Raise :class:`ConfigError` for values that are syntactically fine but unsafe."""
    g, a, l, p, n = config.general, config.apt, config.llm, config.policy, config.notify
    if g.mode not in VALID_MODES:
        raise ConfigError(f"general.mode must be one of {VALID_MODES}, got {g.mode!r}")
    if not 0 <= g.max_rounds <= 10:
        raise ConfigError("general.max_rounds must be between 0 and 10")
    if g.log_level.upper() not in ("DEBUG", "INFO", "WARNING", "ERROR"):
        raise ConfigError("general.log_level must be DEBUG, INFO, WARNING or ERROR")
    if a.command_timeout < 30:
        raise ConfigError("apt.command_timeout must be at least 30 seconds")
    if a.needrestart_mode not in VALID_NEEDRESTART:
        raise ConfigError(f"apt.needrestart_mode must be one of {VALID_NEEDRESTART}")
    if a.on_excessive_removals not in VALID_REMOVAL_POLICIES:
        raise ConfigError(f"apt.on_excessive_removals must be one of {VALID_REMOVAL_POLICIES}")
    if a.max_upgrade_removals < 0 or a.max_autoremove_removals < 0:
        raise ConfigError("apt removal limits must not be negative")
    if l.effort not in VALID_EFFORTS:
        raise ConfigError(f"llm.effort must be one of {VALID_EFFORTS}")
    if l.max_tokens < 1024:
        raise ConfigError("llm.max_tokens must be at least 1024")
    if l.timeout < 10:
        raise ConfigError("llm.timeout must be at least 10 seconds")
    if not l.base_url.startswith("https://"):
        raise ConfigError("llm.base_url must be an https:// URL")
    if p.max_risk not in VALID_RISKS:
        raise ConfigError(f"policy.max_risk must be one of {VALID_RISKS}")
    if p.max_actions_per_round < 1 or p.max_actions_per_round > 20:
        raise ConfigError("policy.max_actions_per_round must be between 1 and 20")
    if p.max_removals < 0:
        raise ConfigError("policy.max_removals must not be negative")
    if p.max_new_installs < 1:
        raise ConfigError("policy.max_new_installs must be at least 1")
    if not 1000 <= config.privacy.max_payload_chars <= 500000:
        raise ConfigError("privacy.max_payload_chars must be between 1000 and 500000")
    if config.privacy.dpkg_log_lines < 0:
        raise ConfigError("privacy.dpkg_log_lines must not be negative")
    for url in (n.slack.webhook_url, n.mattermost.webhook_url):
        if url and not url.startswith(("https://", "http://")):
            raise ConfigError("notify webhook URLs must be http(s) URLs")


def resolve_secret(value: str, file_path: str, env_var: str = "") -> str:
    """Resolve a secret from an env var, an inline value or a mode-checked file."""
    if env_var:
        from_env = os.environ.get(env_var, "").strip()
        if from_env:
            return from_env
    if value:
        return value.strip()
    if file_path and os.path.exists(file_path):
        try:
            mode = os.stat(file_path).st_mode
            if mode & 0o077:
                raise ConfigError(
                    f"{file_path} is group/world readable; run: chmod 600 {file_path}"
                )
            with open(file_path, encoding="utf-8") as handle:
                return handle.read().strip()
        except OSError as exc:
            raise ConfigError(f"{file_path}: cannot be read: {exc}") from exc
    return ""
