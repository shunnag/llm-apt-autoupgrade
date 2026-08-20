# aptai — unattended apt upgrades that ask an LLM when they break

[![ci](https://github.com/shunnag/llm-apt-autoupgrade/actions/workflows/ci.yml/badge.svg)](https://github.com/shunnag/llm-apt-autoupgrade/actions/workflows/ci.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![python: 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](#requirements)

`apt update` → `apt full-upgrade` → `apt autoremove`, unattended. When a stage
fails, aptai sends the captured output and a redacted host diagnosis to the
Claude API (Opus 5 by default), gets back a plan, applies what survives its
local safety policy, and retries — up to three rounds. If it still fails, it
pages you on Slack or Mattermost with the full history.

*日本語: [README.md](README.md)*

---

## ⚠️ Read this first

This tool **executes LLM-proposed operations as root**.

That could be reckless, so aptai is built on the premise that the model never
writes a command. It can only choose from a **closed vocabulary of typed
actions that aptai itself implements**. On top of that:

- a local policy filters every proposal (`aptai/policy.py`);
- every destructive apt operation is **simulated with `apt-get -s` first** and
  the resulting plan is inspected (`aptai/executor.py`);
- Essential packages, `Priority: required` packages, the running kernel and a
  configured protected list can **never** be removed.

Still: **try it in a VM first.** Start with `mode = "suggest"` and `--dry-run`.
The full reasoning is in [SECURITY.md](SECURITY.md).

---

## How it works

```
preflight ──► apt-get update ──► apt-get full-upgrade ──► apt-get autoremove ──► postflight
                   │                    │                        │
                   └── failure ─────────┴────────────────────────┘
                                        │
                                        ▼
                    ┌──────────────────────────────────────────────┐
                    │ 1. capture output + diagnostics (redacted)   │
                    │ 2. ask Claude → typed actions, not commands  │
                    │ 3. local policy filters the plan             │
                    │ 4. apt-get -s simulates → plan is inspected  │
                    │ 5. run what survived → retry the stage       │
                    └──────────────────────────────────────────────┘
                                        │
                    still failing after 3 rounds ▼
                       Slack / Mattermost + a JSON run report
```

Only the failing stage enters the loop, and each stage exposes a different
slice of the vocabulary: a failed `apt-get update` is a repository/keyring
problem, so that stage cannot reach dpkg state at all.

## Requirements

| | |
|---|---|
| OS | Ubuntu 24.04 LTS / 26.04 LTS, Debian 13 (trixie) |
| Python | 3.11+ (for `tomllib`); 24.04 ships 3.12, trixie ships 3.13 |
| Extra packages | **none** — Python standard library only |
| Privileges | root (systemd unit or `sudo`) |
| Optional | `gnupg`, only if you enable `allow_key_import` |

**Why zero dependencies:** this tool's job is to repair a broken package
manager, so it must not depend on anything installed *through* that package
manager — and `pip install anthropic` is blocked by PEP 668 on both targets
anyway. That is also why the Claude API is spoken over raw HTTPS with
`urllib.request` instead of the official SDK. See the comment at the top of
`aptai/llm.py`.

## Install

```bash
git clone https://github.com/shunnag/llm-apt-autoupgrade.git
cd llm-apt-autoupgrade
sudo ./scripts/install.sh                  # into /usr/local
sudo ./scripts/install.sh --enable-timer   # and start the daily timer
```

| Path | What |
|---|---|
| `/usr/local/lib/aptai/aptai/` | the Python package |
| `/usr/local/bin/aptai` | launcher (`python3 -Es`) |
| `/etc/aptai/config.toml` | configuration (existing files are kept, new one saved as `.new`) |
| `/etc/aptai/env` | API key and webhook URLs, mode 0600 |
| `/etc/systemd/system/aptai.{service,timer}` | systemd units |
| `/var/log/aptai/`, `/var/lib/aptai/` | logs, run reports, backups |

Uninstall with `sudo ./scripts/uninstall.sh` (`--purge` also removes config and logs).

### API key

```bash
sudo install -o root -g root -m 0600 /dev/null /etc/aptai/env
sudoedit /etc/aptai/env
```

```sh
ANTHROPIC_API_KEY=sk-ant-...
#APTAI_SLACK_WEBHOOK=https://hooks.slack.com/services/...
#APTAI_MATTERMOST_WEBHOOK=https://mattermost.example.com/hooks/...
```

`/etc/aptai/env` and `/etc/aptai/api_key` are on the never-read list; the
diagnostics collector will not open them.

### Verify the setup

```bash
sudo aptai check          # preflight, API key, notification targets
sudo aptai diagnose       # exactly what would be uploaded
sudo aptai test-llm       # one small request to the API
sudo aptai notify-test    # a test message to Slack/Mattermost
sudo aptai run --dry-run  # a full cycle that changes nothing
```

## Usage

```
aptai [-c CONFIG] [-v|-q] <command>

  run           run the upgrade cycle (default)
    --dry-run             simulate everything, change nothing
    --mode auto|suggest   execute approved actions, or only report them
    --max-rounds N        advisor rounds per failed stage (default 3)
    --no-llm              never contact the API; fail the stage instead
    --stage NAME          run only this stage (repeatable)
    --json                print the run report as JSON
  check         preflight only
  diagnose      print the exact payload (--json, --prompt)
  test-llm      verify API access
  notify-test   send a test notification
  show-config   effective configuration, secrets masked
  show-policy   the action vocabulary and the local limits
```

## systemd

```bash
sudo systemctl enable --now aptai.timer   # daily at 04:00 ±1h
systemctl list-timers aptai.timer
sudo systemctl start aptai.service        # one manual run
journalctl -u aptai.service -f
```

Change the schedule with `systemctl edit aptai.timer`:

```ini
[Timer]
OnCalendar=
OnCalendar=Sun *-*-* 03:00:00
```

The unit is **deliberately not sandboxed** — `ProtectSystem=`, `PrivateTmp=`
and friends break dpkg's maintainer scripts. Use a VM or container for
isolation, not a systemd sandbox around dpkg.

## The safety layers

**1. The model cannot write a command.** Its answer is constrained to a JSON
schema whose `action` field is an enum of implemented actions. Every subprocess
call is a list with `shell=False`; no command string is ever built. Package
names must match Debian's grammar, so a name can never start with `-` and be
read as an option.

**2. The local policy** (`aptai/policy.py`) enforces the per-stage vocabulary,
the protected-package rules, the per-round action budget, removal limits, a
maximum risk level, and refuses to repeat an action that already failed.
Purge, version pinning, source editing and key import are off by default.

**3. apt's own simulation** — every destructive operation runs with `-s` first,
and the plan is abandoned if it removes a protected package, exceeds the
removal ceiling, or downgrades. This check asks apt, not the model.

**4. Prompt-injection handling** — machine output is fenced as untrusted data;
`import_repo_key` only accepts a key id apt itself reported as missing; and
`disable_apt_source` only accepts a host apt itself reported an error for.

Run `aptai show-policy` to see all of it on your machine.

## What gets uploaded

`sudo aptai diagnose` prints the payload; `--prompt` prints the whole prompt.

Sent: OS/kernel/architecture, apt and dpkg versions, free disk space, the
failed command's output, `dpkg --audit`, `apt-get -s -f install`, held
packages, `/etc/apt/sources.list*` (redacted) and the tail of
`/var/log/dpkg.log`.

Never sent, never even opened: `/etc/apt/auth.conf`, `auth.conf.d/*`,
`/root/.netrc`, `/etc/aptai/env`, `/etc/aptai/api_key`.

With `redact = true` (the default), `user:pass@host` credentials, API keys,
webhook URLs, bearer tokens and `password=`-shaped values are masked. Narrow it
further with `send_sources_list = false` or `dpkg_log_lines = 0`, or set
`llm.enabled = false` for no external calls at all.

## Notifications

Slack and Mattermost incoming webhooks, both at once if you like — the payload
is Slack-compatible, so one message format serves both.

```toml
[notify]
on_failure = true
on_success = false
on_reboot_required = true

[notify.slack]
webhook_url_file = "/etc/aptai/slack_webhook"   # mode 0600

[notify.mattermost]
webhook_url = "https://mattermost.example.com/hooks/xxxxxxxx"
channel = "ops"
```

The message carries the host, the failed stage, the number of advisor rounds,
the duration, the report path and a redacted error excerpt. The complete
history — every accepted and refused action, every command and its exit
status — is in `/var/log/aptai/run-<timestamp>.json`.

## Configuration

Every option is documented inline in [`config/aptai.toml`](config/aptai.toml).
**Unknown keys are a hard error**, so a typo in a safety limit cannot be
silently ignored.

```toml
[general]
mode = "auto"        # start with "suggest"
max_rounds = 3

[apt]
on_excessive_removals = "abort"   # or "fallback_upgrade" / "proceed"
max_upgrade_removals = 10
reboot_if_required = false

[llm]
model = "claude-opus-5"
effort = "high"      # low | medium | high | xhigh | max

[policy]
max_risk = "medium"
max_removals = 5
allow_sources_edit = false
allow_key_import = false
```

## Development

```bash
make test     # 155 unit tests; no network, no root, no apt required
make lint     # byte-compile + shellcheck + systemd-analyze verify
make check    # both
make dry-run  # a harmless local run
```

Most of the suite feeds hostile plans to the validator and asserts they are
refused (`tests/test_policy.py`). Add a test there before changing the policy.

CI runs the suite on Python 3.11/3.12/3.13, statically asserts that **no
third-party import** has crept in, and installs and uninstalls the tool inside
`ubuntu:24.04` and `debian:trixie` containers.

## Troubleshooting

| Symptom | What to do |
|---|---|
| `dpkg lock held ... by unattended-upgrade` | Normal; aptai waits up to `apt.lock_wait_seconds` (15 min) |
| `only NN MiB free on /boot` | Preflight stop. Clear old kernels with `apt-get autoremove` |
| `no API key` | Put `ANTHROPIC_API_KEY` in `/etc/aptai/env`, mode 0600 |
| `the model declined to answer` | A safety classifier declined; `llm.use_refusal_fallbacks` is on by default |
| `Claude API rejected the request` (400) | The 400 body is logged verbatim; individual features can be switched off in `[llm]` |
| `every proposed action was refused by the local policy` | Working as intended — the reasons are in the run report |
| Ran fine but nothing upgraded | `on_excessive_removals` may have degraded it to a removal-free `upgrade`; check `degraded` in the report |

## License

MIT — see [LICENSE](LICENSE). Security policy: [SECURITY.md](SECURITY.md).
