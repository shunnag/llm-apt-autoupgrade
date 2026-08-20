# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-08-20

First release.

### Added

- Unattended upgrade cycle: preflight → `apt-get update` → `full-upgrade` →
  `autoremove` → optional `autoclean` → postflight.
- LLM advisor over the Claude Messages API (`claude-opus-5` by default), spoken
  over raw HTTPS with `urllib.request` — no SDK, no third-party dependency.
- A closed vocabulary of 19 typed remediation actions; the model can never
  return a shell command.
- Per-stage action vocabularies, so a failing `apt-get update` cannot reach
  dpkg state and a failing `full-upgrade` cannot rewrite repository config.
- Local safety policy: protected packages (configured list, `Essential: yes`,
  `Priority: required/important`, the running kernel), per-round action budget,
  removal limits, a maximum risk level and refusal of repeated actions.
- Simulation gate: every destructive apt operation is run with `-s` first and
  the resulting plan is inspected before anything is executed.
- Prompt-injection handling: machine output is fenced as untrusted data;
  `import_repo_key` requires the key id to appear in apt's own `NO_PUBKEY`
  error; `disable_apt_source` requires the host to appear in apt's error and
  refuses the distribution's own sources files.
- Redaction of credentials before anything leaves the host, and a refusal list
  covering `/etc/apt/auth.conf*`, `/root/.netrc` and the aptai secret files.
- Slack and Mattermost notifications with a JSON run report per run.
- systemd service and timer, plus `install.sh` / `uninstall.sh` and a Makefile.
- CLI: `run`, `check`, `diagnose`, `test-llm`, `notify-test`, `show-config`,
  `show-policy`.
- Defences against apt's own argument grammar: a leading `-` (option), a
  trailing `-` (apt's remove selector) and unresolvable names (POSIX regex
  expansion) are all refused, and every proposed package must resolve to a real
  package on the system.
- Fail-closed behaviour when `dpkg-query` cannot be read: no package is removed
  when Essential status cannot be verified.
- Partial `apt-get update` failures are treated as stage failures rather than
  success, so a stale security index is never upgraded against silently.
- Secret-shaped environment variables are scrubbed from the environment handed
  to apt/dpkg maintainer scripts, and the on-disk run report is redacted.
- 238 unit tests, most of them hostile-plan tests for the policy validator.
- CI on Python 3.11/3.12/3.13, a static stdlib-only import check, and
  install/uninstall smoke tests in `ubuntu:24.04` and `debian:trixie`.

[0.1.0]: https://github.com/shunnag/llm-apt-autoupgrade/releases/tag/v0.1.0
