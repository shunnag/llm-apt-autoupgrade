# Contributing

Thanks for looking at aptai. A few things are non-negotiable because of what
this tool does; everything else is open to discussion.

## Hard rules

1. **Standard library only.** `aptai/` must not import anything outside the
   Python standard library, and the floor is Python 3.11. CI enforces this
   statically. The reason is in the README: this tool repairs a broken package
   manager, so it cannot depend on one.
2. **No shell.** Every subprocess goes through `aptai/sysexec.py:run_command`,
   which takes a list and hard-codes `shell=False`. Do not add a code path that
   builds a command string.
3. **New actions need three things.** Adding to the vocabulary means:
   an `ActionKind` entry and an `ACTION_DOCS` description in `aptai/plan.py`,
   a validator branch in `aptai/policy.py`, and an implementation in
   `aptai/executor.py` — plus a test that a hostile version of it is refused.
   Also decide which stages may use it in `STAGE_ACTIONS`.
4. **Policy changes come with tests first.** `tests/test_policy.py` is the file
   that decides whether this project is safe. If you relax a check, show what
   still catches the thing it used to catch.

## Running the tests

```bash
make check     # byte-compile, shellcheck, systemd-analyze, unit tests
make test      # just the unit tests
```

The suite needs no network, no root and no apt: `PackageFacts` is constructed
directly in `tests/helpers.py`, and HTTP is mocked. Keep it that way — a test
that needs a real Debian box will not run in CI.

## Testing against a real system

Use a throwaway VM or a container:

```bash
docker run --rm -it -v "$PWD:/src" ubuntu:24.04 bash
apt-get update && apt-get install -y python3
/src/scripts/install.sh
aptai run --dry-run --no-llm
```

To exercise the repair path, break something on purpose first — a bogus
`sources.list.d` entry for the update stage, or an interrupted `dpkg` for the
upgrade stage.

## Style

Match the surrounding code: 4 spaces, ~100 columns, `from __future__ import
annotations`, dataclasses for structured values, English comments. Comments
should explain *why* — the "what" is usually already readable.

## Commit messages

One logical change per commit, imperative mood, and say what the change means
for someone running this as root at 4am.
