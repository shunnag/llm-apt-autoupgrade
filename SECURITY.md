# Security model

aptai runs as root, unattended, on a machine whose package manager has just
failed, and it asks a language model what to do next. That is a genuinely
dangerous shape for a program, so the design starts from the assumption that
**the model's answer is hostile** and works backwards from there.

This document describes what is guaranteed, what is merely mitigated, and what
you take on yourself when you turn certain options on.

---

## Threat model

Assumed capable of influencing the model's answer:

* **Prompt injection through machine output.** apt error text, package
  descriptions, `Release` file fields, maintainer-script output and repository
  banners all flow into the prompt. Any of them can contain text shaped like
  instructions, and a third-party repository is enough to get text in front of
  the model.
* **A compromised or impersonated API endpoint.** `llm.base_url` is
  configurable, TLS is verified with the system trust store, but a
  sufficiently placed attacker who can present a valid certificate can return
  arbitrary JSON.
* **A model that is simply wrong.** Not malice — an ordinary bad answer that
  would, for example, "fix" a dependency conflict by removing `libc6`.

Explicitly **not** in the threat model: a local attacker who is already root
(they do not need aptai), and a malicious operator editing
`/etc/aptai/config.toml` (that file *is* the policy).

---

## What is structurally guaranteed

These properties do not depend on the model behaving:

### 1. The model cannot express a shell command

The response is constrained to a JSON schema whose `action` field is an `enum`
of the actions aptai implements (`aptai/plan.py`). Anything else fails to parse
and the round is abandoned. There is no "run this command" action, no
free-text command field, and no code path that concatenates a command string.

Every subprocess goes through `aptai/sysexec.py:run_command`, which takes a
list and hard-codes `shell=False`. Nothing in the package builds a command
line as text.

### 2. Arguments cannot be options, selectors or regexes

Package names must match Debian's package-name grammar, optionally with a
`:arch` qualifier and an `=version` pin. The pattern is anchored, so a name can
contain no whitespace, quotes, slashes or shell metacharacters.

The subtler half is apt's *own* argument grammar, which turns two innocuous
strings into something else entirely:

| Argument | What apt-get does with it |
|---|---|
| `--allow-remove-essential` | an option — blocked because a name may not start with `-` |
| `ufw-` | **removes** ufw: a trailing `-` is apt's "remove instead" selector |
| `anything+` | installs it: a trailing `+` is the mirror selector |
| `linux-image.` | a POSIX regex, expanded across every matching package |

So aptai refuses a leading `-`, refuses a trailing `-`, and — the general fix —
requires every model-supplied name to **resolve to a package that exists on
this system**, checked against the local dpkg database and then `apt-cache
show` with an exact `Package:` match (`policy.require_known_packages`, on by
default). A regex that expands to other packages does not match itself, so it
is refused; an invented name is refused; a genuine fix always names a real
package. `aptcmd` re-applies the same pattern immediately before building argv,
so the guarantee survives a future refactor of the policy.

### 3. Boot-critical packages cannot be removed

`aptai/policy.py:protected_reason` refuses removal, purge and `apt-mark auto`
for any package that is:

* listed in `policy.protected_packages`, or
* marked `Essential: yes` in the local dpkg database, or
* `Priority: required` / `important` (while `protect_required_priority` is on), or
* part of the **currently booted** kernel — which matters because a machine that
  has not rebooted since its last kernel upgrade still needs those files.

`apt-mark auto` gets the same treatment as a removal because it is a deferred
one: `autoremove` would take the package later.

### 4. apt is asked before apt is trusted

Independently of anything the model said, every destructive apt operation is
first run with `-s` and the resulting plan is parsed
(`aptai/executor.py:_review_simulation`). The operation is abandoned when:

* the simulation output could not be parsed at all — an unknown plan is never
  executed;
* the plan removes a protected package;
* it removes more packages than the configured ceiling — and for `apt_install`
  and `apt_reinstall` that ceiling is **zero**, so an install that resolves
  into a removal always escalates instead of proceeding;
* it installs more than `policy.max_new_installs` new packages;
* it downgrades packages without `policy.allow_downgrade`.

Purges (`Purg` lines) count as removals, and a missing dpkg database is fatal
to all of it: if `dpkg-query` could not be read, `protected_reason` returns a
refusal for *every* package, so nothing is removed at all. Failing closed here
is deliberate — without the database, nothing can be shown to be safe.

This is the check that catches the realistic failure: an innocuous-looking
`apt_install` whose dependency resolution cascades into removing half the
system. The model's own description of its action is never used for this
decision.

### 5. The blast radius is bounded per stage

Each stage exposes a different slice of the vocabulary (`plan.STAGE_ACTIONS`).
A failing `apt-get update` is a repository or keyring problem, so that stage
cannot touch dpkg state at all. A failing `full-upgrade` is a dpkg problem, so
it cannot rewrite repository configuration. `autoclean` can only touch the
package cache.

### 6. A partial `apt-get update` is not a success

apt exits 0 even when individual repositories fail to refresh, which would let
a machine upgrade against a stale — possibly stale *security* — index and
report success. `apt.fail_on_partial_update` (on by default) scans the
untruncated output for `Err:`, `W: Failed to fetch`, `W: GPG error` and
`W: Some index files failed to download` and fails the stage instead.

### 7. Secrets are not uploaded

`/etc/apt/auth.conf`, `/etc/apt/auth.conf.d/*`, `/root/.netrc`,
`/etc/aptai/env` and `/etc/aptai/api_key` are on a refusal list and are never
opened. Everything that does leave the host passes through
`aptai/redact.py:redact`, which masks `scheme://user:pass@host` credentials,
Anthropic/Slack/GitHub/GitLab/AWS token shapes, `Bearer` tokens and
`password=`/`token=`/`api_key=` style assignments.

Run `aptai diagnose` to see the exact payload, and `aptai diagnose --prompt`
to see the full prompt. Nothing is uploaded that this command does not print.

Two related paths carry the same filter. The run report on disk quotes the raw
stdout/stderr of every apt command — where a private repository's credentials
would appear — so it is redacted before it is written, at mode 0640. And the
child environment handed to apt/dpkg is scrubbed of anything secret-shaped
(`*_KEY`, `*_TOKEN`, `*_SECRET`, `*_WEBHOOK`, `*_PASSWORD`, plus the explicit
aptai names): systemd loads `/etc/aptai/env` into aptai's environment, and
without that scrub the API key and webhook URLs would be visible to every
maintainer script of every package being upgraded — third-party code running
as root.

### 8. A crash still pages you

The stage loop is wrapped so that an unexpected exception still writes the run
report and sends the notification before re-raising. Dying silently half way
through an upgrade is the one outcome this tool exists to prevent, so the
parsers are written to raise `PlanParseError` rather than anything else — a
model answer of `{"seconds": 1e400}` is legal JSON that decodes to `inf`, and
`int(inf)` raises `OverflowError`, which is exactly the kind of exception that
would otherwise escape every handler.

### 9. The loop terminates

At most `general.max_rounds` (default 3) consult-and-remediate cycles per
stage. An action whose signature was already attempted in this stage is
refused, and if the failure's normalised signature is unchanged after a round,
aptai stops early rather than spending the remaining rounds.

---

## What is mitigated, not guaranteed

* **Prompt injection.** The machine output is fenced with explicit
  begin/end markers and the system prompt defines it as data. That reduces the
  risk; it does not eliminate it. The real defence is that a successful
  injection still cannot express anything outside the vocabulary, and still has
  to pass the policy and the simulation. Treat the fencing as depth, not as the
  boundary.
* **A wrong-but-permitted action.** `apt-mark hold` on the wrong package,
  `reset_apt_lists` when the real problem was a proxy, an `apt_install` that
  pulls in something unwanted — all of these are within policy and can happen.
  The run report records every one of them.
* **Denial of service by the advisor.** A model that always answers
  "escalate" turns aptai into a paging machine. That is the intended failure
  direction.

---

## Options that are off by default, and why

Turning either of these on moves a decision out of the guaranteed column.

### `policy.allow_key_import`

Imports an OpenPGP key from a keyserver into `/etc/apt/trusted.gpg.d/`, which
grants that key **repository-wide trust**: apt will then accept packages signed
by it from any source. This is the standard fix for `NO_PUBKEY`, and it is also
the single most valuable thing an attacker could get aptai to do.

Mitigations when enabled: the keyserver must be in
`policy.allowed_keyservers`; key ids must be hexadecimal; and — the important
one — **the key id must appear in apt's own error output for this failure**. A
key the model invented, or one named only inside injected text that apt did not
report as missing, is refused (`executor._key_mentioned`).

Even so: prefer fixing a missing key by hand, once, with a keyring you have
verified out of band.

### `policy.allow_sources_edit`

Comments out repository entries that match a URI, in a single file, after
taking a backup into `/var/lib/aptai/backups/`.

Mitigations when enabled: the path must resolve (via `realpath`, so symlinks
cannot redirect it) to a `.list` or `.sources` file under `/etc/apt`; the
distribution's own sources files are refused outright, so aptai can never cut
a machine off from its security updates; and the URI's host must appear in
apt's error output for this failure.

### `policy.allow_downgrade`

Permits `=version` pins, which can install an older version than the one
present. The simulation gate still refuses a plan that downgrades when this is
off, so this option must be enabled in both places for a downgrade to happen.

### `apt.reboot_if_required`

Reboots the machine when `/var/run/reboot-required` appears after a successful
run. Off by default. This is a policy decision about your fleet, not a
technical one.

---

## Operational hardening

* Keep `mode = "suggest"` until you have seen a few real runs. It performs the
  whole diagnosis and reports what *would* have been done.
* Use a **dedicated Anthropic API key** for aptai, so it can be revoked without
  touching anything else, and give it its own spend limit.
* `/etc/aptai/env` must be mode `0600` and owned by root; aptai refuses to read
  a group- or world-readable `api_key_file`.
* Run it on a canary host first. `RandomizedDelaySec=3600` in the timer keeps a
  fleet from failing simultaneously, but it does not keep it from failing
  identically.
* Read `/var/log/aptai/run-*.json` after the first few runs. Every accepted and
  refused action is recorded there with its reason.
* If you do not want any external network call, set `llm.enabled = false`.
  aptai still upgrades, still enforces the simulation gate, and still notifies
  on failure — it just does not ask for advice.

### The systemd unit is deliberately not sandboxed

`ProtectSystem=`, `PrivateTmp=`, `ProtectHome=` and `ReadOnlyPaths=` break
dpkg: maintainer scripts write across the filesystem, restart services and
expect a real `/tmp`. Adding them would produce upgrade failures that look like
package bugs. If you need isolation, use a VM or a container — not a systemd
sandbox around dpkg.

---

## Reporting a vulnerability

Please report security issues privately through
[GitHub Security Advisories](https://github.com/shunnag/llm-apt-autoupgrade/security/advisories/new)
rather than in a public issue.

Especially interesting:

* a way to make aptai execute anything outside the action vocabulary;
* a package name, key id, keyserver, URI or path that passes validation and is
  then interpreted as an option, an apt selector, a POSIX regex, a path outside
  `/etc/apt`, or shell syntax;
* an input that makes aptai raise instead of escalating, since a crash skips
  both the run report and the page;
* a way to remove, purge or auto-mark a protected, Essential or running-kernel
  package;
* a credential shape that reaches the API or a webhook unredacted;
* a way to make the consult loop exceed `max_rounds` or not terminate.

A reproduction as a failing test in `tests/test_policy.py` or
`tests/test_executor.py` is the most useful form a report can take.
