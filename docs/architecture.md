# Architecture

A map of the code, for someone about to change it.

## Module layout

```
aptai/
  cli.py          argument parsing, subcommands, exit codes
  runner.py       stage orchestration + the consult loop     ← the control flow
  executor.py     apt stages, action implementations, simulation gate
  policy.py       the trust boundary: which actions may run  ← the safety core
  plan.py         action vocabulary, JSON schema, parsing
  llm.py          Claude Messages API over urllib
  aptcmd.py       argv construction, apt-get -s parsing, dpkg lock probe
  pkgfacts.py     one dpkg-query snapshot: Essential, Priority, running kernel
  diagnostics.py  the host state that is shown to the model
  redact.py       secret masking + the never-read path list
  config.py       TOML loading, strict validation, secret resolution
  notify.py       Slack / Mattermost webhooks
  report.py       the per-run JSON record
  sysexec.py      the single subprocess wrapper (shell=False, always)
  logsetup.py     console + rotating file logging
  errors.py       exception hierarchy and exit codes
```

Dependency direction is one-way: `cli → runner → {executor, llm, policy, notify}`,
and everything may use `sysexec`, `config`, `redact`, `errors`. `policy` depends
on `pkgfacts` and `plan` but never on `executor` or `llm` — it must be testable
against a synthetic dpkg database with nothing else present.

## The run

```
cli.main
 └─ Runner.run
     ├─ preflight            root, apt-get present, disk floors, dpkg lock wait
     ├─ PackageFacts.collect one dpkg-query for the whole run
     ├─ for stage in (update, full_upgrade, autoremove, autoclean):
     │    ├─ Executor.<stage>()
     │    └─ on failure: _consult_loop(stage)
     ├─ reboot_required(), diagnostics.collect(deep=False)
     ├─ RunReport.write  → /var/log/aptai/run-<ts>.json
     ├─ Notifier.send    → Slack / Mattermost
     └─ _maybe_reboot
```

A stage failure stops the run: there is no point running `autoremove` when
`full-upgrade` left the machine half-configured.

## The consult loop

```
_consult_loop(stage, failure):
  for round in 1..max_rounds:
      diagnostics = diagnostics.collect(deep=True)     fresh every round
      executor.stage_error_text = failure.error_text   used by the injection guards
      consultation = ClaudeClient.consult(stage, error, diagnostics, history)
          ↓ output_config.format → JSON → plan.parse_plan → Plan
      decision = Policy.review(plan, stage, previous_signatures)
          ↓ per-stage vocabulary, protected packages, budgets, repeats
      if decision.escalate or nothing accepted: return (escalated)
      if mode == "suggest": report the plan and return
      for action in decision.accepted:
          Executor.execute(action)                      simulate → inspect → run
      failure = <re-run the stage>
      if failure.success: return (recovered)
      if error_signature(failure) unchanged: return (no progress)
```

Three properties of this loop matter:

* **`previous_signatures` accumulates across rounds**, so the model cannot burn
  all three attempts on the same action.
* **`history` is fed back** into the next consultation with the outcome of each
  action, and the system prompt tells the model not to repeat what failed.
* **`error_signature`** normalises digits out of the interesting error lines
  (`E:`, `Err:`, `dpkg:`), so a failure that is materially the same across
  rounds ends the loop early instead of spending the remaining rounds.

## Where the two safety layers sit

```
model answer
   │
   ├─ plan.parse_plan ......... shape only. Unknown action → PlanParseError.
   │
   ├─ policy.Policy.review .... LAYER 1. Local config + dpkg facts.
   │                            Stage vocabulary, protected packages, budgets,
   │                            risk ceiling, repeats, per-action validation.
   │
   └─ executor.Executor ....... LAYER 2. apt's own opinion.
        _guarded(subcommand):
            apt-get -s <cmd>          ← ask apt what would happen
            parse_simulation(...)
            _review_simulation(...)   ← protected removals? over the ceiling?
                                        downgrades?
            apt-get -y <cmd>          ← only now
```

Layer 1 trusts the local configuration. Layer 2 trusts nothing but apt. An
action that lies about its consequences — `apt_install` on a package whose
dependency resolution removes forty others — is caught by layer 2, which never
reads the model's description of the action at all.

## Adding an action

1. `plan.py`: add to `ActionKind`, write an `ACTION_DOCS` entry (the model sees
   this text verbatim), add any new parameter to the schema in `plan_schema`
   and to `Action` / `_parse_action` / `Action.to_dict`.
2. `plan.py`: add it to the `STAGE_ACTIONS` entries where it makes sense — and
   only there. An action that touches dpkg state does not belong in `update`.
3. `policy.py`: add a `_check_*` branch in the `_check` dispatch table. Default
   to refusing; require an explicit config flag for anything that changes what
   the machine trusts or where it fetches packages from.
4. `executor.py`: implement it in the `execute` dispatch table. Route anything
   destructive through `_guarded` so it inherits the simulation gate. Honour
   `self.dry_run`.
5. `config/aptai.toml` + `config.py`: add the flag if you introduced one.
6. `tests/test_policy.py`: add the hostile version of the action and assert it
   is refused. This is the part that is not optional.

## Testing strategy

`tests/helpers.py` builds a synthetic `PackageFacts` (a small dpkg database
with known Essential/Priority packages and a known running kernel), so policy
tests run anywhere in milliseconds without root, apt or network.

| File | What it pins down |
|---|---|
| `test_policy.py` | hostile plans are refused — injection, protected packages, budgets, stage vocabulary, escalation |
| `test_executor.py` | the simulation gate; path/symlink handling; the key-mention and host-mention injection guards |
| `test_plan.py` | schema/parse shape; unknown actions rejected; the schema enum tracks the stage vocabulary |
| `test_aptcmd.py` | `apt-get -s` parsing against real output shapes; argv construction |
| `test_llm.py` | request shape for `claude-opus-5`; 400 degradation; retries; refusal handling |
| `test_config.py` | unknown keys and wrong types are hard errors; secret file modes |
| `test_redact.py` | credential shapes are masked; ordinary apt output is not |
| `test_notify.py` | Slack/Mattermost payloads; delivery failures are reported, not raised |
| `test_runner.py` | `error_signature` behaviour; stage wiring is complete |

## Claude API specifics

`llm.ClaudeClient.build_request` is the only place the request body is
assembled. For `claude-opus-5`:

* `thinking` is **omitted** — adaptive thinking is the default on this model,
  and `budget_tokens` is rejected with a 400.
* `output_config` carries `effort` and `format` as siblings; `format` is
  `{"type": "json_schema", "schema": ...}` with the enum restricted to the
  current stage.
* Refusal fallbacks use the scalar form `fallbacks: "default"` together with
  the `server-side-fallback-2026-07-01` beta header. Pairing the scalar form
  with the older `-2026-06-01` header is a 400.
* `stop_reason == "refusal"` is a normal outcome, not an exception: it becomes
  "no plan available" and the stage escalates.

Every optional feature above is behind a config flag, and a 400 triggers one
automatic retry with all of them stripped, with the 400 body logged verbatim.
That way an API change is a configuration edit on the affected fleet rather
than a code release.
