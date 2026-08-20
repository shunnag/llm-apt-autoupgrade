"""Command line interface."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys

from aptai import diagnostics as diag_mod
from aptai.config import DEFAULT_CONFIG_PATH, Config, load_config, validate
from aptai.errors import AptaiError, ConfigError
from aptai.llm import ClaudeClient, build_user_prompt, vocabulary_text
from aptai.logsetup import setup_logging
from aptai.notify import Notifier
from aptai.pkgfacts import PackageFacts
from aptai.plan import STAGE_ACTIONS
from aptai.policy import Policy
from aptai.runner import Runner
from aptai.version import __version__

LOG = logging.getLogger("aptai")

DESCRIPTION = """\
aptai -- LLM-assisted unattended APT upgrades for Debian and Ubuntu.

Runs apt-get update, full-upgrade and autoremove. When a stage fails, the
captured output and a redacted host diagnosis are sent to the Claude API,
which answers with a plan built from a fixed vocabulary of typed actions.
A local policy filters that plan, apt itself simulates every destructive
step, and only what survives both checks is executed. After three failed
rounds the run stops and pages a human over Slack or Mattermost.
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aptai",
        description=DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"aptai {__version__}")
    parser.add_argument("-c", "--config", default=DEFAULT_CONFIG_PATH,
                        help=f"configuration file (default: {DEFAULT_CONFIG_PATH})")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    parser.add_argument("-q", "--quiet", action="store_true", help="errors only on the console")
    sub = parser.add_subparsers(dest="command")

    run = sub.add_parser("run", help="run the full upgrade cycle (the default command)")
    run.add_argument("--dry-run", action="store_true",
                     help="simulate every apt operation; change nothing")
    run.add_argument("--mode", choices=("auto", "suggest"),
                     help="auto: execute the advisor's approved actions; "
                          "suggest: only report them")
    run.add_argument("--max-rounds", type=int, metavar="N",
                     help="advisor rounds per failed stage (default: from the config)")
    run.add_argument("--no-llm", action="store_true",
                     help="never contact the Claude API; fail the stage instead")
    run.add_argument("--stage", action="append", choices=[s for s in STAGE_ACTIONS],
                     help="run only this stage (repeatable)")
    run.add_argument("--json", action="store_true", help="print the run report as JSON")

    sub.add_parser("check", help="run the preflight checks and exit")

    diagnose = sub.add_parser(
        "diagnose", help="print exactly what aptai would upload to the Claude API")
    diagnose.add_argument("--json", action="store_true", help="print as JSON")
    diagnose.add_argument("--stage", default="full_upgrade", choices=[s for s in STAGE_ACTIONS],
                          help="render the prompt for this stage (default: full_upgrade)")
    diagnose.add_argument("--prompt", action="store_true",
                          help="also print the full prompt that would be sent")

    sub.add_parser("test-llm", help="send a one-token request to verify API access")
    sub.add_parser("notify-test", help="send a test message to Slack/Mattermost")
    sub.add_parser("show-config", help="print the effective configuration")
    sub.add_parser("show-policy", help="print the action vocabulary and the local limits")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    command = args.command or "run"

    # An explicitly given --config must exist; the default one may be absent,
    # in which case the built-in defaults are used.
    explicit = args.config != DEFAULT_CONFIG_PATH
    config_path = args.config if (explicit or os.path.exists(args.config)) else None
    try:
        config = load_config(config_path)
    except ConfigError as exc:
        print(f"aptai: {exc}", file=sys.stderr)
        return exc.exit_code

    _apply_overrides(config, args)
    log_path = setup_logging(
        config.general.log_dir if command == "run" else "",
        config.general.log_level,
        quiet=args.quiet,
        verbose=args.verbose,
    )
    if log_path:
        LOG.debug("logging to %s", log_path)

    handlers = {
        "run": cmd_run,
        "check": cmd_check,
        "diagnose": cmd_diagnose,
        "test-llm": cmd_test_llm,
        "notify-test": cmd_notify_test,
        "show-config": cmd_show_config,
        "show-policy": cmd_show_policy,
    }
    try:
        return handlers[command](config, args)
    except AptaiError as exc:
        LOG.error("%s", exc)
        return exc.exit_code
    except KeyboardInterrupt:
        print("aptai: interrupted", file=sys.stderr)
        return 130


def _apply_overrides(config: Config, args: argparse.Namespace) -> None:
    if getattr(args, "dry_run", False):
        config.general.dry_run = True
    if getattr(args, "mode", None):
        config.general.mode = args.mode
    if getattr(args, "max_rounds", None) is not None:
        config.general.max_rounds = max(0, args.max_rounds)
    if args.verbose:
        config.general.log_level = "DEBUG"
    # load_config() validated the file; command line overrides have to face the
    # same limits, or --max-rounds 500 would walk straight past them.
    validate(config)


# ------------------------------------------------------------------ commands


def cmd_run(config: Config, args: argparse.Namespace) -> int:
    runner = Runner(
        config,
        dry_run=config.general.dry_run,
        mode=config.general.mode,
        use_llm=not getattr(args, "no_llm", False),
        only_stages=getattr(args, "stage", None),
    )
    report = runner.run()
    if getattr(args, "json", False):
        print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
    else:
        print(report.summary_text())
        if report.path:
            print(f"report: {report.path}")
    return 0 if report.success else 1


def cmd_check(config: Config, args: argparse.Namespace) -> int:
    runner = Runner(config, dry_run=True)
    runner.preflight()
    print("preflight: ok")
    facts = PackageFacts.collect()
    print(f"dpkg database: {len(facts.packages)} packages, running kernel {facts.kernel_release}")
    client = ClaudeClient(config)
    print(f"claude api key: {'present' if client.api_key else 'MISSING'}")
    notifier = Notifier(config)
    print(f"notification targets: {', '.join(notifier.targets) or 'none configured'}")
    return 0


def cmd_diagnose(config: Config, args: argparse.Namespace) -> int:
    facts = PackageFacts.collect()
    diagnostics = diag_mod.collect(config, facts, deep=True)
    if args.json:
        print(json.dumps(diagnostics.to_dict(), indent=2, ensure_ascii=False))
    else:
        print(diagnostics.to_text())
    if args.prompt:
        allowed = STAGE_ACTIONS[args.stage]
        print("\n" + "=" * 72)
        print(vocabulary_text(allowed))
        print("=" * 72)
        print(
            build_user_prompt(
                stage=args.stage,
                error_text="(the captured output of the failed stage goes here)",
                diagnostics_text=diagnostics.to_text(),
                history=[],
                round_number=1,
                max_rounds=config.general.max_rounds,
                allowed=allowed,
                max_chars=config.privacy.max_payload_chars,
            )
        )
    return 0


def cmd_test_llm(config: Config, args: argparse.Namespace) -> int:
    ok, message = ClaudeClient(config).probe()
    print(("ok: " if ok else "failed: ") + message)
    return 0 if ok else 5


def cmd_notify_test(config: Config, args: argparse.Namespace) -> int:
    results = Notifier(config).send_test()
    failed = False
    for result in results:
        print(f"{result.target}: {'ok' if result.ok else 'FAILED'} {result.message}".rstrip())
        failed = failed or not result.ok
    return 6 if failed else 0


def cmd_show_config(config: Config, args: argparse.Namespace) -> int:
    data = config.to_dict()
    data["source_path"] = config.source_path or "(built-in defaults; no file loaded)"
    print(json.dumps(data, indent=2, ensure_ascii=False))
    return 0


def cmd_show_policy(config: Config, args: argparse.Namespace) -> int:
    facts = PackageFacts.collect()
    policy = Policy(config, facts)
    print("Action vocabulary per stage")
    print("=" * 72)
    for stage, actions in STAGE_ACTIONS.items():
        print(f"\n[{stage}]")
        for action in actions:
            print(f"  - {action.value}")
    print("\nLocal limits")
    print("=" * 72)
    limits = config.policy
    print(f"  mode                     {config.general.mode}")
    print(f"  max advisor rounds       {config.general.max_rounds}")
    print(f"  max actions per round    {limits.max_actions_per_round}")
    print(f"  max risk accepted        {limits.max_risk}")
    print(f"  max packages removed     {limits.max_removals}")
    print(f"  max new packages         {limits.max_new_installs} (per advisor install action)")
    print(f"  require known packages   {limits.require_known_packages}")
    print(f"  removals during upgrade  {config.apt.max_upgrade_removals} "
          f"(on excess: {config.apt.on_excessive_removals})")
    print(f"  removals during autorm   {config.apt.max_autoremove_removals}")
    print(f"  allow remove/purge       {limits.allow_remove}/{limits.allow_purge}")
    print(f"  allow sources edit       {limits.allow_sources_edit}")
    print(f"  allow key import         {limits.allow_key_import}")
    print(f"  allow downgrade          {limits.allow_downgrade}")
    print(f"  partial update fails     {config.apt.fail_on_partial_update}")
    print(f"  protected packages       {len(limits.protected_packages)} listed, "
          f"plus Essential/required and the running kernel")
    kernel = sorted(facts.running_kernel_packages())
    if kernel:
        print(f"  running kernel packages  {', '.join(kernel[:6])}"
              f"{' ...' if len(kernel) > 6 else ''}")
    if not facts.collected:
        print("\n  WARNING: the dpkg database could not be read on this machine, so aptai")
        print("           cannot verify Essential status. Every removal will be refused.")
    unsafe = [p for p in ("libc6", "systemd", "apt", "dpkg") if not policy.protected_reason(p)]
    if unsafe:
        print(f"  WARNING: not protected:  {', '.join(unsafe)}")
    return 0
