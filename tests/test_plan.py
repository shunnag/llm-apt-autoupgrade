"""Parsing of the model's answer -- shape validation only."""

from __future__ import annotations

import unittest

from aptai.plan import (
    ActionKind,
    PlanParseError,
    extract_json_object,
    parse_plan,
    plan_schema,
    STAGE_ACTIONS,
    ACTION_DOCS,
)


class TestParsePlan(unittest.TestCase):
    def test_parses_a_well_formed_plan(self):
        plan = parse_plan(
            {
                "diagnosis": "dpkg was interrupted",
                "confidence": "high",
                "escalate": False,
                "actions": [
                    {"action": "dpkg_configure_pending", "reason": "finish the interrupted run",
                     "risk": "medium"},
                    {"action": "apt_fix_broken", "reason": "let apt repair deps", "risk": "medium"},
                ],
            }
        )
        self.assertEqual(2, len(plan.actions))
        self.assertEqual(ActionKind.DPKG_CONFIGURE_PENDING, plan.actions[0].kind)
        self.assertEqual("high", plan.confidence)

    def test_unknown_action_is_rejected(self):
        with self.assertRaises(PlanParseError):
            parse_plan({"actions": [{"action": "rm_rf_slash", "reason": "x", "risk": "low"}]})

    def test_shell_command_shaped_action_is_rejected(self):
        with self.assertRaises(PlanParseError):
            parse_plan({"actions": [{"action": "bash -c 'rm -rf /'", "reason": "x", "risk": "low"}]})

    def test_unparseable_risk_becomes_high(self):
        plan = parse_plan(
            {"actions": [{"action": "apt_clean", "reason": "x", "risk": "totally-safe-trust-me"}]}
        )
        self.assertEqual("high", plan.actions[0].risk)

    def test_non_object_payload_is_rejected(self):
        for payload in ([], "text", 5, None):
            with self.subTest(payload=payload):
                with self.assertRaises(PlanParseError):
                    parse_plan(payload)

    def test_actions_must_be_a_list(self):
        with self.assertRaises(PlanParseError):
            parse_plan({"actions": {"action": "apt_clean"}})

    def test_package_list_is_capped(self):
        with self.assertRaises(PlanParseError):
            parse_plan(
                {"actions": [{"action": "apt_install", "reason": "x", "risk": "low",
                              "packages": [f"p{i}" for i in range(60)]}]}
            )

    def test_a_single_package_string_is_accepted(self):
        plan = parse_plan(
            {"actions": [{"action": "apt_install", "reason": "x", "risk": "low",
                          "packages": "nginx"}]}
        )
        self.assertEqual(["nginx"], plan.actions[0].packages)


class TestExtractJson(unittest.TestCase):
    def test_bare_json(self):
        self.assertEqual({"a": 1}, extract_json_object('{"a": 1}'))

    def test_fenced_json(self):
        self.assertEqual({"a": 1}, extract_json_object('```json\n{"a": 1}\n```'))

    def test_json_with_prose_around_it(self):
        self.assertEqual(
            {"a": 1}, extract_json_object('Here is the plan:\n{"a": 1}\nHope that helps.')
        )

    def test_no_json_raises(self):
        with self.assertRaises(PlanParseError):
            extract_json_object("I could not determine the cause.")


class TestSchema(unittest.TestCase):
    def test_schema_enum_matches_the_stage_vocabulary(self):
        for stage, allowed in STAGE_ACTIONS.items():
            with self.subTest(stage=stage):
                schema = plan_schema(allowed)
                enum = schema["properties"]["actions"]["items"]["properties"]["action"]["enum"]
                self.assertEqual([a.value for a in allowed], enum)
                self.assertFalse(schema["additionalProperties"])
                self.assertFalse(schema["properties"]["actions"]["items"]["additionalProperties"])

    def test_every_action_is_documented(self):
        for kind in ActionKind:
            self.assertIn(kind, ACTION_DOCS, f"{kind} has no description for the model")

    def test_no_stage_exposes_an_undocumented_action(self):
        for stage, allowed in STAGE_ACTIONS.items():
            for kind in allowed:
                self.assertIsInstance(ACTION_DOCS[kind], str)


if __name__ == "__main__":
    unittest.main()


class TestHostileNumbers(unittest.TestCase):
    """`1e400` is legal JSON and decodes to inf; int(inf) raises OverflowError."""

    def test_infinity_becomes_a_parse_error(self):
        import json as _json

        payload = _json.loads(
            '{"diagnosis":"d","confidence":"low","escalate":false,'
            '"actions":[{"action":"wait","reason":"r","risk":"low","seconds":1e400}]}'
        )
        with self.assertRaises(PlanParseError):
            parse_plan(payload)

    def test_negative_infinity_becomes_a_parse_error(self):
        with self.assertRaises(PlanParseError):
            parse_plan({"actions": [{"action": "wait", "reason": "r", "risk": "low",
                                     "seconds": float("-inf")}]})

    def test_nan_becomes_a_parse_error(self):
        with self.assertRaises(PlanParseError):
            parse_plan({"actions": [{"action": "wait", "reason": "r", "risk": "low",
                                     "seconds": float("nan")}]})

    def test_huge_integer_becomes_a_parse_error(self):
        with self.assertRaises(PlanParseError):
            parse_plan({"actions": [{"action": "wait", "reason": "r", "risk": "low",
                                     "seconds": 10 ** 30}]})

    def test_ordinary_numbers_still_work(self):
        plan = parse_plan(
            {"actions": [{"action": "wait", "reason": "r", "risk": "low", "seconds": 30}]}
        )
        self.assertEqual(30, plan.actions[0].seconds)


class TestPackageGrammar(unittest.TestCase):
    def test_rejects_apt_selector_suffixes(self):
        from aptai.plan import PACKAGE_RE

        for name in ["ufw-", "apparmor-", "linux-image."]:
            self.assertIsNone(PACKAGE_RE.match(name), f"{name!r} must not match")

    def test_accepts_real_package_names(self):
        from aptai.plan import PACKAGE_RE

        for name in ["nginx", "g++", "libstdc++6", "python3.12", "linux-image-6.8.0-45-generic",
                     "libfoo1:amd64", "nginx=1.24.0-1"]:
            self.assertIsNotNone(PACKAGE_RE.match(name), f"{name!r} must match")

    def test_schema_uses_only_widely_supported_keywords(self):
        # The structured-output validator accepts a conservative subset; keep
        # the schema inside it so a plan is never rejected with a 400.
        allowed = {"type", "properties", "required", "additionalProperties", "items",
                   "enum", "description"}
        seen = set()

        def walk(node):
            if isinstance(node, dict):
                for key, value in node.items():
                    if key in ("properties",):
                        seen.add(key)
                        for sub in value.values():
                            walk(sub)
                        continue
                    seen.add(key)
                    walk(value)
            elif isinstance(node, list):
                for item in node:
                    walk(item)

        walk(plan_schema(STAGE_ACTIONS["full_upgrade"]))
        self.assertEqual(set(), seen - allowed, f"unexpected schema keywords: {seen - allowed}")
