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
