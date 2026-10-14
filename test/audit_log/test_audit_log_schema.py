#!/usr/bin/env python3
"""
Validate the proxy's audit-log examples against its JSON Schema.

proxy/audit/audit-log.examples.jsonl is generated from the proxy's own code
(see proxy/src/audit.rs), and the Rust tests check the schema's reason table
against that code.  This test closes the loop from the consumer's side: every
example line must validate against proxy/audit/audit-log.schema.json with a
standard JSON Schema validator, and the examples must cover every reason the
schema defines, with the stage and severity the schema promises.

Requirements:
    pip install jsonschema

Usage (from repo root):
    python3 test/audit_log/test_audit_log_schema.py
"""

import copy
import json
import unittest
from pathlib import Path

try:
    from jsonschema import Draft202012Validator, FormatChecker
except ImportError:  # pragma: no cover - exercised only without the dependency
    Draft202012Validator = None

AUDIT_DIR = Path(__file__).resolve().parents[2] / "proxy" / "audit"
SCHEMA = AUDIT_DIR / "audit-log.schema.json"
EXAMPLES = AUDIT_DIR / "audit-log.examples.jsonl"


def load_examples():
    with EXAMPLES.open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


@unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
class AuditLogSchemaTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        cls.validator = Draft202012Validator(cls.schema, format_checker=FormatChecker())
        cls.examples = load_examples()
        cls.audit = [e for e in cls.examples if e["event"]["kind"] == "audit"]
        cls.reasons = {
            r["const"]: r for r in cls.schema["$defs"]["reason"]["oneOf"]
        }

    def test_schema_is_valid_draft_2020_12(self):
        Draft202012Validator.check_schema(self.schema)

    def test_every_example_validates(self):
        for n, record in enumerate(self.examples, 1):
            with self.subTest(line=n):
                errors = [e.message for e in self.validator.iter_errors(record)]
                self.assertEqual(errors, [])

    def test_every_reason_has_an_example_with_its_stage_and_severity(self):
        seen = {}
        for record in self.audit:
            reason = record["event"]["reason"]
            if reason is not None:
                seen[reason] = record
        self.assertEqual(sorted(seen), sorted(self.reasons))
        for code, record in seen.items():
            with self.subTest(reason=code):
                self.assertEqual(record["event"]["stage"], self.reasons[code]["x-stage"])
                self.assertEqual(record["event"]["severity"], self.reasons[code]["x-severity"])

    def test_every_action_has_an_example(self):
        actions = {r["event"]["action"] for r in self.audit}
        self.assertEqual(actions, set(self.schema["$defs"]["action"]["enum"]))

    def test_no_record_carries_a_path(self):
        # The whole point of dropping paths: no key anywhere may carry one.
        def keys(value):
            if isinstance(value, dict):
                for k, v in value.items():
                    yield k
                    yield from keys(v)
            elif isinstance(value, list):
                for v in value:
                    yield from keys(v)

        for record in self.examples:
            for key in keys(record):
                self.assertNotIn(key, {"path", "url", "uri", "query"})

    def test_schema_rejects_inconsistent_records(self):
        success = next(r for r in self.audit if r["event"]["outcome"] == "success")
        failure = next(r for r in self.audit if r["event"]["outcome"] == "failure")

        cases = {
            "success with a reason": lambda r: r["event"].update(reason="nonce_replay"),
            "unknown reason": lambda r: r["event"].update(reason="made_up"),
            "path smuggled into http": lambda r: r["http"].update(path="/secret.docx"),
            "unverified machine with a hostname": lambda r: r["machine"].update(
                status="failed", hostname="ws-1.example.com"
            ),
            "timestamp without milliseconds": lambda r: r.update(
                timestamp="2026-10-14T13:04:05Z"
            ),
        }
        for name, mutate in cases.items():
            with self.subTest(case=name):
                record = copy.deepcopy(success)
                mutate(record)
                self.assertFalse(self.validator.is_valid(record))

        record = copy.deepcopy(failure)
        record["event"]["severity"] = "info"
        self.assertFalse(self.validator.is_valid(record), "failure at severity info")


if __name__ == "__main__":
    unittest.main()
