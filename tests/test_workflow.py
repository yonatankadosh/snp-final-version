from __future__ import annotations

import asyncio
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

from privacy_agent import scanner
from privacy_agent.mcp_server import mcp
from privacy_agent.service import PrivacyService

RAW_EMAIL = "jane.doe@gmail.com"


class WorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self._git("init", "-b", "main")
        self._git("config", "user.email", "test@example.invalid")
        self._git("config", "user.name", "Privacy Agent Test")
        PrivacyService.init_repo(self.root)
        self.service = PrivacyService(self.root)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _git(self, *args: str) -> None:
        subprocess.run(
            ["git", *args],
            cwd=self.root,
            check=True,
            capture_output=True,
        )

    def _write(self, name: str, content: str) -> None:
        (self.root / name).write_text(content, encoding="utf-8")

    def _commit_file(self, content: str, name: str = "app.py") -> None:
        self._write(name, content)
        self._git("add", ".")
        self._git("commit", "-m", "fixture")

    def _finding(self, **overrides) -> dict:
        finding = {
            "rule_id": "HIPAA-001",
            "file": "app.py",
            "line": 1,
            "quote": f'CONTACT = "{RAW_EMAIL}"',
            "explanation": "Hardcoded personal email address.",
            "confidence": "high",
        }
        finding.update(overrides)
        return finding

    # ------------------------------------------------------------------ init

    def test_init_repo_creates_layout_and_never_overwrites(self) -> None:
        agent = self.root / ".privacy-agent"
        for relative in (
            "config.yaml",
            "policies/hipaa.yaml",
            "policies/gdpr.yaml",
            "audit-logs/.gitkeep",
            ".gitignore",
        ):
            self.assertTrue((agent / relative).is_file(), relative)

        (agent / "config.yaml").write_text("custom: true\n", encoding="utf-8")
        result = PrivacyService.init_repo(self.root)
        self.assertEqual(result["created"], [])
        self.assertIn(".privacy-agent/config.yaml", result["existing"])
        self.assertEqual((agent / "config.yaml").read_text(), "custom: true\n")

    def test_template_rules_carry_model_facing_fields(self) -> None:
        for name in ("hipaa.yaml", "gdpr.yaml"):
            policy = yaml.safe_load(
                (self.root / ".privacy-agent" / "policies" / name).read_text()
            )
            for rule in policy["rules"]:
                self.assertTrue(rule["description"].strip(), rule["id"])
                self.assertTrue(rule["examples"]["violating"], rule["id"])
                self.assertTrue(rule["examples"]["compliant"], rule["id"])

    # ----------------------------------------------------------------- rules

    def test_active_rules_exclude_disabled_and_inactive(self) -> None:
        before = self.service.get_active_rules()
        ids = {rule["rule_id"] for rule in before["rules"]}
        self.assertIn("HIPAA-001", ids)
        self.assertFalse(any(rule_id.startswith("GDPR") for rule_id in ids))

        self.service.set_rule_enabled("HIPAA-001", False)
        after = self.service.get_active_rules()
        self.assertNotIn("HIPAA-001", {rule["rule_id"] for rule in after["rules"]})
        self.assertNotEqual(before["policy_hash"], after["policy_hash"])
        self.assertNotIn("HIPAA-001", json.dumps(after))

    def test_any_policy_file_can_be_activated(self) -> None:
        custom = {
            "policy_id": "internal",
            "name": "Internal",
            "rules": [
                {
                    "id": "INT-001",
                    "name": "No internal hostnames",
                    "severity": "medium",
                    "description": "Do not hardcode internal hostnames.",
                }
            ],
        }
        (self.root / ".privacy-agent" / "policies" / "internal.yaml").write_text(
            yaml.safe_dump(custom), encoding="utf-8"
        )
        self.service.set_active_policies(["internal"])
        rules = self.service.get_active_rules()["rules"]
        self.assertEqual([rule["rule_id"] for rule in rules], ["INT-001"])
        with self.assertRaises(ValueError):
            self.service.set_active_policies(["missing"])

    # ------------------------------------------------------------------ scans

    def test_full_scan_prepares_targets_and_hints(self) -> None:
        self._commit_file(f'CONTACT = "{RAW_EMAIL}"\n')
        prepared = self.service.prepare_scan("full-scan")

        self.assertEqual(prepared["status"], "pending_findings")
        self.assertEqual(prepared["targets"], [{"file": "app.py"}])
        self.assertIn(
            {"file": "app.py", "line": 1, "rule_id": "HIPAA-001", "detector": "email_literal"},
            prepared["hints"],
        )
        self.assertTrue(
            (self.service.pending_dir / f"{prepared['scan_id']}.json").is_file()
        )

    def test_accepted_findings_write_redacted_audit_log(self) -> None:
        self._commit_file(f'CONTACT = "{RAW_EMAIL}"\n')
        prepared = self.service.prepare_scan("full-scan")

        result = self.service.submit_findings(prepared["scan_id"], [self._finding()])

        self.assertTrue(result["accepted"], result)
        self.assertEqual(result["summary"]["verdict"], "DO_NOT_COMMIT")
        report_path = self.root / result["report_path"]
        self.assertTrue(report_path.is_file())
        self.assertTrue(report_path.parent.name == "audit-logs")
        report = json.loads(report_path.read_text())
        self.assertNotIn(RAW_EMAIL, json.dumps(report))
        violation = report["violations"][0]
        self.assertEqual(violation["evidence_summary"], 'CONTACT = "[REDACTED]"')
        self.assertEqual(violation["source"], "llm")
        self.assertFalse(
            (self.service.pending_dir / f"{prepared['scan_id']}.json").exists()
        )

    def test_empty_submission_is_safe_to_commit(self) -> None:
        self._commit_file('VALUE = "clean"\n')
        prepared = self.service.prepare_scan("full-scan")
        result = self.service.submit_findings(prepared["scan_id"], [])
        self.assertEqual(result["summary"]["verdict"], "SAFE_TO_COMMIT")

    def test_invalid_findings_are_rejected_and_scan_stays_pending(self) -> None:
        self._commit_file(f'CONTACT = "{RAW_EMAIL}"\n')
        self._commit_file('VALUE = "clean"\n', name="other.py")
        self.service.set_rule_enabled("HIPAA-003", False)
        prepared = self.service.prepare_scan("full-scan")
        cases = {
            "quote does not appear": self._finding(quote="print(user.ssn)"),
            "not an active rule": self._finding(rule_id="HIPAA-003"),
            "not a target": self._finding(file="missing.py"),
            "outside": self._finding(line=99),
            "missing": {"rule_id": "HIPAA-001"},
            "confidence": self._finding(confidence="certain"),
        }
        for needle, finding in cases.items():
            with self.subTest(needle):
                result = self.service.submit_findings(prepared["scan_id"], [finding])
                self.assertFalse(result["accepted"])
                self.assertIn(needle, " ".join(result["errors"]))

        accepted = self.service.submit_findings(prepared["scan_id"], [self._finding()])
        self.assertTrue(accepted["accepted"])

    def test_file_edited_after_prepare_is_stale(self) -> None:
        self._commit_file(f'CONTACT = "{RAW_EMAIL}"\n')
        prepared = self.service.prepare_scan("full-scan")
        self._write("app.py", 'CONTACT = "changed"\n')

        result = self.service.submit_findings(prepared["scan_id"], [])

        self.assertFalse(result["accepted"])
        self.assertTrue(result["stale"])
        with self.assertRaises(ValueError):
            self.service.submit_findings(prepared["scan_id"], [])

    def test_rule_toggled_after_prepare_is_stale(self) -> None:
        self._commit_file('VALUE = "clean"\n')
        prepared = self.service.prepare_scan("full-scan")
        self.service.set_rule_enabled("HIPAA-002", False)
        result = self.service.submit_findings(prepared["scan_id"], [])
        self.assertTrue(result["stale"])

    def test_diff_scan_covers_branch_unstaged_and_untracked(self) -> None:
        self._commit_file('A = 1\nB = 2\n')
        self._git("checkout", "-b", "feature")
        self._commit_file('A = 1\nB = 2\nC = 3\n')  # committed on branch
        self._write("app.py", 'A = 1\nB = 2\nC = 3\nD = 4\n')  # unstaged
        self._write("new.py", 'X = 1\nY = 2\n')  # untracked

        prepared = self.service.prepare_scan("diff-scan")

        targets = {item["file"]: item["changed_lines"] for item in prepared["targets"]}
        self.assertEqual(targets, {"app.py": [[3, 4]], "new.py": [[1, 2]]})
        result = self.service.submit_findings(
            prepared["scan_id"],
            [self._finding(line=1, quote="A = 1")],
        )
        self.assertFalse(result["accepted"])
        self.assertIn("not a changed line", result["errors"][0])

    def test_diff_scan_with_no_changes_writes_not_applicable_log(self) -> None:
        self._commit_file('A = 1\n')
        prepared = self.service.prepare_scan("diff-scan")
        self.assertEqual(prepared["status"], "no_targets")
        self.assertEqual(prepared["verdict"], "NOT_APPLICABLE")
        self.assertTrue((self.root / prepared["report_path"]).is_file())

    def test_hints_skip_disabled_rules(self) -> None:
        self._commit_file(f'CONTACT = "{RAW_EMAIL}"\n')
        self.service.set_rule_enabled("HIPAA-001", False)
        prepared = self.service.prepare_scan("full-scan")
        self.assertEqual(prepared["hints"], [])

    def test_fingerprint_is_independent_of_line_number(self) -> None:
        self._commit_file(f'CONTACT = "{RAW_EMAIL}"\n')
        first = self.service.prepare_scan("full-scan")
        a = self.service.submit_findings(first["scan_id"], [self._finding()])

        self._commit_file(f'# header\nCONTACT = "{RAW_EMAIL}"\n')
        second = self.service.prepare_scan("full-scan")
        b = self.service.submit_findings(second["scan_id"], [self._finding(line=2)])

        first_id = self.service.get_report(a["scan_id"])["violations"][0]["fingerprint"]
        second_id = self.service.get_report(b["scan_id"])["violations"][0]["fingerprint"]
        self.assertEqual(first_id, second_id)

    # ---------------------------------------------------------------- verify

    def _scan_with_finding(self) -> str:
        self._commit_file(f'CONTACT = "{RAW_EMAIL}"\nOTHER = 1\n')
        prepared = self.service.prepare_scan("full-scan")
        return self.service.submit_findings(prepared["scan_id"], [self._finding()])["scan_id"]

    def test_verify_marks_fixed_when_code_changed_and_not_reported(self) -> None:
        source_id = self._scan_with_finding()
        self._write("app.py", 'CONTACT = "user@example.invalid"\nOTHER = 1\n')

        prepared = self.service.prepare_scan("verify", source_scan_id=source_id)
        self.assertEqual(prepared["targets"], [{"file": "app.py"}])
        result = self.service.submit_findings(prepared["scan_id"], [])

        self.assertEqual(len(result["verification"]["fixed"]), 1)
        source = self.service.get_report(source_id)
        self.assertEqual(source["violations"][0]["status"], "fixed")
        self.assertIsNone(self.service.get_next_fix(source_id)["violation"])

    def test_verify_keeps_open_when_reported_again(self) -> None:
        source_id = self._scan_with_finding()
        prepared = self.service.prepare_scan("verify", source_scan_id=source_id)
        result = self.service.submit_findings(prepared["scan_id"], [self._finding()])
        self.assertEqual(len(result["verification"]["still_open"]), 1)
        self.assertEqual(self.service.get_report(source_id)["violations"][0]["status"], "open")

    def test_verify_keeps_open_when_code_unchanged_but_unreported(self) -> None:
        source_id = self._scan_with_finding()
        prepared = self.service.prepare_scan("verify", source_scan_id=source_id)
        result = self.service.submit_findings(prepared["scan_id"], [])
        self.assertEqual(len(result["verification"]["unchanged_code"]), 1)
        self.assertEqual(self.service.get_report(source_id)["violations"][0]["status"], "open")

    def test_verify_with_deleted_file_marks_fixed(self) -> None:
        source_id = self._scan_with_finding()
        (self.root / "app.py").unlink()
        prepared = self.service.prepare_scan("verify", source_scan_id=source_id)
        self.assertEqual(prepared["status"], "no_targets")
        self.assertEqual(len(prepared["verification"]["fixed"]), 1)

    def test_status_fixed_cannot_be_set_directly(self) -> None:
        source_id = self._scan_with_finding()
        violation_id = self.service.get_next_fix(source_id)["violation"]["violation_id"]
        with self.assertRaises(ValueError):
            self.service.set_violation_status(violation_id, "fixed", source_id)
        self.service.set_violation_status(violation_id, "skipped", source_id)
        self.assertIsNone(self.service.get_next_fix(source_id)["violation"])

    # ------------------------------------------------------------ utilities

    def test_redaction_masks_literals_and_detector_hits(self) -> None:
        policies = self.service.effective_policies()
        self.assertEqual(
            scanner.redact_evidence(f"send({RAW_EMAIL!r}, user.name)", policies),
            "send('[REDACTED]', user.name)",
        )
        self.assertEqual(
            scanner.redact_evidence(f"# contact {RAW_EMAIL}", policies),
            "# contact [REDACTED]",
        )
        self.assertEqual(
            scanner.redact_evidence('logger.info(f"created {patient}")', policies),
            'logger.info(f"[REDACTED]")',
        )
        self.assertEqual(
            scanner.redact_evidence("console.log(patient.email);", policies),
            "console.log(patient.email);",
        )

    def test_rule_applies_to_globs(self) -> None:
        rule = {"applies_to": ["src/**/*.py", "*.js"]}
        self.assertTrue(scanner.rule_applies(rule, "src/a.py"))
        self.assertTrue(scanner.rule_applies(rule, "src/x/y/a.py"))
        self.assertTrue(scanner.rule_applies(rule, "a.js"))
        self.assertFalse(scanner.rule_applies(rule, "lib/a.py"))
        self.assertTrue(scanner.rule_applies({}, "anything.go"))

    def test_mcp_exposes_expected_tools(self) -> None:
        tools = {tool.name for tool in asyncio.run(mcp.list_tools())}
        self.assertEqual(
            tools,
            {
                "init_repo", "get_active_rules", "prepare_scan", "prepare_verify",
                "submit_findings", "get_latest_report", "get_open_findings",
                "get_report", "list_policies", "set_active_policies", "list_rules",
                "set_rule_enabled", "set_finding_status",
            },
        )


if __name__ == "__main__":
    unittest.main()
