from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

from privacy_agent.cli import build_parser
from privacy_agent.service import PrivacyService

PROJECT = Path(__file__).resolve().parents[1]


class WorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "policies").mkdir()
        (self.root / ".privacy-agent").mkdir()
        for name in ("hipaa.yaml", "gdpr.yaml"):
            shutil.copy(PROJECT / "policies" / name, self.root / "policies" / name)
        shutil.copy(
            PROJECT / ".privacy-agent" / "config.yaml",
            self.root / ".privacy-agent" / "config.yaml",
        )
        self._git("init", "-b", "main")
        self._git("config", "user.email", "test@example.invalid")
        self._git("config", "user.name", "Privacy Agent Test")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _git(self, *args: str) -> None:
        subprocess.run(
            ["git", *args],
            cwd=self.root,
            check=True,
            capture_output=True,
        )

    def _commit_file(self, content: str) -> None:
        (self.root / "app.py").write_text(content, encoding="utf-8")
        self._git("add", ".")
        self._git("commit", "-m", "fixture")

    def test_init_scan_persists_redacted_report(self) -> None:
        raw_email = "patient@example.com"
        self._commit_file(f'CONTACT = "{raw_email}"\n')

        report = PrivacyService(self.root).scan_repository()

        self.assertEqual(report["summary"]["verdict"], "DO_NOT_COMMIT")
        self.assertEqual(len(report["violations"]), 1)
        self.assertNotIn(raw_email, json.dumps(report))
        self.assertIn("[REDACTED]", report["violations"][0]["evidence_summary"])
        self.assertTrue((self.root / report["report_path"]).is_file())
        self.assertTrue(
            (self.root / ".privacy-agent" / "violations" / "latest.json").is_file()
        )

    def test_diff_scans_only_staged_added_lines(self) -> None:
        self._commit_file('VALUE = "clean"\n')
        path = self.root / "app.py"
        path.write_text('VALUE = "clean"\nEMAIL = "new@example.com"\n', encoding="utf-8")
        service = PrivacyService(self.root)

        unstaged = service.scan_diff()
        self.assertEqual(unstaged["status"], "no_staged_changes")
        self.assertEqual(unstaged["violations"], [])

        self._git("add", "app.py")
        staged = service.scan_diff()
        self.assertEqual(staged["status"], "completed")
        self.assertEqual(len(staged["violations"]), 1)
        self.assertEqual(staged["violations"][0]["location"], "app.py:2")

    def test_both_policies_aggregate_same_finding(self) -> None:
        self._commit_file('EMAIL = "shared@example.com"\n')
        service = PrivacyService(self.root)
        service.set_active_policies(["hipaa", "gdpr"])

        report = service.scan_repository()

        self.assertEqual(len(report["violations"]), 1)
        rules = {
            rule["rule_id"]
            for rule in report["violations"][0]["matched_rules"]
        }
        self.assertEqual(rules, {"HIPAA-001", "GDPR-001"})

    def test_rule_can_be_disabled_and_reenabled(self) -> None:
        self._commit_file('EMAIL = "disabled@example.com"\n')
        service = PrivacyService(self.root)
        service.set_rule_enabled("HIPAA-001", False)
        self.assertEqual(service.scan_repository()["violations"], [])
        service.set_rule_enabled("HIPAA-001", True)
        self.assertEqual(len(service.scan_repository()["violations"]), 1)

    def test_fix_queue_status_and_verification_link(self) -> None:
        self._commit_file('EMAIL = "queue@example.com"\n')
        service = PrivacyService(self.root)
        source = service.scan_repository()
        next_fix = service.get_next_fix(source["scan_id"])
        violation_id = next_fix["violation"]["violation_id"]

        service.set_violation_status(violation_id, "fixed", source["scan_id"])
        self.assertIsNone(service.get_next_fix(source["scan_id"])["violation"])
        verification = service.verify_report(source["scan_id"])
        self.assertEqual(verification["verification_of"], source["scan_id"])

    def test_config_has_no_roles_or_database_sections(self) -> None:
        for name in ("hipaa.yaml", "gdpr.yaml"):
            policy = yaml.safe_load((self.root / "policies" / name).read_text())
            self.assertNotIn("roles", policy)
            serialized = yaml.safe_dump(policy).lower()
            self.assertNotIn("database", serialized)

    def test_cli_exposes_all_operations(self) -> None:
        parser = build_parser()
        for command in ("init", "scan-diff", "fix", "config", "exclude"):
            namespace = parser.parse_args([command])
            self.assertEqual(namespace.command, command)


if __name__ == "__main__":
    unittest.main()
