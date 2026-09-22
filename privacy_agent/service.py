"""Shared application service used by both the CLI and MCP server."""

from __future__ import annotations

import json
import os
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from . import scanner

VALID_POLICIES = {"hipaa", "gdpr"}
VALID_VIOLATION_STATUSES = {"open", "fixed", "skipped"}


def find_project_root(start: Path | None = None) -> Path:
    current = (start or Path.cwd()).resolve()
    for candidate in (current, *current.parents):
        if (candidate / ".privacy-agent" / "config.yaml").is_file():
            return candidate
    raise RuntimeError(
        "privacy agent is not installed here: .privacy-agent/config.yaml not found"
    )


class PrivacyService:
    def __init__(self, root: Path | str | None = None) -> None:
        self.root = Path(root).resolve() if root else find_project_root()
        self.config_path = self.root / ".privacy-agent" / "config.yaml"
        self.reports_dir = self.root / ".privacy-agent" / "violations"
        self.policies_dir = self.root / "policies"

    def get_config(self) -> dict[str, Any]:
        return yaml.safe_load(self.config_path.read_text(encoding="utf-8")) or {}

    def _write_yaml(self, path: Path, value: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=path.parent, delete=False
        ) as handle:
            yaml.safe_dump(value, handle, sort_keys=False)
            temporary = Path(handle.name)
        os.replace(temporary, path)

    def _write_json(self, path: Path, value: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=path.parent, delete=False
        ) as handle:
            json.dump(value, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
            temporary = Path(handle.name)
        os.replace(temporary, path)

    def set_active_policies(self, policies: list[str]) -> dict[str, Any]:
        normalized = list(dict.fromkeys(item.lower() for item in policies))
        if not normalized or not set(normalized) <= VALID_POLICIES:
            raise ValueError("policies must contain hipaa, gdpr, or both")
        config = self.get_config()
        config["active_policies"] = normalized
        self._write_yaml(self.config_path, config)
        return self.get_config()

    def _load_policy(self, policy_id: str) -> dict[str, Any]:
        path = self.policies_dir / f"{policy_id}.yaml"
        if not path.is_file():
            raise RuntimeError(f"policy file not found: {path}")
        policy = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if policy.get("policy_id") != policy_id:
            raise RuntimeError(f"policy_id mismatch in {path.name}")
        return policy

    def effective_policies(self) -> list[dict[str, Any]]:
        config = self.get_config()
        return [
            self._load_policy(policy_id)
            for policy_id in config.get("active_policies", [])
        ]

    def list_rules(self) -> dict[str, Any]:
        config = self.get_config()
        disabled = set(config.get("disabled_rules", []))
        rules = []
        for policy in self.effective_policies():
            for rule in policy.get("rules", []):
                rules.append(
                    {
                        "policy_id": policy["policy_id"],
                        "rule_id": rule["id"],
                        "name": rule["name"],
                        "severity": rule["severity"],
                        "enabled": rule["id"] not in disabled,
                    }
                )
        return {"rules": rules}

    def set_rule_enabled(self, rule_id: str, enabled: bool) -> dict[str, Any]:
        rules = self.list_rules()["rules"]
        known = {rule["rule_id"] for rule in rules}
        if rule_id not in known:
            raise ValueError(f"unknown rule in active policies: {rule_id}")

        config = self.get_config()
        disabled = set(config.get("disabled_rules", []))
        if enabled:
            disabled.discard(rule_id)
        else:
            disabled.add(rule_id)
            if known <= disabled:
                raise ValueError("cannot disable every rule in the active policies")
        config["disabled_rules"] = sorted(disabled)
        self._write_yaml(self.config_path, config)
        return self.list_rules()

    @staticmethod
    def _now() -> datetime:
        return datetime.now(timezone.utc)

    def _report(
        self,
        mode: str,
        files: list[str],
        violations: list[dict[str, Any]],
        *,
        status: str = "completed",
        verification_of: str | None = None,
    ) -> dict[str, Any]:
        now = self._now()
        scan_id = f"{now.strftime('%Y%m%dT%H%M%S.%fZ')}-{uuid.uuid4().hex[:8]}"
        config = self.get_config()
        report = {
            "schema_version": 1,
            "scan_id": scan_id,
            "timestamp": now.isoformat().replace("+00:00", "Z"),
            "mode": mode,
            "status": status,
            "verification_of": verification_of,
            "git_commit": scanner.git_commit(self.root),
            "active_policies": config.get("active_policies", []),
            "disabled_rules": config.get("disabled_rules", []),
            "scanned_files": files,
            "summary": {
                "violation_count": len(violations),
                "file_count": len({item["file"] for item in violations}),
                "verdict": (
                    "NOT_APPLICABLE"
                    if status == "no_staged_changes"
                    else "SAFE_TO_COMMIT"
                    if not violations
                    else "DO_NOT_COMMIT"
                ),
            },
            "violations": violations,
        }
        filename = f"{scan_id}-{mode}.json"
        report["report_path"] = str(
            (Path(".privacy-agent") / "violations" / filename).as_posix()
        )
        self._write_json(self.reports_dir / filename, report)
        self._write_json(self.reports_dir / "latest.json", report)
        return report

    def scan_repository(
        self, *, verification_of: str | None = None
    ) -> dict[str, Any]:
        config = self.get_config()
        files, lines = scanner.repository_lines(self.root, config)
        violations = scanner.scan_lines(lines, self.effective_policies(), config)
        return self._report(
            "init", files, violations, verification_of=verification_of
        )

    def scan_diff(self, *, verification_of: str | None = None) -> dict[str, Any]:
        config = self.get_config()
        lines = scanner.staged_added_lines(self.root, config)
        files = sorted({path for path, _, _ in lines})
        violations = scanner.scan_lines(lines, self.effective_policies(), config)
        return self._report(
            "scan-diff",
            files,
            violations,
            status="completed" if lines else "no_staged_changes",
            verification_of=verification_of,
        )

    def get_latest_report(self) -> dict[str, Any]:
        path = self.reports_dir / "latest.json"
        if not path.is_file():
            raise RuntimeError("no scan report exists; run init or scan-diff first")
        return json.loads(path.read_text(encoding="utf-8"))

    def get_report(self, scan_id: str) -> dict[str, Any]:
        for path in self.reports_dir.glob(f"{scan_id}-*.json"):
            return json.loads(path.read_text(encoding="utf-8"))
        raise ValueError(f"unknown scan_id: {scan_id}")

    def _persist_report(self, report: dict[str, Any]) -> None:
        path = self.root / report["report_path"]
        self._write_json(path, report)
        latest = self.reports_dir / "latest.json"
        if latest.is_file():
            current = json.loads(latest.read_text(encoding="utf-8"))
            if current.get("scan_id") == report.get("scan_id"):
                self._write_json(latest, report)

    def get_next_fix(self, scan_id: str | None = None) -> dict[str, Any]:
        report = self.get_report(scan_id) if scan_id else self.get_latest_report()
        for violation in report.get("violations", []):
            if violation.get("status") == "open":
                return {
                    "scan_id": report["scan_id"],
                    "mode": report["mode"],
                    "violation": violation,
                    "remaining_open": sum(
                        item.get("status") == "open"
                        for item in report.get("violations", [])
                    ),
                }
        return {
            "scan_id": report["scan_id"],
            "mode": report["mode"],
            "violation": None,
            "remaining_open": 0,
        }

    def set_violation_status(
        self, violation_id: str, status: str, scan_id: str | None = None
    ) -> dict[str, Any]:
        if status not in VALID_VIOLATION_STATUSES:
            raise ValueError(
                f"status must be one of {sorted(VALID_VIOLATION_STATUSES)}"
            )
        report = self.get_report(scan_id) if scan_id else self.get_latest_report()
        for violation in report.get("violations", []):
            if violation["violation_id"] == violation_id:
                violation["status"] = status
                self._persist_report(report)
                return violation
        raise ValueError(f"unknown violation_id: {violation_id}")

    def verify_report(self, scan_id: str) -> dict[str, Any]:
        source = self.get_report(scan_id)
        if source["mode"] == "init":
            return self.scan_repository(verification_of=scan_id)
        if source["mode"] == "scan-diff":
            return self.scan_diff(verification_of=scan_id)
        raise ValueError(f"unsupported report mode: {source['mode']}")
