"""Application service used by the MCP server.

A scan is a two-step handshake with the reviewing model:

1. `prepare_scan` selects targets, collects regex hints, and records a pending
   scan (file hashes, active rules).
2. `submit_findings` validates the model's findings against that pending scan
   and writes the audit log.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import uuid
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from . import scanner

AGENT_DIR = ".privacy-agent"
VALID_VIOLATION_STATUSES = {"open", "skipped"}
SCAN_MODES = {"full-scan", "diff-scan"}
VALID_CONFIDENCE = {"low", "medium", "high"}
MAX_HINTS = 300
FINDING_FIELDS = ("rule_id", "file", "line", "quote", "explanation")


def find_project_root(start: Path | None = None) -> Path:
    current = (start or Path.cwd()).resolve()
    for candidate in (current, *current.parents):
        if (candidate / AGENT_DIR / "config.yaml").is_file():
            return candidate
    raise RuntimeError(
        "privacy agent is not installed here: .privacy-agent/config.yaml not found; "
        "run init first"
    )


def repository_root(start: Path | None = None) -> Path:
    """Git top-level of `start` (default cwd), or `start` itself outside Git."""
    current = (start or Path.cwd()).resolve()
    result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=current,
        capture_output=True,
        check=False,
    )
    top = result.stdout.decode("utf-8", errors="replace").strip()
    return Path(top) if result.returncode == 0 and top else current


def _sha256_json(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def fingerprint(rule_id: str, path: str, line_text: str) -> str:
    """Stable across line moves: rule, file, and the normalized line content."""
    return hashlib.sha256(
        f"{rule_id}\0{path}\0{scanner.normalize(line_text)}".encode("utf-8")
    ).hexdigest()


class PrivacyService:
    def __init__(self, root: Path | str | None = None) -> None:
        self.root = Path(root).resolve() if root else find_project_root()
        self.agent_dir = self.root / AGENT_DIR
        self.config_path = self.agent_dir / "config.yaml"
        self.policies_dir = self.agent_dir / "policies"
        self.logs_dir = self.agent_dir / "audit-logs"
        self.pending_dir = self.logs_dir / ".pending"

    # ------------------------------------------------------------------ setup

    @staticmethod
    def init_repo(root: Path | str | None = None) -> dict[str, Any]:
        """Install the default policy set into a repository without
        overwriting anything that already exists."""
        target_root = Path(root).resolve() if root else repository_root()
        agent_dir = target_root / AGENT_DIR
        templates = resources.files("privacy_agent") / "templates"
        planned: list[tuple[Path, Any]] = [
            (agent_dir / "config.yaml", templates / "config.yaml"),
            *(
                (agent_dir / "policies" / item.name, item)
                for item in sorted(
                    (templates / "policies").iterdir(), key=lambda entry: entry.name
                )
                if item.name.endswith(".yaml")
            ),
            (agent_dir / ".gitignore", "audit-logs/.pending/\n"),
            (agent_dir / "audit-logs" / ".gitkeep", ""),
        ]
        created: list[str] = []
        existing: list[str] = []
        for destination, source in planned:
            relative = destination.relative_to(target_root).as_posix()
            if destination.exists():
                existing.append(relative)
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(source, str):
                destination.write_text(source, encoding="utf-8")
            else:
                with resources.as_file(source) as path:
                    shutil.copyfile(path, destination)
            created.append(relative)
        return {"root": str(target_root), "created": created, "existing": existing}

    # ----------------------------------------------------------------- config

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

    def available_policies(self) -> list[str]:
        return sorted(path.stem for path in self.policies_dir.glob("*.yaml"))

    def set_active_policies(self, policies: list[str]) -> dict[str, Any]:
        normalized = list(dict.fromkeys(item.lower() for item in policies))
        available = set(self.available_policies())
        if not normalized or not set(normalized) <= available:
            raise ValueError(
                f"policies must be a non-empty subset of {sorted(available)}"
            )
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
        """Every rule of the active policies with its enabled flag (humans only)."""
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

    def _active_rules(self) -> list[tuple[dict[str, Any], dict[str, Any]]]:
        disabled = set(self.get_config().get("disabled_rules", []))
        return [
            (policy, rule)
            for policy in self.effective_policies()
            for rule in policy.get("rules", [])
            if rule["id"] not in disabled
        ]

    def get_active_rules(self) -> dict[str, Any]:
        """Enabled rules only, in the shape the reviewing model judges against."""
        rules = [
            {
                "rule_id": rule["id"],
                "policy_id": policy["policy_id"],
                "name": rule["name"],
                "severity": rule["severity"],
                "description": " ".join(rule.get("description", rule["name"]).split()),
                "examples": rule.get("examples", {}),
                "applies_to": rule.get("applies_to") or ["**"],
                "remediation": rule.get("remediation", {}).get("suggestion", ""),
            }
            for policy, rule in self._active_rules()
        ]
        return {"policy_hash": _sha256_json(rules), "rules": rules}

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

    # ------------------------------------------------------------------ scans

    @staticmethod
    def _now() -> datetime:
        return datetime.now(timezone.utc)

    def _new_scan_id(self) -> str:
        return f"{self._now().strftime('%Y%m%dT%H%M%S.%fZ')}-{uuid.uuid4().hex[:8]}"

    def _pending_path(self, scan_id: str) -> Path:
        if not scan_id or "/" in scan_id or scan_id.startswith("."):
            raise ValueError(f"invalid scan_id: {scan_id!r}")
        return self.pending_dir / f"{scan_id}.json"

    def prepare_scan(
        self,
        mode: str,
        base: str | None = None,
        source_scan_id: str | None = None,
    ) -> dict[str, Any]:
        """Select targets and hints for the model, and record a pending scan.

        `mode` is `full-scan`, `diff-scan`, or `verify` (which re-scans the
        files of `source_scan_id`, whole-file)."""
        config = self.get_config()
        active = self.get_active_rules()
        active_ids = {rule["rule_id"] for rule in active["rules"]}
        rules_by_id = {rule["id"]: rule for _, rule in self._active_rules()}

        ranges_by_file: dict[str, list[list[int]] | None]
        base_commit = None
        if mode == "full-scan":
            ranges_by_file = {
                path: None for path in scanner.tracked_files(self.root, config)
            }
        elif mode == "diff-scan":
            base_commit, changes = scanner.branch_changes(self.root, config, base)
            ranges_by_file = {
                path: [[start, end] for start, end in ranges]
                for path, ranges in changes.items()
            }
        elif mode == "verify":
            if not source_scan_id:
                raise ValueError("verify requires source_scan_id")
            source = self.get_report(source_scan_id)
            ranges_by_file = {
                item["file"]: None
                for item in source.get("violations", [])
                if item.get("status") != "fixed" and (self.root / item["file"]).is_file()
            }
        else:
            raise ValueError("mode must be full-scan, diff-scan, or verify")

        policies = self.effective_policies()
        targets: dict[str, dict[str, Any]] = {}
        hints: list[dict[str, Any]] = []
        for path, ranges in sorted(ranges_by_file.items()):
            applicable = sorted(
                rule_id for rule_id in active_ids
                if scanner.rule_applies(rules_by_id[rule_id], path)
            )
            lines = scanner.read_lines(self.root / path)
            if not applicable or lines is None:
                continue
            targets[path] = {
                "sha256": scanner.file_sha256(self.root / path),
                "ranges": ranges,
                "rule_ids": applicable,
            }
            hints.extend(
                scanner.collect_hints(path, lines, ranges, policies, active_ids)
            )

        scan_id = self._new_scan_id()
        pending = {
            "scan_id": scan_id,
            "mode": mode,
            "source_scan_id": source_scan_id,
            "base_commit": base_commit,
            "git_commit": scanner.git_commit(self.root),
            "policy_hash": active["policy_hash"],
            "rule_ids": sorted(active_ids),
            "targets": targets,
            "hint_count": len(hints),
        }

        if not targets:
            verification = (
                self._apply_verification(pending, []) if mode == "verify" else None
            )
            report = self._finalize(
                pending, [], status="no_targets", verification=verification
            )
            return {
                "scan_id": scan_id,
                "status": "no_targets",
                "message": "nothing to scan; an empty audit log was written",
                "report_path": report["report_path"],
                "verdict": report["summary"]["verdict"],
                "verification": verification,
            }

        self._write_json(self._pending_path(scan_id), pending)
        return {
            "scan_id": scan_id,
            "mode": mode,
            "status": "pending_findings",
            "rules": active["rules"],
            "targets": [
                {"file": path, **({"changed_lines": info["ranges"]} if info["ranges"] else {})}
                for path, info in targets.items()
            ],
            "hints": hints[:MAX_HINTS],
            "hints_truncated": len(hints) > MAX_HINTS,
        }

    def _load_pending(self, scan_id: str) -> dict[str, Any]:
        path = self._pending_path(scan_id)
        if not path.is_file():
            raise ValueError(
                f"no pending scan {scan_id!r}; it was already submitted or never "
                "prepared. Call prepare_scan again."
            )
        return json.loads(path.read_text(encoding="utf-8"))

    def submit_findings(
        self, scan_id: str, findings: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Validate model findings against the pending scan and write the log.

        On any error nothing is written and the pending scan is kept, so the
        model can correct its findings and resubmit."""
        pending = self._load_pending(scan_id)
        targets = pending["targets"]

        stale = [
            path for path, info in targets.items()
            if scanner.file_sha256(self.root / path) != info["sha256"]
        ]
        if self.get_active_rules()["policy_hash"] != pending["policy_hash"]:
            stale.append(".privacy-agent policy configuration")
        if stale:
            self._pending_path(scan_id).unlink(missing_ok=True)
            return {
                "accepted": False,
                "stale": True,
                "errors": [f"changed since prepare_scan: {item}" for item in stale],
                "next_step": "call prepare_scan again and re-review",
            }

        if not isinstance(findings, list):
            return {"accepted": False, "errors": ["findings must be a list"]}

        rules_by_id = {rule["id"]: (policy, rule) for policy, rule in self._active_rules()}
        policies = self.effective_policies()
        line_cache: dict[str, list[str]] = {}
        errors: list[str] = []
        violations: dict[str, dict[str, Any]] = {}

        for index, finding in enumerate(findings):
            where = f"finding[{index}]"
            if not isinstance(finding, dict):
                errors.append(f"{where}: must be an object")
                continue
            missing = [field for field in FINDING_FIELDS if field not in finding]
            if missing:
                errors.append(f"{where}: missing {', '.join(missing)}")
                continue
            rule_id, path, line = finding["rule_id"], finding["file"], finding["line"]
            quote = scanner.normalize(str(finding["quote"]))
            if rule_id not in pending["rule_ids"]:
                errors.append(f"{where}: {rule_id!r} is not an active rule")
                continue
            if path not in targets:
                errors.append(f"{where}: {path!r} is not a target of this scan")
                continue
            if rule_id not in targets[path]["rule_ids"]:
                errors.append(f"{where}: {rule_id} does not apply to {path}")
                continue
            if path not in line_cache:
                line_cache[path] = scanner.read_lines(self.root / path) or []
            lines = line_cache[path]
            if not isinstance(line, int) or not 1 <= line <= len(lines):
                errors.append(f"{where}: line {line!r} is outside {path} (1-{len(lines)})")
                continue
            if not scanner.in_ranges(line, targets[path]["ranges"]):
                errors.append(f"{where}: {path}:{line} is not a changed line in this diff")
                continue
            line_text = lines[line - 1]
            if not quote or quote not in scanner.normalize(line_text):
                errors.append(
                    f"{where}: quote does not appear on {path}:{line}; quote the "
                    "exact code from that single line"
                )
                continue
            confidence = finding.get("confidence", "medium")
            if confidence not in VALID_CONFIDENCE:
                errors.append(f"{where}: confidence must be one of {sorted(VALID_CONFIDENCE)}")
                continue

            policy, rule = rules_by_id[rule_id]
            print_id = fingerprint(rule_id, path, line_text)
            violations[print_id] = {
                "violation_id": f"v_{print_id[:16]}",
                "fingerprint": print_id,
                "status": "open",
                "source": "llm",
                "file": path,
                "line": line,
                "location": f"{path}:{line}",
                "policy_id": policy["policy_id"],
                "rule_id": rule_id,
                "rule_name": rule["name"],
                "severity": rule["severity"],
                "risk_score": int(rule.get("risk_score", 0)),
                "confidence": confidence,
                "evidence_summary": scanner.redact_evidence(line_text, policies),
                "explanation": scanner.redact_evidence(
                    str(finding["explanation"]), policies, max_len=500
                ),
                "quote_sha256": hashlib.sha256(quote.encode("utf-8")).hexdigest(),
                "remediation": rule.get("remediation", {}),
            }

        if errors:
            return {
                "accepted": False,
                "errors": errors,
                "next_step": "fix the listed findings and call submit_findings again "
                "with the complete list",
            }

        ordered = sorted(
            violations.values(),
            key=lambda item: (
                -scanner.SEVERITY_ORDER.get(item["severity"], 0),
                item["file"],
                item["line"],
            ),
        )
        verification = None
        if pending["mode"] == "verify":
            verification = self._apply_verification(pending, ordered)
        report = self._finalize(pending, ordered, verification=verification)
        self._pending_path(scan_id).unlink(missing_ok=True)
        return {
            "accepted": True,
            "scan_id": scan_id,
            "report_path": report["report_path"],
            "summary": report["summary"],
            "verification": verification,
        }

    def _apply_verification(
        self, pending: dict[str, Any], new_violations: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """A source finding is fixed only if the re-scan did not report it AND
        its original line no longer exists unchanged in the file."""
        source = self.get_report(pending["source_scan_id"])
        reported = {item["fingerprint"] for item in new_violations}
        outcome: dict[str, list[str]] = {"fixed": [], "still_open": [], "unchanged_code": []}
        for item in source.get("violations", []):
            if item.get("status") == "fixed":
                continue
            lines = scanner.read_lines(self.root / item["file"]) or []
            unchanged = any(
                fingerprint(item["rule_id"], item["file"], text) == item["fingerprint"]
                for text in lines
            )
            if item["fingerprint"] in reported:
                item["status"] = "open"
                outcome["still_open"].append(item["violation_id"])
            elif unchanged:
                item["status"] = "open"
                outcome["unchanged_code"].append(item["violation_id"])
            else:
                item["status"] = "fixed"
                outcome["fixed"].append(item["violation_id"])
        self._persist_report(source)
        return {"source_scan_id": source["scan_id"], **outcome}

    def _finalize(
        self,
        pending: dict[str, Any],
        violations: list[dict[str, Any]],
        *,
        status: str = "completed",
        verification: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        config = self.get_config()
        report = {
            "schema_version": 2,
            "scan_id": pending["scan_id"],
            "timestamp": self._now().isoformat().replace("+00:00", "Z"),
            "mode": pending["mode"],
            "status": status,
            "judge": "llm",
            "verification_of": pending.get("source_scan_id"),
            "verification": verification,
            "git_commit": pending["git_commit"],
            "base_commit": pending.get("base_commit"),
            "active_policies": config.get("active_policies", []),
            "disabled_rules": config.get("disabled_rules", []),
            "policy_hash": pending["policy_hash"],
            "rule_ids": pending["rule_ids"],
            "scanned_files": sorted(pending["targets"]),
            "summary": {
                "violation_count": len(violations),
                "file_count": len({item["file"] for item in violations}),
                "verdict": (
                    "NOT_APPLICABLE"
                    if status == "no_targets"
                    else "SAFE_TO_COMMIT"
                    if not violations
                    else "DO_NOT_COMMIT"
                ),
            },
            "violations": violations,
        }
        filename = f"{pending['scan_id']}-{pending['mode']}.json"
        report["report_path"] = (Path(AGENT_DIR) / "audit-logs" / filename).as_posix()
        self._write_json(self.logs_dir / filename, report)
        self._write_json(self.logs_dir / "latest.json", report)
        return report

    # ---------------------------------------------------------------- reports

    def get_latest_report(self) -> dict[str, Any]:
        path = self.logs_dir / "latest.json"
        if not path.is_file():
            raise RuntimeError("no audit log exists; run full-scan or diff-scan first")
        return json.loads(path.read_text(encoding="utf-8"))

    def get_report(self, scan_id: str) -> dict[str, Any]:
        for path in self.logs_dir.glob(f"{scan_id}-*.json"):
            return json.loads(path.read_text(encoding="utf-8"))
        raise ValueError(f"unknown scan_id: {scan_id}")

    def _persist_report(self, report: dict[str, Any]) -> None:
        path = self.root / report["report_path"]
        self._write_json(path, report)
        latest = self.logs_dir / "latest.json"
        if latest.is_file():
            current = json.loads(latest.read_text(encoding="utf-8"))
            if current.get("scan_id") == report.get("scan_id"):
                self._write_json(latest, report)

    def get_open_findings(self, scan_id: str | None = None) -> dict[str, Any]:
        report = self.get_report(scan_id) if scan_id else self.get_latest_report()
        open_items = [
            item for item in report.get("violations", [])
            if item.get("status") == "open"
        ]
        return {
            "scan_id": report["scan_id"],
            "mode": report["mode"],
            "git_commit": report.get("git_commit"),
            "current_commit": scanner.git_commit(self.root),
            "open_findings": open_items,
        }

    def get_next_fix(self, scan_id: str | None = None) -> dict[str, Any]:
        payload = self.get_open_findings(scan_id)
        items = payload.pop("open_findings")
        return {
            **payload,
            "violation": items[0] if items else None,
            "remaining_open": len(items),
        }

    def set_violation_status(
        self, violation_id: str, status: str, scan_id: str | None = None
    ) -> dict[str, Any]:
        """Human triage only. `fixed` is set exclusively by verification."""
        if status not in VALID_VIOLATION_STATUSES:
            raise ValueError(
                f"status must be one of {sorted(VALID_VIOLATION_STATUSES)}; "
                "fixed is set only by a verification scan"
            )
        report = self.get_report(scan_id) if scan_id else self.get_latest_report()
        for violation in report.get("violations", []):
            if violation["violation_id"] == violation_id:
                violation["status"] = status
                self._persist_report(report)
                return violation
        raise ValueError(f"unknown violation_id: {violation_id}")
