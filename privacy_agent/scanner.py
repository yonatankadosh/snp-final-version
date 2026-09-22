"""Policy-driven, code-only scanning for tracked files and staged Git diffs."""

from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path
from typing import Any, Iterable

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "very_high": 3}


def git(root: Path, *args: str, check: bool = True) -> str:
    """Run Git without a shell and return decoded stdout."""
    result = subprocess.run(
        ["git", *args],
        cwd=root,
        capture_output=True,
        check=False,
    )
    if check and result.returncode:
        message = result.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(message or f"git {' '.join(args)} failed")
    return result.stdout.decode("utf-8", errors="replace")


def git_commit(root: Path) -> str:
    commit = git(root, "rev-parse", "HEAD", check=False).strip()
    return commit or "UNBORN"


def _is_included(path: str, config: dict[str, Any]) -> bool:
    scan = config.get("scan", {})
    prefixes = tuple(scan.get("exclude_prefixes", []))
    if path.startswith(prefixes):
        return False
    extensions = set(scan.get("include_extensions", []))
    return Path(path).suffix.lower() in extensions


def tracked_files(root: Path, config: dict[str, Any]) -> list[str]:
    output = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=root,
        capture_output=True,
        check=False,
    )
    if output.returncode:
        raise RuntimeError(output.stderr.decode("utf-8", errors="replace").strip())
    paths = output.stdout.decode("utf-8", errors="replace").split("\0")
    return sorted(path for path in paths if path and _is_included(path, config))


def staged_added_lines(root: Path, config: dict[str, Any]) -> list[tuple[str, int, str]]:
    """Return `(path, new_line_number, text)` for added lines in the staged diff."""
    patch = git(
        root,
        "diff",
        "--cached",
        "--unified=0",
        "--no-color",
        "--find-renames",
        "--diff-filter=ACMR",
        "--",
    )
    added: list[tuple[str, int, str]] = []
    current_path: str | None = None
    new_line: int | None = None

    for raw in patch.splitlines():
        if raw.startswith("+++ "):
            marker = raw[4:]
            current_path = marker[2:] if marker.startswith("b/") else marker
            if current_path == "/dev/null" or not _is_included(current_path, config):
                current_path = None
            continue

        if raw.startswith("@@ "):
            match = re.search(r"\+(\d+)(?:,\d+)?", raw)
            new_line = int(match.group(1)) if match else None
            continue

        if current_path is None or new_line is None:
            continue
        if raw.startswith("+") and not raw.startswith("+++"):
            added.append((current_path, new_line, raw[1:]))
            new_line += 1
        elif raw.startswith("-") and not raw.startswith("---"):
            continue
        elif not raw.startswith("\\"):
            new_line += 1

    return added


def _matches(detector: dict[str, Any], text: str) -> list[re.Match[str]]:
    if detector.get("type") != "regex":
        return []
    return list(re.finditer(detector["pattern"], text, flags=re.IGNORECASE))


def _redact(text: str, spans: Iterable[tuple[int, int]], token: str, max_len: int) -> str:
    merged: list[list[int]] = []
    for start, end in sorted(set(spans)):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    for start, end in reversed(merged):
        text = text[:start] + token + text[end:]
    text = " ".join(text.split())
    if len(text) > max_len:
        text = text[: max_len - 1].rstrip() + "…"
    return text


def analyze_line(
    path: str,
    line_number: int,
    text: str,
    policies: list[dict[str, Any]],
    disabled_rules: set[str],
    redaction_token: str = "[REDACTED]",
    max_evidence_length: int = 160,
) -> dict[str, Any] | None:
    matched_rules: list[dict[str, Any]] = []
    detector_names: set[str] = set()
    data_classes: set[str] = set()
    spans: list[tuple[int, int]] = []

    for policy in policies:
        detectors = policy.get("detectors", {})
        for rule in policy.get("rules", []):
            if rule["id"] in disabled_rules:
                continue
            rule_hits: list[tuple[str, dict[str, Any], re.Match[str]]] = []
            for detector_name in rule.get("detectors", []):
                detector = detectors.get(detector_name, {})
                for match in _matches(detector, text):
                    rule_hits.append((detector_name, detector, match))
            if not rule_hits:
                continue

            matched_rules.append(
                {
                    "policy_id": policy["policy_id"],
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "severity": rule["severity"],
                    "risk_score": int(rule["risk_score"]),
                    "remediation": rule["remediation"],
                }
            )
            for detector_name, detector, match in rule_hits:
                detector_names.add(f"{policy['policy_id']}:{detector_name}")
                data_classes.add(detector.get("maps_to", "unknown"))
                spans.append((match.start(), match.end()))

    if not matched_rules:
        return None

    highest = max(
        (rule["severity"] for rule in matched_rules),
        key=lambda value: SEVERITY_ORDER.get(value, 0),
    )
    risk_score = max(rule["risk_score"] for rule in matched_rules)
    source_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
    fingerprint = hashlib.sha256(
        f"{path}:{line_number}:{source_hash}".encode("utf-8")
    ).hexdigest()

    return {
        "violation_id": f"v_{fingerprint[:16]}",
        "fingerprint": fingerprint,
        "status": "open",
        "file": path,
        "line": line_number,
        "location": f"{path}:{line_number}",
        "severity": highest,
        "risk_score": risk_score,
        "data_classes": sorted(data_classes),
        "detectors": sorted(detector_names),
        "evidence_summary": _redact(
            text, spans, redaction_token, max_evidence_length
        ),
        "matched_rules": matched_rules,
    }


def scan_lines(
    lines: Iterable[tuple[str, int, str]],
    policies: list[dict[str, Any]],
    config: dict[str, Any],
) -> list[dict[str, Any]]:
    disabled = set(config.get("disabled_rules", []))
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for path, line_number, text in lines:
        finding = analyze_line(path, line_number, text, policies, disabled)
        if finding and finding["fingerprint"] not in seen:
            findings.append(finding)
            seen.add(finding["fingerprint"])
    return sorted(
        findings,
        key=lambda item: (
            -SEVERITY_ORDER.get(item["severity"], 0),
            item["file"],
            item["line"],
        ),
    )


def repository_lines(
    root: Path, config: dict[str, Any]
) -> tuple[list[str], list[tuple[str, int, str]]]:
    files = tracked_files(root, config)
    lines: list[tuple[str, int, str]] = []
    for relative in files:
        path = root / relative
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        lines.extend(
            (relative, number, text)
            for number, text in enumerate(content.splitlines(), start=1)
        )
    return files, lines
