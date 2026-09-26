"""Deterministic scan inputs: target selection, Git diffs, regex hints, redaction.

Nothing here decides whether code violates a rule. That judgment belongs to the
reviewing model; this module only selects what it should look at and supplies
regex hits as leads.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path
from typing import Any, Iterable

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "very_high": 3}
EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
_STRING_LITERAL = re.compile(r"""(?P<q>["'`])(?P<body>(?:\\.|(?!(?P=q)).)*)(?P=q)""")


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


def _glob_regex(pattern: str) -> re.Pattern[str]:
    parts: list[str] = []
    index = 0
    while index < len(pattern):
        if pattern.startswith("**/", index):
            parts.append("(?:.*/)?")
            index += 3
        elif pattern.startswith("**", index):
            parts.append(".*")
            index += 2
        elif pattern[index] == "*":
            parts.append("[^/]*")
            index += 1
        elif pattern[index] == "?":
            parts.append("[^/]")
            index += 1
        else:
            parts.append(re.escape(pattern[index]))
            index += 1
    return re.compile("".join(parts) + r"\Z")


def rule_applies(rule: dict[str, Any], path: str) -> bool:
    """A rule without `applies_to` applies to every scanned file."""
    patterns = rule.get("applies_to") or []
    return not patterns or any(_glob_regex(p).match(path) for p in patterns)


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
    return sorted(
        path
        for path in paths
        if path and _is_included(path, config) and (root / path).is_file()
    )


def resolve_base(root: Path, base: str | None = None) -> str:
    """Return the merge-base commit the branch diff is measured from."""
    if git_commit(root) == "UNBORN":
        return EMPTY_TREE
    candidates = [base] if base else []
    if not base:
        remote_head = git(
            root, "rev-parse", "--abbrev-ref", "origin/HEAD", check=False
        ).strip()
        candidates += [remote_head, "main", "master"]
    for candidate in filter(None, candidates):
        merge_base = git(root, "merge-base", "HEAD", candidate, check=False).strip()
        if merge_base:
            return merge_base
    if base:
        raise RuntimeError(f"cannot resolve base branch: {base}")
    return git(root, "rev-parse", "HEAD").strip()


def branch_changes(
    root: Path, config: dict[str, Any], base: str | None = None
) -> tuple[str, dict[str, list[tuple[int, int]]]]:
    """Return `(base, {path: [(start, end), ...]})` for lines added or changed
    since the merge-base, including uncommitted and untracked files."""
    base_commit = resolve_base(root, base)
    patch = git(
        root,
        "diff",
        base_commit,
        "--unified=0",
        "--no-color",
        "--find-renames",
        "--diff-filter=ACMR",
        "--",
    )
    changes: dict[str, list[tuple[int, int]]] = {}
    current_path: str | None = None

    for raw in patch.splitlines():
        if raw.startswith("+++ "):
            marker = raw[4:]
            current_path = marker[2:] if marker.startswith("b/") else marker
            if current_path == "/dev/null" or not _is_included(current_path, config):
                current_path = None
            continue
        if raw.startswith("@@ ") and current_path is not None:
            match = re.search(r"\+(\d+)(?:,(\d+))?", raw)
            if not match:
                continue
            start = int(match.group(1))
            count = int(match.group(2)) if match.group(2) is not None else 1
            if count:
                changes.setdefault(current_path, []).append((start, start + count - 1))

    untracked = git(root, "ls-files", "--others", "--exclude-standard", "-z")
    for path in filter(None, untracked.split("\0")):
        if not _is_included(path, config):
            continue
        lines = read_lines(root / path)
        if lines:
            changes[path] = [(1, len(lines))]

    return base_commit, {
        path: ranges for path, ranges in sorted(changes.items())
        if (root / path).is_file()
    }


def read_lines(path: Path) -> list[str] | None:
    try:
        return path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return None


def file_sha256(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def normalize(text: str) -> str:
    return " ".join(text.split())


def in_ranges(line: int, ranges: Iterable[Iterable[int]] | None) -> bool:
    if ranges is None:
        return True
    return any(start <= line <= end for start, end in ranges)


def _matches(detector: dict[str, Any], text: str) -> list[re.Match[str]]:
    if detector.get("type") != "regex":
        return []
    return list(re.finditer(detector["pattern"], text, flags=re.IGNORECASE))


def collect_hints(
    path: str,
    lines: list[str],
    ranges: list[tuple[int, int]] | None,
    policies: list[dict[str, Any]],
    active_rule_ids: set[str],
) -> list[dict[str, Any]]:
    """Regex hits on active rules, as leads for the reviewing model."""
    hints: list[dict[str, Any]] = []
    for number, text in enumerate(lines, start=1):
        if not in_ranges(number, ranges):
            continue
        for policy in policies:
            detectors = policy.get("detectors", {})
            for rule in policy.get("rules", []):
                if rule["id"] not in active_rule_ids or not rule_applies(rule, path):
                    continue
                for detector_name in rule.get("detectors", []):
                    if _matches(detectors.get(detector_name, {}), text):
                        hints.append(
                            {
                                "file": path,
                                "line": number,
                                "rule_id": rule["id"],
                                "detector": detector_name,
                            }
                        )
    return hints


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


def redact_evidence(
    text: str,
    policies: list[dict[str, Any]],
    token: str = "[REDACTED]",
    max_len: int = 160,
) -> str:
    """Mask every string literal body and every value detector match (those
    without `redact: false`), keeping the code structure readable while
    dropping the values that may be personal."""
    spans = [
        (match.start("body"), match.end("body"))
        for match in _STRING_LITERAL.finditer(text)
        if match.group("body")
    ]
    for policy in policies:
        for detector in policy.get("detectors", {}).values():
            if detector.get("redact", True):
                spans.extend((m.start(), m.end()) for m in _matches(detector, text))
    return _redact(text, spans, token, max_len)
