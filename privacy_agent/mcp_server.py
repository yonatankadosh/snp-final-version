"""Stdio MCP server used by the privacy-agent Claude Code plugin.

The server owns everything deterministic (targets, active rules, validation,
audit logs). The connected model only judges code and proposes fixes.

The configuration tools (policies, rules, finding status) exist only for the
user-invoked /config, /exclude and /triage commands, which are the only
commands that pre-approve them. Anywhere else, calling them triggers a
permission prompt.
"""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from .service import PrivacyService

mcp = FastMCP("privacy-agent", json_response=True)


def _service() -> PrivacyService:
    return PrivacyService()


@mcp.tool()
def init_repo() -> dict:
    """Install the default privacy policy set into `.privacy-agent/` of the
    current Git repository. Never overwrites existing files."""
    return PrivacyService.init_repo()


@mcp.tool()
def get_active_rules() -> dict:
    """Return only the enabled rules of the active policies."""
    return _service().get_active_rules()


@mcp.tool()
def prepare_scan(mode: str, base: str = "") -> dict:
    """Start a scan. `mode` is `full-scan` (all tracked code files) or
    `diff-scan` (lines changed since the merge-base with `base`, default the
    remote default branch, including uncommitted and untracked files).

    Returns a `scan_id`, the active rules, the target files (with
    `changed_lines` ranges for diff scans), and regex hints. Read every target
    with your own file tools, judge it against the rules, then call
    `submit_findings`."""
    if mode not in {"full-scan", "diff-scan"}:
        raise ValueError("mode must be full-scan or diff-scan")
    return _service().prepare_scan(mode, base=base or None)


@mcp.tool()
def prepare_verify(scan_id: str) -> dict:
    """Start a verification re-scan of the files with open findings in
    `scan_id`. Judge the returned targets from scratch and call
    `submit_findings`; the server then marks each source finding fixed or
    still open."""
    return _service().prepare_scan("verify", source_scan_id=scan_id)


@mcp.tool()
def submit_findings(scan_id: str, findings: list[dict[str, Any]]) -> dict:
    """Submit the complete list of violations for a prepared scan (an empty
    list means no violations).

    Each finding: {"rule_id", "file", "line", "quote", "explanation",
    "confidence"}. `quote` must be exact code copied from that single line.
    `explanation` must not repeat raw personal values. `confidence` is low,
    medium, or high. If the response has `accepted: false`, correct the listed
    errors and resubmit the full list."""
    return _service().submit_findings(scan_id, findings)


@mcp.tool()
def get_latest_report() -> dict:
    """Return the latest audit log."""
    return _service().get_latest_report()


@mcp.tool()
def get_open_findings(scan_id: str = "") -> dict:
    """Return the open findings of `scan_id` (default: the latest audit log)."""
    return _service().get_open_findings(scan_id or None)


@mcp.tool()
def get_report(scan_id: str) -> dict:
    """Return the audit log of `scan_id`."""
    return _service().get_report(scan_id)


@mcp.tool()
def list_policies() -> dict:
    """Return the available policy IDs and the currently active ones.
    Only for the /privacy-agent:config command."""
    service = _service()
    return {
        "available": service.available_policies(),
        "active": service.get_config().get("active_policies", []),
    }


@mcp.tool()
def set_active_policies(policies: list[str]) -> dict:
    """Set the active policies, e.g. ["gdpr"] or ["hipaa", "gdpr"] (["both"]
    means hipaa and gdpr). Only for the /privacy-agent:config command, at the
    user's explicit request."""
    if [item.lower() for item in policies] == ["both"]:
        policies = ["hipaa", "gdpr"]
    return _service().set_active_policies(policies)


@mcp.tool()
def list_rules() -> dict:
    """Return every rule of the active policies with its enabled state.
    Only for the /privacy-agent:exclude command."""
    return _service().list_rules()


@mcp.tool()
def set_rule_enabled(rule_id: str, enabled: bool) -> dict:
    """Enable or disable one rule. Only for the /privacy-agent:exclude
    command, at the user's explicit request."""
    return _service().set_rule_enabled(rule_id, enabled)


@mcp.tool()
def set_finding_status(violation_id: str, status: str, scan_id: str = "") -> dict:
    """Mark a finding `skipped` (false positive or accepted risk) or back to
    `open`. Only for the /privacy-agent:triage command, at the user's explicit
    request. `fixed` is set only by verification."""
    return _service().set_violation_status(violation_id, status, scan_id or None)


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
