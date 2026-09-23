"""IDE-agnostic stdio MCP server for user-provided LLM clients."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from .service import PrivacyService

mcp = FastMCP("privacy-precommit-agent", json_response=True)


def _service() -> PrivacyService:
    return PrivacyService()


@mcp.tool()
def get_config() -> dict:
    """Return the shared project policy selection and disabled rules."""
    return _service().get_config()


@mcp.tool()
def set_active_policies(selection: str) -> dict:
    """Set shared policy selection to `hipaa`, `gdpr`, or `both`."""
    mapping = {
        "hipaa": ["hipaa"],
        "gdpr": ["gdpr"],
        "both": ["hipaa", "gdpr"],
    }
    if selection.lower() not in mapping:
        raise ValueError("selection must be hipaa, gdpr, or both")
    return _service().set_active_policies(mapping[selection.lower()])


@mcp.tool()
def list_rules() -> dict:
    """List effective HIPAA/GDPR rules and whether each is enabled."""
    return _service().list_rules()


@mcp.tool()
def set_rule_enabled(rule_id: str, enabled: bool) -> dict:
    """Enable or disable one rule in the shared project configuration."""
    return _service().set_rule_enabled(rule_id, enabled)


@mcp.tool()
def init_scan() -> dict:
    """Scan all tracked code files and persist a timestamped JSON report."""
    return _service().scan_repository()


@mcp.tool()
def scan_diff() -> dict:
    """Scan only added lines in the staged Git diff and persist a JSON report."""
    return _service().scan_diff()


@mcp.tool()
def get_latest_report() -> dict:
    """Read the latest persisted scan report."""
    return _service().get_latest_report()


@mcp.tool()
def get_report(scan_id: str) -> dict:
    """Read a persisted scan report by scan ID."""
    return _service().get_report(scan_id)


@mcp.tool()
def get_next_fix(scan_id: str = "") -> dict:
    """Return the next open finding and its policy-defined remediation."""
    return _service().get_next_fix(scan_id or None)


@mcp.tool()
def set_violation_status(
    violation_id: str, status: str, scan_id: str = ""
) -> dict:
    """Mark one finding `open`, `fixed`, or `skipped` after user review."""
    return _service().set_violation_status(
        violation_id, status, scan_id or None
    )


@mcp.tool()
def verify_fixes(scan_id: str) -> dict:
    """Re-run the originating scan mode and save a linked verification report."""
    return _service().verify_report(scan_id)


@mcp.prompt(name="init")
def init_prompt() -> str:
    return (
        "Run the one-time baseline privacy scan. Call init_scan, present every "
        "finding with redacted evidence and remediation, state where the JSON "
        "report was saved, and finish with its commit verdict."
    )


@mcp.prompt(name="agentic-init")
def agentic_init_prompt() -> str:
    return (
        "Establish a trustworthy privacy baseline using get_config and "
        "init_scan. Use judgment to group repeated findings, prioritize the "
        "most severe issues, explain what deserves attention first, and report "
        "the saved JSON path and commit verdict. Keep raw sensitive values out "
        "of user-visible output. If contextual triage is not reliable, follow "
        "the strict init prompt as the deterministic fallback."
    )


@mcp.prompt(name="scan-diff")
def scan_diff_prompt() -> str:
    return (
        "Run the normal pre-commit privacy check. Call scan_diff, report only "
        "findings in staged added lines, include the saved report path, and give "
        "the commit verdict. If there are no staged lines, say so clearly."
    )


@mcp.prompt(name="agentic-scan")
def agentic_scan_prompt() -> str:
    return (
        "Assess the staged change with scan_diff. Group related findings, "
        "prioritize them, explain their practical significance, recommend the "
        "next action, and report the saved JSON path and verdict. If there are "
        "no staged lines, explain that clearly and suggest an appropriate next "
        "step without silently scanning unstaged files. If contextual assessment "
        "is not reliable, follow the strict scan-diff prompt as the deterministic "
        "fallback."
    )


@mcp.prompt(name="fix")
def fix_prompt() -> str:
    return (
        "Call get_latest_report and get_next_fix. For exactly one open finding, "
        "explain the policy-derived proposed code change using only redacted "
        "evidence and ask the user for permission before editing. After an "
        "approved edit, use your native file tools, call set_violation_status "
        "with fixed, then ask permission to move to the next finding. If denied, "
        "mark it skipped only when the user requests that. When no open findings "
        "remain, call verify_fixes with the source scan ID and report the new "
        "verdict. Never edit more than one finding per approval."
    )


@mcp.prompt(name="agentic-fix")
def agentic_fix_prompt() -> str:
    return (
        "Review the latest open findings and inspect the relevant source "
        "context. Group only similar, low-risk findings that share one clear "
        "remediation. Present a bounded plan listing every intended edit and "
        "obtain explicit permission before changing source code. Apply only the "
        "approved edits, call verify_fixes with the source scan ID, and mark a "
        "finding fixed only when verification confirms it is absent. Use only "
        "redacted evidence in user-visible output. Stop and ask when remediation "
        "is ambiguous or exceeds the approved plan. Fall back to the strict fix "
        "prompt for one-finding-at-a-time handling when grouping is unsafe, the "
        "change is high risk, or the user requests strict supervision."
    )


@mcp.prompt(name="config")
def config_prompt() -> str:
    return (
        "Call get_config, ask the user to choose HIPAA, GDPR, or both, call "
        "set_active_policies, then call list_rules and summarize the effective "
        "rule count."
    )


@mcp.prompt(name="exclude")
def exclude_prompt() -> str:
    return (
        "Call list_rules, show rule IDs and enabled status, ask which rule to "
        "enable or disable, then call set_rule_enabled and show the result."
    )


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
