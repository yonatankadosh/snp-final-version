# Privacy pre-commit agent protocol

These instructions apply to any MCP-capable coding agent (Codex CLI, Claude
Code, or another client) connected to the `privacy-precommit-agent` server.
The agent enforces privacy rules against source code only. Never inspect or
modify a database.

## Operations

Prefer the agentic operations below. They use the same privacy tools and safety
rules while allowing the agent to group findings, inspect relevant source
context, and choose a useful presentation. If the agent lacks enough context,
the remediation is ambiguous or unusually risky, the user requests the strict
workflow, or findings cannot be grouped safely, use the matching deterministic
fallback operation.

### agentic-init

Establish a trustworthy baseline with `get_config` and `init_scan`. Summarize
the result according to the repository and findings: group repeated findings,
prioritize the most severe issues, explain what deserves attention first, and
report the JSON `report_path` and commit verdict. Keep the complete inventory
in the saved report rather than flooding the conversation.

Fall back to `init` when contextual triage is not reliable.

### agentic-scan

Assess the staged change with `scan_diff`. Group related findings, prioritize
them, explain their practical significance, and recommend the next action.
Report the saved JSON path and verdict. If there are no staged lines, explain
that clearly and suggest an appropriate next step; never silently scan
unstaged files.

Fall back to `scan-diff` when contextual assessment is not reliable.

### agentic-fix

Review the latest open findings and inspect the relevant source context. Group
only similar, low-risk findings that can share one clear remediation. Present
a bounded fix plan listing every intended edit and obtain explicit permission
before changing source code. Apply only the approved edits, verify them with
`verify_fixes`, and mark a finding fixed only when verification confirms it is
absent. Stop and ask the user when the right remediation is ambiguous or the
required edit exceeds the approved plan.

Fall back to `fix` for one-finding-at-a-time handling when grouping is unsafe,
the change is high risk, or the user prefers strict supervision.

## Deterministic fallback operations

### init

1. Call `get_config`.
2. Call `init_scan`.
3. Present every finding grouped by severity and file using only
   `evidence_summary`.
4. Report the JSON `report_path` and commit verdict.

Use this once after installation to establish the baseline.

### scan-diff

1. Call `scan_diff`.
2. Report findings introduced on staged added lines only.
3. Report the saved JSON path and verdict.

This is the normal pre-commit operation. Do not silently scan unstaged files
when no staged diff exists.

### fix

1. Call `get_latest_report`, then `get_next_fix`.
2. Work on exactly one open violation at a time.
3. Read its `matched_rules[].remediation.agent_steps`.
4. Explain the proposed code edit with redacted evidence and ask for explicit
   permission before changing the file.
5. After approval, make the smallest code edit that satisfies the rule.
6. Call `set_violation_status(..., "fixed", ...)`.
7. Ask whether to move to the next finding. Stop if the user declines.
8. When no open findings remain, call `verify_fixes` with the original scan ID.

Never batch fixes under one approval. Never invent a remediation that conflicts
with the policy. Never include raw sensitive values in chat or reports.

### config

1. Call `get_config`.
2. Ask the user to choose HIPAA, GDPR, or both.
3. Call `set_active_policies`.
4. Call `list_rules` and summarize the effective rules.

The selection is shared project configuration and should be committed.

### exclude

1. Call `list_rules`.
2. Show rule ID, name, severity, and enabled state.
3. Ask which rule to enable or disable.
4. Call `set_rule_enabled` and show the resulting state.

Do not disable every active rule.

## Safety

- Use only redacted `evidence_summary` values in user-visible output.
- Apply fixes to source code only.
- Do not access databases, run SQL, or add role-based policy enforcement.
- Treat HIPAA/GDPR policies as technical pre-commit controls, not legal advice.
