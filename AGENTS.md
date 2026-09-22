# Privacy pre-commit agent protocol

These instructions apply to any MCP-capable coding agent (Codex CLI, Claude
Code, or another client) connected to the `privacy-precommit-agent` server.
The agent enforces privacy rules against source code only. Never inspect or
modify a database.

## Operations

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
