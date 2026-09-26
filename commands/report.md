---
description: Summarize the latest (or a given) privacy audit log without rescanning
argument-hint: "[scan-id]"
allowed-tools: mcp__plugin_privacy-agent_privacy-agent__get_latest_report, mcp__plugin_privacy-agent_privacy-agent__get_report
---

Summarize a privacy audit log. Requested scan: "$ARGUMENTS".

1. If a scan ID was requested above, call `get_report` with it; otherwise call `get_latest_report`.
2. Report:
   - verdict, mode, scan time, commit, and the audit log path;
   - for a verification log, what it marked fixed, still open, or unchanged;
   - counts of findings by status (open, skipped, fixed) and by severity;
   - the findings grouped by severity, then file: `file:line  RULE-ID  rule name  [status]` with one line of explanation.
3. Quote code only through the redacted `evidence_summary`. Never print raw personal values.
4. If open findings remain, suggest `/privacy-agent:fix` (or `/privacy-agent:triage` for false positives).

Do not rescan or change anything.
