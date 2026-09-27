---
description: Review open findings and mark false positives or accepted risks as skipped
argument-hint: "[scan-id]"
disable-model-invocation: true
allowed-tools: mcp__plugin_privacy-agent_privacy-agent__get_open_findings, mcp__plugin_privacy-agent_privacy-agent__set_finding_status
---

Triage the open privacy findings.

1. Call `get_open_findings` with `scan_id: "$ARGUMENTS"` (empty means the latest audit log). If there are none, say so and stop.
2. Show the findings as a numbered list: location, rule ID and name, severity, redacted `evidence_summary`, and `explanation`. Never print raw personal values.
3. Ask the user which findings to mark **skipped** (false positive or accepted risk) and wait for the answer. The decision is the user's; do not skip anything on your own judgment.
4. Call `set_finding_status` with `status: "skipped"` for each chosen finding (use the same scan_id).
5. Summarize what was skipped and what is still open. Skipped findings are ignored by `/privacy-agent:fix`. Findings become `fixed` only through `/privacy-agent:fix` verification.
