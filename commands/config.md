---
description: Choose which privacy policies (e.g. HIPAA, GDPR) are active
argument-hint: "[policy ...]"
disable-model-invocation: true
allowed-tools: mcp__plugin_privacy-agent_privacy-agent__list_policies, mcp__plugin_privacy-agent_privacy-agent__set_active_policies, mcp__plugin_privacy-agent_privacy-agent__get_active_rules
---

Change the active privacy policies. Requested policies: "$ARGUMENTS".

1. Call `list_policies` and show the available and currently active policies.
2. If policies were requested above, use them (`both` means hipaa and gdpr). Otherwise ask the user which policies to activate and wait for the answer. Do not choose for the user.
3. Call `set_active_policies` with the chosen list.
4. Call `get_active_rules` and show the enabled rules as a table (ID, severity, name).
5. Remind the user to commit `.privacy-agent/config.yaml` so the team shares the change.
