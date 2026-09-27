---
description: Enable or disable a single privacy rule
argument-hint: "[RULE-ID] [on|off]"
disable-model-invocation: true
allowed-tools: mcp__plugin_privacy-agent_privacy-agent__list_rules, mcp__plugin_privacy-agent_privacy-agent__set_rule_enabled
---

Enable or disable a privacy rule. Request: "$ARGUMENTS".

1. Call `list_rules` and show a table: rule ID, enabled, severity, name.
2. If the request above names a rule and `on`/`off` (or enable/disable), use it. Otherwise ask the user which rule to change and whether to enable or disable it, and wait for the answer. Do not choose for the user.
3. Call `set_rule_enabled`, then show the updated table.
4. Remind the user that disabled rules are skipped by every scan, and to commit `.privacy-agent/config.yaml` so the team shares the change.
