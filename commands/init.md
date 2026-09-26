---
description: Install the privacy policy configuration into this repository
allowed-tools: mcp__plugin_privacy-agent_privacy-agent__init_repo, mcp__plugin_privacy-agent_privacy-agent__get_active_rules
---

Install the privacy agent into the current repository.

1. Call `init_repo`. It copies the default policies into `.privacy-agent/` and never overwrites existing files.
2. Call `get_active_rules` and list the enabled rules (ID, name, severity) in a short table.
3. Tell the user:
   - which files were created and which already existed;
   - policies live in `.privacy-agent/policies/`, and active policies / disabled rules are chosen in `.privacy-agent/config.yaml` (or with `privacy-agent config` / `privacy-agent exclude` in a terminal);
   - audit logs are written to `.privacy-agent/audit-logs/`;
   - to commit `.privacy-agent/` so the whole team shares the policy;
   - next step: `/privacy-agent:full-scan` for a baseline, then `/privacy-agent:diff-scan` before each commit.

Do not read or edit the policy files yourself.
