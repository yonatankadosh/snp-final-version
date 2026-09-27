# privacy-agent

A Claude Code plugin that checks code against privacy regulation policies
(HIPAA- and GDPR-oriented rule sets ship by default) before you commit.

Claude judges the code. Everything else is deterministic code in an MCP server:
which rules are active, which files are scanned, validating Claude's findings,
redaction, and the audit log. This is a technical pre-commit control, not
legal advice.

## Commands

Everything runs through Claude Code slash commands; there is no separate CLI.

| Command | What it does |
|---|---|
| `/privacy-agent:init` | Installs `.privacy-agent/` (policies, config, audit-logs) into the repo |
| `/privacy-agent:full-scan` | Reviews every tracked code file and writes an audit log |
| `/privacy-agent:diff-scan [base]` | Reviews lines changed since the merge-base with `base` (default: the remote default branch), including uncommitted and untracked files |
| `/privacy-agent:fix [scan-id]` | Proposes fixes for open findings, edits after your approval, then runs a verification scan |
| `/privacy-agent:report [scan-id]` | Summarizes the latest (or a given) audit log without rescanning |
| `/privacy-agent:triage [scan-id]` | Lets you mark findings as skipped (false positive or accepted risk) |
| `/privacy-agent:config [policy ...]` | Chooses the active policies (e.g. `gdpr`, `hipaa gdpr`, `both`) |
| `/privacy-agent:exclude [RULE-ID] [on\|off]` | Enables or disables a single rule |

`config`, `exclude` and `triage` can only be started by you (Claude cannot
invoke them on its own), and only they pre-approve the tools that change
policies, rules or finding status. If Claude tries to call those tools during a
scan or fix, Claude Code asks you first. A scan is also rejected if the policy
changes between its start and its submission.

## How a scan works

```
prepare_scan  (server)  → active rules only, target files/line ranges, regex hints
review        (Claude)  → reads the targets with its own tools, judges against the rules
submit_findings (server) → validates every finding, redacts, writes the audit log
```

The server rejects a finding when:

- the rule is not active or does not apply to the file,
- the file is not a target, or the line is outside the file or outside the diff,
- the `quote` does not appear on the stated line (catches invented findings),
- any target file or the policy changed since `prepare_scan` (the scan must be redone).

Regex detectors in the policies are hints only. They point Claude at likely
spots; Claude confirms or dismisses them and reports what they miss.

A finding becomes `fixed` only through `/privacy-agent:fix`'s verification
scan: the re-review must not report it **and** its original line must no longer
exist unchanged. Claude cannot mark findings fixed.

## Install

Prerequisites: [uv](https://docs.astral.sh/uv/) (it runs the MCP server) and Git.

```
/plugin marketplace add <org>/privacy-agent
/plugin install privacy-agent@privacy-agent
```

Then, in each repository:

```
/privacy-agent:init
```

Choose policies with `/privacy-agent:config`, turn off rules you don't need with
`/privacy-agent:exclude`, and commit `.privacy-agent/` so the team shares the
policy and the audit trail.

### Team setup

Add to the repository's `.claude/settings.json` so every developer is offered
the plugin, and so Claude reads policies only through the server (which hides
disabled rules):

```json
{
  "extraKnownMarketplaces": {
    "privacy-agent": { "source": { "source": "github", "repo": "<org>/privacy-agent" } }
  },
  "enabledPlugins": { "privacy-agent@privacy-agent": true },
  "permissions": { "deny": ["Read(.privacy-agent/policies/**)"] }
}
```

## Repository layout after init

```
.privacy-agent/
├── config.yaml          # active_policies, disabled_rules, scanned extensions/excludes
├── policies/            # one YAML per policy; add your own
│   ├── hipaa.yaml
│   └── gdpr.yaml
└── audit-logs/          # one JSON per scan + latest.json (.pending/ is gitignored)
```

### Writing rules

```yaml
rules:
  - id: PII-LOG-001
    name: No personal data in logs
    severity: high            # low | medium | high | very_high
    risk_score: 85
    description: >            # what Claude judges against: be specific
      Log/print/console calls must not emit personal data ...
    examples:
      violating: ['console.log(user.email)']
      compliant: ['logger.info("user_id=%s", user.id)']
    applies_to: ["src/**/*.ts"]   # optional; default is every scanned file
    detectors: [sensitive_logging] # optional regex hints (see `detectors:`)
    remediation:
      suggestion: Log a pseudonymous ID instead.
      agent_steps: [...]
```

A detector that matches code patterns rather than personal values should set
`redact: false` so it does not blank out evidence in the audit log.

## Development

```
uv run python -m unittest
claude --plugin-dir .                # load the plugin from this checkout
```

`tests/fixtures/sample_app/` is a small app with known violations and known
regex false positives (`EXPECTED.md`) for manual end-to-end runs.

Not yet supported: splitting very large scans into chunks, and running scans
headless (git hooks/CI) without a Claude Code session.
