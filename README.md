# privacy-agent

A Claude Code plugin that checks code against privacy regulation policies
before you commit. HIPAA- and GDPR-oriented rule sets ship by default.

Claude judges the code. Everything else is deterministic code in a local MCP
server: which rules are active, which files are scanned, validating Claude's
findings, redaction, and the audit log. This is a technical pre-commit control,
not legal advice or certification.

- [What you get](#what-you-get)
- [Installation](#installation)
  - [1. Prerequisites](#1-prerequisites)
  - [2. Install the plugin](#2-install-the-plugin)
  - [3. Verify the plugin loaded](#3-verify-the-plugin-loaded)
  - [4. Set up each repository](#4-set-up-each-repository)
  - [5. Run your first scan](#5-run-your-first-scan)
  - [6. Optional: team setup](#6-optional-team-setup)
  - [Updating and uninstalling](#updating-and-uninstalling)
  - [Troubleshooting](#troubleshooting)
- [Commands](#commands)
- [How a scan works](#how-a-scan-works)
- [Repository layout after init](#repository-layout-after-init)
- [Configuration](#configuration)
- [Writing rules](#writing-rules)
- [Development](#development)

## What you get

| Piece | Where | Role |
|---|---|---|
| Slash commands | `commands/*.md` | The agent protocol Claude follows (`/privacy-agent:full-scan`, etc.) |
| MCP server `privacy-agent` | `privacy_agent/` (Python, run by `uv`) | Selects targets and rules, validates findings, redacts, writes audit logs |
| Default policies | `privacy_agent/templates/` | `hipaa.yaml`, `gdpr.yaml`, `config.yaml`, copied into your repo by `init` |
| Plugin manifests | `.claude-plugin/`, `.mcp.json` | Tell Claude Code how to install the plugin and start the server |

There is no separate CLI. Everything runs through Claude Code slash commands.

## Installation

### 1. Prerequisites

You need all of the following on the machine where you run Claude Code
(macOS, Linux, or Windows via WSL).

#### 1.1 Claude Code

Install Claude Code and sign in. Plugins need a recent version, so update an
older install first.

```bash
claude --version        # check that it is installed
claude update           # update to the latest version
```

If `claude` is not found, install it by following
<https://docs.claude.com/en/docs/claude-code/setup>, then run `claude` once and
sign in.

#### 1.2 Git

The scanner uses Git to list tracked files and compute diffs, so each
repository you scan must be a Git repository.

```bash
git --version
```

If Git is missing:

- macOS: `xcode-select --install` (or `brew install git`)
- Debian/Ubuntu: `sudo apt-get install git`
- Fedora: `sudo dnf install git`

#### 1.3 uv

Claude Code starts the MCP server with [uv](https://docs.astral.sh/uv/)
(`uv run ... privacy-agent-mcp`, see `.mcp.json`). uv must be on the `PATH`
that Claude Code sees.

```bash
uv --version
```

If uv is missing, install it:

```bash
# macOS / Linux (official installer)
curl -LsSf https://astral.sh/uv/install.sh | sh

# or with Homebrew on macOS
brew install uv
```

The official installer puts `uv` in `~/.local/bin`. Open a **new** terminal
afterwards, and run `uv --version` again to confirm it is on your `PATH`. If
it isn't, add `export PATH="$HOME/.local/bin:$PATH"` to `~/.zshrc` or
`~/.bashrc` and open a new terminal.

#### 1.4 Python 3.11 or newer (handled by uv)

The server needs Python ≥ 3.11 (`pyproject.toml`). You don't have to install
it yourself. If no suitable Python is installed, uv downloads one the first
time the server starts. To fetch it ahead of time:

```bash
uv python install 3.12
```

#### 1.5 Network access on first start

The first time the server starts, uv creates a virtual environment inside the
plugin's install directory and downloads the dependencies (`mcp`, `PyYAML`,
and possibly Python). That start needs internet access and can take a few
seconds. Later starts are fast and work offline.

### 2. Install the plugin

The plugin is distributed as a Claude Code **marketplace** (named
`privacy-agent`) that contains one **plugin** (also named `privacy-agent`).
That's why the full plugin ID is `privacy-agent@privacy-agent`.

Choose **one** of the options below.

#### Option A: install from GitHub (recommended)

1. Open a terminal and start Claude Code in any directory:

   ```bash
   claude
   ```

2. Add the marketplace. In the Claude Code prompt, type:

   ```
   /plugin marketplace add yonatankadosh/snp-final-version
   ```

   This clones the GitHub repository and registers a marketplace named
   `privacy-agent`.

3. Install the plugin:

   ```
   /plugin install privacy-agent@privacy-agent
   ```

   If you're asked for an installation scope, choose one:

   | Scope | Effect |
   |---|---|
   | `user` (default) | Available in every project for you |
   | `project` | Recorded in the repo's `.claude/settings.json`, so it's shared with your team |
   | `local` | Only for you, only in this repo (`.claude/settings.local.json`) |

   You can also run `/plugin` with no arguments and do the same thing from
   the interactive menu: **Marketplaces → Add**, then **Discover/Browse →
   privacy-agent → Install**.

4. **Restart Claude Code.** Exit with `/exit` (or Ctrl+D twice) and run
   `claude` again. Plugins, their commands and their MCP server load at
   startup.

You can do the same from your shell instead of the Claude Code prompt:

```bash
claude plugin marketplace add yonatankadosh/snp-final-version
claude plugin install privacy-agent@privacy-agent            # user scope
# or: claude plugin install privacy-agent@privacy-agent --scope project
```

#### Option B: install from a local clone

Use this option if you can't reach GitHub from Claude Code, want a specific
branch, or are editing the plugin.

1. Clone the repository:

   ```bash
   git clone https://github.com/yonatankadosh/snp-final-version.git
   cd snp-final-version
   ```

2. Optional: check that the server's dependencies install and the tests pass:

   ```bash
   uv run python -m unittest
   ```

   You should see `OK` at the end.

3. Register the clone as a marketplace and install from it. Use the
   **absolute** path:

   ```bash
   claude plugin marketplace add "$(pwd)"
   claude plugin install privacy-agent@privacy-agent
   ```

4. Restart Claude Code.

#### Option C: load for one session only (no install)

To try the plugin without installing it, start Claude Code with the plugin
directory:

```bash
claude --plugin-dir /absolute/path/to/snp-final-version
```

The plugin is active only for that session. You need to pass the flag every
time.

### 3. Verify the plugin loaded

After restarting Claude Code, check all three of the following:

1. **Plugin installed and enabled:** run `/plugin`, open the installed
   plugins list, and confirm that `privacy-agent` is listed and enabled. From
   a shell, `claude plugin list` shows the same.
2. **Commands available:** type `/privacy-agent:` in the prompt. The
   autocomplete should list `init`, `full-scan`, `diff-scan`, `fix`, `report`,
   `triage`, `config` and `exclude`.
3. **MCP server connected:** run `/mcp`. The `privacy-agent` server from the
   plugin should show as **connected**. Its tools are named
   `mcp__plugin_privacy-agent_privacy-agent__<tool>` (`init_repo`,
   `prepare_scan`, `submit_findings`, …).

If the server shows as failed, see [Troubleshooting](#troubleshooting).

### 4. Set up each repository

Do this once per repository you want to scan.

1. **Start Claude Code from inside the repository** (the repo root or any
   subdirectory). The server finds the repository from Claude Code's working
   directory:

   ```bash
   cd /path/to/your/repo
   claude
   ```

2. **Make sure it's a Git repository.** If it isn't, run `git init` first.
   `init` installs into the Git top-level directory.

3. **Install the policy files:**

   ```
   /privacy-agent:init
   ```

   This creates the following files and never overwrites existing ones, so
   it's safe to run again:

   ```
   .privacy-agent/config.yaml
   .privacy-agent/policies/hipaa.yaml
   .privacy-agent/policies/gdpr.yaml
   .privacy-agent/.gitignore          # ignores audit-logs/.pending/
   .privacy-agent/audit-logs/.gitkeep
   ```

   Claude then lists the enabled rules.

4. **Choose the active policies.** By default **only `hipaa` is active**. To
   change that:

   ```
   /privacy-agent:config gdpr          # GDPR only
   /privacy-agent:config hipaa gdpr    # both
   /privacy-agent:config both          # same as above
   /privacy-agent:config               # no argument: Claude shows the options and asks
   ```

5. **Optional: turn off rules you don't need:**

   ```
   /privacy-agent:exclude                  # show all rules and choose
   /privacy-agent:exclude HIPAA-003 off    # disable one rule
   /privacy-agent:exclude HIPAA-003 on     # re-enable it
   ```

   You can't disable every rule of the active policies.

6. **Optional: adjust which files are scanned** in
   `.privacy-agent/config.yaml` (`scan.include_extensions` and
   `scan.exclude_prefixes`). See [Configuration](#configuration).

7. **Commit the setup** so your team shares the same policy and audit trail:

   ```bash
   git add .privacy-agent
   git commit -m "Add privacy-agent policies"
   ```

### 5. Run your first scan

1. **Baseline: scan the whole repository:**

   ```
   /privacy-agent:full-scan
   ```

   A full scan covers files that Git tracks (`git ls-files`). New files must
   be `git add`-ed before a full scan sees them. A diff scan covers untracked
   files too.

2. **Before each commit, scan only what changed:**

   ```
   /privacy-agent:diff-scan            # vs. the remote default branch
   /privacy-agent:diff-scan develop    # vs. a specific base branch
   ```

   This covers lines changed since the merge-base with the base branch,
   including uncommitted and untracked files. With no argument, the base is
   `origin/HEAD`, then `main`, then `master`, whichever exists first. If
   `origin/HEAD` isn't set, run `git remote set-head origin --auto` once.

3. **Read the verdict.** Each scan ends with `SAFE_TO_COMMIT`,
   `DO_NOT_COMMIT` or `NOT_APPLICABLE` (nothing to scan), plus the path of
   the audit log in `.privacy-agent/audit-logs/`.

4. **Handle findings:**

   ```
   /privacy-agent:fix        # Claude proposes fixes, edits after your approval, then re-verifies
   /privacy-agent:triage     # you mark false positives / accepted risks as skipped
   /privacy-agent:report     # re-show the latest audit log without rescanning
   ```

Claude Code may ask for permission the first time a command calls one of the
plugin's tools. Approve it. Every command pre-approves only the tools it
needs.

### 6. Optional: team setup

To have every developer offered the plugin automatically, and to make Claude
read policies only through the server (which hides disabled rules), add the
following to the repository's `.claude/settings.json` and commit it:

```json
{
  "extraKnownMarketplaces": {
    "privacy-agent": {
      "source": { "source": "github", "repo": "yonatankadosh/snp-final-version" }
    }
  },
  "enabledPlugins": { "privacy-agent@privacy-agent": true },
  "permissions": { "deny": ["Read(.privacy-agent/policies/**)"] }
}
```

When a teammate trusts the folder in Claude Code, they're prompted to install
the marketplace and plugin. Each teammate still needs Git and uv
([Prerequisites](#1-prerequisites)).

### Updating and uninstalling

```bash
claude plugin marketplace update privacy-agent      # fetch the latest marketplace contents
claude plugin update privacy-agent@privacy-agent    # update the plugin, then restart Claude Code
```

```bash
claude plugin uninstall privacy-agent@privacy-agent
claude plugin marketplace remove privacy-agent
```

You can also do all of this from the `/plugin` menu. Uninstalling the plugin
doesn't touch the `.privacy-agent/` directory in your repositories. Delete it
yourself if you no longer want it.

Updating the plugin doesn't change policy files already copied into a
repository. Running `/privacy-agent:init` again adds only files that are
missing.

### Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `/privacy-agent:...` commands don't appear | Claude Code wasn't restarted after installing, or the plugin is disabled. Restart and check `/plugin`. |
| `/mcp` shows `privacy-agent` as failed | Usually `uv` isn't on the `PATH` Claude Code inherited. Run `which uv` in the same terminal you start `claude` from. If you just installed uv, open a new terminal. On macOS, if you launch Claude Code from an IDE, make sure the IDE also sees `~/.local/bin` or `/opt/homebrew/bin`. |
| Server fails or times out on first start | The first start downloads dependencies, which needs internet access. To pre-warm it, run `uv run python -c "import privacy_agent"` inside a clone of this repo, or start Claude Code again once the network is available. |
| `privacy agent is not installed here: .privacy-agent/config.yaml not found; run init first` | Run `/privacy-agent:init`, and make sure you started `claude` inside the repository (or a subdirectory of it). |
| A full scan reports `NOT_APPLICABLE` / no targets | No tracked file matches `scan.include_extensions`, or the files aren't committed or `git add`-ed yet. Check `git ls-files` and `.privacy-agent/config.yaml`. |
| `cannot resolve base branch: X` | The base branch passed to `diff-scan` doesn't exist locally. Run `git fetch` or pass an existing branch. |
| A diff scan only sees uncommitted changes | No `origin/HEAD`, `main` or `master` to diff against, so the base falls back to `HEAD`. Pass a base branch explicitly, or run `git remote set-head origin --auto`. |
| `changed since prepare_scan` / `stale` | A target file or the policy changed during the scan. Run the scan again. |
| Claude asks permission before changing policies, rules or finding status | This is intentional. Only `/privacy-agent:config`, `/privacy-agent:exclude` and `/privacy-agent:triage` pre-approve those tools. |

## Commands

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

Only you can start `config`, `exclude` and `triage`. Claude can't invoke them
on its own, and only they pre-approve the tools that change policies, rules or
finding status. If Claude tries to call those tools during a scan or fix,
Claude Code asks you first. The server also rejects a scan if the policy
changes between its start and its submission.

### Default rules

| Policy | Rule | Severity | Name |
|---|---|---|---|
| hipaa | HIPAA-001 | high | No hardcoded direct identifiers |
| hipaa | HIPAA-002 | high | No PHI in logs or console output |
| hipaa | HIPAA-003 | high | No hardcoded clinical information |
| hipaa | HIPAA-004 | high | Minimize PHI in exports |
| gdpr | GDPR-001 | high | No hardcoded personal data |
| gdpr | GDPR-002 | high | No personal or special-category data in logs |
| gdpr | GDPR-003 | very_high | No hardcoded special-category data |
| gdpr | GDPR-004 | high | Minimize personal data in exports |

Run `/privacy-agent:exclude` to see the current severities and enabled state
for your repository.

## How a scan works

```
prepare_scan    (server) → active rules only, target files/line ranges, regex hints
review          (Claude) → reads the targets with its own tools, judges against the rules
submit_findings (server) → validates every finding, redacts, writes the audit log
```

The server rejects a finding when:

- the rule isn't active or doesn't apply to the file,
- the file isn't a target, or the line is outside the file or outside the diff,
- the `quote` doesn't appear on the stated line (this catches invented findings),
- any target file or the policy changed since `prepare_scan` (the scan must be redone).

Regex detectors in the policies are hints only. They point Claude at likely
spots. Claude confirms or dismisses them and reports violations they miss.

A finding becomes `fixed` only through `/privacy-agent:fix`'s verification
scan. The re-review must not report it, **and** its original line must no
longer exist unchanged. Claude can't mark findings fixed.

## Repository layout after init

```
.privacy-agent/
├── config.yaml          # active_policies, disabled_rules, scanned extensions/excludes
├── .gitignore           # ignores audit-logs/.pending/
├── policies/            # one YAML per policy; add your own
│   ├── hipaa.yaml
│   └── gdpr.yaml
└── audit-logs/          # one JSON per scan + latest.json (.pending/ is gitignored)
```

Audit logs are named `<scan-id>-<mode>.json` (`full-scan`, `diff-scan` or
`verify`). `latest.json` is a copy of the most recent one. Evidence in the logs
is redacted: string literal contents and detector matches are replaced with
`[REDACTED]`.

## Configuration

`.privacy-agent/config.yaml`, as installed:

```yaml
schema_version: 2
active_policies:
  - hipaa            # file stems from policies/, e.g. [hipaa, gdpr]
disabled_rules: []   # rule IDs skipped by every scan
scan:
  include_extensions: [.c, .cc, .cpp, .cs, .go, .java, .js, .jsx, .kt,
                       .php, .py, .rb, .rs, .swift, .ts, .tsx, .vue]
  exclude_prefixes: [.git/, .privacy-agent/, .venv/, node_modules/,
                     vendor/, dist/, build/]
```

- Prefer `/privacy-agent:config` and `/privacy-agent:exclude` to editing
  `active_policies` and `disabled_rules` by hand. Both edit this file.
- `exclude_prefixes` are plain path prefixes relative to the repo root, not
  globs.
- Only UTF-8 text files are scanned.
- To add a policy, drop a `<id>.yaml` file into `policies/` whose `policy_id`
  equals `<id>`, then activate it with `/privacy-agent:config`.

## Writing rules

```yaml
schema_version: 2
policy_id: mypolicy             # must match the file name (mypolicy.yaml)
name: My policy
detectors:
  sensitive_logging:
    type: regex
    pattern: 'console\.log\([^\n]*email'
    redact: false               # matches code patterns, not personal values
rules:
  - id: PII-LOG-001
    name: No personal data in logs
    severity: high              # low | medium | high | very_high
    risk_score: 85
    description: >              # what Claude judges against: be specific
      Log/print/console calls must not emit personal data ...
    examples:
      violating: ['console.log(user.email)']
      compliant: ['logger.info("user_id=%s", user.id)']
    applies_to: ["src/**/*.ts"]     # optional; default is every scanned file
    detectors: [sensitive_logging]  # optional regex hints (see `detectors:`)
    remediation:
      suggestion: Log a pseudonymous ID instead.
      agent_steps: [...]
```

A detector that matches code patterns rather than personal values should set
`redact: false`, so it doesn't blank out evidence in the audit log. Rule IDs
must be unique across all active policies.

## Development

```bash
uv run python -m unittest            # run the tests
claude --plugin-dir .                # load the plugin from this checkout
claude plugin validate .             # validate the plugin/marketplace manifests
```

`tests/fixtures/sample_app/` is a small app with known violations and known
regex false positives (`EXPECTED.md`, with GDPR active) for manual end-to-end
runs.

Not yet supported:

- splitting very large scans into chunks;
- running scans headless (git hooks/CI) without a Claude Code session.
