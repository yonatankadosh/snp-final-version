"""Terminal UI for the pre-commit privacy agent."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from .service import PrivacyService


def _print_report(report: dict[str, Any]) -> None:
    summary = report["summary"]
    print(f"\n{report['mode']} scan: {summary['verdict']}")
    print(
        f"{summary['violation_count']} violation(s) across "
        f"{summary['file_count']} file(s)"
    )
    print(f"Saved: {report['report_path']}")
    for item in report["violations"]:
        rule_ids = ", ".join(rule["rule_id"] for rule in item["matched_rules"])
        print(
            f"\n[{item['severity'].upper()}] {rule_ids} "
            f"at {item['location']} (risk {item['risk_score']})"
        )
        print(f"  Evidence: {item['evidence_summary']}")
        print(
            "  Fix: "
            + " / ".join(
                rule["remediation"]["suggestion"]
                for rule in item["matched_rules"]
            )
        )


def _print_rules(payload: dict[str, Any]) -> None:
    for rule in payload["rules"]:
        marker = "enabled" if rule["enabled"] else "disabled"
        print(
            f"{rule['rule_id']:<12} {marker:<8} "
            f"{rule['severity']:<10} {rule['name']}"
        )


def _configure(service: PrivacyService, selection: str | None = None) -> None:
    if selection is None:
        print("1) HIPAA\n2) GDPR\n3) Both")
        selection = input("Policy selection: ").strip()
        selection = {"1": "hipaa", "2": "gdpr", "3": "both"}.get(
            selection, selection
        )
    mapping = {
        "hipaa": ["hipaa"],
        "gdpr": ["gdpr"],
        "both": ["hipaa", "gdpr"],
    }
    if selection not in mapping:
        raise ValueError("selection must be hipaa, gdpr, or both")
    config = service.set_active_policies(mapping[selection])
    print(f"Active policies: {', '.join(config['active_policies'])}")
    print(f"Effective rules: {len(service.list_rules()['rules'])}")


def _exclude(
    service: PrivacyService,
    rule_id: str | None = None,
    enabled: bool | None = None,
) -> None:
    _print_rules(service.list_rules())
    if rule_id is None:
        rule_id = input("\nRule ID to change (blank to cancel): ").strip()
        if not rule_id:
            return
    if enabled is None:
        action = input("Enable or disable? [e/d]: ").strip().lower()
        if action not in {"e", "d"}:
            raise ValueError("choose e or d")
        enabled = action == "e"
    result = service.set_rule_enabled(rule_id, enabled)
    print()
    _print_rules(result)


def _fix_queue(service: PrivacyService, scan_id: str | None = None) -> None:
    """Human queue UI; a connected LLM performs contextual source edits via MCP."""
    while True:
        payload = service.get_next_fix(scan_id)
        violation = payload["violation"]
        if violation is None:
            print("No open findings remain. Run verification from the connected agent.")
            return
        rules = violation["matched_rules"]
        print(
            f"\nNext: {violation['violation_id']} "
            f"at {violation['location']} [{violation['severity']}]"
        )
        print(f"Evidence: {violation['evidence_summary']}")
        for rule in rules:
            print(f"\n{rule['rule_id']}: {rule['remediation']['suggestion']}")
            for index, step in enumerate(
                rule["remediation"].get("agent_steps", []), start=1
            ):
                print(f"  {index}. {step}")
        print(
            "\nA connected LLM should ask permission, edit this one finding, "
            "then mark its status through MCP."
        )
        action = input("Mark [f]ixed, [s]kipped, or [q]uit: ").strip().lower()
        if action == "q":
            return
        if action not in {"f", "s"}:
            print("Unknown choice.")
            continue
        status = "fixed" if action == "f" else "skipped"
        service.set_violation_status(
            violation["violation_id"], status, payload["scan_id"]
        )
        if input("Move to the next finding? [y/N]: ").strip().lower() != "y":
            return


def _interactive(service: PrivacyService) -> int:
    actions = {
        "1": ("Initial full scan", lambda: _print_report(service.scan_repository())),
        "2": ("Scan staged diff", lambda: _print_report(service.scan_diff())),
        "3": ("Fix queue", lambda: _fix_queue(service)),
        "4": ("Configure policy", lambda: _configure(service)),
        "5": ("Enable/disable rules", lambda: _exclude(service)),
    }
    while True:
        print("\nPrivacy Agent")
        for key, (label, _) in actions.items():
            print(f"{key}) {label}")
        print("q) Quit")
        choice = input("Choose: ").strip().lower()
        if choice == "q":
            return 0
        action = actions.get(choice)
        if not action:
            print("Unknown choice.")
            continue
        try:
            action[1]()
        except (RuntimeError, ValueError) as error:
            print(f"Error: {error}", file=sys.stderr)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="privacy-agent")
    parser.add_argument("--json", action="store_true", help="print machine JSON")
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("init", help="scan every tracked code file")
    subparsers.add_parser("scan-diff", help="scan added lines in the staged diff")

    fix = subparsers.add_parser("fix", help="inspect the latest fix queue")
    fix.add_argument("--scan-id")

    config = subparsers.add_parser("config", help="choose HIPAA, GDPR, or both")
    config.add_argument("selection", nargs="?", choices=["hipaa", "gdpr", "both"])

    exclude = subparsers.add_parser("exclude", help="enable or disable a rule")
    exclude.add_argument("rule_id", nargs="?")
    state = exclude.add_mutually_exclusive_group()
    state.add_argument("--enable", action="store_true")
    state.add_argument("--disable", action="store_true")

    subparsers.add_parser("rules", help="list effective rules")
    subparsers.add_parser("mcp-server", help=argparse.SUPPRESS)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "mcp-server":
        from .mcp_server import main as mcp_main

        mcp_main()
        return 0

    try:
        service = PrivacyService()
        if args.command is None:
            return _interactive(service)
        if args.command == "init":
            result = service.scan_repository()
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                _print_report(result)
            return 0 if not result["violations"] else 2
        if args.command == "scan-diff":
            result = service.scan_diff()
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                _print_report(result)
            return 0 if not result["violations"] else 2
        if args.command == "fix":
            _fix_queue(service, args.scan_id)
        elif args.command == "config":
            _configure(service, args.selection)
        elif args.command == "exclude":
            requested_state = (
                True if args.enable else False if args.disable else None
            )
            _exclude(service, args.rule_id, requested_state)
        elif args.command == "rules":
            result = service.list_rules()
            print(json.dumps(result, indent=2) if args.json else "")
            if not args.json:
                _print_rules(result)
        return 0
    except (RuntimeError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
