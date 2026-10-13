import argparse
import json
import os
import sys
import tkinter as tk
from pathlib import Path

from .enforcement import Enforcer, is_admin
from .levels import LABELS, Level, parse_level
from .service_client import ServiceClient
from .store import Store, current_operator
from .ui import BannerApp
from .updates import apply_signed_update
from .verification import verify_downgrade


def _default_database() -> Path:
    if sys.platform == "win32":
        root = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "ClassificationApp"
    else:
        root = Path.home() / ".local" / "share" / "classification-app"
    return root / "classification.db"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Lightweight Windows classification banner")
    parser.add_argument("--db", default=str(_default_database()), help="SQLite database path")
    parser.add_argument(
        "--enforce",
        action="store_true",
        help="Apply Windows policy changes (requires Administrator; default is dry-run)",
    )
    parser.add_argument(
        "--service-client",
        action="store_true",
        help="Use the installed machine enforcement service; never falls back to local enforcement",
    )
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("run", help="Show the always-on-top banner")
    classify = subparsers.add_parser("classify", help="Classify a file")
    classify.add_argument("file")
    set_level = subparsers.add_parser("set-level", help="Change the active classification")
    set_level.add_argument("level")
    set_level.add_argument("--confirm-downgrade", action="store_true")
    update = subparsers.add_parser("update", help="Apply an HMAC-signed local rule bundle")
    update.add_argument("bundle")
    subparsers.add_parser("verify-audit", help="Verify the local hash-chained audit log")
    subparsers.add_parser("status", help="Show current level and installed rule version")
    return parser


def main() -> int:
    parser = _parser()
    args = parser.parse_args()
    if args.enforce and args.service_client:
        parser.error("--enforce cannot be combined with --service-client")
    store = Store(args.db)
    dry_run = not args.enforce and not args.service_client
    service_client = ServiceClient() if args.service_client else None
    try:
        operator = current_operator()
        command = args.command or "run"
        if command == "verify-audit":
            valid, count = store.verify_audit()
            print(f"Audit valid: {valid}; entries checked: {count}")
            return 0 if valid else 2
        if command == "status":
            service_status = service_client.status() if service_client else None
            level = service_status.level if service_status else Level(store.current_level())
            print(
                json.dumps(
                    {
                        "classification": LABELS[level],
                        "dry_run": dry_run if not service_client else False,
                        "service_client": service_client is not None,
                        "enforcement_error": (
                            service_status.enforcement_error if service_status else None
                        ),
                        "rules_version": int(store.get_state("rules_version") or "0"),
                    },
                    indent=2,
                )
            )
            return 0
        if command == "update":
            key = os.environ.get("CLS_UPDATE_KEY", "")
            version = apply_signed_update(args.bundle, store, key)
            store.audit("rules_updated", store.current_level(), operator, {"version": version})
            print(f"Installed signed rule version {version}")
            return 0
        if command == "classify":
            from .classifier import classify_file

            result = classify_file(args.file, store)
            print(
                json.dumps(
                    {
                        "classification": LABELS[result.level],
                        "sha256": result.sha256,
                        "path": result.path,
                        "evidence": result.evidence,
                    },
                    indent=2,
                )
            )
            return 0
        if command == "set-level":
            level = parse_level(args.level)
            previous = Level(
                service_client.current_level() if service_client else store.current_level()
            )
            if level < previous and not args.confirm_downgrade:
                raise ValueError("A downgrade requires --confirm-downgrade")
            if level < previous and not verify_downgrade(store, previous, level):
                raise PermissionError(
                    "Windows Hello verification was not approved; classification is unchanged"
                )
            if args.enforce and not service_client and not is_admin():
                raise PermissionError("--enforce requires an elevated Administrator session")
            if service_client:
                actions = service_client.set_level(level, "command_line")
            else:
                store.set_current_level(int(level))
                store.audit(
                    "classification_change",
                    int(level),
                    operator,
                    {"from": int(previous), "to": int(level), "reason": "command_line"},
                )
                actions = Enforcer(store, dry_run).reconcile(level)
            print(f"Classification: {LABELS[level]}")
            for action in actions:
                print(("WOULD " if dry_run and not service_client else "") + action)
            return 0

        if args.enforce and not service_client and not is_admin():
            raise PermissionError("--enforce requires an elevated Administrator session")
        root = tk.Tk()
        BannerApp(root, store, Enforcer(store, dry_run), dry_run, service_client)
        root.mainloop()
        return 0
    except (OSError, ValueError, RuntimeError, PermissionError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
