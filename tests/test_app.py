import hashlib
import hmac
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch, Mock

from classification_app.__main__ import main
from classification_app.classifier import classify_file
from classification_app.enforcement import Enforcer
from classification_app.levels import Level, parse_level
from classification_app.netmonitor import inspect_connections, parse_connections
from classification_app.service_client import ServiceClient
from classification_app.service_policy import ClientPrincipal, ServicePolicy
from classification_app.store import Store
from classification_app.ui import BannerApp
from classification_app.updates import apply_signed_update
from classification_app.verification import verify_downgrade


class AppTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(Path(self.temp.name) / "state.db")
        self.addCleanup(self.store.close)

    def test_parse_levels(self):
        self.assertEqual(parse_level("top secret"), Level.TOP_SECRET)
        self.assertEqual(parse_level("confidential"), Level.CONFIDENTIAL)

    def test_banner_render_centers_on_start_and_after_level_change(self):
        class FakeRoot:
            def __init__(self):
                self.width = 400
                self.height = 20
                self.x = 30
                self.y = 900

            def update_idletasks(self):
                pass

            def winfo_reqwidth(self):
                return self.width

            def winfo_x(self):
                return self.x

            def winfo_y(self):
                return self.y

            def winfo_width(self):
                return self.width

            def winfo_height(self):
                return self.height

            def winfo_screenwidth(self):
                return 1920

            def winfo_screenheight(self):
                return 1080

            def geometry(self, value):
                dimensions, x, y = value.split("+")
                if dimensions:
                    width, height = dimensions.split("x")
                    self.width = int(width)
                    self.height = int(height)
                self.x = int(x)
                self.y = int(y)

        class FakeLabel:
            def __init__(self):
                self.text = ""

            def configure(self, *, text, bg):
                self.text = text

            def winfo_reqwidth(self):
                return len(self.text) * 9

        app = object.__new__(BannerApp)
        app.root = FakeRoot()
        app.label = FakeLabel()
        app.dry_run = False
        app.warning = ""
        app.current = Level.CONFIDENTIAL

        app._render()
        self.assertEqual(app.root.x, (1920 - app.root.width) // 2)
        self.assertEqual(app.root.y, (1080 - app.root.height) // 2)

        app.root.x = 30
        app.root.y = 900
        app.current = Level.TOP_SECRET
        app._render()
        self.assertEqual(app.root.x, (1920 - app.root.width) // 2)
        self.assertEqual(app.root.y, (1080 - app.root.height) // 2)

    def test_service_policy_allows_escalation_for_regular_user(self):
        class FakeEnforcer:
            def reconcile(self, level):
                return [f"enforced:{level.name}"]

        self.store.set_current_level(int(Level.CONFIDENTIAL))
        policy = ServicePolicy(self.store, FakeEnforcer())
        principal = ClientPrincipal("S-1-5-21-1", "DOMAIN\\user", frozenset())

        response = policy.handle(
            {"op": "set_level", "level": int(Level.SECRET), "reason": "test"},
            principal,
        )

        self.assertEqual(self.store.current_level(), int(Level.SECRET))
        self.assertEqual(response["actions"], ["enforced:SECRET"])
        self.assertEqual(self.store.verify_audit(), (True, 1))

    def test_service_policy_rejects_and_audits_unauthorized_downgrade(self):
        class FakeEnforcer:
            def reconcile(self, level):
                return []

        self.store.set_current_level(int(Level.SECRET))
        policy = ServicePolicy(self.store, FakeEnforcer(), "S-1-5-21-99")
        principal = ClientPrincipal("S-1-5-21-1", "DOMAIN\\user", frozenset())

        with self.assertRaises(PermissionError):
            policy.handle(
                {"op": "set_level", "level": int(Level.UNCLASS), "reason": "test"},
                principal,
            )

        self.assertEqual(self.store.current_level(), int(Level.SECRET))
        self.assertEqual(self.store.verify_audit(), (True, 1))
        with self.store.transaction() as db:
            row = db.execute("SELECT event FROM audit").fetchone()
        self.assertEqual(row["event"], "classification_change_denied")

    def test_service_policy_allows_only_configured_group_or_administrator_downgrade(self):
        class FakeEnforcer:
            def reconcile(self, level):
                return []

        policy = ServicePolicy(self.store, FakeEnforcer(), "S-1-5-21-99")
        self.store.set_current_level(int(Level.SECRET))
        authorized_user = ClientPrincipal(
            "S-1-5-21-1",
            "DOMAIN\\operator",
            frozenset({"S-1-5-21-99"}),
        )
        policy.handle(
            {"op": "set_level", "level": int(Level.CONFIDENTIAL), "reason": "approved"},
            authorized_user,
        )
        self.assertEqual(self.store.current_level(), int(Level.CONFIDENTIAL))

        self.store.set_current_level(int(Level.SECRET))
        administrator = ClientPrincipal(
            "S-1-5-21-2",
            "MACHINE\\admin",
            frozenset({"S-1-5-32-544"}),
        )
        policy.handle(
            {"op": "set_level", "level": int(Level.UNCLASS), "reason": "admin"},
            administrator,
        )
        self.assertEqual(self.store.current_level(), int(Level.UNCLASS))

    def test_service_policy_does_not_accept_client_claims_of_authorization(self):
        class FakeEnforcer:
            def reconcile(self, level):
                return []

        self.store.set_current_level(int(Level.SECRET))
        policy = ServicePolicy(self.store, FakeEnforcer())
        principal = ClientPrincipal("S-1-5-21-1", "DOMAIN\\user", frozenset())
        with self.assertRaises(ValueError):
            policy.handle(
                {
                    "op": "set_level",
                    "level": int(Level.UNCLASS),
                    "reason": "test",
                    "is_admin": True,
                    "windows_hello_verified": True,
                },
                principal,
            )
        self.assertEqual(self.store.current_level(), int(Level.SECRET))

    def test_service_policy_exposes_and_clears_enforcement_errors(self):
        class FakeEnforcer:
            failing = True

            def reconcile(self, level):
                if self.failing:
                    raise RuntimeError("radio enforcement failed")
                return []

        enforcer = FakeEnforcer()
        policy = ServicePolicy(self.store, enforcer)
        principal = ClientPrincipal("S-1-5-21-1", "DOMAIN\\user", frozenset())
        with self.assertRaisesRegex(RuntimeError, "radio enforcement failed"):
            policy.reconcile()
        status = policy.handle({"op": "status"}, principal)
        self.assertEqual(status["enforcement_error"], "radio enforcement failed")

        enforcer.failing = False
        policy.reconcile()
        status = policy.handle({"op": "status"}, principal)
        self.assertIsNone(status["enforcement_error"])

    def test_service_client_failure_does_not_fall_back_to_local_state(self):
        self.store.set_current_level(int(Level.CONFIDENTIAL))
        command_line = [
            "classification_app",
            "--db",
            str(Path(self.temp.name) / "state.db"),
            "--service-client",
            "set-level",
            "SECRET",
        ]
        with (
            patch.object(sys, "argv", command_line),
            patch.object(ServiceClient, "current_level", return_value=int(Level.CONFIDENTIAL)),
            patch.object(ServiceClient, "set_level", side_effect=RuntimeError("service unavailable")),
            redirect_stdout(io.StringIO()),
            redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(main(), 1)
        self.assertEqual(self.store.current_level(), int(Level.CONFIDENTIAL))

    def test_unknown_defaults_to_confidential(self):
        path = Path(self.temp.name) / "plain.txt"
        path.write_text("ordinary text", encoding="utf-8")
        result = classify_file(path, self.store)
        self.assertEqual(result.level, Level.CONFIDENTIAL)
        self.assertIn("default:unknown-file-fails-closed", result.evidence)

    def test_marking_detected(self):
        path = Path(self.temp.name) / "marked.txt"
        path.write_text("CLASSIFICATION: TOP SECRET", encoding="utf-8")
        self.assertEqual(classify_file(path, self.store).level, Level.TOP_SECRET)

    def test_utf16_marking_detected(self):
        path = Path(self.temp.name) / "marked.txt"
        path.write_bytes("CONFIDENTIAL".encode("utf-16-le"))
        self.assertEqual(classify_file(path, self.store).level, Level.CONFIDENTIAL)

    def test_audit_chain_detects_tampering(self):
        self.store.audit("test", 0, "tester", {"ok": True})
        self.assertEqual(self.store.verify_audit(), (True, 1))
        with self.store.transaction() as db:
            db.execute("UPDATE audit SET event = 'tampered' WHERE seq = 1")
        self.assertEqual(self.store.verify_audit(), (False, 1))

    def test_downgrade_requires_approved_windows_hello(self):
        with patch("classification_app.verification.request_windows_hello_verification", return_value=True):
            self.assertTrue(verify_downgrade(self.store, Level.SECRET, Level.CONFIDENTIAL))
        self.assertEqual(self.store.verify_audit(), (True, 1))

    def test_denied_windows_hello_verification_is_audited(self):
        with patch("classification_app.verification.request_windows_hello_verification", return_value=False):
            self.assertFalse(verify_downgrade(self.store, Level.SECRET, Level.UNCLASS))
        self.assertEqual(self.store.verify_audit(), (True, 1))
        with self.store.transaction() as db:
            row = db.execute("SELECT detail FROM audit").fetchone()
        self.assertIn('"result":"denied"', row["detail"])

    def test_cli_downgrade_stops_when_windows_hello_is_denied(self):
        self.store.set_current_level(int(Level.SECRET))
        command_line = [
            "classification_app",
            "--db",
            str(Path(self.temp.name) / "state.db"),
            "set-level",
            "UNCLASS",
            "--confirm-downgrade",
        ]
        with (
            patch.object(sys, "argv", command_line),
            patch(
                "classification_app.verification.request_windows_hello_verification",
                return_value=False,
            ),
            redirect_stdout(io.StringIO()),
            redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(main(), 1)
        self.assertEqual(self.store.current_level(), int(Level.SECRET))

    def test_windows_hello_result_is_fail_closed(self):
        verified = Mock(returncode=0, stdout="Verified\r\n", stderr="")
        cancelled = Mock(returncode=0, stdout="Canceled\r\n", stderr="")
        with (
            patch("classification_app.verification.sys.platform", "win32"),
            patch(
                "classification_app.verification.subprocess.run",
                side_effect=[verified, cancelled],
            ) as run,
        ):
            from classification_app.verification import request_windows_hello_verification

            self.assertTrue(request_windows_hello_verification())
            self.assertFalse(request_windows_hello_verification())
        self.assertIn("-STA", run.call_args_list[0].args[0])

    def test_enforcer_disables_radios_and_offlines_usb_then_restores(self):
        radios = [
            {"name": "Bluetooth", "kind": "Bluetooth", "state": "On"},
            {"name": "Wi-Fi", "kind": "WiFi", "state": "On"},
        ]
        adapters = ["Wi-Fi"]
        disks = [{"unique_id": "usb-disk-1", "offline": False}]
        policy = {"existed": False}
        calls = []

        def run_command(action, names=None, items=None, state=None, offline=None):
            calls.append((action, names, items, state, offline))
            if action == "radio-list":
                return [
                    {"name": radio["name"], "kind": radio["kind"]}
                    for radio in radios
                    if radio["state"] == "On"
                ]
            if action == "adapter-list":
                return list(adapters)
            if action == "usb-list":
                return [dict(disk) for disk in disks]
            if action == "radio-set":
                for item in items:
                    next(
                        radio for radio in radios
                        if radio["name"] == item["name"] and radio["kind"] == item["kind"]
                    )["state"] = state
            if action == "adapter-set":
                if state == "disabled":
                    adapters.clear()
                else:
                    adapters.extend(name for name in names if name not in adapters)
            if action == "usb-set":
                for item in items:
                    next(disk for disk in disks if disk["unique_id"] == item["unique_id"])[
                        "offline"
                    ] = offline
            return {"ok": True}

        def write_policy(value):
            policy.clear()
            if value is None:
                policy.update({"existed": False})
            else:
                policy.update({"existed": True, "value": value})

        with (
            patch("classification_app.enforcement.sys.platform", "win32"),
            patch("classification_app.enforcement.is_admin", return_value=True),
            patch("classification_app.enforcement._powershell", side_effect=run_command),
            patch("classification_app.enforcement._read_usb_policy", side_effect=lambda: dict(policy)),
            patch("classification_app.enforcement._write_usb_policy", side_effect=write_policy),
        ):
            enforcer = Enforcer(self.store, dry_run=False)
            actions = enforcer.reconcile(Level.SECRET)
            self.assertTrue(any("Disable wireless radios" in action for action in actions))
            self.assertTrue(any("Take USB disks offline" in action for action in actions))
            self.assertEqual([radio["state"] for radio in radios], ["Off", "Off"])
            self.assertEqual(adapters, [])
            self.assertTrue(disks[0]["offline"])
            self.assertEqual(policy, {"existed": True, "value": 1})

            radios.append({"name": "Bluetooth 2", "kind": "Bluetooth", "state": "On"})
            adapters.append("Bluetooth Network Connection")
            disks.append({"unique_id": "usb-disk-2", "offline": False})
            enforcer.reconcile(Level.SECRET)
            self.assertEqual([radio["state"] for radio in radios], ["Off", "Off", "Off"])
            self.assertEqual(adapters, [])
            self.assertTrue(disks[1]["offline"])

            enforcer.reconcile(Level.UNCLASS)
            self.assertEqual([radio["state"] for radio in radios], ["On", "On", "On"])
            self.assertEqual(adapters, ["Wi-Fi", "Bluetooth Network Connection"])
            self.assertFalse(any(disk["offline"] for disk in disks))
            self.assertEqual(policy, {"existed": False})
            self.assertIsNone(self.store.get_state("wireless_snapshot"))
            self.assertIsNone(self.store.get_state("usb_snapshot"))
        self.assertTrue(any(call[0] == "radio-set" for call in calls))
        self.assertTrue(any(call[0] == "usb-set" for call in calls))

    def test_removable_usb_offline_limitation_uses_deny_policy(self):
        policy = {"existed": False}
        disk_id = "removable-usb-stick"

        def run_command(action, **_kwargs):
            if action in ("radio-list", "adapter-list"):
                return []
            if action == "usb-list":
                return [{"unique_id": disk_id, "offline": False}]
            if action == "usb-set":
                return {"ok": True, "unsupported_offline": [disk_id]}
            return {"ok": True}

        def write_policy(value):
            policy.clear()
            policy.update({"existed": value is not None})
            if value is not None:
                policy["value"] = value

        with (
            patch("classification_app.enforcement.sys.platform", "win32"),
            patch("classification_app.enforcement.is_admin", return_value=True),
            patch("classification_app.enforcement._powershell", side_effect=run_command),
            patch(
                "classification_app.enforcement._read_usb_policy",
                side_effect=lambda: dict(policy),
            ),
            patch("classification_app.enforcement._write_usb_policy", side_effect=write_policy),
        ):
            actions = Enforcer(self.store, dry_run=False).reconcile(Level.SECRET)
        self.assertEqual(policy, {"existed": True, "value": 1})
        self.assertTrue(
            any("cannot take removable media offline" in action for action in actions)
        )
        self.assertIsNotNone(self.store.get_state("usb_snapshot"))

    def test_network_parser_and_deny_rule(self):
        sample = (
            "  TCP    192.168.1.10:5000   203.0.113.9:443   ESTABLISHED  1234\r\n"
            "  TCP    [::1]:10   [::1]:20   ESTABLISHED  1234\r\n"
        )
        self.assertEqual({str(item) for item in parse_connections(sample)}, {"203.0.113.9"})
        with self.store.transaction() as db:
            db.execute(
                "INSERT INTO network_rules(cidr, action) VALUES (?, ?)",
                ("203.0.113.0/24", "deny"),
            )
        self.assertEqual(
            inspect_connections(self.store, sample),
            ["Denied network rule matched active TCP peer 203.0.113.9"],
        )

    def test_signed_update_applies_rules_and_rejects_rollback(self):
        key = "k" * 32
        payload = {
            "version": 1,
            "file_hashes": [
                {
                    "sha256": hashlib.sha256(b"example").hexdigest(),
                    "level": "SECRET",
                }
            ],
            "path_rules": [{"pattern": "c:/secret/*", "level": "TOP SECRET"}],
            "network_rules": [{"cidr": "203.0.113.0/24", "action": "deny"}],
        }
        signature = hmac.new(
            key.encode(),
            json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(),
            hashlib.sha256,
        ).hexdigest()
        bundle = Path(self.temp.name) / "bundle.json"
        bundle.write_text(
            json.dumps({"payload": payload, "signature": signature}), encoding="utf-8"
        )
        self.assertEqual(apply_signed_update(str(bundle), self.store, key), 1)
        self.assertEqual(self.store.file_level(hashlib.sha256(b"example").hexdigest()), 2)
        with self.assertRaisesRegex(ValueError, "newer"):
            apply_signed_update(str(bundle), self.store, key)


if __name__ == "__main__":
    unittest.main()
