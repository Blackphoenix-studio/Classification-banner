import base64
import ctypes
import json
import os
import sqlite3
import subprocess
import sys
import winreg

from .levels import Level
from .store import Store

_POLICY_PATH = r"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices"
_POLICY_VALUE = "Deny_All"
_PS_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$payload = ConvertFrom-Json -InputObject $env:CLS_PAYLOAD
Add-Type -AssemblyName System.Runtime.WindowsRuntime

function Wait-WinRtOperation($operation, [type]$resultType) {
    $method = [System.WindowsRuntimeSystemExtensions].GetMethods() |
        Where-Object {
            $_.Name -eq 'AsTask' -and
            $_.IsGenericMethod -and
            $_.GetParameters().Count -eq 1 -and
            $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'
        } |
        Select-Object -First 1
    if ($null -eq $method) {
        throw 'Windows radio asynchronous operation adapter is unavailable'
    }
    $task = $method.MakeGenericMethod($resultType).Invoke($null, @($operation))
    return $task.GetAwaiter().GetResult()
}

function Get-Radios {
    $radioType = [Windows.Devices.Radios.Radio, Windows.System.Devices, ContentType = WindowsRuntime]
    $method = $radioType.GetMethods() | Where-Object Name -eq 'GetRadiosAsync' | Select-Object -First 1
    $operation = [Windows.Devices.Radios.Radio]::GetRadiosAsync()
    $resultType = $method.ReturnType.GenericTypeArguments[0]
    return Wait-WinRtOperation $operation $resultType
}

try {
    if ($payload.action -eq 'adapter-list') {
        $items = @(Get-NetAdapter | Where-Object {
            $_.Status -eq 'Up' -and
            $_.PhysicalMediaType -match '(?i)802\.11|wireless|bluetooth|wwan|mobile broadband'
        } | ForEach-Object { $_.Name })
        ConvertTo-Json -InputObject @($items) -Compress
    } elseif ($payload.action -eq 'adapter-set') {
        foreach ($name in $payload.names) {
            if ($payload.state -eq 'disabled') {
                Get-NetAdapter -Name $name -ErrorAction SilentlyContinue |
                    Where-Object Status -eq 'Up' |
                    Disable-NetAdapter -Confirm:$false -ErrorAction Stop | Out-Null
            } else {
                Get-NetAdapter -Name $name -ErrorAction SilentlyContinue |
                    Where-Object Status -ne 'Up' |
                    Enable-NetAdapter -Confirm:$false -ErrorAction Stop | Out-Null
            }
        }
        ConvertTo-Json -InputObject @{ok=$true} -Compress
    } elseif ($payload.action -eq 'radio-list') {
        $items = @(Get-Radios | Where-Object { $_.State.ToString() -eq 'On' } |
            ForEach-Object {
                [PSCustomObject]@{ name=[string]$_.Name; kind=$_.Kind.ToString() }
            })
        ConvertTo-Json -InputObject $items -Compress
    } elseif ($payload.action -eq 'radio-set') {
        $radioType = [Windows.Devices.Radios.Radio, Windows.System.Devices, ContentType = WindowsRuntime]
        $stateType = [Windows.Devices.Radios.RadioState, Windows.System.Devices, ContentType = WindowsRuntime]
        $method = $radioType.GetMethods() | Where-Object Name -eq 'SetStateAsync' | Select-Object -First 1
        $resultType = $method.ReturnType.GenericTypeArguments[0]
        $targetState = [Enum]::Parse($stateType, [string]$payload.state)
        foreach ($item in $payload.items) {
            $radio = Get-Radios | Where-Object {
                $_.Name -eq [string]$item.name -and $_.Kind.ToString() -eq [string]$item.kind
            } | Select-Object -First 1
            if ($null -eq $radio -or $radio.State.ToString() -eq $targetState.ToString()) {
                continue
            }
            $operation = $radio.SetStateAsync($targetState)
            $status = Wait-WinRtOperation $operation $resultType
            if ($status.ToString() -ne 'Allowed') {
                throw "Could not set radio '$($radio.Name)' to $targetState`: $status"
            }
        }
        ConvertTo-Json -InputObject @{ok=$true} -Compress
    } elseif ($payload.action -eq 'usb-list') {
        $items = @(Get-Disk | Where-Object {
            $_.BusType -eq 'USB' -and -not $_.IsBoot -and -not $_.IsSystem
        } | ForEach-Object {
            [PSCustomObject]@{ unique_id=[string]$_.UniqueId; offline=[bool]$_.IsOffline }
        })
        ConvertTo-Json -InputObject $items -Compress
    } elseif ($payload.action -eq 'usb-set') {
        $offline = [bool]$payload.offline
        $unsupported = @()
        foreach ($item in $payload.items) {
            $uniqueId = [string]$item.unique_id
            $disk = Get-Disk -UniqueId $uniqueId -ErrorAction SilentlyContinue |
                Select-Object -First 1
            if ($null -ne $disk -and [bool]$disk.IsOffline -ne $offline) {
                try {
                    Set-Disk -UniqueId $uniqueId -IsOffline $offline -ErrorAction Stop | Out-Null
                } catch {
                    $failure = @($_.Exception.Message, $_.ErrorDetails.Message, $_.ToString()) -join ' '
                    if ($offline -and $failure -match '(?i)removable media cannot be set to offline') {
                        $unsupported += $uniqueId
                    } else {
                        throw
                    }
                }
            }
        }
        ConvertTo-Json -InputObject @{ok=$true; unsupported_offline=@($unsupported)} -Compress
    } else {
        throw 'Unsupported action'
    }
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
"""


def is_admin() -> bool:
    if sys.platform != "win32":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except OSError:
        return False


def _powershell(
    action: str,
    names: list[str] | None = None,
    items: list[dict[str, object]] | None = None,
    state: str | None = None,
    offline: bool | None = None,
) -> object:
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    executable = os.path.join(
        system_root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"
    )
    payload = {"action": action, "names": names or [], "items": items or []}
    if state is not None:
        payload["state"] = state
    if offline is not None:
        payload["offline"] = offline
    environment = os.environ.copy()
    environment["CLS_PAYLOAD"] = json.dumps(payload)
    encoded = base64.b64encode(_PS_SCRIPT.encode("utf-16-le")).decode("ascii")
    try:
        completed = subprocess.run(
            [executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
            capture_output=True,
            text=True,
            timeout=30,
            env=environment,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError(f"Windows enforcement command failed: {error}") from error
    if completed.returncode:
        message = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(f"Windows adapter operation failed: {message}")
    output = completed.stdout.strip()
    if not output:
        raise RuntimeError("Windows adapter operation returned no result")
    try:
        return json.loads(output)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"Invalid result from Windows adapter operation: {output}") from error


def _read_usb_policy() -> dict[str, object]:
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            _POLICY_PATH,
            0,
            winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0),
        ) as key:
            value, value_type = winreg.QueryValueEx(key, _POLICY_VALUE)
        if value_type != winreg.REG_DWORD:
            raise RuntimeError(f"Unexpected registry type for {_POLICY_VALUE}")
        return {"existed": True, "value": int(value)}
    except FileNotFoundError:
        return {"existed": False}


def _write_usb_policy(value: int | None) -> None:
    access = winreg.KEY_SET_VALUE | getattr(winreg, "KEY_WOW64_64KEY", 0)
    if value is None:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _POLICY_PATH, 0, access) as key:
                winreg.DeleteValue(key, _POLICY_VALUE)
        except FileNotFoundError:
            return
    else:
        with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, _POLICY_PATH, 0, access) as key:
            winreg.SetValueEx(key, _POLICY_VALUE, 0, winreg.REG_DWORD, value)


class Enforcer:
    def __init__(self, store: Store, dry_run: bool):
        self.store = store
        self.dry_run = dry_run

    @staticmethod
    def _wireless_snapshot(raw: str | None) -> tuple[dict[str, object], bool]:
        if raw is None:
            return {"radios": [], "adapters": []}, False
        value = json.loads(raw)
        if isinstance(value, list) and all(isinstance(name, str) for name in value):
            return {"radios": [], "adapters": value}, True
        if not isinstance(value, dict):
            raise ValueError("Invalid saved wireless enforcement state")
        radios = value.get("radios")
        adapters = value.get("adapters")
        if not isinstance(radios, list) or not isinstance(adapters, list):
            raise ValueError("Invalid saved wireless enforcement state")
        if not all(
            isinstance(item, dict)
            and isinstance(item.get("name"), str)
            and isinstance(item.get("kind"), str)
            for item in radios
        ):
            raise ValueError("Invalid radio entry in saved enforcement state")
        if not all(isinstance(name, str) for name in adapters):
            raise ValueError("Invalid adapter entry in saved enforcement state")
        return {"radios": radios, "adapters": adapters}, False

    @staticmethod
    def _usb_snapshot(raw: str | None) -> tuple[dict[str, object] | None, bool]:
        if raw is None:
            return None, False
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("Invalid saved USB enforcement state")
        if "policy" not in value:
            if not isinstance(value.get("existed"), bool):
                raise ValueError("Invalid saved removable-storage policy")
            return {"policy": value, "unique_ids": []}, True
        policy = value.get("policy")
        unique_ids = value.get("unique_ids")
        if not isinstance(policy, dict) or not isinstance(policy.get("existed"), bool):
            raise ValueError("Invalid saved removable-storage policy")
        if policy["existed"] and not isinstance(policy.get("value"), int):
            raise ValueError("Invalid saved removable-storage policy value")
        if not isinstance(unique_ids, list) or not all(
            isinstance(unique_id, str) and unique_id for unique_id in unique_ids
        ):
            raise ValueError("Invalid saved USB disk identifiers")
        return {"policy": policy, "unique_ids": unique_ids}, False

    @staticmethod
    def _validate_radios(value: object) -> list[dict[str, str]]:
        if not isinstance(value, list) or not all(
            isinstance(item, dict)
            and isinstance(item.get("name"), str)
            and isinstance(item.get("kind"), str)
            for item in value
        ):
            raise RuntimeError("Invalid Windows radio list")
        return value

    @staticmethod
    def _validate_adapters(value: object) -> list[str]:
        if not isinstance(value, list) or not all(isinstance(name, str) for name in value):
            raise RuntimeError("Invalid Windows wireless adapter list")
        return value

    @staticmethod
    def _validate_usb_disks(value: object) -> list[dict[str, object]]:
        if not isinstance(value, list) or not all(
            isinstance(item, dict)
            and isinstance(item.get("unique_id"), str)
            and bool(item.get("unique_id"))
            and isinstance(item.get("offline"), bool)
            for item in value
        ):
            raise RuntimeError("Invalid USB disk list or missing unique disk identifier")
        return value

    def _reconcile_wireless(self, level: Level) -> tuple[list[str], list[str]]:
        actions: list[str] = []
        errors: list[str] = []
        raw = self.store.get_state("wireless_snapshot")
        snapshot, migrated = self._wireless_snapshot(raw)
        if level >= Level.CONFIDENTIAL:
            try:
                radios = self._validate_radios(_powershell("radio-list"))
            except (OSError, RuntimeError, ValueError) as error:
                radios = []
                errors.append(f"Wireless radio discovery failed: {error}")
            try:
                adapters = self._validate_adapters(_powershell("adapter-list"))
            except (OSError, RuntimeError, ValueError) as error:
                adapters = []
                errors.append(f"Wireless adapter discovery failed: {error}")

            known_radios = {
                (item["name"].casefold(), item["kind"].casefold())
                for item in snapshot["radios"]
            }
            snapshot_changed = raw is None or migrated
            for radio in radios:
                key = (radio["name"].casefold(), radio["kind"].casefold())
                if key not in known_radios:
                    snapshot["radios"].append(radio)
                    known_radios.add(key)
                    snapshot_changed = True
            known_adapters = {name.casefold() for name in snapshot["adapters"]}
            for name in adapters:
                if name.casefold() not in known_adapters:
                    snapshot["adapters"].append(name)
                    known_adapters.add(name.casefold())
                    snapshot_changed = True

            if not self.dry_run and snapshot_changed:
                self.store.set_state(
                    "wireless_snapshot",
                    json.dumps(snapshot, sort_keys=True, separators=(",", ":")),
                )
            if radios:
                names = ", ".join(item["name"] for item in radios)
                actions.append(f"Disable wireless radios: {names}")
                if not self.dry_run:
                    try:
                        _powershell("radio-set", items=radios, state="Off")
                    except (OSError, RuntimeError, ValueError) as error:
                        errors.append(f"Disabling wireless radios failed: {error}")
            if adapters and snapshot["adapters"]:
                actions.append(f"Disable wireless network adapters: {', '.join(adapters)}")
            if snapshot["adapters"] and not self.dry_run:
                try:
                    _powershell(
                        "adapter-set",
                        names=snapshot["adapters"],
                        state="disabled",
                    )
                except (OSError, RuntimeError, ValueError) as error:
                    errors.append(f"Disabling wireless network adapters failed: {error}")
        elif raw is not None:
            if snapshot["radios"]:
                actions.append("Restore wireless radios")
            if snapshot["adapters"]:
                actions.append("Restore wireless network adapters")
            if not self.dry_run:
                if snapshot["radios"]:
                    try:
                        _powershell("radio-set", items=snapshot["radios"], state="On")
                    except (OSError, RuntimeError, ValueError) as error:
                        errors.append(f"Restoring wireless radios failed: {error}")
                if snapshot["adapters"]:
                    try:
                        _powershell(
                            "adapter-set",
                            names=snapshot["adapters"],
                            state="enabled",
                        )
                    except (OSError, RuntimeError, ValueError) as error:
                        errors.append(f"Restoring wireless network adapters failed: {error}")
                if not errors:
                    self.store.set_state("wireless_snapshot", None)
        return actions, errors

    def _reconcile_usb(self, level: Level) -> tuple[list[str], list[str]]:
        actions: list[str] = []
        errors: list[str] = []
        raw = self.store.get_state("usb_snapshot")
        snapshot, migrated = self._usb_snapshot(raw)
        if level >= Level.SECRET:
            if snapshot is None:
                snapshot = {"policy": _read_usb_policy(), "unique_ids": []}
            if not self.dry_run and (raw is None or migrated):
                self.store.set_state(
                    "usb_snapshot",
                    json.dumps(snapshot, sort_keys=True, separators=(",", ":")),
                )

            try:
                current_policy = _read_usb_policy()
                if not current_policy.get("existed") or current_policy.get("value") != 1:
                    actions.append("Set removable-storage deny policy")
                    if not self.dry_run:
                        _write_usb_policy(1)
            except (OSError, RuntimeError) as error:
                errors.append(f"Applying removable-storage policy failed: {error}")

            try:
                disks = self._validate_usb_disks(_powershell("usb-list"))
            except (OSError, RuntimeError, ValueError) as error:
                disks = []
                errors.append(f"USB disk discovery failed: {error}")
            online = [disk for disk in disks if not disk["offline"]]
            tracked = set(snapshot["unique_ids"])
            additions = [
                disk["unique_id"] for disk in online if disk["unique_id"] not in tracked
            ]
            can_offline = True
            if additions:
                snapshot["unique_ids"].extend(additions)
                if not self.dry_run:
                    try:
                        self.store.set_state(
                            "usb_snapshot",
                            json.dumps(snapshot, sort_keys=True, separators=(",", ":")),
                        )
                    except sqlite3.Error as error:
                        errors.append(f"Saving USB disk restore state failed: {error}")
                        can_offline = False
            if online:
                names = ", ".join(disk["unique_id"] for disk in online)
                if self.dry_run:
                    actions.append(f"Take USB disks offline where supported: {names}")
                elif can_offline:
                    try:
                        result = _powershell(
                            "usb-set",
                            items=[{"unique_id": disk["unique_id"]} for disk in online],
                            offline=True,
                        )
                        if not isinstance(result, dict) or result.get("ok") is not True:
                            raise RuntimeError("USB disk command returned an invalid result")
                        unsupported = result.get("unsupported_offline", [])
                        if not isinstance(unsupported, list) or not all(
                            isinstance(unique_id, str) for unique_id in unsupported
                        ):
                            raise RuntimeError("USB disk command returned invalid device details")
                        unsupported_ids = set(unsupported)
                        changed = [
                            disk["unique_id"]
                            for disk in online
                            if disk["unique_id"] not in unsupported_ids
                        ]
                        if changed:
                            actions.append(f"Take USB disks offline: {', '.join(changed)}")
                        if unsupported:
                            actions.append(
                                "Windows cannot take removable media offline; the "
                                "Removable Storage Deny_All policy is used to block access: "
                                + ", ".join(unsupported)
                            )
                    except (OSError, RuntimeError, ValueError) as error:
                        errors.append(f"Taking USB disks offline failed: {error}")
        elif snapshot is not None:
            actions.append("Restore prior removable-storage policy")
            if snapshot["unique_ids"]:
                actions.append("Restore previously online USB disks")
            if not self.dry_run:
                restoration_failed = False
                policy = snapshot["policy"]
                try:
                    _write_usb_policy(
                        int(policy["value"]) if policy.get("existed") else None
                    )
                except OSError as error:
                    restoration_failed = True
                    errors.append(f"Restoring removable-storage policy failed: {error}")
                if snapshot["unique_ids"]:
                    try:
                        _powershell(
                            "usb-set",
                            items=[
                                {"unique_id": unique_id}
                                for unique_id in snapshot["unique_ids"]
                            ],
                            offline=False,
                        )
                    except (OSError, RuntimeError, ValueError) as error:
                        restoration_failed = True
                        errors.append(f"Restoring USB disks failed: {error}")
                if not restoration_failed:
                    self.store.set_state("usb_snapshot", None)
        return actions, errors

    def reconcile(self, level: Level) -> list[str]:
        if sys.platform != "win32":
            if self.dry_run:
                return ["WOULD apply Windows wireless and removable-storage policy"]
            raise RuntimeError("Active enforcement is supported only on Windows")
        if not self.dry_run and not is_admin():
            raise PermissionError("Run with Administrator privileges to enforce system policy")

        actions: list[str] = []
        errors: list[str] = []
        for reconcile_domain in (self._reconcile_wireless, self._reconcile_usb):
            try:
                domain_actions, domain_errors = reconcile_domain(level)
                actions.extend(domain_actions)
                errors.extend(domain_errors)
            except (OSError, RuntimeError, ValueError, sqlite3.Error) as error:
                errors.append(str(error))
        if errors:
            raise RuntimeError("; ".join(errors))
        return actions
