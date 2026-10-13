import ipaddress
import os
import re
import subprocess
import sys
from collections.abc import Callable

from .store import Store

_LINE = re.compile(r"^\s*TCP\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)\s*$", re.IGNORECASE)


def _remote_ip(endpoint: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if endpoint.startswith("[") and "]:" in endpoint:
        end = endpoint.rfind("]:")
        host = endpoint[1:end]
        port = endpoint[end + 2 :]
    elif ":" in endpoint:
        host, port = endpoint.rsplit(":", 1)
    else:
        return None
    if not port.isdigit() or int(port) == 0:
        return None
    host = host.split("%", 1)[0]
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return None
    if address.is_unspecified or address.is_loopback:
        return None
    return address


def parse_connections(output: str) -> set[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    addresses = set()
    for line in output.splitlines():
        match = _LINE.match(line)
        if match:
            address = _remote_ip(match.group(2))
            if address is not None:
                addresses.add(address)
    return addresses


def inspect_connections(store: Store, output: str) -> list[str]:
    rules = [(ipaddress.ip_network(cidr), action) for cidr, action in store.network_rules()]
    allow_rules = [network for network, action in rules if action == "allow"]
    deny_rules = [network for network, action in rules if action == "deny"]
    alerts = []
    for address in sorted(parse_connections(output), key=str):
        if any(address in network for network in deny_rules):
            alerts.append(f"Denied network rule matched active TCP peer {address}")
        elif allow_rules and not any(address in network for network in allow_rules):
            alerts.append(f"Active TCP peer {address} is outside the allow list")
    return alerts


class NetworkMonitor:
    def __init__(self, store: Store, notify: Callable[[str], None]):
        self.store = store
        self.notify = notify
        self._reported: set[str] = set()

    def poll(self) -> None:
        if sys.platform != "win32":
            return
        system_root = os.environ.get("SystemRoot", r"C:\Windows")
        command = [
            system_root + r"\System32\netstat.exe",
            "-ano",
            "-p",
            "TCP",
        ]
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=10, check=False
        )
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or "netstat failed")
        for alert in inspect_connections(self.store, result.stdout):
            if alert not in self._reported:
                self._reported.add(alert)
                self.store.audit("network_alert", self.store.current_level(), "system", {"alert": alert})
                self.notify(alert)
