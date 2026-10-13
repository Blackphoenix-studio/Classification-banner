import re
import threading
from dataclasses import dataclass

from .enforcement import Enforcer
from .levels import LABELS, Level
from .store import Store

_SID_PATTERN = re.compile(r"^S-\d-(?:\d+-){1,14}\d+$", re.IGNORECASE)


@dataclass(frozen=True)
class ClientPrincipal:
    sid: str
    name: str
    group_sids: frozenset[str]


class ServicePolicy:
    def __init__(
        self,
        store: Store,
        enforcer: Enforcer,
        authorized_downgrade_sid: str | None = None,
    ):
        self.store = store
        self.enforcer = enforcer
        self.authorized_downgrade_sid = authorized_downgrade_sid
        self._lock = threading.RLock()
        self._last_enforcement_error: str | None = None

    def current_level(self) -> Level:
        return Level(self.store.current_level())

    def handle(self, request: object, principal: ClientPrincipal) -> dict[str, object]:
        if not isinstance(request, dict) or not isinstance(request.get("op"), str):
            raise ValueError("Invalid service request")
        operation = request["op"]
        if operation == "status":
            if set(request) != {"op"}:
                raise ValueError("Invalid status request")
            with self._lock:
                return {
                    "ok": True,
                    "level": int(self.current_level()),
                    "enforcement_error": self._last_enforcement_error,
                }
        if operation != "set_level" or set(request) != {"op", "level", "reason"}:
            raise ValueError("Unsupported service request")
        raw_level = request["level"]
        if not isinstance(raw_level, int) or isinstance(raw_level, bool):
            raise ValueError("Classification level must be an integer")
        try:
            target = Level(raw_level)
        except ValueError as error:
            raise ValueError("Unknown classification level") from error
        reason = request["reason"]
        if not isinstance(reason, str) or len(reason) > 256:
            raise ValueError("Invalid classification change reason")
        if any(ord(character) < 32 for character in reason):
            raise ValueError("Classification change reason contains control characters")

        with self._lock:
            previous = self.current_level()
            if target < previous and not self._may_downgrade(principal):
                self.store.audit(
                    "classification_change_denied",
                    int(previous),
                    principal.name,
                    {"from": int(previous), "to": int(target), "reason": reason},
                )
                raise PermissionError(
                    "Only the configured Active Directory downgrade group or an "
                    "elevated local Administrator may lower the classification"
                )
            if target != previous:
                self.store.set_current_level(int(target))
                self.store.audit(
                    "classification_change",
                    int(target),
                    principal.name,
                    {
                        "from": int(previous),
                        "to": int(target),
                        "reason": reason,
                        "operator_sid": principal.sid,
                    },
                )
                actions = self._reconcile(target)
            else:
                actions = []
            return {
                "ok": True,
                "level": int(target),
                "label": LABELS[target],
                "actions": actions,
            }

    def reconcile(self) -> list[str]:
        with self._lock:
            return self._reconcile(self.current_level())

    def _reconcile(self, level: Level) -> list[str]:
        try:
            actions = self.enforcer.reconcile(level)
        except Exception as error:
            self._last_enforcement_error = str(error)
            raise
        self._last_enforcement_error = None
        return actions

    def _may_downgrade(self, principal: ClientPrincipal) -> bool:
        if "S-1-5-32-544" in principal.group_sids:
            return True
        allowed_sid = self.authorized_downgrade_sid
        return bool(
            allowed_sid
            and _SID_PATTERN.fullmatch(allowed_sid)
            and allowed_sid.upper() in {sid.upper() for sid in principal.group_sids}
        )
