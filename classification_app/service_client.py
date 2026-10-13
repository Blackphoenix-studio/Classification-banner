import json
import os
import time
from dataclasses import dataclass
from typing import cast

from .levels import Level

PIPE_NAME = r"\\.\pipe\ClassificationApp.Policy.v1"
_MAX_REQUEST_BYTES = 4096
_MAX_RESPONSE_BYTES = 65536


@dataclass(frozen=True)
class ServiceStatus:
    level: Level
    enforcement_error: str | None


class ServiceClient:
    def __init__(self, pipe_name: str = PIPE_NAME, timeout_ms: int = 3000):
        self.pipe_name = pipe_name
        self.timeout_ms = timeout_ms

    def _request(self, message: dict[str, object]) -> dict[str, object]:
        if os.name != "nt":
            raise RuntimeError("The Windows classification service is only available on Windows")

        try:
            import pywintypes
            import win32con
            import win32file
            import win32pipe
        except ImportError as error:
            raise RuntimeError(
                "Service-client mode requires the optional pywin32 dependency; "
                'install this app with `python -m pip install ".[service]"`'
            ) from error

        payload = json.dumps(message, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        if len(payload) > _MAX_REQUEST_BYTES:
            raise ValueError("Service request exceeds the protocol size limit")

        handle = None
        try:
            deadline = time.monotonic() + self.timeout_ms / 1000
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError("Timed out waiting for the classification service pipe")
                try:
                    win32pipe.WaitNamedPipe(
                        self.pipe_name,
                        max(1, int(remaining * 1000)),
                    )
                    handle = win32file.CreateFile(
                        self.pipe_name,
                        win32con.GENERIC_READ | win32con.GENERIC_WRITE,
                        0,
                        None,
                        win32con.OPEN_EXISTING,
                        0,
                        None,
                    )
                    break
                except pywintypes.error as error:
                    if error.winerror not in (2, 121, 231) or time.monotonic() >= deadline:
                        raise
                    time.sleep(min(0.05, max(0, deadline - time.monotonic())))
            win32pipe.SetNamedPipeHandleState(
                cast(int, handle),
                win32pipe.PIPE_READMODE_MESSAGE,
                None,
                None,
            )
            win32file.WriteFile(cast(int, handle), payload)
            error_code, response_bytes = win32file.ReadFile(
                cast(int, handle), _MAX_RESPONSE_BYTES
            )
            if error_code:
                raise RuntimeError(f"Named pipe returned Windows error {error_code}")
        except pywintypes.error as error:
            raise RuntimeError(
                "Could not communicate with the classification service. "
                "Confirm that the service is installed and running."
            ) from error
        finally:
            if handle is not None:
                win32file.CloseHandle(cast(int, handle))

        try:
            response = json.loads(cast(bytes, response_bytes).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise RuntimeError("Classification service returned an invalid response") from error
        if not isinstance(response, dict):
            raise RuntimeError("Classification service returned an invalid response")
        if response.get("ok") is not True:
            message_text = response.get("error")
            if not isinstance(message_text, str):
                message_text = "Classification service rejected the request"
            if response.get("denied") is True:
                raise PermissionError(message_text)
            raise RuntimeError(message_text)
        return response

    def status(self) -> ServiceStatus:
        response = self._request({"op": "status"})
        level = response.get("level")
        if not isinstance(level, int) or isinstance(level, bool):
            raise RuntimeError("Classification service returned an invalid level")
        try:
            classification = Level(level)
        except ValueError as error:
            raise RuntimeError("Classification service returned an unknown level") from error
        enforcement_error = response.get("enforcement_error")
        if enforcement_error is not None and not isinstance(enforcement_error, str):
            raise RuntimeError("Classification service returned invalid enforcement status")
        return ServiceStatus(classification, enforcement_error)

    def current_level(self) -> int:
        return int(self.status().level)

    def set_level(self, level: Level, reason: str) -> list[str]:
        response = self._request(
            {
                "op": "set_level",
                "level": int(level),
                "reason": reason[:256],
            }
        )
        returned_level = response.get("level")
        if (
            not isinstance(returned_level, int)
            or isinstance(returned_level, bool)
            or returned_level != int(level)
        ):
            raise RuntimeError("Classification service did not confirm the requested level")
        actions = response.get("actions", [])
        if not isinstance(actions, list) or any(not isinstance(item, str) for item in actions):
            raise RuntimeError("Classification service returned invalid enforcement actions")
        return actions
