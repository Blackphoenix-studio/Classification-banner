import json
import os
import re
import stat
import threading
from pathlib import Path
from typing import cast

from .enforcement import Enforcer
from .levels import Level
from .service_client import PIPE_NAME
from .service_policy import ClientPrincipal, ServicePolicy
from .store import Store

SERVICE_NAME = "ClassificationEnforcement"
SERVICE_DISPLAY_NAME = "Classification Enforcement Service"
SERVICE_DESCRIPTION = (
    "Maintains the machine classification and reapplies its Windows restrictions."
)
_CONFIG_KEY = r"SOFTWARE\Policies\ClassificationApp"
_GROUP_VALUE = "AuthorizedDowngradeGroupSid"
_SID_PATTERN = re.compile(r"^S-\d-(?:\d+-){1,14}\d+$", re.IGNORECASE)
_PIPE_BUFFER_SIZE = 8192
_ENFORCEMENT_INTERVAL_SECONDS = 10


def _database_path() -> Path:
    program_data = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
    return Path(program_data) / "ClassificationApp" / "policy.db"


def _set_service_data_acl(path: Path, directory: bool) -> None:
    import win32con
    import win32security

    system_sid = win32security.CreateWellKnownSid(win32security.WinLocalSystemSid, None)
    administrators_sid = win32security.CreateWellKnownSid(
        win32security.WinBuiltinAdministratorsSid,
        None,
    )
    inheritance = (
        win32security.OBJECT_INHERIT_ACE | win32security.CONTAINER_INHERIT_ACE
        if directory
        else 0
    )
    dacl = win32security.ACL()
    for sid in (system_sid, administrators_sid):
        dacl.AddAccessAllowedAceEx(
            win32security.ACL_REVISION_DS,
            inheritance,
            win32con.GENERIC_ALL,
            sid,
        )
    descriptor = win32security.SECURITY_DESCRIPTOR()
    descriptor.Initialize()
    descriptor.SetSecurityDescriptorOwner(system_sid, False)
    descriptor.SetSecurityDescriptorDacl(True, dacl, False)
    descriptor.SetSecurityDescriptorControl(
        win32security.SE_DACL_PROTECTED,
        win32security.SE_DACL_PROTECTED,
    )
    security_information = (
        win32security.OWNER_SECURITY_INFORMATION
        | win32security.DACL_SECURITY_INFORMATION
    )
    win32security.SetFileSecurity(
        str(path),
        security_information,
        descriptor,
    )


def _validate_service_data_path(path: Path, directory: bool) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    if getattr(metadata, "st_file_attributes", 0) & 0x400:
        raise OSError(f"Refusing reparse-point service data path: {path}")
    expected_type = stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
    if not expected_type:
        raise OSError(f"Unexpected service data path type: {path}")
    if not directory and metadata.st_nlink != 1:
        raise OSError(f"Refusing hard-linked service data file: {path}")
    return True


def _require_system_owner(path: Path) -> None:
    import win32security

    descriptor = win32security.GetNamedSecurityInfo(
        str(path),
        win32security.SE_FILE_OBJECT,
        win32security.OWNER_SECURITY_INFORMATION,
    )
    owner = descriptor.GetSecurityDescriptorOwner()
    system_sid = win32security.CreateWellKnownSid(
        win32security.WinLocalSystemSid,
        None,
    )
    if (
        win32security.ConvertSidToStringSid(owner).upper()
        != win32security.ConvertSidToStringSid(system_sid).upper()
    ):
        raise OSError(
            f"Existing service data path is not owned by LocalSystem: {path}"
        )


def _secure_directory(path: Path) -> None:
    existed = _validate_service_data_path(path, directory=True)
    if not existed:
        path.mkdir(parents=True, exist_ok=True)
    if not _validate_service_data_path(path, directory=True):
        raise OSError(f"Service data directory does not exist: {path}")
    _require_system_owner(path)
    _set_service_data_acl(path, directory=True)


def _secure_existing_policy_files(directory: Path) -> None:
    for suffix in ("", "-wal", "-shm", "-journal"):
        path = directory / f"policy.db{suffix}"
        if _validate_service_data_path(path, directory=False):
            _require_system_owner(path)
            _set_service_data_acl(path, directory=False)


def _authorized_group_sid() -> str | None:
    import pywintypes
    import winreg
    import win32security

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _CONFIG_KEY) as key:
            value, value_type = winreg.QueryValueEx(key, _GROUP_VALUE)
    except FileNotFoundError:
        return None
    if value_type != winreg.REG_SZ or not isinstance(value, str):
        raise ValueError(f"Registry policy {_GROUP_VALUE} must be a string SID")
    value = value.strip()
    if not _SID_PATTERN.fullmatch(value):
        raise ValueError(f"Registry policy {_GROUP_VALUE} is not a valid SID")
    try:
        win32security.ConvertStringSidToSid(value)
    except pywintypes.error as error:
        raise ValueError(f"Registry policy {_GROUP_VALUE} is not a valid SID") from error
    return value


def _client_principal(pipe_handle: object) -> ClientPrincipal:
    import win32api
    import win32con
    import win32security

    win32security.ImpersonateNamedPipeClient(pipe_handle)
    token = None
    try:
        token = win32security.OpenThreadToken(
            win32api.GetCurrentThread(),
            win32con.TOKEN_QUERY,
            True,
        )
        user_sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
        user_sid_text = win32security.ConvertSidToStringSid(user_sid)
        try:
            domain, username, _ = win32security.LookupAccountSid(None, user_sid)
            name = f"{domain}\\{username}" if domain else username
        except win32security.error:
            name = user_sid_text
        token_groups = win32security.GetTokenInformation(
            token, win32security.TokenGroups
        )
        if not isinstance(token_groups, (tuple, list)):
            raise RuntimeError("Windows returned an invalid client group list")
        group_sids: set[str] = set()
        for group in token_groups:
            if not isinstance(group, tuple) or len(group) != 2:
                raise RuntimeError("Windows returned an invalid client group entry")
            sid, attributes = group
            if not isinstance(attributes, int):
                raise RuntimeError("Windows returned invalid client group attributes")
            if (
                attributes & win32con.SE_GROUP_ENABLED
                and not attributes & win32security.SE_GROUP_USE_FOR_DENY_ONLY
            ):
                group_sids.add(win32security.ConvertSidToStringSid(sid))
        return ClientPrincipal(user_sid_text, name, frozenset(group_sids))
    finally:
        if token is not None:
            win32api.CloseHandle(token)
        win32security.RevertToSelf()


def _security_attributes():
    import win32security

    descriptor = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)",
        win32security.SDDL_REVISION_1,
    )
    attributes = win32security.SECURITY_ATTRIBUTES()
    attributes.SECURITY_DESCRIPTOR = descriptor
    return attributes, descriptor


def _wake_pipe_listener(pipe_name: str = PIPE_NAME) -> bool:
    import pywintypes
    import win32con
    import win32file
    import win32pipe

    handle = None
    try:
        win32pipe.WaitNamedPipe(pipe_name, 1000)
        handle = win32file.CreateFile(
            pipe_name,
            win32con.GENERIC_READ | win32con.GENERIC_WRITE,
            0,
            None,
            win32con.OPEN_EXISTING,
            0,
            None,
        )
        return True
    except pywintypes.error as error:
        if error.winerror in (2, 121, 231):
            return False
        raise
    finally:
        if handle is not None:
            win32file.CloseHandle(cast(int, handle))


def _read_pipe_message(handle: object) -> bytes:
    import win32file

    error_code, data = win32file.ReadFile(cast(int, handle), _PIPE_BUFFER_SIZE)
    if error_code:
        raise ValueError("Named-pipe request exceeds the protocol size limit")
    if isinstance(data, str):
        return data.encode("utf-8")
    return data


def _write_pipe_message(handle: object, response: dict[str, object]) -> None:
    import win32file

    data = json.dumps(response, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    if len(data) > _PIPE_BUFFER_SIZE:
        data = b'{"ok":false,"error":"Service response exceeds the protocol size limit"}'
    win32file.WriteFile(cast(int, handle), data)


def _serve_pipe(
    policy: ServicePolicy,
    stop_event: threading.Event,
    pipe_name: str = PIPE_NAME,
) -> None:
    import pywintypes
    import win32file
    import win32pipe

    security = _security_attributes()
    attributes = security[0]
    pipe_access = win32pipe.PIPE_ACCESS_DUPLEX
    pipe_mode = (
        win32pipe.PIPE_TYPE_MESSAGE
        | win32pipe.PIPE_READMODE_MESSAGE
        | win32pipe.PIPE_WAIT
        | getattr(win32pipe, "PIPE_REJECT_REMOTE_CLIENTS", 0)
    )
    while not stop_event.is_set():
        pipe = win32pipe.CreateNamedPipe(
            pipe_name,
            pipe_access,
            pipe_mode,
            win32pipe.PIPE_UNLIMITED_INSTANCES,
            _PIPE_BUFFER_SIZE,
            _PIPE_BUFFER_SIZE,
            0,
            attributes,
        )
        try:
            try:
                win32pipe.ConnectNamedPipe(pipe, None)
            except pywintypes.error as error:
                if error.winerror != 535:  # ERROR_PIPE_CONNECTED
                    if stop_event.is_set():
                        break
                    raise
            if stop_event.is_set():
                break
            try:
                payload = json.loads(_read_pipe_message(pipe).decode("utf-8"))
                principal = _client_principal(pipe)
                response = policy.handle(payload, principal)
            except PermissionError as error:
                response = {"ok": False, "denied": True, "error": str(error)}
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
                response = {"ok": False, "error": str(error)}
            except Exception as error:
                import servicemanager

                servicemanager.LogErrorMsg(f"Classification service request failed: {error}")
                response = {"ok": False, "error": "Classification service operation failed"}
            _write_pipe_message(pipe, response)
        finally:
            try:
                win32pipe.DisconnectNamedPipe(pipe)
            except pywintypes.error:
                pass
            win32file.CloseHandle(pipe)


if os.name == "nt":
    import servicemanager
    import win32service
    import win32serviceutil

    class ClassificationEnforcementService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY_NAME
        _svc_description_ = SERVICE_DESCRIPTION

        def __init__(self, args: list[str]):
            super().__init__(args)
            self._stop_event = threading.Event()

        def SvcStop(self) -> None:
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self._stop_event.set()
            try:
                if not _wake_pipe_listener():
                    servicemanager.LogInfoMsg(
                        "Classification service pipe was not listening during stop"
                    )
            except Exception as error:
                servicemanager.LogErrorMsg(
                    f"Could not wake classification service pipe during stop: {error}"
                )

        def SvcDoRun(self) -> None:
            servicemanager.LogInfoMsg("Classification enforcement service starting")
            store = None
            listener = None
            try:
                directory = _database_path().parent
                _secure_directory(directory)
                _secure_existing_policy_files(directory)
                database = directory / "policy.db"
                store = Store(database)
                _secure_existing_policy_files(directory)
                if store.get_state("service_initialized") is None:
                    store.set_current_level(int(Level.CONFIDENTIAL))
                    store.set_state("service_initialized", "1")
                    store.audit(
                        "service_initialized",
                        int(Level.CONFIDENTIAL),
                        "SYSTEM",
                        {"initial_level": "CONFIDENTIAL"},
                    )
                policy = ServicePolicy(
                    store,
                    Enforcer(store, dry_run=False),
                    _authorized_group_sid(),
                )
                listener = threading.Thread(
                    target=_serve_pipe,
                    args=(policy, self._stop_event),
                    name="classification-service-pipe",
                    daemon=True,
                )
                listener.start()
                try:
                    policy.reconcile()
                except Exception as error:
                    servicemanager.LogErrorMsg(
                        f"Initial classification enforcement failed: {error}"
                    )
                self.ReportServiceStatus(win32service.SERVICE_RUNNING)
                while not self._stop_event.wait(_ENFORCEMENT_INTERVAL_SECONDS):
                    try:
                        policy.reconcile()
                    except Exception as error:
                        servicemanager.LogErrorMsg(
                            f"Classification enforcement reconciliation failed: {error}"
                        )
            except Exception as error:
                servicemanager.LogErrorMsg(
                    f"Classification enforcement service failed: {error}"
                )
                raise
            finally:
                if listener is not None and listener.is_alive():
                    listener.join(timeout=2)
                if store is not None and (listener is None or not listener.is_alive()):
                    store.close()
                servicemanager.LogInfoMsg("Classification enforcement service stopped")


def main() -> int:
    if os.name != "nt":
        raise RuntimeError("The Windows classification service can only run on Windows")
    import win32serviceutil

    win32serviceutil.HandleCommandLine(
        ClassificationEnforcementService,
        serviceClassString=(
            "classification_app.windows_service.ClassificationEnforcementService"
        ),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
