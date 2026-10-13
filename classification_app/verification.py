import base64
import os
import subprocess
import sys

from .levels import Level
from .store import Store, current_operator

_POWERSHELL_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try {
    Add-Type -AssemblyName System.Runtime.WindowsRuntime
    $operation = [Windows.Security.Credentials.UI.UserConsentVerifier, Windows.Security.Credentials.UI, ContentType = WindowsRuntime]::RequestVerificationAsync('Confirm your identity to lower the classification level.')
    $method = [System.WindowsRuntimeSystemExtensions].GetMethods() |
        Where-Object {
            $_.Name -eq 'AsTask' -and
            $_.IsGenericMethod -and
            $_.GetParameters().Count -eq 1 -and
            $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'
        } |
        Select-Object -First 1
    if ($null -eq $method) {
        throw 'Windows Hello asynchronous operation adapter is unavailable'
    }
    $resultType = [Windows.Security.Credentials.UI.UserConsentVerificationResult, Windows.Security.Credentials.UI, ContentType = WindowsRuntime]
    $task = $method.MakeGenericMethod($resultType).Invoke($null, @($operation))
    $outcome = $task.GetAwaiter().GetResult()
    [Console]::Out.WriteLine($outcome.ToString())
} catch {
    [Console]::Error.WriteLine($_.Exception.GetBaseException().Message)
    exit 1
}
"""


def request_windows_hello_verification() -> bool:
    if sys.platform != "win32":
        raise RuntimeError("Windows Hello verification is available only on Windows")

    executable = os.path.join(
        os.environ.get("SystemRoot", r"C:\Windows"),
        "System32",
        "WindowsPowerShell",
        "v1.0",
        "powershell.exe",
    )
    encoded = base64.b64encode(_POWERSHELL_SCRIPT.encode("utf-16-le")).decode("ascii")
    try:
        result = subprocess.run(
            [
                executable,
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-STA",
                "-OutputFormat",
                "Text",
                "-EncodedCommand",
                encoded,
            ],
            capture_output=True,
            text=True,
            timeout=120,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError(f"Windows Hello verification could not complete: {error}") from error

    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"Windows Hello verification failed: {detail}")
    outcome = result.stdout.strip()
    if not outcome:
        raise RuntimeError("Windows Hello verification returned no result")
    return outcome == "Verified"


def verify_downgrade(store: Store, current: Level, target: Level) -> bool:
    try:
        approved = request_windows_hello_verification()
    except RuntimeError as error:
        store.audit(
            "downgrade_verification_error",
            int(current),
            current_operator(),
            {"to": int(target), "error": str(error)},
        )
        raise

    store.audit(
        "downgrade_verification",
        int(current),
        current_operator(),
        {"to": int(target), "result": "approved" if approved else "denied"},
    )
    return approved
