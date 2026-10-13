# Classification-banner
Pyhton app for display current pc classification including Unclass, Confidential, Secret &amp; Top Secret



Classification software

Concept operation:
- This app can classifies files into four types: Unclass, Confidential, Secret and Top Secret during opening by user.
- The logic: if sofware detect Unclass files, all networking capabilities are allowed, but keep monitoring the unwanted traffic from un-authorized source. Update by database from DoD or else that have right info.
- If sofware detects Confidential or higher level, it will automatically all wireless traffic including Bluetooth, Wi-fi and other RF sources.
- If the Classification are Secret & Top secret, it will block the file transfer including move, copy or any else in the USB storage.

Simply like the Cybersecurity Agent App to frevent unwanted access to get files specially for Secret & Top Secret data.

Display: 
- the app shows as header banner with the classification, size 1/6 screen width and 10px font (bold), always on top.
- Unclass : Green Background
- Confidential : Blue Background
- Secret : Red Background
- Top Secret : Orange Background

- Right Click function : change the classification level (Drop Down list)
- The banner starts centered on screen and re-centers whenever the classification
  changes.
- Double Left Click function : re center the banner

Python implementation
----------------------

The lightweight Python implementation is in `classification_app` and uses only the
standard library. Python 3.10 or newer is recommended.

Run from this folder:

    python -m classification_app

The default is **dry-run**: the banner works, files can be classified, and proposed
policy actions are shown, but Windows settings are not changed. Right-click the banner
to classify a file or change the active level. Unknown files default to CONFIDENTIAL.
The classifier checks SHA-256 and installed path rules and scans a bounded portion of
files for explicit classification markings. This is a heuristic, not a reliable
replacement for human classification or content-aware data-loss-prevention software.

To enable Windows policy changes, open an elevated terminal and run:

    python -m classification_app --enforce

`--enforce` enforces the currently saved classification; it does not raise the level.
The initial level is UNCLASS. To test SECRET enforcement directly from an elevated
terminal, run:

    python -m classification_app --enforce set-level SECRET

At CONFIDENTIAL and above, the app uses the Windows Radio API to turn off radios that
are on, including Bluetooth and Wi-Fi, and disables active wireless network adapters.
At SECRET and above, it applies the Windows Removable Storage `Deny_All` policy and
attempts to take non-system USB disks offline where Windows supports it. The app polls
periodically to handle radios and USB disks connected after the level is raised.
Original radio, adapter, disk, and registry
states are saved and restored when the level is lowered. Lowering requires
Windows Hello verification. Enforcement failures are reported in the UI. These controls
are best-effort: Windows may deny radio changes by policy or hardware, some portable
flash drives do not support the Windows offline-disk operation (for those devices the
Removable Storage `Deny_All` policy is used), some portable devices do not appear as
USB disks, and this prototype does not intercept every file open operation. Keep the
app running while enforcement is required; it is not a Windows service and can be
terminated externally.

### Active Directory-managed service mode

For a domain-managed Windows computer, the optional service mode keeps policy state
and Windows enforcement outside the user's desktop process. The base app still uses
only Python's standard library; the service extra adds `pywin32`.

From an elevated terminal in this folder, install the package and register the service:

    py -3 -m pip install -r requirements.txt
    py -3 -m classification_app.windows_service install --startup auto
    py -3 -m classification_app.windows_service start

The service runs as LocalSystem, stores its machine policy and audit chain under
`%ProgramData%\ClassificationApp`, and secures that directory for SYSTEM and local
Administrators. On first start it initializes the machine classification to
CONFIDENTIAL and begins enforcing it. Lowering that level requires a caller whose
Windows access token has enabled membership in elevated local Administrators or the
configured authorized group. The service independently checks token membership; it
does not trust a client-supplied Windows Hello or authorization result.
Let the service create its data directory on first start; a pre-existing directory
not owned by LocalSystem causes startup to fail closed and must be remediated by IT.

Set the authorized Active Directory group's SID with a computer GPO registry setting:

    Hive: HKEY_LOCAL_MACHINE
    Key:  SOFTWARE\Policies\ClassificationApp
    Name: AuthorizedDowngradeGroupSid
    Type: REG_SZ
    Data: <SID of the approved downgrade group>

For example, an administrator can retrieve the group SID with
`Get-ADGroup -Identity "Classification Downgrade Operators" | Select-Object -ExpandProperty SID`.
If the value is absent, only local Administrators can lower the level. An invalid
value prevents the service from starting rather than granting downgrade access.
Restart the service after changing the configured SID; users must obtain a new
Windows logon token after their group membership changes.

Deploy the application and its service dependency to a fixed, machine-managed Python
installation using the organization's software deployment process or a computer
startup script. Use Group Policy's **Computer Configuration > Policies > Windows
Settings > Security Settings > System Services** to keep the service Automatic and
prevent standard users from stopping or reconfiguring it. Deploy the authorized-group
registry setting with a computer policy. Desktop users must launch the banner in
service-client mode:

    py -3 -m classification_app --service-client
    py -3 -m classification_app --service-client status
    py -3 -m classification_app --service-client set-level SECRET

The CLI still requires `--confirm-downgrade` and Windows Hello for a downgrade, but
the service's group/administrator check is the authorization boundary. If the service
is missing or unavailable, service-client mode reports an error; it never silently
falls back to the less-protected per-user desktop state. The original `--enforce`
mode remains available for local testing and is not a substitute for service mode.
Service-client `status` reports the latest enforcement error, and the banner displays
a warning until a later successful service reconciliation clears it.

The service rechecks enforcement every 10 seconds and at startup. Group Policy can
additionally restrict who may change device and network settings, but available
controls vary by Windows edition, hardware, and domain baseline. Reapplication is
not instantaneous, does not guarantee zero RF emissions, and cannot constrain local
Administrators or firmware/hardware radio switches. Validate the final policy on the
organization's supported Windows builds; strict RF isolation requires approved
hardware/firmware controls. Service installation, domain GPO changes, and real radio
or USB enforcement are intentionally not performed by the app's unit tests.

The network monitor checks active TCP peers every 15 seconds against imported allow/deny
CIDR rules and alerts on matches (or peers outside a non-empty allow list). It only
monitors and alerts; it does not install firewall blocks. No authority or network-rule
list is included by default.

Useful commands:

    python -m classification_app classify "C:\path\to\file.txt"
    python -m classification_app set-level SECRET
    python -m classification_app --enforce set-level SECRET
    python -m classification_app verify-audit
    python -m classification_app update rules.json

Classification downgrades require explicit confirmation followed by Windows Hello
identity verification in both the banner and `set-level` command. Windows Hello may
allow the user's configured PIN as a fallback, so this is not a biometric-only check.
Approved, denied, and failed verification attempts are added to the audit log.
`set-level` also requires `--confirm-downgrade`. Rule bundles use an HMAC-SHA256
signature and must be created by a trusted rules authority; set the
shared signing key in `CLS_UPDATE_KEY` before applying an update. No authority URL or
signing key is bundled, and HMAC uses a shared secret rather than a public-key
signature. Never put the signing key in the rules file or source code.

The local SQLite audit log is hash-chained to detect edits within the log, but it is
not externally anchored and cannot detect deletion of trailing entries. Protect the
database and its host with Windows account permissions and operational controls. This
prototype is not a certified security boundary and should not be used to handle
classified information without a security review and deployment in an approved
environment.

Run tests with:

    python -m unittest discover -s tests -v

