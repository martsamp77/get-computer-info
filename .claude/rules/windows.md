---
description: Windows script (server-audit.ps1) playbook — how to port the audit to PowerShell without leaking secrets.
paths:
  - "**/server-audit.ps1"
---

# Windows playbook — `server-audit.ps1`

PowerShell port of `server-audit.sh`. **First read** `.claude/rules/security.md`
and `.claude/rules/report-structure.md`, and skim the Linux reference for the
report shape. Keep the **same section order**, **Markdown output**, and the
**three security layers** — reimplemented in PowerShell.

## Runtime & conventions

- Target **PowerShell 5.1 (built-in) and 7+ (pwsh)**; prefer cmdlets available in
  both. `#requires -Version 5.1`.
- Use `Set-StrictMode -Version Latest` and `$ErrorActionPreference = 'Continue'`
  so a failing probe doesn't abort the run (the equivalent of "no `-e`"). Guard
  each tool with `Get-Command <name> -ErrorAction SilentlyContinue`.
- Prefer **CIM** (`Get-CimInstance`) over deprecated WMI (`Get-WmiObject`).
- Some probes need elevation — detect with
  `([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrators')`
  and warn (don't require) when not elevated.

## Helpers to build (mirror the Bash ones)

Markdown emitters `H1/H2/H3`, `KV`, `Note`, and a `Block` that wraps text in a
fenced block **after redaction**; `Safe-Cat`, `Safe-Ls`, `Exists-Note`,
`Is-SensitivePath`, `Redact` (the Layer-2 regex filter, ported), and
`Detect-Service` (port+process+version only). Output `[hostname]_context_[timestamp].md`.

## Native tooling per section

- **System/OS:** `Get-ComputerInfo`, `Get-CimInstance Win32_OperatingSystem`,
  `[Environment]::OSVersion`, `Get-TimeZone`.
- **Hardware:** `Win32_Processor` (**mask ProcessorId**), `Win32_PhysicalMemory`,
  `Win32_BIOS` (**mask SerialNumber**), `Win32_ComputerSystem`,
  `Win32_BaseBoard` (mask serial).
- **GPU:** `Get-CimInstance Win32_VideoController`; `nvidia-smi` if present.
- **Storage:** `Get-Disk`, `Get-Volume`, `Get-Partition`, `Get-PSDrive -PSProvider FileSystem`.
- **Network:** `Get-NetIPConfiguration`, `Get-NetAdapter`, `Get-NetIPAddress`,
  `Get-DnsClientServerAddress`, listening ports via
  `Get-NetTCPConnection -State Listen` joined to `Get-Process`,
  `Get-NetFirewallProfile`/`Get-NetFirewallRule`, hosts file
  `C:\Windows\System32\drivers\etc\hosts`.
- **Users/Groups:** `Get-LocalUser`, `Get-LocalGroup`,
  `Get-LocalGroupMember Administrators`, `Get-CimInstance Win32_UserAccount`,
  `query user`. **Never** read SAM/SECURITY registry hives.
- **Services/Scheduled:** `Get-Service`, `Get-CimInstance Win32_Service` (StartMode/StartName),
  `Get-ScheduledTask` / `schtasks`.
- **Processes:** `Get-Process | Sort-Object WorkingSet -Desc`; by CPU likewise.
- **Packages:** `winget list`, `choco list --local-only`, `Get-Package`,
  `Get-AppxPackage | Select Name,Version`, installed programs from the Uninstall
  registry keys (read display names/versions — **not** secrets); language runtimes.
- **Containers:** Docker Desktop (`docker …`), WSL (`wsl -l -v`), Hyper-V (`Get-VM`).
- **Security:** `Get-MpComputerStatus` (Defender), `Get-BitLockerVolume`,
  `Get-NetFirewallProfile`, UAC (registry `EnableLUA`), `Get-ExecutionPolicy`,
  `Confirm-SecureBootUEFI`. SSH server flags from `sshd_config` (flags only).
- **Boot/Kernel:** `Get-CimInstance Win32_SystemDriver`, `bcdedit` (elevated).
- **Health (counts only):** `Get-WinEvent -FilterHashtable @{LogName='System';Level=1,2}`
  → **count** errors/critical, never dump message text.
- **Environment:** `Get-ChildItem Env:` → **names only** (`.Name`, never `.Value`).

## Windows-specific sensitive paths/stores (add to the denylist)

DPAPI master keys (`%APPDATA%\Microsoft\Protect\*`), Windows Credential Manager /
Vault (never enumerate values), SAM & SECURITY registry hives, `%USERPROFILE%\.ssh`,
`*.pfx`, `*.pem`, `*.key`, `unattend.xml` / `sysprep.xml`, browser credential
stores, `*.kdbx` — plus everything in `security.md`. Never print registry values
that could be secrets; run them through `Redact`.

## Interactive wizard

Port the same wizard/output modes as the Linux script (see "Interactive wizard &
output modes" in `report-structure.md`): destinations (screen/CWD/home/custom),
formats (`md`/`txt`/`html` — HTML via pandoc with an escaped-`<pre>` fallback),
quick/full scope, mask-net, confirm + clipboard offer. Windows specifics: use
`-Param` switches (`-Output`, `-Format`, `-Quick`, `-MaskNet`, `-NoWizard`,
`-Screen`) parsed via `param(...)`; clipboard via **`Set-Clipboard`**; gate the
wizard on `[Environment]::UserInteractive` plus "no output params passed", and
read answers with `Read-Host`. Build the report into a `[System.Text.StringBuilder]`
or temp file, then mask/format/route.

## Lint & test

- Lint with **PSScriptAnalyzer**: `Invoke-ScriptAnalyzer -Path server-audit.ps1
  -Severity Warning,Error`. The PostToolUse hook already runs this on `*.ps1` edits
  when `pwsh` + the module are available.
- Run on a real Windows box (elevated for full coverage); run the secret-safety
  red-team from `security.md`.
- Update the README Windows row to ✅ and fill in the usage block.
