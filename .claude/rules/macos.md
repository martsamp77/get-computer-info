---
description: macOS script (server-audit-macos.sh) playbook — how to port the Linux audit to macOS without leaking secrets.
paths:
  - "**/server-audit-macos.sh"
---

# macOS playbook — `server-audit-macos.sh`

Port of `server-audit.sh` to macOS. **First read** `.claude/rules/security.md`,
`.claude/rules/report-structure.md`, and skim the Linux reference
`server-audit.sh` for the helper structure. Reuse the same helpers (`h1/h2/h3`,
`kv`, `note`, `block`, `safe_cat`, `safe_ls`, `exists_note`, `is_sensitive_path`,
`redact`, `detect_service`, `have`, `to`) — copy them over, adjusting only what's
OS-specific. Keep the **same section order** and the **three security layers**.

## Runtime gotcha (important)

macOS ships **bash 3.2** at `/bin/bash`. The Linux script uses bash-4 features
that will break there. Either:
- target **bash 3.2-safe** syntax (recommended, zero install): replace `${var,,}`
  with `tr '[:upper:]' '[:lower:]'`, avoid associative arrays (`declare -A`),
  `mapfile`/`readarray`, and `${arr[@]: -1}`; or
- target **zsh** (`#!/usr/bin/env zsh`, default shell since Catalina); or
- require Homebrew bash (`#!/usr/bin/env bash` + document the dependency).

Prefer bash-3.2-safe so it runs out of the box. Keep `set -uo pipefail` (no `-e`).
BSD userland differs from GNU: `find`, `sed`, `stat`, `date` take different flags —
test them.

## Native tooling per section

- **System/OS:** `sw_vers`, `system_profiler SPSoftwareDataType`, `uname -a`,
  `sysctl -n kern.*`, `scutil --get ComputerName`, `systemsetup -gettimezone`.
- **Hardware:** `system_profiler SPHardwareDataType` (**mask Serial/Hardware UUID**),
  `sysctl -n machdep.cpu.brand_string`, `sysctl hw.memsize hw.ncpu`. Apple Silicon:
  note chip via `sysctl machdep.cpu`.
- **GPU:** `system_profiler SPDisplaysDataType` (Apple GPU / Metal).
- **Storage:** `diskutil list`, `df -h`, `mount`; APFS containers via `diskutil apfs list`.
- **Network:** `ifconfig`, `networksetup -listallhardwareports`, `scutil --dns`,
  `netstat -anv` or `lsof -nP -iTCP -sTCP:LISTEN` (ports + process), `/etc/hosts`,
  firewall `/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate`,
  `pfctl -s rules` (root).
- **Users/Groups:** `dscl . list /Users`, `dscl . list /Groups`,
  `dscl . -read /Groups/admin GroupMembership`, `id`, `who`, `last`.
  **Never** read `/var/db/dslocal/nodes/Default/users/*.plist` (password hashes).
- **Services/Scheduled:** `launchctl list`, list names in `/Library/LaunchDaemons`,
  `/Library/LaunchAgents`, `~/Library/LaunchAgents`; `brew services list`;
  `crontab -l`; periodic jobs in `/etc/periodic`.
- **Processes:** `ps aux`, `top -l 1 -n 20`.
- **Packages:** Homebrew (`brew list --versions`, `brew list --cask`), MacPorts
  (`port installed`), `mas list`, `pkgutil --pkgs`; language runtimes.
- **Containers:** Docker Desktop / Colima / OrbStack / Podman (`docker …` if present);
  detect by process/port like Linux.
- **Security:** `csrutil status` (SIP), `spctl --status` (Gatekeeper),
  `fdesetup status` (FileVault), socketfilterfw, SSH config flags. **Never** dump
  Keychain (`security` / `~/Library/Keychains`).
- **Health (counts only):** `log show --last 1h --style compact` filtered to errors
  → **count only**; `pmset -g`.
- **Environment:** `env` → **names only**.

## macOS-specific sensitive paths (add to the denylist)

`~/Library/Keychains/*`, `/Library/Keychains/*`, `*.keychain`, `*.keychain-db`,
`/var/db/dslocal/nodes/Default/users/*`, `*.mobileprovision`, `*.p8`,
`~/Library/Application Support/*/*` credential files — plus everything in
`security.md`.

## Interactive wizard

Port the same wizard/output modes as the Linux script (see the "Interactive
wizard & output modes" section of `report-structure.md`): destinations
(screen/CWD/home/custom), formats (`md`/`txt`/`html` — HTML via pandoc with the
escaped-`<pre>` fallback), quick/full scope, mask-net, and the same flags. macOS
specifics: clipboard via **`pbcopy`**; prompts read from `/dev/tty`; the wizard
runs only when interactive and no flags are passed (bash 3.2 supports `[ -t 0 ]`
and `read -p` fine).

## Lint & test

- Lint with `shellcheck --severity=warning server-audit-macos.sh` (the existing
  PostToolUse hook already covers `*.sh`).
- Run on a real Mac; run the secret-safety red-team from `security.md`.
- Update the README macOS row to ✅ and fill in the usage block.
