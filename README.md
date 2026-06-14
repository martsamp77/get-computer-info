# Machine Context Report

Read-only diagnostic scripts that map a machine — OS, users/groups, filesystem
layout, services, scheduled tasks, packages, containers, databases, hardware,
GPU, network, and security posture — into a single **Markdown** report you can
hand to an AI assistant (e.g. Claude in a terminal) so it has full context about
the box you're working on.

The whole point is **maximum context without leaking secrets**: the scripts
never read sensitive files, redact anything secret-shaped they do read, and
detect services without ever connecting or using credentials.

## Platforms

| Platform | Script | Shell / runtime | Status |
|----------|--------|-----------------|--------|
| Linux    | `server-audit.sh`        | Bash 4+            | ✅ Available |
| macOS    | `server-audit-macos.sh`  | Bash/zsh          | 🚧 Planned |
| Windows  | `server-audit.ps1`       | PowerShell 5+/7   | 🚧 Planned |

> The macOS and Windows variants will be added by running the project on each of
> those machines and adapting the script + this README to that platform's tools.
> The **security guarantees below apply to every platform** — any new script must
> preserve all three layers.

## Security guarantees (all platforms)

Three independent layers, so a miss in one is caught by another:

1. **Sensitive paths are existence-only — never read.** SSH keys, `.env` files,
   cloud credentials (`.aws`, gcloud, Azure), `.pgpass`, `.netrc`, kubeconfig,
   `/etc/shadow`, private keys, NetworkManager connections, keystores, etc. are
   reported as *present, not read*.
2. **Everything that is read is redacted.** Passwords, tokens, API keys
   (AWS/GitHub/Slack/OpenAI/GitLab), JWTs, `Bearer`/`Authorization` values,
   credential-bearing URLs (`user:pass@host`), PEM private-key blocks, and
   hardware serial numbers / UUIDs are masked.
3. **No credentialed access, ever.** Databases and services are detected by
   port + process + version only — never connected to or queried. Environment
   variables are reported by **name only**, never their values.

> ⚠️ The report still contains hostnames, IP/MAC addresses, and a full software
> inventory. **Treat the output as sensitive — do not commit it to a public
> repository.** Generated reports (`*_context_*.md`) are gitignored by default.

## Usage

### Linux

```bash
chmod +x server-audit.sh

./server-audit.sh                    # print the Markdown report to stdout
sudo ./server-audit.sh               # run as root for complete coverage
sudo ./server-audit.sh --output .    # also save <hostname>_context_<timestamp>.md
./server-audit.sh --help
```

Runs without root (coverage degrades for things like DIMM details, SMART
health, firewall rules, and the full process list). Works on most distros
(Ubuntu/Debian primarily) and degrades gracefully when tools are missing.

To hand the result to an AI assistant, save it and open/attach the file:

```bash
sudo ./server-audit.sh --output .
# -> ./<hostname>_context_<timestamp>.md
```

### macOS — 🚧 planned

```bash
# coming: ./server-audit-macos.sh --output .
```

Will use macOS-native tools (`system_profiler`, `sw_vers`, `scutil`, `pmset`,
`launchctl`, `dscl`, `networksetup`, Homebrew/MacPorts inventory) while keeping
the same report layout and the same three security layers.

### Windows — 🚧 planned

```powershell
# coming: .\server-audit.ps1 -Output .
```

Will use PowerShell + CIM/WMI (`Get-ComputerInfo`, `Get-CimInstance`,
`Get-Service`, `Get-LocalUser`/`Get-LocalGroup`, `Get-NetIPConfiguration`,
scheduled tasks, winget/Chocolatey inventory) and apply the same redaction and
existence-only rules (never read DPAPI stores, credential vaults, `.pem`/`.pfx`,
SSH keys, etc.).

## What's in the report

Hardware (CPU/RAM/GPU), OS & platform, storage and a filesystem map, network
(interfaces, listening ports, firewall), users & groups, services & scheduled
tasks, top processes, installed packages & language runtimes, containers &
orchestration (Docker/Podman/Kubernetes), databases & AI/ML runtimes (detection
only), developer tooling, security posture, boot/kernel, health counts, and an
at-a-glance summary table.

## Development

See `CLAUDE.md` for the contributor rules (the non-negotiable secret-safety
constraints, helper conventions, and how to add a new section via the
`/add-audit-section` skill).

- Lint (Bash, Linux/macOS): `shellcheck --severity=warning <script>.sh`
- Lint (PowerShell, Windows): `Invoke-ScriptAnalyzer -Path server-audit.ps1 -Severity Warning,Error`
- The PostToolUse hook in `.claude/settings.json` lints both automatically on edit.
- Per-platform contributor playbooks live in `.claude/rules/` (loaded automatically
  by Claude Code); the secret-safety contract is `.claude/rules/security.md`.
- Secret-safety red-team: plant decoy credential files and a secret env var,
  run the script, then grep the output for those values — it must find nothing.
