---
description: Non-negotiable secret-safety model. Applies to EVERY platform script (Linux/macOS/Windows). Always in effect.
---

# Secret-safety model (all platforms — the whole point of this project)

These three layers are the reason this project exists. **Every probe you add, on
any platform, must preserve all three.** A report that leaks a secret is a bug,
no matter how much context it provides.

## Layer 1 — Sensitive paths are existence-only, never read

Report only that the path *exists* — never its contents. Categories (translate to
each OS's real locations):

- **SSH / keys:** `~/.ssh`, `id_*`, `*_rsa/_dsa/_ecdsa/_ed25519`, `*.pem`, `*.key`,
  `*.ppk`, `authorized_keys`, `known_hosts`, host private keys.
- **Cloud / cred files:** `~/.aws`, gcloud, Azure, `~/.kube/config`/kubeconfig,
  `~/.docker/config.json`, `~/.netrc`, `~/.pgpass`, `~/.my.cnf`, `.git-credentials`.
- **Secret stores:** GPG (`~/.gnupg`), password stores, `*.kdbx`, `*.gpg`, `*.asc`;
  **macOS** Keychains (`~/Library/Keychains`, `*.keychain-db`); **Windows** DPAPI
  master keys (`%APPDATA%\Microsoft\Protect`), Credential Manager / vault, SAM &
  SECURITY registry hives.
- **System secrets:** `/etc/shadow`, `/etc/sudoers*`, private TLS keys
  (`/etc/ssl/private`), NetworkManager/wpa_supplicant connections; **macOS**
  `/var/db/dslocal/.../users/*` (password hashes); **Windows** `unattend.xml`.
- **Keystores / certs:** `*.p12`, `*.pfx`, `*.jks`, `*.keystore`, `*.htpasswd`, `*.p8`.
- **Env / secret-named files:** `.env`, `.env.*`, `*secret*`, `*credential*`, `*token*`.

The Linux script implements this as `is_sensitive_path` + `exists_note`/`safe_cat`/
`safe_ls`. Each platform script must have an equivalent denylist consulted before
ever reading a file, and must prune these from any directory walk.

## Layer 2 — Everything that IS read is redacted

Pipe **every** file content and config-bearing command output through a redactor
that masks:

- `key|secret|token|password|passwd|api_key|access_key|private_key|auth|credential|
  connection_string = <value>` (and `:`-separated / JSON / YAML / INI / env forms).
- Credential-bearing URLs `scheme://user:pass@host` → `scheme://***:***@host`.
- Token shapes: AWS `AKIA/ASIA…`, GitHub `ghp_/github_pat_…`, Slack `xox[baprs]-…`,
  OpenAI `sk-…`, GitLab `glpat-…`, JWT `eyJ….….…`, `Bearer …`, `Authorization:` headers.
- PEM private-key blocks; long opaque base64/hex blobs (≥40 chars).
- Hardware identifiers: serial numbers, UUIDs, asset tags, IMEIs.

Never emit raw config you didn't redact. The Linux reference is the `redact`
filter; reimplement the same patterns in each platform's language.

## Layer 3 — No credentialed access; env values never shown

- **Detect services by port + process + version only.** Never connect,
  authenticate, query, or read data from any database or service. (Linux helper:
  `detect_service "Display" <procname> <port>`.)
- **Environment variables: names only, never values.** Their values routinely
  contain secrets.
- Directory/filesystem mapping lists **names/structure only**, never file contents.

## Verifying (do this after any change, on any platform)

Plant decoy credentials reachable by your probes (a fake SSH private key, a `.env`
with `PASSWORD=…`/`API_KEY=AKIA…`, cloud creds, `.pgpass`) **and** export a secret
env var, run the script to a file, then grep the output for those values. It must
find **nothing** — only `***REDACTED***` / `present, not read` markers. Also
confirm the env var appears by name but not value.
