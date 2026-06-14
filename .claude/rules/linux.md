---
description: Linux script (server-audit.sh) conventions — Bash helpers, idioms, linting. The reference implementation for all platforms.
paths:
  - "**/server-audit.sh"
---

# Linux playbook — `server-audit.sh`

This is the **reference implementation**. macOS and Windows variants mirror its
structure and security model. Also read `.claude/rules/security.md` and
`.claude/rules/report-structure.md` (always loaded).

## Runtime

- `#!/usr/bin/env bash`; uses **Bash 4+** features (`${var,,}`, arrays). Fine on
  Linux. (The macOS port must avoid these — see `macos.md`.)
- `set -uo pipefail` — **no `-e`**: a failing probe must not kill the run.

## Helpers (use these — don't hand-roll)

- `h1/h2/h3 "Title"` — Markdown headings.
- `kv "Label" "value"` — fact line.
- `note "text"` — italic note.
- `block` — stdin → fenced, **redacted** code block (`_n/a_` if empty). Pipe
  command/file output through it: `lscpu | block`.
- `safe_cat <file>` — read a config file: refuses denylisted paths, redacts the rest.
- `safe_ls <dir>` — list entry **names only**.
- `exists_note <path>` — `present, not read (sensitive)` / `not present`.
- `is_sensitive_path <path>` — Layer-1 denylist predicate (add new globs here).
- `redact` — Layer-2 secret filter (stdin).
- `detect_service "Display" <procname> <port>` — credential-free detection.
- `have <cmd>` — `command -v` guard.
- `to <secs> <cmd…>` — bounded run; wrap hangy probes (network, `find`, `smartctl`).

## Linting

- `shellcheck --severity=warning server-audit.sh` must pass. Info/style notes
  (SC2016 on Markdown `printf` formats, SC2012 for deliberate names-only `ls`) are
  intentionally allowed.
- This shellcheck build does not auto-read `.shellcheckrc`, so the `--severity`
  flag is passed explicitly (the PostToolUse hook does this too).

## Adding a section

Use the `/add-audit-section` skill. Placement, helper usage, summary-table update,
lint, and the secret-safety red-team check are all spelled out there.

## Testing

Run on a real Linux server (`sudo ./server-audit.sh --output .`) for full
coverage; non-root works but degrades.
