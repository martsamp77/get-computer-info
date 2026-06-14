---
name: add-audit-section
description: Add a new probe/section to server-audit.sh that follows the script's conventions (Markdown h1/h2/h3 + block helpers, graceful fallbacks, read-only safety, and the never-leak-secrets rules). Use when asked to audit/report something new (a service, tool, hardware fact, file, or AI/ML component).
---

# Add an audit section to server-audit.sh

Use this when the user wants `server-audit.sh` to report on something new. The output is a Markdown server-context report fed to an AI assistant.

## Rules (inherit the script's constraints — all mandatory)

1. **Never leak secrets.** This is the script's core guarantee. Three layers:
   - **Sensitive files are existence-only.** If your probe touches a path that could hold secrets, route it through `safe_cat <file>` (reads + redacts, refuses denylisted paths) or report it with `exists_note <path>`. Never `cat` a sensitive file directly. Add new sensitive globs to `is_sensitive_path`.
   - **Everything read gets redacted.** Pipe file contents and any config-bearing command output through the `block` helper (it fences + runs `redact`), or call `redact` explicitly. Never bypass it.
   - **No credentialed access; env values never shown.** Detect services with `detect_service "Display" <procname> <port>` (port+process+version only — never connect, authenticate, or query). Environment variables are reported by **name only**.
2. **Read-only.** No installs, writes, restarts, or config edits — inspect only.
3. **Degrade gracefully.** Guard every external tool with `have <tool>`; use `... 2>/dev/null` fallbacks; the script runs `set -uo pipefail` (no `-e`) so a failing probe must not abort. Wrap hangy probes (network/`find`/`smartctl`) in `to <secs> <cmd>`.
4. **Stay generic.** No machine-, site-, or stack-specific names, ports, or credentials.

## Helpers available

`h1/h2/h3 "Title"` (headings) · `kv "Label" "value"` (fact line) · `note "text"` (italic) · `block` (stdin → fenced + redacted code block, prints `_n/a_` if empty) · `safe_cat <file>` · `safe_ls <dir>` (names only) · `exists_note <path>` · `detect_service <display> <proc> <port>` · `have <cmd>` · `to <secs> <cmd...>` · `redact` (stdin filter).

## Steps

1. **Placement** — add the subsection under the most relevant existing `h1` block (e.g. a new database in section 12, a model server in section 13). Open a new `h1 "N. Topic"` block only for a genuinely new top-level category.
2. **Heading** — start with `h3 "Name"`; don't hand-roll separators or code fences.
3. **Probe** — write it with the helpers above. For command/file output: `<cmd> | block` or `safe_cat <file>`. For facts: `kv`. For service presence: `detect_service`. For sensitive paths: `exists_note`.
4. **Summary** — if it's a key at-a-glance fact, add a row to the final `Summary` Markdown table near the end of the file.
5. **Lint** — run `shellcheck --severity=warning server-audit.sh` and fix all findings.
6. **Secret-safety check** — plant a decoy secret reachable by your new probe (and/or a secret env var), run the script, and grep the output for the value; it must NOT appear (only `***REDACTED***` / `present, not read`). See the verification section of the plan for the full red-team recipe.
7. Tell the user to validate a real run with `sudo ./server-audit.sh` on a target server for complete coverage.
