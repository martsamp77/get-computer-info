---
description: Canonical report layout shared by all platform scripts so every machine produces a consistent Markdown context report.
---

# Canonical report structure (all platforms)

Every platform script outputs **one Markdown report** with the same shape, so a
report from any machine reads consistently for an AI assistant. Use the Linux
`server-audit.sh` as the reference implementation; keep the section order and the
intent of each section, translating the probes to native tooling.

## Output

- Format: **Markdown** (`.md`).
- Default: print to stdout. With an output flag, also save
  `<hostname>_context_<timestamp>.md`.
- Start with: title, a metadata block (hostname, generated-at, tool+version, run
  user + privilege level), a privilege warning if not elevated, and a
  **redaction notice** stating that secrets are omitted/masked and the report is
  still sensitive (don't publish).
- Wrap every command/file output in a fenced code block, after redaction.
- Degrade gracefully: a missing tool prints a short note, never aborts the run.

## Interactive wizard & output modes (all platforms)

Every platform script behaves the same way at the CLI:

- **No flags on an interactive terminal → wizard.** Prompt for: destination
  (screen / current dir / home / custom path), format (`md` default / `txt` /
  `html`), scope (full default / quick), and "mask network identifiers?" — then a
  confirm step, and an offer to copy to the clipboard when done.
- **Non-interactive → never block.** When stdin/stdout is not a TTY (pipe, cron,
  `ssh host 'bash -s'`, `curl | bash`) or `--no-wizard` is given, fall back to the
  defaults (print Markdown to stdout) without prompting. Read wizard input from
  the controlling terminal, not stdin.
- **Scriptable flags bypass the wizard:** `--screen`, `--output <dir>`, `--home`,
  `--format <md|txt|html>`, `--quick`/`--full`, `--mask-net`, `--no-wizard`
  (PowerShell uses the `-Param` equivalents).
- **Formats:** `md` = the report as-is; `txt` = Markdown stripped to plain text;
  `html` = via pandoc if present, else a minimal escaped wrapper.
- **Quick scope** skips only the heaviest sections (full installed-package list,
  filesystem map, largest-dirs scan) and notes that it did; everything else stays.
- **Mask-net** masks IPs/MACs/hostname for a shareable report and names the file
  `masked_context_<timestamp>.<ext>` (no hostname). It is *additive* — it never
  replaces the core secret redaction.
- Implementation note: generate the whole report to a temp buffer/file, then apply
  masking + format and route to the destination (avoids partial-write races).

## Sections (in order)

1. **System & OS** — metadata, OS release/version, kernel/build, arch, platform
   (boot mode, virtualization/container, init/service manager), timezone, locale,
   time sync, machine id.
2. **Hardware** — CPU (model/cores/flags), memory, system/board model
   (serials masked), sensors/thermal, battery if a laptop.
3. **GPU / Accelerators** — display adapters; NVIDIA/AMD/Apple-Silicon GPU detail;
   CUDA/Metal/ROCm where relevant.
4. **Storage & Filesystem** — disks/volumes, usage, mounts, RAID/LVM/ZFS,
   SMART health, a names-only filesystem map of common roots, home dirs (top-level
   names only), largest directories.
5. **Network** — interfaces + IP/MAC, routes, DNS, hosts file, listening ports +
   owning process, firewall rules. (IPs/MACs are kept — see CLAUDE.md.)
6. **Users & Groups** — accounts (no password hashes ever), groups, privileged-group
   members (admin/sudo/wheel), logged-in users, recent logins.
7. **Services & Scheduled Tasks** — running / failed / enabled services + timers;
   cron / launchd / Task Scheduler entries (redacted).
8. **Processes** — top by memory, top by CPU, total count.
9. **Packages & Software** — package manager(s) + full installed inventory,
   language runtimes & versions, configured repos (redacted), pending updates.
10. **Containers & Orchestration** — Docker/Podman (containers, images, volumes,
    networks, compose discovery: paths + service/image names only, never `.env`),
    Kubernetes (client/version, kubeconfig existence only), VMs/WSL/LXD.
11. **Web / Proxy Servers** — nginx/apache/caddy/traefik/haproxy/IIS: presence,
    version, enabled-site filenames only (no config dumps).
12. **Databases & Data Services** — detection only (port + process + version).
13. **AI / ML Runtimes** — detection only (Ollama/vLLM/llama.cpp/etc.); ML packages;
    model-cache existence + size only.
14. **Developer Tooling** — git (config redacted), compilers, version managers, SDKs.
15. **Security Posture** — MAC/AV (SELinux/AppArmor, Defender), disk encryption,
    firewall summary, SSH server flags only, secure boot, externally-bound services.
16. **Boot & Kernel** — modules/drivers, key tunables, boot/kernel cmdline (redacted).
17. **Health (counts only)** — load, failed units, error/critical log **counts**
    (never log line text), OOM/crash counts, reboot count.
18. **Environment** — variable **names only**, PATH summary, default shell, umask.

End with a **Summary** Markdown table of at-a-glance facts (OS, kernel, CPU, RAM,
GPU, disk, containers, uptime, failed units, …).

When a section is meaningless on a platform, keep the heading and note it
"n/a on <platform>" rather than dropping it — consistency helps the AI reader.
