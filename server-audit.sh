#!/usr/bin/env bash
# ============================================================================
# Linux Server Context Report
#
# Generic, run-anywhere audit that maps out as much as possible about a Linux
# server — OS, users, groups, filesystem layout, services, packages, containers,
# databases, hardware, GPU, network, security posture — and writes a single
# Markdown report you can hand to an AI assistant (e.g. Claude in a terminal)
# for full context about the machine.
#
# USAGE:
#   chmod +x server-audit.sh
#   ./server-audit.sh                     # print Markdown report to stdout
#   sudo ./server-audit.sh                # run as root for complete coverage
#   sudo ./server-audit.sh --output .     # also save <hostname>_context_<ts>.md
#   ./server-audit.sh --help
#
# SECURITY GUARANTEES (defense in depth — never leak secrets):
#   1. Sensitive paths (.ssh, .env, .aws, .pgpass, /etc/shadow, private keys,
#      kubeconfig, NetworkManager connections, ...) are NEVER read — the report
#      states only that they exist.
#   2. Everything that IS read is passed through a redactor that masks
#      passwords, tokens, API keys, credential-bearing URLs, PEM key blocks,
#      and hardware serial numbers / UUIDs.
#   3. No credentialed access of any kind: databases/services are detected by
#      port + process + version only (never connected to, never queried).
#      Environment variables are reported by NAME only — never their values.
#
#   The report still contains hostnames, IP/MAC addresses and software
#   inventory. Treat the output as sensitive; do not commit it to a public
#   repository.
#
# NOTES:
#   - Safe to run on production servers (read-only operations).
#   - Works on most Linux distros; degrades gracefully when tools are missing.
#   - Run as root/sudo for complete information; non-root still works.
# ============================================================================

set -uo pipefail

VERSION="2.0"
OUTPUT_DIR=""
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
HOSTNAME_SHORT=$(hostname 2>/dev/null || echo "unknown")

# --- Parse arguments --------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --output|-o)
            OUTPUT_DIR="${2:-}"
            [ -z "$OUTPUT_DIR" ] && { echo "Error: --output needs a directory" >&2; exit 1; }
            shift 2
            ;;
        --help|-h)
            sed -n '2,40p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *)
            echo "Unknown option: $1 (try --help)" >&2
            exit 1
            ;;
    esac
done

# --- Output handling --------------------------------------------------------
REPORT_FILE=""
TEE_PID=""
if [ -n "$OUTPUT_DIR" ]; then
    mkdir -p "$OUTPUT_DIR" || { echo "Error: cannot create $OUTPUT_DIR" >&2; exit 1; }
    REPORT_FILE="${OUTPUT_DIR%/}/${HOSTNAME_SHORT}_context_${TIMESTAMP}.md"
    exec > >(tee "$REPORT_FILE")
    TEE_PID=$!
fi

# Flush and wait for the tee process substitution so the saved file is complete.
finish() {
    if [ -n "$TEE_PID" ]; then
        exec 1>&-
        wait "$TEE_PID" 2>/dev/null
    fi
}
trap finish EXIT

# ============================================================================
# Helpers
# ============================================================================

have() { command -v "$1" >/dev/null 2>&1; }

is_root() { [ "$(id -u 2>/dev/null)" = "0" ]; }

# Bounded run for commands that can hang (network probes, find, smartctl).
to() { if have timeout; then timeout "$1" "${@:2}"; else "${@:2}"; fi; }

# Layer 2: redact secrets from any text passed on stdin.
redact() {
    sed -E \
        -e 's#((password|passwd|pwd|secret|secret[_-]?key|access[_-]?key|access[_-]?key[_-]?id|secret[_-]?access[_-]?key|api[_-]?key|apikey|private[_-]?key|auth[_-]?token|client[_-]?secret|credentials?|conn(ection)?[_-]?str(ing)?)["'"'"']?[[:space:]]*[=:][[:space:]]*)["'"'"']?[^"'"'"'[:space:]]+#\1***REDACTED***#gI' \
        -e 's#([a-zA-Z][a-zA-Z0-9+.-]*://)[^:/@[:space:]]+:[^@/[:space:]]+@#\1***:***@#g' \
        -e 's#A(KIA|SIA)[0-9A-Z]{16}#***REDACTED-AWS-KEY***#g' \
        -e 's#gh[pousr]_[A-Za-z0-9]{20,}#***REDACTED-GH-TOKEN***#g' \
        -e 's#github_pat_[A-Za-z0-9_]{20,}#***REDACTED-GH-TOKEN***#g' \
        -e 's#xox[baprs]-[A-Za-z0-9-]{10,}#***REDACTED-SLACK-TOKEN***#g' \
        -e 's#sk-[A-Za-z0-9]{20,}#***REDACTED-OPENAI-KEY***#g' \
        -e 's#glpat-[A-Za-z0-9_-]{18,}#***REDACTED-GITLAB-TOKEN***#g' \
        -e 's#eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+#***REDACTED-JWT***#g' \
        -e 's#([Bb]earer[[:space:]]+)[A-Za-z0-9._-]{10,}#\1***REDACTED***#g' \
        -e 's#([Aa]uthorization[[:space:]]*:[[:space:]]*).*#\1***REDACTED***#g' \
        -e 's#(Serial Number|UUID|Asset Tag|IMEI)([[:space:]]*[:=][[:space:]]*).*#\1\2***REDACTED***#gI' \
        -e 's#-----BEGIN[ A-Z]*PRIVATE KEY-----#***REDACTED-PRIVATE-KEY-BLOCK***#g' \
        -e 's#^[[:space:]]*[A-Za-z0-9+/]{40,}={0,2}[[:space:]]*$#***REDACTED-BLOB***#g'
}

# Markdown emitters.
h1() { printf '\n# %s\n\n' "$1"; }
h2() { printf '\n## %s\n\n' "$1"; }
h3() { printf '\n### %s\n\n' "$1"; }
note() { printf '_%s_\n\n' "$1"; }
kv() { printf -- '- **%s:** %s\n' "$1" "${2:-n/a}"; }

# Wrap stdin in a fenced code block (redacted). Prints _n/a_ if empty.
block() {
    local out
    out="$(cat)"
    out="$(printf '%s' "$out" | redact)"
    if [ -z "${out//[[:space:]]/}" ]; then printf '_n/a_\n\n'; return; fi
    printf '```\n%s\n```\n\n' "$out"
}

# Layer 1: is this path sensitive (existence-only, never read)?
is_sensitive_path() {
    local p="${1,,}"
    case "$p" in
        */.ssh|*/.ssh/*|*_rsa|*_dsa|*_ecdsa|*_ed25519|*/id_*|*.pem|*.key|*.ppk|*authorized_keys*|*known_hosts*) return 0 ;;
        */.aws/*|*/.config/gcloud/*|*/.azure/*|*/.kube/config|*kubeconfig*|*/.docker/config.json|*/.netrc|*/.pgpass|*/.my.cnf|*/.mylogin.cnf|*/.git-credentials) return 0 ;;
        */.gnupg/*|*/.password-store/*|*.kdbx|*.gpg|*.asc) return 0 ;;
        /etc/shadow|/etc/gshadow|/etc/sudoers|/etc/sudoers.d/*|/etc/ssl/private/*|/etc/ssh/*_key|/etc/networkmanager/system-connections/*|/etc/wpa_supplicant/*) return 0 ;;
        *.p12|*.pfx|*.jks|*.keystore|*.htpasswd) return 0 ;;
        */.env|*/.env.*|*.env|*secret*|*credential*|*token*) return 0 ;;
    esac
    return 1
}

exists_note() {
    if [ -e "$1" ]; then printf -- '- `%s` — **present, not read** (sensitive)\n' "$1"
    else printf -- '- `%s` — not present\n' "$1"; fi
}

# Read a config file safely: refuse sensitive paths, redact the rest.
safe_cat() {
    local f="$1"
    if [ ! -e "$f" ]; then printf '_not present: `%s`_\n\n' "$f"; return; fi
    if is_sensitive_path "$f"; then printf -- '`%s` — **present, not read** (sensitive)\n\n' "$f"; return; fi
    block < "$f"
}

# List directory entry NAMES only (never contents).
safe_ls() {
    local d="$1"
    if [ ! -d "$d" ]; then printf '_not present: `%s`_\n\n' "$d"; return; fi
    ls -A1 -- "$d" 2>/dev/null | block
}

# Credential-free service detection.
port_listen() { ss -tlnH 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$1\$"; }
proc_running() { pgrep -x "$1" >/dev/null 2>&1 || pgrep -f "$1" >/dev/null 2>&1; }

# Print a one-line detection result for a service (no connection, no creds).
detect_service() { # display proc port
    local display="$1" proc="$2" port="${3:-}" parts=()
    proc_running "$proc" && parts+=("process running")
    [ -n "$port" ] && port_listen "$port" && parts+=("listening :$port")
    if [ ${#parts[@]} -eq 0 ]; then
        printf -- '- %s: _not detected_\n' "$display"
    else
        local IFS=", "; printf -- '- **%s**: %s\n' "$display" "${parts[*]}"
    fi
}

# ============================================================================
# Report header
# ============================================================================

printf '# Linux Server Context Report\n\n'
kv "Hostname" "$(hostname 2>/dev/null)"
kv "Generated" "$(date '+%Y-%m-%d %H:%M:%S %Z')"
kv "Report tool" "server-audit.sh v${VERSION}"
kv "Run as" "$(whoami 2>/dev/null) ($(is_root && echo root || echo non-root))"
is_root || note "⚠️ Running as non-root — some sections (DIMM/SMART/firewall/full process list) will be limited. Re-run with sudo for complete coverage."
printf '\n> **Redaction notice:** sensitive files (SSH keys, .env, cloud credentials, /etc/shadow, etc.) are reported as *present, not read*. Passwords, tokens, API keys, credential URLs and hardware serials are masked. Environment variables are listed by name only. Databases are detected without connecting. This report still contains hostnames, IPs and software inventory — do not publish it.\n'

# ============================================================================
h1 "1. System & OS"
# ============================================================================

h3 "Metadata"
kv "FQDN" "$(hostname -f 2>/dev/null)"
kv "Timestamp (UTC)" "$(date -u '+%Y-%m-%d %H:%M:%S %Z')"
kv "Uptime" "$(uptime -p 2>/dev/null || uptime 2>/dev/null)"
kv "Last boot" "$(who -b 2>/dev/null | awk '{print $3, $4}')"
kv "Timezone" "$(timedatectl show -p Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null)"
kv "Locale" "${LANG:-$(locale 2>/dev/null | grep -m1 '^LANG=' | cut -d= -f2)}"

h3 "OS Release"
safe_cat /etc/os-release

h3 "Kernel & Architecture"
kv "Kernel" "$(uname -r 2>/dev/null)"
kv "Architecture" "$(uname -m 2>/dev/null)"
kv "Full uname" "$(uname -a 2>/dev/null)"

h3 "Platform"
kv "Boot mode" "$([ -d /sys/firmware/efi ] && echo UEFI || echo 'Legacy BIOS')"
kv "Init system" "$( [ -d /run/systemd/system ] && echo systemd || (have openrc && echo openrc || echo 'sysvinit/other') )"
kv "Virtualization" "$(systemd-detect-virt 2>/dev/null || echo 'unknown/bare-metal')"
kv "In container" "$([ -f /.dockerenv ] && echo 'yes (docker)' || (grep -qaE 'docker|lxc|kubepods' /proc/1/cgroup 2>/dev/null && echo yes || echo no))"
kv "Machine ID" "$(cat /etc/machine-id 2>/dev/null)"

h3 "Time Synchronization"
{ timedatectl 2>/dev/null || true; chronyc tracking 2>/dev/null || true; } | block

# ============================================================================
h1 "2. Hardware"
# ============================================================================

h3 "CPU"
{
echo "Model:    $(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | xargs)"
echo "Sockets:  $(grep -c 'physical id' /proc/cpuinfo 2>/dev/null && grep 'physical id' /proc/cpuinfo | sort -u | wc -l)"
echo "Threads:  $(nproc 2>/dev/null)"
echo "Hypervisor: $(lscpu 2>/dev/null | grep -i 'Hypervisor vendor' | cut -d: -f2 | xargs)"
} | block

h3 "CPU capability flags"
{
flags=$(grep -m1 '^flags' /proc/cpuinfo 2>/dev/null | cut -d: -f2)
for f in vmx svm avx avx2 avx512f avx512_vnni amx_bf16 amx_int8 sse4_1 sse4_2 fma aes sha_ni; do
    if echo "$flags" | grep -qw "$f"; then echo "  $f: yes"; else echo "  $f: no"; fi
done
} | block

h3 "Full lscpu"
lscpu 2>/dev/null | block

h3 "System / Baseboard (serials masked)"
if have dmidecode && is_root; then
    dmidecode -t system -t baseboard -t chassis 2>/dev/null | grep -iE "Manufacturer|Product|Version|Serial|UUID|Asset|Family|Type:" | block
else
    note "dmidecode unavailable or non-root."
fi

h3 "Memory"
free -h 2>/dev/null | block
{
echo "Total:     $(awk '/MemTotal/{printf "%.1f GB",$2/1024/1024}' /proc/meminfo 2>/dev/null)"
echo "Available: $(awk '/MemAvailable/{printf "%.1f GB",$2/1024/1024}' /proc/meminfo 2>/dev/null)"
echo "Swap:      $(awk '/SwapTotal/{printf "%.1f GB",$2/1024/1024}' /proc/meminfo 2>/dev/null)"
} | block

h3 "DIMM slots (serials masked)"
if have dmidecode && is_root; then
    dmidecode -t memory 2>/dev/null | grep -E "Size|Speed|Type:|Locator:|Manufacturer:" | grep -v "Serial" | block
else
    note "Requires root + dmidecode."
fi

h3 "Sensors / Thermal"
if have sensors; then sensors 2>/dev/null | block; else note "lm-sensors not installed."; fi

# ============================================================================
h1 "3. GPU / Accelerators"
# ============================================================================

h3 "PCI display devices"
lspci 2>/dev/null | grep -iE "vga|3d|display|nvidia|amd/ati" | block

h3 "NVIDIA"
if have nvidia-smi; then
    nvidia-smi 2>/dev/null | block
    h3 "NVIDIA per-GPU"
    nvidia-smi --query-gpu=index,name,memory.total,memory.used,temperature.gpu,power.draw,driver_version --format=csv 2>/dev/null | block
else
    note "nvidia-smi not found."
fi

h3 "AMD ROCm"
if have rocm-smi; then rocm-smi 2>/dev/null | block; else note "rocm-smi not found."; fi

h3 "CUDA"
kv "nvcc" "$(nvcc --version 2>/dev/null | grep -i release | awk '{print $5,$6}' | tr -d ',')"
{
for lib in libcudart libcublas libcudnn libnccl; do
    if ldconfig -p 2>/dev/null | grep -q "$lib"; then echo "  $lib: found"; else echo "  $lib: not found"; fi
done
} | block

# ============================================================================
h1 "4. Storage & Filesystem"
# ============================================================================

h3 "Block devices"
lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,MODEL,ROTA 2>/dev/null | block

h3 "Filesystem usage"
df -hT 2>/dev/null | grep -vE "tmpfs|devtmpfs|squashfs|overlay" | block

h3 "Mounts"
findmnt --real -o TARGET,SOURCE,FSTYPE,SIZE,USE% 2>/dev/null | block

h3 "fstab (redacted)"
safe_cat /etc/fstab

h3 "LVM / RAID / ZFS"
{
have lvs && { echo "== LVM =="; lvs 2>/dev/null; }
[ -f /proc/mdstat ] && { echo "== mdstat =="; cat /proc/mdstat 2>/dev/null; }
have zpool && { echo "== ZFS =="; zpool status 2>/dev/null; }
} | block

h3 "SMART health (serials masked)"
if have smartctl && is_root; then
    { for d in /dev/sd? /dev/nvme?n?; do [ -e "$d" ] && echo "$d: $(to 10 smartctl -H "$d" 2>/dev/null | grep -iE 'overall-health|SMART Health' | cut -d: -f2 | xargs)"; done; } | block
else
    note "smartctl unavailable or non-root."
fi

h3 "Filesystem map (names only, sensitive dirs pruned)"
for d in / /opt /srv /var/www /usr/local; do
    [ -d "$d" ] || continue
    printf '**%s**\n\n' "$d"
    if have tree; then
        tree -L 2 -a -I '.ssh|.gnupg|.aws|.env|.kube|node_modules' "$d" 2>/dev/null | head -200 | block
    else
        to 15 find "$d" -maxdepth 2 \( -name .ssh -o -name .gnupg -o -name .aws \) -prune -o -print 2>/dev/null | head -200 | block
    fi
done

h3 "Home directories (top-level names only)"
for h in /home/* /root; do
    [ -d "$h" ] || continue
    printf '**%s**\n\n' "$h"
    safe_ls "$h"
done

h3 "Largest top-level directories"
to 30 du -xhd1 / 2>/dev/null | sort -rh | head -15 | block

# ============================================================================
h1 "5. Network"
# ============================================================================

h3 "Interfaces & addresses"
ip -br addr 2>/dev/null | block
ip addr 2>/dev/null | block

h3 "Routes"
ip route 2>/dev/null | block

h3 "DNS"
safe_cat /etc/resolv.conf

h3 "/etc/hosts"
safe_cat /etc/hosts

h3 "Listening ports + owning process"
{ ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null; } | block

h3 "Firewall"
{
if have ufw; then echo "== ufw =="; ufw status verbose 2>/dev/null; fi
if have firewall-cmd; then echo "== firewalld =="; firewall-cmd --list-all 2>/dev/null; fi
if have nft; then echo "== nftables =="; nft list ruleset 2>/dev/null | head -100; fi
if have iptables; then echo "== iptables =="; iptables -S 2>/dev/null | head -100; fi
} | redact | block

h3 "NetworkManager connections (names only — connection files never read)"
if have nmcli; then nmcli -t -f NAME,TYPE,DEVICE connection show 2>/dev/null | block; else note "nmcli not present."; fi

# ============================================================================
h1 "6. Users & Groups"
# ============================================================================
note "/etc/shadow and password hashes are NEVER read."

h3 "User accounts (from /etc/passwd)"
getent passwd 2>/dev/null | awk -F: '{printf "%-20s uid=%-6s gid=%-6s shell=%-18s home=%s\n",$1,$3,$4,$7,$6}' | block

h3 "Accounts with login shells"
getent passwd 2>/dev/null | grep -vE '/nologin|/false' | cut -d: -f1,6,7 | block

h3 "Groups"
getent group 2>/dev/null | block

h3 "Privileged group members (sudo / wheel / admin / docker)"
{
for g in sudo wheel admin adm docker root; do
    m=$(getent group "$g" 2>/dev/null | cut -d: -f4)
    [ -n "$m" ] && echo "$g: $m"
done
} | block

h3 "Currently logged in"
{ who 2>/dev/null; echo "---"; w 2>/dev/null; } | block

h3 "Recent logins"
last -n 20 2>/dev/null | block

# ============================================================================
h1 "7. Services & Scheduled Tasks"
# ============================================================================

h3 "Running services"
systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | block

h3 "Failed services"
systemctl list-units --type=service --state=failed --no-pager --no-legend 2>/dev/null | block

h3 "Enabled-at-boot services"
systemctl list-unit-files --type=service --state=enabled --no-pager --no-legend 2>/dev/null | block

h3 "Systemd timers"
systemctl list-timers --all --no-pager --no-legend 2>/dev/null | block

h3 "System cron (redacted)"
safe_cat /etc/crontab
h3 "/etc/cron.d entries"
for f in /etc/cron.d/*; do [ -f "$f" ] && { printf '**%s**\n\n' "$f"; safe_cat "$f"; }; done
h3 "cron.daily / weekly / monthly (names only)"
{ ls -1 /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null; } | block

h3 "Per-user crontabs (redacted)"
{ for u in $(getent passwd | cut -d: -f1); do c=$(crontab -l -u "$u" 2>/dev/null); [ -n "$c" ] && echo "# $u" && echo "$c"; done; } 2>/dev/null | block

# ============================================================================
h1 "8. Processes"
# ============================================================================

h3 "Top 20 by memory"
ps aux --sort=-%mem 2>/dev/null | head -21 | block
h3 "Top 20 by CPU"
ps aux --sort=-%cpu 2>/dev/null | head -21 | block
kv "Total processes" "$(ps -e --no-headers 2>/dev/null | wc -l)"

# ============================================================================
h1 "9. Packages & Software"
# ============================================================================

h3 "Package manager & installed packages"
if have dpkg; then
    kv "Manager" "dpkg/apt"
    kv "Installed count" "$(dpkg -l 2>/dev/null | grep -c '^ii')"
    h3 "Installed (dpkg)"; dpkg -l 2>/dev/null | awk '/^ii/{print $2" "$3}' | block
elif have rpm; then
    kv "Manager" "rpm"
    kv "Installed count" "$(rpm -qa 2>/dev/null | wc -l)"
    h3 "Installed (rpm)"; rpm -qa 2>/dev/null | sort | block
elif have apk; then
    kv "Manager" "apk"
    h3 "Installed (apk)"; apk info -v 2>/dev/null | sort | block
elif have pacman; then
    kv "Manager" "pacman"
    h3 "Installed (pacman)"; pacman -Q 2>/dev/null | block
fi

h3 "Snap / Flatpak"
{ have snap && { echo "== snap =="; snap list 2>/dev/null; }; have flatpak && { echo "== flatpak =="; flatpak list 2>/dev/null; }; } | block

h3 "Language runtimes"
{
for c in "python3 --version" "python --version" "node --version" "go version" "java -version" "ruby --version" "php --version" "rustc --version" "gcc --version" "perl --version"; do
    name=${c%% *}; have "$name" && echo "$name: $(eval "$c" 2>&1 | head -1)"
done
} | block

h3 "Global package lists"
{ have pip3 && { echo "== pip (global) =="; pip3 list 2>/dev/null; }; } | block
{ have npm && { echo "== npm (global) =="; npm ls -g --depth=0 2>/dev/null; }; } | block

h3 "Configured repositories (redacted)"
safe_cat /etc/apt/sources.list
for f in /etc/apt/sources.list.d/*; do [ -f "$f" ] && { printf '**%s**\n\n' "$f"; safe_cat "$f"; }; done

h3 "Pending updates"
if have apt; then kv "apt upgradable" "$(apt list --upgradable 2>/dev/null | grep -c upgradable)"
elif have dnf; then kv "dnf updates" "$(dnf check-update -q 2>/dev/null | grep -c .)"; fi

# ============================================================================
h1 "10. Containers & Orchestration"
# ============================================================================

h3 "Docker"
if have docker; then
    kv "Version" "$(docker --version 2>/dev/null)"
    kv "Compose" "$(docker compose version 2>/dev/null || docker-compose version 2>/dev/null | head -1)"
    docker info 2>/dev/null | grep -E "Root Dir|Default Runtime|Runtimes|Storage Driver|Live Restore|CPUs|Total Memory" | block
    h3 "Running containers"; docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null | block
    h3 "All containers"; docker ps -a --format "table {{.Names}}\t{{.Image}}\t{{.Status}}" 2>/dev/null | block
    h3 "Images"; docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}" 2>/dev/null | block
    h3 "Volumes"; docker volume ls 2>/dev/null | block
    h3 "Networks"; docker network ls 2>/dev/null | block
    h3 "Disk usage"; docker system df 2>/dev/null | block
    kv "GPU runtime" "$(docker info 2>/dev/null | grep -qi nvidia && echo configured || echo 'not configured')"
    h3 "Compose project files (paths + service/image only; env values redacted, .env never read)"
    { to 20 find /opt /srv /home /root /docker /data -maxdepth 4 \( -name 'docker-compose.y*ml' -o -name 'compose.y*ml' \) 2>/dev/null | head -50; } | block
else
    note "Docker not installed."
fi

h3 "Podman"
if have podman; then podman ps -a 2>/dev/null | block; else note "podman not installed."; fi

h3 "Kubernetes"
{
have kubectl && echo "kubectl: $(kubectl version --client -o yaml 2>/dev/null | grep -m1 gitVersion | xargs)"
have k3s && echo "k3s: $(k3s --version 2>/dev/null | head -1)"
have kubeadm && echo "kubeadm: present"
} | block
exists_note "$HOME/.kube/config"

h3 "LXC/LXD & VMs"
{
have lxc && lxc list 2>/dev/null
have virsh && { echo "== libvirt VMs =="; virsh list --all 2>/dev/null; }
} | block

# ============================================================================
h1 "11. Web / Proxy Servers"
# ============================================================================
{
for s in nginx apache2 httpd caddy traefik haproxy; do
    have "$s" && echo "$s: $("$s" -v 2>&1 | head -1)"
done
} | block
h3 "nginx enabled sites (filenames only)"
{ ls -1 /etc/nginx/sites-enabled 2>/dev/null; ls -1 /etc/nginx/conf.d 2>/dev/null; } | block
h3 "apache enabled sites (filenames only)"
{ ls -1 /etc/apache2/sites-enabled 2>/dev/null; } | block

# ============================================================================
h1 "12. Databases & Data Services (detection only — no connection, no creds)"
# ============================================================================
note "Detected by port + process + version only. The script never connects, authenticates, queries, or reads data."
{
detect_service "PostgreSQL"     "postgres"      "5432"
detect_service "MySQL/MariaDB"  "mysqld"        "3306"
detect_service "MongoDB"        "mongod"        "27017"
detect_service "Redis"          "redis-server"  "6379"
detect_service "Memcached"      "memcached"     "11211"
detect_service "Elasticsearch"  "java"          "9200"
detect_service "OpenSearch"     "java"          "9200"
detect_service "ClickHouse"     "clickhouse"    "8123"
detect_service "Cassandra"      "java"          "9042"
detect_service "RabbitMQ"       "beam.smp"      "5672"
detect_service "Kafka"          "java"          "9092"
detect_service "etcd"           "etcd"          "2379"
detect_service "MinIO"          "minio"         "9000"
detect_service "Qdrant"         "qdrant"        "6333"
detect_service "Milvus"         "milvus"        "19530"
detect_service "Weaviate"       "weaviate"      "8080"
printf '\n'
} | block

# ============================================================================
h1 "13. AI / ML Runtimes (detection only)"
# ============================================================================
{
detect_service "Ollama"             "ollama"   "11434"
detect_service "vLLM"               "vllm"     "8000"
detect_service "llama.cpp server"   "llama"    "8080"
detect_service "LocalAI"            "local-ai" "8080"
detect_service "Text-Gen-WebUI"     "server.py" "7860"
printf '\n'
} | block
h3 "ML Python packages"
if have pip3; then pip3 list 2>/dev/null | grep -iE "torch|tensorflow|vllm|transformers|langchain|llama|sentence|onnx|jax|accelerate|diffusers" | block; else note "pip3 not present."; fi
h3 "Model caches (existence + size only, contents never read)"
{ for d in "$HOME/.ollama" "$HOME/.cache/huggingface" /usr/share/ollama/.ollama /root/.ollama; do [ -d "$d" ] && echo "$d: $(du -sh "$d" 2>/dev/null | cut -f1)"; done; } | block

# ============================================================================
h1 "14. Developer Tooling"
# ============================================================================
{
for c in "git --version" "make --version" "cmake --version" "docker --version" "terraform --version" "ansible --version"; do
    name=${c%% *}; have "$name" && echo "$name: $(eval "$c" 2>&1 | head -1)"
done
have nvm && echo "nvm: present"; have pyenv && echo "pyenv: present"; have asdf && echo "asdf: present"
} | block
h3 "Git global config (redacted)"
git config --global --list 2>/dev/null | redact | block
h3 "Installed shells"
safe_cat /etc/shells

# ============================================================================
h1 "15. Security Posture"
# ============================================================================
note "SSH host keys and shadow hashes are never read; only config flags are reported."

h3 "Mandatory access control"
{
have getenforce && echo "SELinux: $(getenforce 2>/dev/null)"
have aa-status && echo "AppArmor: $(aa-status --enabled 2>/dev/null && echo enabled || echo disabled)"
} | block

h3 "SSH server config (flags only)"
{
for k in Port PermitRootLogin PasswordAuthentication PubkeyAuthentication X11Forwarding PermitEmptyPasswords; do
    v=$(grep -iE "^[[:space:]]*$k" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1)
    echo "$k: ${v:-default}"
done
} | block

h3 "Security services"
{
detect_service "fail2ban" "fail2ban-server" ""
have auditctl && echo "auditd: $(auditctl -s 2>/dev/null | grep -m1 enabled)"
[ -f /etc/apt/apt.conf.d/20auto-upgrades ] && echo "unattended-upgrades: configured"
} | block

h3 "Services bound to 0.0.0.0 (externally reachable)"
ss -tlnH 2>/dev/null | awk '{print $4}' | grep -E '^0\.0\.0\.0|^\*|^\[::\]' | sort -u | block

# ============================================================================
h1 "16. Boot & Kernel"
# ============================================================================
h3 "Kernel command line (redacted)"
safe_cat /proc/cmdline
h3 "Loaded modules"
lsmod 2>/dev/null | awk 'NR>1{print $1}' | sort | block
h3 "Key sysctl"
{ for k in vm.swappiness vm.overcommit_memory net.ipv4.ip_forward kernel.hostname fs.file-max; do echo "$k = $(sysctl -n "$k" 2>/dev/null)"; done; } | block

# ============================================================================
h1 "17. Health (counts only)"
# ============================================================================
kv "Load average" "$(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null)"
kv "Failed systemd units" "$(systemctl list-units --state=failed --no-legend --no-pager 2>/dev/null | wc -l)"
kv "Journal errors (this boot)" "$(journalctl -p err -b --no-pager 2>/dev/null | wc -l)"
kv "Journal critical (this boot)" "$(journalctl -p crit -b --no-pager 2>/dev/null | wc -l)"
kv "dmesg error/warn lines" "$(dmesg --level=err,warn 2>/dev/null | wc -l)"
kv "OOM-kill events (this boot)" "$(dmesg 2>/dev/null | grep -c -i 'out of memory')"
kv "Reboots recorded" "$(last -x reboot 2>/dev/null | grep -c reboot)"

# ============================================================================
h1 "18. Environment (variable NAMES only — values never shown)"
# ============================================================================
note "Variable values are intentionally omitted; they frequently contain secrets."
env 2>/dev/null | cut -d= -f1 | sort -u | block
kv "PATH entries" "$(echo "${PATH:-}" | tr ':' '\n' | wc -l)"
kv "Default shell" "${SHELL:-n/a}"
kv "umask" "$(umask 2>/dev/null)"

# ============================================================================
h1 "Summary"
# ============================================================================
{
echo "| Field | Value |"
echo "|-------|-------|"
echo "| OS | $(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '\"') |"
echo "| Kernel | $(uname -r 2>/dev/null) |"
echo "| Arch | $(uname -m 2>/dev/null) |"
echo "| Virtualization | $(systemd-detect-virt 2>/dev/null || echo bare-metal) |"
echo "| CPU | $(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | xargs) ($(nproc 2>/dev/null) threads) |"
echo "| RAM | $(awk '/MemTotal/{printf "%.1f GB",$2/1024/1024}' /proc/meminfo 2>/dev/null) |"
echo "| GPU | $(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | paste -sd, - || echo none) |"
echo "| Docker | $(docker --version 2>/dev/null | awk '{print $3}' | tr -d ',' || echo 'not installed') |"
echo "| Containers | $(docker ps -q 2>/dev/null | wc -l) running / $(docker ps -aq 2>/dev/null | wc -l) total |"
echo "| Uptime | $(uptime -p 2>/dev/null) |"
echo "| Failed units | $(systemctl list-units --state=failed --no-legend --no-pager 2>/dev/null | wc -l) |"
} | block

printf '\n---\n_Audit complete: %s_\n' "$(date '+%Y-%m-%d %H:%M:%S %Z')"

if [ -n "$REPORT_FILE" ]; then
    printf '\n_Report saved to: %s_\n' "$REPORT_FILE" >&2
fi
