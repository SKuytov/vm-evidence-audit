#!/usr/bin/env bash
# Read-only evidence collection for one Ubuntu VM.
#
# It does not change passwords, users, SSH, firewall rules, services, or Tailscale.
# It does not scan the company network, capture other people's traffic, or bypass filtering.
# It cannot prove that a person acted intentionally. Root or hypervisor access can change
# this VM from outside anything a guest script can see.
#
# Usage, as the administrator user, not as a pasted root shell:
#   bash vm-evidence-audit.sh
#   bash vm-evidence-audit.sh --no-capture
#   bash vm-evidence-audit.sh --since "2026-09-01" --target skuytov.eu --path /grafik/admin.php
#
# Paste FINDINGS.txt and IT-NOTE.txt back for interpretation.
# Do not paste /etc/shadow, private keys, password hashes, cookies, or Tailscale auth keys.

set -u

TARGET="skuytov.eu"
URL_PATH="/grafik/admin.php"
SINCE=""
DO_CAPTURE=1

usage() {
  cat <<'EOF'
Usage: bash vm-evidence-audit.sh [options]

Options:
  --target HOST     Hostname to test (default: skuytov.eu)
  --path PATH       URL path to test (default: /grafik/admin.php)
  --since DATE      Journal/file start time (default: 30 days ago)
  --no-capture      Skip the short packet capture to this host only
  -h, --help        Show this help

The script is read-only. It writes a report under your home directory.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      TARGET="${2:-}"
      shift 2
      ;;
    --path)
      URL_PATH="${2:-}"
      shift 2
      ;;
    --since)
      SINCE="${2:-}"
      shift 2
      ;;
    --no-capture)
      DO_CAPTURE=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$TARGET" || "$TARGET" == *"/"* || "$TARGET" == *","* || "$TARGET" == *" "* ]]; then
  echo "Target must be one hostname, not a path, list, or network." >&2
  exit 2
fi
if [[ "$URL_PATH" != /* || "$URL_PATH" == *" "* ]]; then
  echo "Path must be a single URL path starting with /." >&2
  exit 2
fi
if [[ -z "$SINCE" ]]; then
  SINCE="$(date -d '30 days ago' '+%Y-%m-%d 00:00:00')"
fi
export SINCE

if [[ "$(id -u)" -eq 0 && -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
  HOME_DIR="$(getent passwd "$SUDO_USER" | awk -F: '{print $6}')"
  RUN_USER="$SUDO_USER"
else
  HOME_DIR="${HOME}"
  RUN_USER="$(id -un)"
fi
if [[ -z "$HOME_DIR" || ! -d "$HOME_DIR" ]]; then
  echo "Cannot find a home directory for the report." >&2
  exit 1
fi

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="${HOME_DIR}/vm-audit-${STAMP}"
mkdir -p "$OUT"/{network,tailscale,accounts,persistence,files,runtime,meta}
chmod 700 "$OUT" "$OUT"/{network,tailscale,accounts,persistence,files,runtime,meta}

log() { printf '%s\n' "$*" >&2; }

if [[ "$(id -u)" -ne 0 ]]; then
  if ! sudo -v; then
    echo "sudo is required for journal, auth, and service checks." >&2
    exit 1
  fi
fi

refresh_sudo() {
  if [[ "$(id -u)" -ne 0 ]]; then
    sudo -v || true
  fi
}

as_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  else
    sudo "$@"
  fi
}

redact_file() {
  local file="$1"
  [[ -f "$file" ]] || return 0
  local tmp
  tmp="$(mktemp)"
  sed -E \
    -e 's/([A-Za-z0-9_.-]*(password|passwd|secret|token|api[_-]?key|authorization)[A-Za-z0-9_.-]*)[[:space:]]*[:=][[:space:]]*[^[:space:]]+/\1=[REDACTED]/Ig' \
    -e 's/(Bearer)[[:space:]]+[A-Za-z0-9._~+/-]+=*/\1 [REDACTED]/Ig' \
    -e 's/(tskey-)[A-Za-z0-9_-]+/\1[REDACTED]/g' \
    -e 's/(\$6\$)[^:[:space:]]+/\1[REDACTED]/g' \
    "$file" >"$tmp" && mv "$tmp" "$file"
}

save() {
  local rel="$1"
  local tmp ec
  tmp="$(mktemp)"
  cat >"$tmp"
  mkdir -p "$(dirname "$OUT/$rel")"
  log "Collecting $rel"
  {
    echo "# collected: $(date -Is)"
    echo "# section: $rel"
    echo
    bash "$tmp"
    ec=$?
    echo
    echo "# section_exit: $ec"
  } >"$OUT/$rel" 2>&1 || true
  redact_file "$OUT/$rel"
  rm -f "$tmp"
}

marker() {
  printf 'MARKER %s=%s\n' "$1" "$2" | tee -a "$OUT/meta/markers.env"
}

have() { command -v "$1" >/dev/null 2>&1; }

curl_class() {
  local ec="$1"
  local text="$2"
  if [[ "$ec" -eq 0 ]]; then
    printf 'ok'
  elif printf '%s' "$text" | grep -q 'Connection reset by peer'; then
    printf 'reset'
  elif [[ "$ec" -eq 28 || "$ec" -eq 124 ]] || printf '%s' "$text" | grep -q 'timed out\|Operation timed out'; then
    printf 'timeout'
  else
    printf 'other'
  fi
}

log "Report directory: $OUT"
log "This script only reads system state. It will not change the VM."

refresh_sudo

save meta/00-scope.txt <<BASH
echo "time_local=$(date -Is)"
echo "time_utc=$(date -u)"
echo "runner=$RUN_USER"
echo "target=$TARGET"
echo "path=$URL_PATH"
echo "since=$SINCE"
echo "capture=$DO_CAPTURE"
echo "hostname=$(hostname -f 2>/dev/null || hostname)"
echo "virt=$(systemd-detect-virt 2>/dev/null || true)"
echo "kernel=$(uname -a)"
. /etc/os-release 2>/dev/null || true
echo "os=\${PRETTY_NAME:-unknown}"
echo
echo "Read-only audit. No passwords, services, firewall rules, or SSH settings were changed."
BASH

save network/01-baseline.txt <<'BASH'
echo "=== TIME ==="
date -Is
date -u
echo "=== HOST ==="
hostname -f 2>/dev/null || hostname
hostnamectl 2>/dev/null || true
echo "=== VIRT ==="
systemd-detect-virt 2>/dev/null || true
echo "=== ADDRESSES ==="
ip -br address
echo "=== ROUTES ==="
ip route
echo "=== RESOLVER ==="
resolvectl status 2>/dev/null || true
echo "=== RESOLV.CONF ==="
cat /etc/resolv.conf 2>/dev/null || true
echo "=== PROXY ENVIRONMENT ==="
env | grep -iE '^(http|https|all|no)_proxy=' || echo "no proxy environment variables"
echo "=== UPTIME / BOOT ==="
uptime
who -b || true
BASH

save network/02-dns.txt <<BASH
echo "=== SYSTEM LOOKUP ==="
getent ahosts "$TARGET" || true
echo "=== RESOLVED ==="
resolvectl query "$TARGET" 2>&1 || true
echo "=== DEFAULT DIG ==="
if command -v dig >/dev/null 2>&1; then
  dig +time=2 +tries=1 "$TARGET" A
  echo
  dig +time=2 +tries=1 "$TARGET" AAAA
  echo "=== COMPANY AND PUBLIC COMPARISON ==="
  servers="\$(resolvectl dns 2>/dev/null | awk '{for (i=1; i<=NF; i++) if (\$i ~ /^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+\$/) print \$i}' | sort -u)"
  printf '%s\n' "\$servers" 8.8.8.8 1.1.1.1 | awk 'NF && !seen[\$0]++' | while read -r server; do
    echo "--- dig @\$server ---"
    dig +time=2 +tries=1 "@\$server" "$TARGET" A || true
    echo
  done
else
  echo "dig is not installed; not installing packages during a read-only audit"
fi
BASH

# Network tests are functions so each result gets its own marker.
run_curl_test() {
  local name="$1"
  local url="$2"
  local extra="${3:-}"
  local outfile="$OUT/network/03-${name}.txt"
  local raw ec klass
  log "Testing $name"
  raw="$(mktemp)"
  # shellcheck disable=SC2086
  timeout 25 curl --noproxy '*' -4 -v --http1.1 \
    --connect-timeout 8 --max-time 18 \
    -o /dev/null \
    $extra \
    "$url" >"$raw" 2>&1
  ec=$?
  klass="$(curl_class "$ec" "$(cat "$raw")")"
  {
    echo "# collected: $(date -Is)"
    echo "# url: $url"
    echo "# extra: ${extra:-none}"
    echo "MARKER ${name}_exit=$ec"
    echo "MARKER ${name}_class=$klass"
    echo
    cat "$raw"
  } >"$outfile"
  redact_file "$outfile"
  rm -f "$raw"
  marker "${name}_exit" "$ec"
  marker "${name}_class" "$klass"
}

run_curl_test "http_path" "http://${TARGET}${URL_PATH}"
run_curl_test "https_path" "https://${TARGET}${URL_PATH}"
run_curl_test "https_root" "https://${TARGET}/"
run_curl_test "control_ubuntu" "https://ubuntu.com/"
run_curl_test "control_example" "https://example.com/"

save network/04-tcp.txt <<BASH
echo "=== TCP 443 ==="
nc -vz -w 6 "$TARGET" 443
echo "tcp443_exit=\$?"
echo "=== TCP 80 ==="
nc -vz -w 6 "$TARGET" 80
echo "tcp80_exit=\$?"
BASH

RESOLVED_IP="$(getent ahostsv4 "$TARGET" 2>/dev/null | awk '{print $1; exit}')"
if [[ -z "$RESOLVED_IP" ]]; then
  RESOLVED_IP="$(getent ahosts "$TARGET" 2>/dev/null | awk '$1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {print $1; exit}')"
fi
marker "resolved_ip" "${RESOLVED_IP:-unresolved}"

if [[ -n "$RESOLVED_IP" ]]; then
  run_curl_test "http_ip_only" "http://${RESOLVED_IP}/"
  run_curl_test "http_ip_with_host" "http://${RESOLVED_IP}/" "-H Host:${TARGET}"

  save network/05-tls-sni.txt <<BASH
run_tls() {
  local label="\$1"
  shift
  local out ec established
  out="\$(mktemp)"
  echo "===== \$label ====="
  timeout 18 openssl s_client "\$@" </dev/null >"\$out" 2>&1
  ec=\$?
  cat "\$out"
  if grep -q 'CONNECTION ESTABLISHED' "\$out"; then
    established=yes
  else
    established=no
  fi
  echo "MARKER \${label}_exit=\$ec"
  echo "MARKER \${label}_established=\$established"
  rm -f "\$out"
  echo
}
run_tls tls_no_sni -connect "${RESOLVED_IP}:443" -noservername -brief
run_tls tls_with_sni -connect "${RESOLVED_IP}:443" -servername "$TARGET" -brief
run_tls tls12_with_sni -connect "${RESOLVED_IP}:443" -servername "$TARGET" -tls1_2 -brief
BASH

  save network/06-path.txt <<BASH
echo "=== TRACEPATH ==="
if command -v tracepath >/dev/null 2>&1; then
  tracepath -4 -m 8 "$RESOLVED_IP" || true
elif command -v traceroute >/dev/null 2>&1; then
  traceroute -n -w 2 -m 8 -q 1 "$RESOLVED_IP" || true
else
  echo "neither tracepath nor traceroute is installed"
fi
echo "=== EGRESS IP ==="
timeout 12 curl --noproxy '*' -4 --connect-timeout 5 --max-time 8 https://api.ipify.org || echo "egress lookup failed"
echo
BASH
else
  echo "Could not resolve $TARGET; skipped IP, SNI, and path tests." >"$OUT/network/05-tls-sni.txt"
fi

if [[ "$DO_CAPTURE" -eq 1 && -n "$RESOLVED_IP" ]] && have tcpdump; then
  log "Capturing only this VM's test connection to ${RESOLVED_IP}:80 and :443"
  refresh_sudo
  as_root timeout 40 tcpdump -i any -nn -s 0 -c 500 \
    -w "$OUT/network/07-failure.pcap" \
    "host ${RESOLVED_IP} and (tcp port 80 or tcp port 443)" &
  cap_pid=$!
  sleep 2
  timeout 18 curl --noproxy '*' -4 --http1.1 --connect-timeout 8 --max-time 12 \
    -o /dev/null "http://${TARGET}${URL_PATH}" >"$OUT/network/07-capture-http.txt" 2>&1 || true
  timeout 18 curl --noproxy '*' -4 --http1.1 --connect-timeout 8 --max-time 12 \
    -o /dev/null "https://${TARGET}${URL_PATH}" >"$OUT/network/07-capture-https.txt" 2>&1 || true
  sleep 2
  as_root kill -INT "$cap_pid" 2>/dev/null || true
  wait "$cap_pid" 2>/dev/null || true
  as_root tcpdump -nn -tttt -r "$OUT/network/07-failure.pcap" \
    'tcp[tcpflags] & (tcp-syn|tcp-fin|tcp-rst) != 0' \
    >"$OUT/network/07-syn-fin-rst.txt" 2>&1 || true
  {
    echo "=== RESETS APPARENTLY FROM REMOTE SIDE ==="
    grep -E "${RESOLVED_IP}\\.(80|443) > " "$OUT/network/07-syn-fin-rst.txt" | grep -E 'Flags \[R' || echo "none found"
    echo "=== RESETS APPARENTLY FROM THIS VM ==="
    grep -E "> ${RESOLVED_IP}\\.(80|443)" "$OUT/network/07-syn-fin-rst.txt" | grep -E 'Flags \[R' || echo "none found"
  } >"$OUT/network/07-reset-direction.txt" 2>&1 || true
  if [[ -f "$OUT/network/07-failure.pcap" ]]; then
    as_root chown "$RUN_USER:" "$OUT/network/07-failure.pcap" 2>/dev/null || true
  fi
elif [[ "$DO_CAPTURE" -eq 1 ]]; then
  echo "tcpdump is not installed or the target did not resolve. Not installing packages." \
    >"$OUT/network/07-syn-fin-rst.txt"
fi

if [[ -f "$OUT/network/05-tls-sni.txt" ]]; then
  while IFS= read -r line; do
    kv="${line#MARKER }"
    marker "${kv%%=*}" "${kv#*=}"
  done < <(grep '^MARKER ' "$OUT/network/05-tls-sni.txt" || true)
fi

save tailscale/01-state.txt <<'BASH'
echo "=== UNIT STATUS ==="
sudo systemctl status tailscaled --no-pager -l || true
echo "=== ACTIVE / ENABLED ==="
echo -n "is-active: "; sudo systemctl is-active tailscaled || true
echo -n "is-enabled: "; sudo systemctl is-enabled tailscaled || true
echo "=== PROPERTIES ==="
sudo systemctl show tailscaled \
  -p FragmentPath -p DropInPaths -p LoadState -p ActiveState -p SubState \
  -p UnitFileState -p Result -p ExecMainCode -p ExecMainStatus \
  -p NRestarts -p Restart -p RestartUSec -p InvocationID || true
echo "=== UNIT AND OVERRIDES ==="
sudo systemctl cat tailscaled || true
echo "=== RELATED UNIT FILES ==="
sudo find /etc/systemd/system /run/systemd/system /lib/systemd/system /usr/lib/systemd/system \
  -iname '*tailscale*' -o -iname '*tailscaled*' 2>/dev/null | head -n 100
echo "=== BINARY ==="
bin="$(command -v tailscaled || true)"
echo "path=$bin"
if [[ -n "$bin" ]]; then
  sudo stat "$bin" || true
  sha256sum "$bin" || true
  dpkg-query -S "$bin" 2>&1 || true
fi
echo "=== VERSION / STATUS ==="
tailscale version 2>&1 || true
sudo tailscale status 2>&1 || true
echo "=== NETCHECK ==="
sudo timeout 30 tailscale netcheck 2>&1 || true
echo "=== INTERFACE ==="
ip -br address show tailscale0 2>&1 || true
BASH

save tailscale/02-journal.txt <<BASH
echo "=== TAILSCALED JOURNAL ==="
sudo journalctl -u tailscaled --since "$SINCE" --no-pager -o short-iso -n 2500 || true
BASH

save tailscale/03-stop-events.txt <<BASH
echo "=== FILTERED TAILSCALE / SHUTDOWN / OOM EVENTS ==="
sudo journalctl --since "$SINCE" --no-pager -o short-iso -n 8000 \
  | grep -iE 'tailscaled|tailscale |Stopped tailscaled|Started tailscaled|Deactivated successfully|code=killed|oom-kill|Out of memory|segfault|systemd-sysv-install|systemctl' \
  | grep -iE 'tailscale|oom|killed process|reboot|shutdown' \
  | tail -n 400 || true
echo
echo "=== BOOTS ==="
sudo journalctl --list-boots --no-pager | tail -n 40 || true
echo
echo "=== OOM FROM DMESG ==="
sudo dmesg -T 2>/dev/null | grep -iE 'out of memory|oom-kill|killed process' | tail -n 40 || echo "no dmesg OOM lines or dmesg unavailable"
BASH

save accounts/01-identity.txt <<'BASH'
echo "=== WHO ==="
whoami
id
echo "=== LOCAL AND RESOLVED ACCOUNTS ==="
getent passwd administrator || true
getent passwd root || true
echo "=== UID 0 ACCOUNTS ==="
getent passwd | awk -F: '$3==0 {print}'
echo "=== HUMAN ACCOUNTS ==="
getent passwd | awk -F: '$3>=1000 && $3<65534 {print $1, $3, $6, $7}'
echo "=== NSS ==="
grep -E '^(passwd|shadow|group):' /etc/nsswitch.conf || true
echo "=== SUDO GROUP ==="
getent group sudo || true
getent group admin || true
echo "=== CURRENT SUDO RIGHTS ==="
sudo -l || true
echo "=== SUDOERS FILE NAMES ONLY ==="
sudo ls -la /etc/sudoers /etc/sudoers.d 2>&1 || true
BASH

save accounts/02-password-source.txt <<'BASH'
echo "=== PASSWORD STATUS, NOT THE PASSWORD ==="
sudo passwd -S administrator 2>&1 || true
sudo passwd -S root 2>&1 || true
echo "=== PASSWORD AGING ==="
sudo chage -l administrator 2>&1 || true
sudo chage -l root 2>&1 || true
echo "=== SHADOW METADATA ONLY, CONTENTS NOT READ ==="
sudo stat /etc/passwd /etc/shadow /etc/group 2>&1 || true
sudo lsattr /etc/passwd /etc/shadow /etc/group 2>&1 || true
echo "=== DIRECTORY AUTH SERVICES ==="
for svc in sssd winbind nslcd systemd-userdbd; do
  echo -n "$svc active: "
  systemctl is-active "$svc" 2>&1 || true
  echo -n "$svc enabled: "
  systemctl is-enabled "$svc" 2>&1 || true
done
echo "=== PAM SOURCES ==="
sudo grep -RInE 'pam_(sss|ldap|winbind|krb5|unix|pwquality|faillock)' \
  /etc/pam.d/common-auth /etc/pam.d/common-password /etc/pam.d/passwd /etc/pam.d/sshd \
  2>/dev/null || true
echo "=== CLOUD-INIT ==="
systemctl is-active cloud-init 2>&1 || true
systemctl is-enabled cloud-init 2>&1 || true
cloud-init status 2>&1 || true
sudo grep -RInE 'users:|lock_passwd|ssh_pwauth|chpasswd|set_passwords|preserve_hostname' \
  /etc/cloud/cloud.cfg /etc/cloud/cloud.cfg.d 2>/dev/null || true
echo "=== CLOUD-INIT MODULE RUNS, NOT USER-DATA ==="
sudo grep -nE 'set_passwords|users-groups|users_groups|Running module' \
  /var/log/cloud-init.log 2>/dev/null | tail -n 40 || echo "no cloud-init module lines"
echo "=== GUEST AGENT ==="
echo -n "qemu-guest-agent active: "
systemctl is-active qemu-guest-agent 2>&1 || true
echo -n "qemu-guest-agent enabled: "
systemctl is-enabled qemu-guest-agent 2>&1 || true
sudo systemctl status qemu-guest-agent --no-pager -l 2>&1 | head -n 40 || true
sudo journalctl -u qemu-guest-agent --since "$SINCE" --no-pager -o short-iso -n 200 2>&1 || true
echo "=== PASSWORD CHANGE EVENTS ==="
sudo journalctl --since "$SINCE" --no-pager -o short-iso \
  | grep -iE 'password changed|password for|chauthtok|pam_unix\(passwd|guest-set-user-password|set-user-password' \
  | tail -n 200 || true
BASH

save accounts/03-ssh.txt <<'BASH'
echo "=== EFFECTIVE SSHD POLICY ==="
sudo sshd -T 2>/dev/null | grep -Ei '^(passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|permitrootlogin|authenticationmethods|authorizedkeysfile|authorizedkeyscommand|authorizedkeyscommanduser|usepam) ' || true
echo "=== SSH CONFIG REFERENCES ==="
sudo grep -RInE '^[[:space:]]*(AuthorizedKeysFile|AuthorizedKeysCommand|PermitRootLogin|PasswordAuthentication|Include|Match)[[:space:]]' \
  /etc/ssh/sshd_config /etc/ssh/sshd_config.d 2>/dev/null || true
echo "=== AUTHORIZED KEY FINGERPRINTS ONLY ==="
sudo find /root /home -xdev -type f \( -name authorized_keys -o -name authorized_keys2 \) -print0 2>/dev/null \
  | while IFS= read -r -d '' file; do
      echo "=== $file ==="
      sudo stat "$file" || true
      sudo ssh-keygen -lf "$file" 2>&1 || true
    done
echo "=== SSH SERVICE ==="
systemctl is-active ssh 2>&1 || systemctl is-active sshd 2>&1 || true
BASH

save accounts/04-access.txt <<BASH
echo "=== RECENT LOGINS ==="
sudo last -Faiwx | head -n 80 || true
echo "=== FAILED LOGINS ==="
sudo lastb -Fai 2>&1 | head -n 80 || true
echo "=== CURRENT SESSIONS ==="
who -a || true
w || true
echo "=== SSH / SUDO JOURNAL ==="
sudo journalctl --since "$SINCE" --no-pager -o short-iso \
  | grep -iE 'sshd|Accepted |Failed password|Invalid user|sudo:|session opened for user root|session closed for user root' \
  | tail -n 500 || true
BASH

save persistence/01-schedulers.txt <<'BASH'
echo "=== SYSTEMD TIMERS ==="
sudo systemctl list-timers --all --no-pager || true
echo "=== CRON PATHS ==="
sudo ls -la /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /var/spool/cron /var/spool/cron/crontabs 2>/dev/null || true
echo "=== /etc/crontab ==="
sudo sed -n '1,240p' /etc/crontab 2>/dev/null || true
echo "=== /etc/cron.d ==="
sudo sh -c 'for f in /etc/cron.d/*; do [ -f "$f" ] || continue; echo "----- $f -----"; sed -n "1,160p" "$f"; done' 2>/dev/null || true
echo "=== ROOT CRONTAB ==="
sudo crontab -l -u root 2>&1 || true
echo "=== ADMINISTRATOR CRONTAB ==="
sudo crontab -l -u administrator 2>&1 || true
echo "=== AT QUEUE ==="
sudo atq 2>&1 || true
echo "=== RC LOCAL ==="
sudo ls -la /etc/rc.local 2>&1 || true
sudo sed -n '1,160p' /etc/rc.local 2>/dev/null || true
BASH

save persistence/02-references.txt <<BASH
echo "=== REFERENCES TO STOPPING TAILSCALE OR RESETTING LOCAL PASSWORDS ==="
echo "A match is a lead, not proof. It may be documentation, history, or a legitimate maintenance script."
pattern='systemctl[[:space:]]+(stop|disable|mask|restart)[[:space:]]+tailscaled|service[[:space:]]+tailscaled[[:space:]]+stop|pkill[[:space:]].*tailscale|killall[[:space:]].*tailscale|tailscale[[:space:]]+(down|logout)|chpasswd|usermod[[:space:]].*-p|guest-set-user-password|cp[[:space:]].*shadow'
sudo grep -RInE -m 3 --binary-files=without-match \
  --exclude='*.log' --exclude='*.journal' --exclude='*.pcap' --exclude='*.gz' \
  --exclude='*.tar' --exclude='*.tar.gz' --exclude='vm-evidence-audit.sh' \
  --exclude-dir="$(basename "$OUT")" \
  "\$pattern" \
  /etc/systemd /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly \
  /etc/crontab /var/spool/cron /usr/local/bin /usr/local/sbin /opt /root \
  /home/administrator /etc/profile.d /etc/rc.local \
  2>/dev/null | head -n 200 || true
BASH

save persistence/03-management-agents.txt <<'BASH'
echo "=== CONFIGURATION MANAGEMENT AND HYPERVISOR AGENTS ==="
for svc in qemu-guest-agent spice-vdagentd cloud-init cloud-final cloud-config \
  landscape-client unattended-upgrades apt-daily.timer apt-daily-upgrade.timer \
  puppet pxp-agent salt-minion chef-client amazon-ssm-agent; do
  state="$(systemctl is-active "$svc" 2>/dev/null || true)"
  enabled="$(systemctl is-enabled "$svc" 2>/dev/null || true)"
  if [[ -n "$state" || -n "$enabled" ]]; then
    printf '%-32s active=%-12s enabled=%s\n' "$svc" "${state:-n/a}" "${enabled:-n/a}"
  fi
done
echo "=== INSTALLED AGENT PACKAGES ==="
dpkg-query -W -f='${binary:Package}\t${Version}\n' 2>/dev/null \
  | grep -Ei 'qemu-guest|cloud-init|landscape|puppet|salt|chef|ansible|tailscale|openssh' || true
echo "=== UNATTENDED UPGRADES ==="
systemctl status unattended-upgrades --no-pager -l 2>&1 | head -n 30 || true
sudo grep -RIn tailscale /var/log/unattended-upgrades /var/log/apt 2>/dev/null | tail -n 40 || true
BASH

save files/01-recent-admin-files.txt <<BASH
echo "=== FILES CHANGED SINCE $SINCE ==="
sudo find /etc /usr/local /opt /root /home/administrator \
  -xdev \
  \( -path '*/.cache' -o -path '*/node_modules' -o -path '*/.git' -o -path '$OUT' -o -path '*/vm-audit-*' \) -prune \
  -o -type f -newermt '$SINCE' \
  -printf '%TY-%Tm-%Td %TH:%TM %u:%g %m %s %p\n' \
  2>/dev/null | sort | head -n 400
BASH

save files/02-packages.txt <<'BASH'
echo "=== PACKAGE VERIFICATION FOR AUTH AND TAILSCALE ==="
sudo dpkg -V passwd login sudo openssh-server openssh-client tailscale 2>&1 || true
echo "=== RECENT APT ACTIONS ==="
sudo zgrep -hE '^(Start-Date|Commandline|Requested-By|Install|Upgrade|Remove|Purge|End-Date)' \
  /var/log/apt/history.log /var/log/apt/history.log.1 /var/log/apt/history.log.*.gz 2>/dev/null \
  | tail -n 250 || true
BASH

save runtime/01-processes.txt <<'BASH'
echo "=== FAILED UNITS ==="
sudo systemctl --failed --no-pager || true
echo "=== LISTENERS ==="
sudo ss -lntup || true
echo "=== DELETED EXECUTABLES ==="
sudo ls -l /proc/[0-9]*/exe 2>/dev/null | grep deleted || echo "none"
echo "=== EXECUTABLES UNDER TEMP ==="
sudo find /tmp /var/tmp /dev/shm -xdev -type f -executable 2>/dev/null | head -n 80 || true
echo "=== PROCESS COMMANDS, REDACTED ==="
sudo ps -eo user,pid,lstart,cmd --sort=lstart || true
BASH

save runtime/02-firewall.txt <<'BASH'
echo "Local VM firewall only. A company gateway filter will not appear here."
echo "=== NFT ==="
sudo nft list ruleset 2>&1 | head -n 300 || true
echo "=== IPTABLES ==="
sudo iptables -S 2>&1 | head -n 200 || true
echo "=== IP6TABLES ==="
sudo ip6tables -S 2>&1 | head -n 80 || true
BASH

log "Writing findings"
FINDINGS="$OUT/FINDINGS.txt"
NOTE="$OUT/IT-NOTE.txt"

mget() {
  local key="$1"
  local value
  value="$(grep -h "^MARKER ${key}=" "$OUT/meta/markers.env" 2>/dev/null | tail -n 1 | cut -d= -f2-)"
  printf '%s' "${value:-unknown}"
}

{
  echo "VM evidence summary"
  echo "Collected: $(date -Is)"
  echo "Host: $(hostname -f 2>/dev/null || hostname)"
  echo "Runner: $RUN_USER"
  echo "Target: $TARGET"
  echo "Resolved IP: $(mget resolved_ip)"
  echo "Window start: $SINCE"
  echo
  echo "This is a technical summary, not a finding of personal intent."
  echo "Company IT with the root password, SSH access, or Proxmox/hypervisor access can change this VM without a script inside it."
  echo
  echo "## Network"
  echo "- HTTP ${URL_PATH}: $(mget http_path_class) (curl exit $(mget http_path_exit))"
  echo "- HTTPS ${URL_PATH}: $(mget https_path_class) (curl exit $(mget https_path_exit))"
  echo "- HTTPS /: $(mget https_root_class) (curl exit $(mget https_root_exit))"
  echo "- Control ubuntu.com: $(mget control_ubuntu_class) (curl exit $(mget control_ubuntu_exit))"
  echo "- Control example.com: $(mget control_example_class) (curl exit $(mget control_example_exit))"
  if [[ -n "$RESOLVED_IP" ]]; then
    echo "- HTTP to IP only: $(mget http_ip_only_class) (curl exit $(mget http_ip_only_exit))"
    echo "- HTTP to IP with Host ${TARGET}: $(mget http_ip_with_host_class) (curl exit $(mget http_ip_with_host_exit))"
  fi
  echo
  echo "How to read the network result:"
  echo "- Controls succeed, but this hostname resets or times out: destination-specific filtering, TLS/SNI handling, or a block aimed at this host or the company public IP."
  echo "- IP-only responds and the same request with Host: ${TARGET} resets: hostname-aware filtering on plaintext HTTP."
  echo "- No-SNI TLS responds and SNI TLS stalls: something acts after reading the hostname from the TLS ClientHello."
  echo "- Controls also fail: this VM has a broader outbound HTTPS problem; it is not specific to ${TARGET}."
  echo "- HTTPS succeeds here: the Ubuntu VM is not the failing point; compare the Windows PC, browser policy, and endpoint protection."
  echo "- A TCP reset still does not identify the person or device that generated it. An inline firewall can forge the server address."
  echo "- TLS without SNI established: $(mget tls_no_sni_established)"
  echo "- TLS with SNI established: $(mget tls_with_sni_established)"
  echo "- TLS 1.2 with SNI established: $(mget tls12_with_sni_established)"
  if [[ "$(mget control_ubuntu_class)" == "ok" && "$(mget https_path_class)" != "ok" ]]; then
    echo "- Pattern: general HTTPS works from this VM, while ${TARGET} does not. The failure is destination-specific."
  fi
  if [[ "$(mget http_ip_only_class)" == "ok" && "$(mget http_ip_with_host_class)" == "reset" ]]; then
    echo "- Pattern: the IP responds until the request names ${TARGET}. That fits hostname-aware filtering."
  fi
  if [[ "$(mget tls_no_sni_established)" == "yes" && "$(mget tls_with_sni_established)" == "no" ]]; then
    echo "- Pattern: TLS completes only when the hostname is omitted. Something acts after reading SNI."
  fi
  echo
  echo "## Tailscale"
  active_line="$(grep -m1 '^is-active:' "$OUT/tailscale/01-state.txt" 2>/dev/null || true)"
  enabled_line="$(grep -m1 '^is-enabled:' "$OUT/tailscale/01-state.txt" 2>/dev/null || true)"
  echo "- ${active_line:-is-active: unknown}"
  echo "- ${enabled_line:-is-enabled: unknown}"
  grep -E '^(NRestarts|Result|UnitFileState|DropInPaths|FragmentPath)=' "$OUT/tailscale/01-state.txt" 2>/dev/null || true
  if grep -q 'masked' "$OUT/tailscale/01-state.txt" 2>/dev/null; then
    echo "- The unit file state mentions masked. That is an administrative systemd setting. Review tailscale/01-state.txt before changing it."
  fi
  if grep -qi 'out of memory\|oom-kill' "$OUT/tailscale/03-stop-events.txt" 2>/dev/null; then
    echo "- Memory-pressure messages exist. Tailscale may have been killed by the kernel rather than by a script."
  fi
  echo "- Review tailscale/03-stop-events.txt for 'Stopped tailscaled', 'code=killed', and reboot lines."
  echo "- If the service stays active but the tailnet drops, this is a connectivity problem, not a script stopping the service."
  echo
  echo "## Accounts and passwords"
  echo "- Password status and aging are in accounts/02-password-source.txt. The password itself was not collected."
  if grep -q 'immutable' "$OUT/accounts/02-password-source.txt" 2>/dev/null || grep -E '^----i' "$OUT/accounts/02-password-source.txt" >/dev/null 2>&1; then
    echo "- The immutable file attribute appears to be set. passwd cannot update an immutable /etc/shadow."
  fi
  if grep -E 'sssd active: active|winbind active: active|nslcd active: active' "$OUT/accounts/02-password-source.txt" >/dev/null 2>&1; then
    echo "- A directory-authentication service is active. The password may not be the local one."
  fi
  if grep -q 'qemu-guest-agent active: active' "$OUT/accounts/02-password-source.txt" 2>/dev/null; then
    echo "- qemu-guest-agent is active. The hypervisor administrator can set a guest password without logging into the VM. Check the guest-agent journal for guest-set-user-password."
  fi
  if grep -q 'guest-set-user-password\|set-user-password' "$OUT/accounts/02-password-source.txt" 2>/dev/null; then
    echo "- A guest-agent password operation was logged. Ask for the matching hypervisor task at that timestamp. This shows the channel used; it does not by itself prove malice."
  fi
  echo "- SSH may accept a public key even after a local password change. See accounts/03-ssh.txt."
  echo "- An already-open SSH session and cached sudo are unaffected by a password change."
  echo
  echo "## Persistence leads"
  refs="$OUT/persistence/02-references.txt"
  if [[ -f "$refs" ]] && grep -E '/.+:[0-9]+:' "$refs" | grep -v '^#' | head -n 20 >"$OUT/meta/reference-hits.txt"; then
    if [[ -s "$OUT/meta/reference-hits.txt" ]]; then
      echo "- Command references found. Review them locally; do not treat a match as proof:"
      sed -n '1,20p' "$OUT/meta/reference-hits.txt"
    else
      echo "- No scheduled-script references matched the Tailscale-stop or local-password-reset patterns in the searched admin paths."
    fi
  else
    echo "- Persistence search produced no readable hits file."
  fi
  echo
  echo "## What would still be needed"
  echo "- Company firewall, proxy, or endpoint-protection log for this VM's source address and ${TARGET}."
  echo "- Proxmox or hypervisor task/audit history for console login, snapshot restore, guest-agent commands, and power actions."
  echo "- Tailscale admin-console device history, if the admin account is available."
  echo "- These logs are outside the VM. Their absence from this report is expected."
  echo
  echo "## Do not do next"
  echo "- Do not delete IT accounts, remove SSH keys, disable SSH, or change firewall policy from this report alone."
  echo "- Do not bypass the site block with a VPN, tunnel, or alternate resolver."
  echo "- Do not capture traffic other than this VM's own test connection."
} >"$FINDINGS"

{
  echo "Neutral technical note"
  echo
  echo "Host: $(hostname -f 2>/dev/null || hostname)"
  echo "Time: $(date -Is)"
  echo "Source address on eth0: $(ip -4 -br addr show eth0 2>/dev/null | awk '{print $3}')"
  echo "Tested name: ${TARGET}"
  echo "Resolved address: $(mget resolved_ip)"
  echo "HTTP ${URL_PATH}: $(mget http_path_class)"
  echo "HTTPS ${URL_PATH}: $(mget https_path_class)"
  echo "HTTPS control ubuntu.com: $(mget control_ubuntu_class)"
  echo "Tailscale service: $(grep -m1 '^is-active:' "$OUT/tailscale/01-state.txt" 2>/dev/null || echo 'unknown')"
  echo
  echo "Please compare this timestamp with the firewall or web-filter log and, if this is a Proxmox guest, the hypervisor task history."
  echo "This note records the observed failure point. It does not identify a person or assign intent."
} >"$NOTE"

(
  cd "$OUT"
  find . -type f ! -name SHA256SUMS.txt -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS.txt
)
archive="${HOME_DIR}/vm-audit-${STAMP}.tar.gz"
tar -C "$(dirname "$OUT")" -czf "$archive" "$(basename "$OUT")"
sha256sum "$archive" > "${archive}.sha256"
if [[ "$(id -u)" -eq 0 && -n "${SUDO_USER:-}" ]]; then
  chown -R "$SUDO_USER:" "$OUT" "$archive" "${archive}.sha256" || true
fi
chmod -R u=rwX,go= "$OUT" || true
chmod 600 "$archive" "${archive}.sha256" || true

log "Done."
log "Summary: $FINDINGS"
log "Neutral note: $NOTE"
log "Archive: $archive"
printf '\n%s\n' "Paste these two files only:"
printf '%s\n' "$FINDINGS"
printf '%s\n' "$NOTE"
