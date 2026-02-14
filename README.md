# ghost.sh

a post-exploitation bash script for hiding your ssh presence on linux targets. written for practice enviroments.

**ROOT REQUIRED**

covers the stuff you'd otherwise have to do manually every time — wiping login logs, scrubbing auth.log, dropping a persistence binary, hiding from `w` and `who`. runs in about 2 seconds.

---

## what it does

- **kills bash history** — nukes `.bash_history`, locks it immutable with `chattr +i`, patches `.bashrc` so it can never write again
- **hides from w/who** — patches systemd-logind session files directly (modern debian/ubuntu/pve don't use utmp anymore, `w` reads over d-bus). falls back to classic utmp binary patching on older systems
- **wipes wtmp** — scrubs your user, ip, and pts from `/var/log/wtmp` so `last` shows nothing
- **clears lastlog** — zeroes your uid's entry in the lastlog binary
- **scrubs auth.log** — deletes lines matching your username and ip from auth.log, syslog, secure etc. then vacuums journald
- **drops a suid shell** — copies bash to a hidden path, sets suid, timestomps it to match `/bin/bash` mtime
- **systemd timer** — recreates the suid binary every hour so it survives if someone finds and deletes it
- **hides your process** — renames the current shell in `/proc/pid/comm` to look like a kernel worker thread
- **verification** — runs checks at the end to confirm each step actually worked

---

## usage

```bash
chmod +x ghost.sh
sudo bash ghost.sh
```

after it runs, re-escalate any time with:

```bash
/var/tmp/.dbus-daemon-launch -p
```

---

## persistence

the systemd timer (`dbus-launch-helper.timer`) fires on boot and every hour after. it's named and described to blend in with real dbus services. unit files are timestomped to match existing systemd services.

to check it's running on the target:
```bash
systemctl list-timers | grep dbus
```

---

## notes

- tested on debian bookworm, proxmox ve (pve), ubuntu 22.04+
- modern systemd systems don't have `/run/utmp` at all — the script handles this automatically
- if you're on a system using `wtmpdb` (debian bookworm+), the script will remind you to also run:
  ```bash
  sqlite3 /var/log/wtmp.db 'DELETE FROM wtmp WHERE user="youruser";'
  ```
- the suid binary is timestomped to match `/bin/bash` so naive `find -newer` searches won't catch it
- ssh in cleanly with `-T` to avoid creating a utmp entry in the first place:
  ```bash
  ssh -T user@target 'unset HISTFILE; exec bash -i'
  ```



## disclaimer

for ctf and authorized penetration testing only.

--Rob
