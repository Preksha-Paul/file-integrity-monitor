# 🔍 File Integrity Monitor (FIM)

A Python tool that detects when files are **modified, added or deleted**, a core technique SOC analysts use to catch attackers who tamper with a system.

It uses only the Python standard library, so there's nothing to install.

## Why this matters

After breaking in, attackers often change system files to keep their access:

| What the attacker does | File that changes |
|---|---|
| Creates a hidden admin account | `/etc/passwd`, `/etc/shadow` |
| Plants their SSH key for a permanent backdoor | `~/.ssh/authorized_keys` |
| Turns on root login | `/etc/ssh/sshd_config` |
| Gives themselves admin rights | `/etc/sudoers` |
| Runs malware on a schedule | `crontab` |

A FIM catches **all of these**, because every change alters the file's fingerprint.

## How it works

1. **Baseline.** It calculates a **SHA-256 hash** (a unique fingerprint) of every file and saves them all to a JSON file.
2. **Check.** Later, it recalculates every hash and compares:
   - The hash is different → **MODIFIED**
   - The file is new → **ADDED**
   - The file is missing → **DELETED**
3. **Alert.** Changes to sensitive files (`passwd`, `shadow`, `sudoers`, `authorized_keys`...) are flagged **CRITICAL**, and every alert is saved to `fim_alerts.log`.

> Change even **one character** in a file and its SHA-256 hash changes completely. That's why hashing is so useful for detecting tampering.

## Usage

Requires Python 3.8 or newer.

```bash
# 1. Take a baseline (do this when the system is known to be clean)
python fim.py baseline /etc

# 2. Check for changes any time later
python fim.py check /etc

# 3. Or watch live, checking every 5 seconds (Ctrl+C to stop)
python fim.py watch /etc --interval 5
```

On Linux, use `sudo` for system folders like `/etc`, because some files can only be read by root.

## Example output

```
===== File Integrity Check =====
Baseline : 2026-11-24T16:50:24 (4 files)

[CRITICAL] MODIFIED etc/passwd  (size 32 -> 62 bytes)
[CRITICAL] MODIFIED etc/ssh/sshd_config  (size 19 -> 20 bytes)
[CRITICAL] ADDED    home/authorized_keys
[WARNING]  DELETED  home/old.txt

4 change(s) found. Logged to fim_alerts.log
```

## Home lab test: catching a backdoor account

I tested this on a Kali Linux VM by fingerprinting `/etc` (1,482 files), then simulating an attacker creating a hidden user with `sudo useradd backdoor`.

**One command changed 12 files, and the FIM caught every one:**

```
===== File Integrity Check =====
Folder   : /etc
Baseline : 2026-11-24T17:14:52 (1482 files)

[CRITICAL] MODIFIED group  (size 1338 -> 1355 bytes)
[WARNING]  MODIFIED group-  (size 1325 -> 1338 bytes)
[WARNING]  MODIFIED gshadow  (size 1122 -> 1135 bytes)
[WARNING]  MODIFIED gshadow-  (size 1111 -> 1122 bytes)
[CRITICAL] MODIFIED passwd  (size 3319 -> 3364 bytes)
[WARNING]  MODIFIED passwd-  (size 3316 -> 3319 bytes)
[CRITICAL] MODIFIED shadow  (size 1458 -> 1488 bytes)
[WARNING]  MODIFIED shadow-  (size 1360 -> 1458 bytes)
[WARNING]  MODIFIED subgid  (size 18 -> 40 bytes)
[WARNING]  MODIFIED subgid-  (size 0 -> 18 bytes)
[WARNING]  MODIFIED subuid  (size 18 -> 40 bytes)
[WARNING]  MODIFIED subuid-  (size 0 -> 18 bytes)

12 change(s) found.
```

**What the test revealed:** `gshadow` and the backup copies (`passwd-`, `shadow-`, ...) hold the same sensitive data as the originals, and an attacker could edit a backup to cover their tracks. They were only flagged as WARNING, so I updated the tool to treat them as **CRITICAL**.

### Run it yourself

On a Linux VM you own, such as Kali:

```bash
sudo python3 fim.py baseline /etc
sudo useradd backdoor            # simulate an attacker creating an account
sudo python3 fim.py check /etc   # passwd, shadow and group should show as CRITICAL
sudo userdel backdoor            # clean up
```

## Known limitations (and what real tools do)

- **The baseline itself can be tampered with.** An attacker who can edit the baseline file can hide their changes. Real FIM tools sign the baseline or store it on a separate, protected server.
- **It checks content, not permissions.** A file made world-writable wouldn't be flagged.
- **It polls instead of listening.** Watch mode re-scans every few seconds. Real tools use OS file events (like Linux `inotify`) to react instantly.

## Ideas for future versions

- [ ] Sign the baseline with HMAC so tampering with it is detected
- [ ] Also track file permissions and owners
- [ ] Send alerts to email or Slack
- [ ] Ignore files that change normally (logs, caches) via an ignore list

---
*Part of my cybersecurity learning portfolio. See also: [Brute-Force Login Detector](https://github.com/Preksha-Paul/brute-force-detector).*
