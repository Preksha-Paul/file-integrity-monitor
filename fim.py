"""
File Integrity Monitor (FIM)
----------------------------
Takes a "fingerprint" (SHA-256 hash) of every file in a folder, saves it,
and later tells you which files were MODIFIED, ADDED, or DELETED.

Attackers often change system files: adding a user to /etc/passwd,
planting an SSH key, or editing a startup script. A FIM catches that.

Usage:
    py fim.py baseline <folder>     Step 1: take fingerprints and save them
    py fim.py check    <folder>     Step 2: compare the folder to the saved fingerprints
    py fim.py watch    <folder>     Keep checking every few seconds (Ctrl+C to stop)
"""

import argparse
import hashlib
import json
import os
import sys
import time
from datetime import datetime

# ---------- Colors for the terminal ----------
os.system("")  # turns on color support in older Windows terminals
RED, YELLOW, GREEN, BOLD, RESET = "\033[91m", "\033[93m", "\033[92m", "\033[1m", "\033[0m"

# Files attackers love to change. A change to one of these is CRITICAL.
SENSITIVE = {
    "passwd", "shadow", "group", "gshadow", "sudoers", "hosts", "crontab",
    "sshd_config", "authorized_keys", ".bashrc", ".profile",
}

# Every alert is also saved here, next to this script
ALERT_LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fim_alerts.log")


# ---------- Step A: fingerprint one file ----------
def hash_file(path):
    """Return the SHA-256 fingerprint of a file.
    Change even ONE letter in the file and this changes completely."""
    sha = hashlib.sha256()
    with open(path, "rb") as f:                        # "rb" = read raw bytes
        for chunk in iter(lambda: f.read(65536), b""): # read in pieces, so big files are OK
            sha.update(chunk)
    return sha.hexdigest()


# ---------- Step B: fingerprint a whole folder ----------
def scan_folder(folder, skip=()):
    """Walk through every file in the folder and fingerprint it.
    Returns a dictionary: relative path -> {hash, size}"""
    results = {}
    unreadable = 0
    for root, _dirs, files in os.walk(folder):
        for name in files:
            full = os.path.join(root, name)
            if os.path.islink(full) or os.path.abspath(full) in skip:
                continue
            rel = os.path.relpath(full, folder).replace("\\", "/")
            try:
                results[rel] = {"hash": hash_file(full), "size": os.path.getsize(full)}
            except (PermissionError, OSError):
                unreadable += 1        # e.g. files only root can read
    return results, unreadable


# ---------- Step C: compare old fingerprints to new ones ----------
def compare(old, new):
    """Return three lists: modified, added, deleted."""
    modified = [p for p in new if p in old and new[p]["hash"] != old[p]["hash"]]
    added = [p for p in new if p not in old]
    deleted = [p for p in old if p not in new]
    return sorted(modified), sorted(added), sorted(deleted)


def severity(path):
    """CRITICAL if it's a file attackers like to change, otherwise WARNING."""
    name = os.path.basename(path)
    # Linux keeps backup copies like "shadow-" with the same sensitive data.
    # Attackers can edit these too, so treat them like the original.
    if name.endswith("-"):
        name = name[:-1]
    # Every file inside sudoers.d can give someone admin rights
    if name in SENSITIVE or "sudoers.d/" in path:
        return "CRITICAL"
    return "WARNING"


# ---------- Saving and loading the baseline ----------
def default_baseline_path(folder):
    """Save the baseline NEXT TO the script, not inside the watched folder."""
    name = os.path.basename(os.path.abspath(folder).rstrip("/\\")) or "root"
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), f"baseline_{name}.json")


def save_baseline(path, folder, files):
    data = {
        "folder": os.path.abspath(folder),
        "created": datetime.now().isoformat(timespec="seconds"),
        "files": files,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def load_baseline(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# ---------- Reporting ----------
def report(modified, added, deleted, old, new):
    """Print each change and also save it to the alert log. Returns number of changes."""
    changes = (
        [("MODIFIED", p) for p in modified]
        + [("ADDED", p) for p in added]
        + [("DELETED", p) for p in deleted]
    )
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(ALERT_LOG, "a", encoding="utf-8") as log:
        for kind, path in changes:
            level = severity(path)
            color = RED if level == "CRITICAL" else YELLOW
            detail = ""
            if kind == "MODIFIED":
                detail = f"  (size {old[path]['size']} -> {new[path]['size']} bytes)"
            print(f"{color}{BOLD}[{level}]{RESET} {kind:<8} {path}{detail}")
            log.write(f"{stamp} [{level}] {kind} {path}\n")
    return len(changes)


# ---------- The three commands ----------
def cmd_baseline(folder, baseline_path):
    files, unreadable = scan_folder(folder, skip={os.path.abspath(baseline_path)})
    save_baseline(baseline_path, folder, files)
    print(f"{GREEN}Baseline saved:{RESET} {len(files)} files fingerprinted -> {baseline_path}")
    if unreadable:
        print(f"{YELLOW}{unreadable} file(s) could not be read (try running with sudo).{RESET}")


def cmd_check(folder, baseline_path, quiet=False):
    base = load_baseline(baseline_path)
    old = base["files"]
    new, _ = scan_folder(folder, skip={os.path.abspath(baseline_path)})
    modified, added, deleted = compare(old, new)

    if not quiet:
        print(f"\n{BOLD}===== File Integrity Check ====={RESET}")
        print(f"Folder   : {base['folder']}")
        print(f"Baseline : {base['created']} ({len(old)} files)\n")

    count = report(modified, added, deleted, old, new)
    if not quiet:
        if count == 0:
            print(f"{GREEN}All {len(new)} files match the baseline. No changes.{RESET}\n")
        else:
            print(f"\n{BOLD}{count} change(s) found.{RESET} Logged to {ALERT_LOG}\n")
    return new


def cmd_watch(folder, baseline_path, interval):
    sys.stdout.reconfigure(line_buffering=True)  # show alerts instantly, even if output is redirected
    print(f"{BOLD}Watching {os.path.abspath(folder)} every {interval}s. Press Ctrl+C to stop.{RESET}")
    try:
        while True:
            time.sleep(interval)
            base = load_baseline(baseline_path)
            new = cmd_check(folder, baseline_path, quiet=True)
            if new != base["files"]:
                # Accept the new state, so each change is only reported once
                save_baseline(baseline_path, folder, new)
    except KeyboardInterrupt:
        print("\nStopped watching.")


def main():
    parser = argparse.ArgumentParser(description="File Integrity Monitor")
    parser.add_argument("command", choices=["baseline", "check", "watch"])
    parser.add_argument("folder", help="the folder to monitor")
    parser.add_argument("--baseline", help="where to save/load fingerprints (optional)")
    parser.add_argument("--interval", type=int, default=5, help="seconds between checks in watch mode")
    args = parser.parse_args()

    if not os.path.isdir(args.folder):
        print(f"{RED}'{args.folder}' is not a folder.{RESET}")
        return

    baseline_path = args.baseline or default_baseline_path(args.folder)

    if args.command == "baseline":
        cmd_baseline(args.folder, baseline_path)
        return

    if not os.path.exists(baseline_path):
        print(f"{RED}No baseline found. Run this first:{RESET}  py fim.py baseline {args.folder}")
        return

    if args.command == "check":
        cmd_check(args.folder, baseline_path)
    else:
        cmd_watch(args.folder, baseline_path, args.interval)


if __name__ == "__main__":
    main()
