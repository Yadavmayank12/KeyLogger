#!/usr/bin/env python3
"""
kl_defender.py — CLI defensive scanner for detecting possible keylogger indicators.

Usage examples:
  python kl_defender.py --scan
  python kl_defender.py --scan --quarantine
  python kl_defender.py --scan --kill --yes
  python kl_defender.py --report report.txt

"""

import os
import sys
import argparse
import shutil
import tempfile
import platform
import re
from pathlib import Path
from datetime import datetime

try:
    import psutil
except Exception as e:
    print("psutil is required. Install: pip install psutil")
    raise


SUSPICIOUS_KEYWORDS = [
    "keylogger", "keyboard", "pynput", "pyHook", "hook", "smtplib",
    "smtp", "sendmail", "mail", "keystroke", "getch", "pyautogui",
    "win32api", "SetWindowsHookEx", "SetWindowsHook", "raw_input"
]
# file extensions to scan content
SCAN_EXTS = {".py", ".pyc", ".exe", ".dll", ".ps1", ".js", ".jar", ".sh"}
# where to look for dropped keyloggers / suspicious files
def default_paths():
    p = []
    system = platform.system().lower()
    home = Path.home()
    if system == "windows":
        appdata = os.getenv("APPDATA")
        localappdata = os.getenv("LOCALAPPDATA")
        temp = os.getenv("TEMP") or os.getenv("TMP")
        userprofile = os.getenv("USERPROFILE")
        p.extend([home, appdata, localappdata, temp, Path(userprofile) / "Downloads"])
    else:
        p.extend([home, home / "Downloads", "/tmp", "/var/tmp", "/usr/local/bin"])
    # filter None and duplicates
    return [Path(x) for x in p if x]

def find_suspicious_processes():
    findings = []
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username']):
        try:
            info = proc.info
            cmd = " ".join(info.get('cmdline') or []) or (info.get('exe') or info.get('name') or "")
            cmd_lower = cmd.lower()
            match = [kw for kw in SUSPICIOUS_KEYWORDS if kw.lower() in cmd_lower]
            if match:
                findings.append({
                    "pid": info.get('pid'),
                    "name": info.get('name'),
                    "cmdline": cmd,
                    "user": info.get('username'),
                    "matches": match
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return findings

def scan_network_connections():
    findings = []
    for conn in psutil.net_connections(kind='inet'):
        try:
            if conn.raddr and conn.status in ("ESTABLISHED", "CONNECTED", "SYN_SENT"):
                pid = conn.pid
                raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}"
                findings.append({
                    "pid": pid,
                    "laddr": laddr,
                    "raddr": raddr,
                    "status": conn.status,
                })
        except Exception:
            continue
    return findings

def scan_files_for_indicators(paths):
    suspicious_files = []
    kws = [kw.lower() for kw in SUSPICIOUS_KEYWORDS]
    for base in paths:
        if not base:
            continue
        try:
            for root, dirs, files in os.walk(base):
                
                depth = Path(root).relative_to(base).parts
                if len(depth) > 6:
                    continue
                for fname in files:
                    fpath = Path(root) / fname
                    try:
                        ext = fpath.suffix.lower()
                        if ext in SCAN_EXTS or fname.lower().endswith(".txt"):
                            # small files only; skip huge binaries to save time
                            if fpath.exists() and fpath.stat().st_size > 5 * 1024 * 1024:
                                continue
                            with open(fpath, "rb") as fh:
                                try:
                                    data = fh.read()
                                except Exception:
                                    continue
                            try:
                                text = data.decode('utf-8', errors='ignore').lower()
                            except Exception:
                                text = ""
                            matches = [kw for kw in kws if kw in text]
                            if matches:
                                suspicious_files.append({
                                    "path": str(fpath),
                                    "size": fpath.stat().st_size,
                                    "matches": matches
                                })
                    except (OSError, PermissionError):
                        continue
        except (OSError, PermissionError):
            continue
    return suspicious_files


def windows_autoruns():
    findings = []
    if platform.system().lower() != "windows":
        return findings
    try:
        import winreg
    except Exception:
        return findings
    RUN_KEYS = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"),
    ]
    for hive, sub in RUN_KEYS:
        try:
            with winreg.OpenKey(hive, sub) as key:
                i = 0
                while True:
                    try:
                        name, val, _ = winreg.EnumValue(key, i)
                        val_l = str(val).lower()
                        match = [kw for kw in SUSPICIOUS_KEYWORDS if kw.lower() in val_l]
                        if match:
                            findings.append({"key": f"{hive}\\{sub}\\{name}", "value": val, "matches": match})
                        i += 1
                    except OSError:
                        break
        except Exception:
            continue
    return findings

def windows_schtasks():
    findings = []
    if platform.system().lower() != "windows":
        return findings
    import subprocess
    try:
        out = subprocess.check_output(["schtasks", "/query", "/fo", "LIST", "/v"], stderr=subprocess.DEVNULL, text=True, encoding='utf-8', errors='ignore')
        # naive parse: split by blank lines into tasks
        tasks = [t.strip() for t in out.split("\n\n") if t.strip()]
        for t in tasks:
            low = t.lower()
            if any(kw in low for kw in SUSPICIOUS_KEYWORDS):
                findings.append({"task": t[:300], "matches": [kw for kw in SUSPICIOUS_KEYWORDS if kw in low]})
    except Exception:
        pass
    return findings

def unix_cron_checks():
    findings = []
    if platform.system().lower() == "windows":
        return findings
    # user crontab
    try:
        import subprocess
        user_cron = subprocess.check_output(["crontab", "-l"], stderr=subprocess.STDOUT, text=True)
        low = user_cron.lower()
        if any(kw in low for kw in SUSPICIOUS_KEYWORDS):
            findings.append({"crontab": user_cron, "matches": [kw for kw in SUSPICIOUS_KEYWORDS if kw in low]})
    except Exception:
        pass
 
    cron_dirs = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly"]
    for d in cron_dirs:
        try:
            for fn in os.listdir(d):
                p = Path(d) / fn
                try:
                    with open(p, "rb") as fh:
                        txt = fh.read().decode('utf-8', errors='ignore').lower()
                    if any(kw in txt for kw in SUSPICIOUS_KEYWORDS):
                        findings.append({"file": str(p), "matches": [kw for kw in SUSPICIOUS_KEYWORDS if kw in txt]})
                except Exception:
                    continue
        except Exception:
            continue
    return findings

def linux_input_device_checks():
    findings = []
    if platform.system().lower() == "windows":
        return findings
    # need root to see many processes holding input devices
    try:
        for dev in Path("/dev").glob("input/*"):
            for proc in psutil.process_iter(['pid', 'name', 'open_files', 'username', 'cwd']):
                try:
                    # psutil doesn't list open device nodes easily; this is heuristic
                    of = proc.open_files()
                    if of:
                        for o in of:
                            if str(dev) in o.path:
                                findings.append({"pid": proc.pid, "name": proc.name(), "device": str(dev)})
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
    except Exception:
        pass
    return findings

def make_report(scan_results):
    ts = datetime.utcnow().isoformat() + "Z"
    lines = [f"kl_defender report - {ts}", "-"*60]
    for k, v in scan_results.items():
        lines.append(f"\n== {k} ==")
        if not v:
            lines.append("  (no findings)")
            continue
        for item in v:
            lines.append(f"  - {item}")
    return "\n".join(lines)

def quarantine_files(suspicious_files, quarantine_dir):
    Path(quarantine_dir).mkdir(parents=True, exist_ok=True)
    moved = []
    for f in suspicious_files:
        src = Path(f["path"])
        try:
            dest = Path(quarantine_dir) / (src.name + "_" + str(f.get("size",0)))
            shutil.move(str(src), str(dest))
            moved.append({"from": str(src), "to": str(dest)})
        except Exception as e:
            moved.append({"from": str(src), "error": str(e)})
    return moved

def kill_processes(proc_list):
    killed = []
    for p in proc_list:
        try:
            proc = psutil.Process(p['pid'])
            proc.terminate()
            proc.wait(timeout=5)
            killed.append({"pid": p['pid'], "name": p.get('name'), "status": "terminated"})
        except Exception as e:
            killed.append({"pid": p.get('pid'), "name": p.get('name'), "error": str(e)})
    return killed


def main():
    parser = argparse.ArgumentParser(description="kl_defender — detect/inspect likely keylogger indicators")
    parser.add_argument("--scan", action="store_true", help="Run full scan")
    parser.add_argument("--paths", nargs="*", help="Paths to scan for suspicious files (overrides defaults)")
    parser.add_argument("--quarantine", action="store_true", help="Move suspicious files to quarantine (requires --yes or confirm)")
    parser.add_argument("--kill", action="store_true", help="Kill suspicious processes (requires --yes or confirm)")
    parser.add_argument("--yes", action="store_true", help="Assume yes for destructive actions")
    parser.add_argument("--report", help="Write report to file")
    args = parser.parse_args()

    if not args.scan:
        parser.print_help()
        sys.exit(0)

    print("[*] Starting kl_defender scan...")
    paths = [Path(p) for p in (args.paths or default_paths()) if p]
    print("[*] Scanning paths:", ", ".join(str(p) for p in paths if p.exists()))
    proc_find = find_suspicious_processes()
    net_find = scan_network_connections()
    file_find = scan_files_for_indicators(paths)
    win_run = windows_autoruns()
    win_sched = windows_schtasks()
    unix_cron = unix_cron_checks()
    linux_dev = linux_input_device_checks()

    
    scan_results = {
        "suspicious_processes": [f"PID {p['pid']} {p['name']} user={p.get('user')} matches={p['matches']} cmd={p['cmdline'][:200]}" for p in proc_find],
        "network_connections": [f"PID {n['pid']} {n['laddr']} -> {n['raddr']} status={n['status']}" for n in net_find if n['pid']],
        "suspicious_files": [f"{f['path']} size={f['size']} matches={f['matches']}" for f in file_find],
        "windows_run_keys": [str(x) for x in win_run],
        "windows_scheduled_tasks": [str(x) for x in win_sched],
        "unix_cron": [str(x) for x in unix_cron],
        "linux_input_device_holders": [str(x) for x in linux_dev]
    }

    print("\n--- Scan summary ---")
    for k, v in scan_results.items():
        print(f"\n{ k }")
        if not v:
            print("  (no findings)")
        else:
            for item in v[:20]:
                print("  ", item)
            if len(v) > 20:
                print(f"  ... +{len(v)-20} more")

    if args.quarantine and file_find:
        if not args.yes:
            ans = input("\nQuarantine files? This will MOVE files to ./quarantine. Type YES to proceed: ")
            if ans.strip().upper() != "YES":
                print("Skipping quarantine.")
                quarantine_report = []
            else:
                quarantine_report = quarantine_files(file_find, Path.cwd() / "quarantine")
        else:
            quarantine_report = quarantine_files(file_find, Path.cwd() / "quarantine")
        print("Quarantine result:", quarantine_report[:10])

    if args.kill and proc_find:
        if not args.yes:
            ans = input("\nKill listed suspicious processes? Type YES to proceed: ")
            if ans.strip().upper() != "YES":
                print("Skipping kills.")
                kill_report = []
            else:
                kill_report = kill_processes(proc_find)
        else:
            kill_report = kill_processes(proc_find)
        print("Kill report:", kill_report)

    if args.report:
        with open(args.report, "w", encoding="utf-8") as fh:
            fh.write(make_report(scan_results))
        print("[*] report written to", args.report)

    print("\n[*] Scan finished. Review findings carefully. If you find rootkit/kernel-level artifacts or signs of credential exfiltration, consider full image + professional IR.")

if __name__ == "__main__":
    main()