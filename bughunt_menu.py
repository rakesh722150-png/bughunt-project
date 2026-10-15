#!/usr/bin/env python3
"""
BugHunt Menu - colorful interactive front-end for bughunt_cli.py

Run this instead of typing commands manually:
    python bughunt_menu.py

Setup (same folder as bughunt_cli.py):
    pip install requests colorama
"""

import os
import sys
import subprocess

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    print("Missing dependency. Run: pip install colorama")
    sys.exit(1)

GREEN = Fore.GREEN + Style.BRIGHT
CYAN = Fore.CYAN + Style.BRIGHT
YELLOW = Fore.YELLOW + Style.BRIGHT
RED = Fore.RED + Style.BRIGHT
WHITE = Fore.WHITE + Style.BRIGHT
DIM = Style.DIM
RESET = Style.RESET_ALL

CLI = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bughunt_cli.py")


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def header():
    print(GREEN + r"""
 ____             _   _            _
| __ ) _   _  __ _| | | |_   _ _ __ | |_
|  _ \| | | |/ _` | |_| | | | | '_ \| __|
| |_) | |_| | (_| |  _  | |_| | | | | |_
|____/ \__,_|\__, |_| |_|\__,_|_| |_|\__|
             |___/
""" + RESET)
    print(CYAN + "        BugHunt CLI - Menu" + RESET)
    print(DIM + "   Passive recon + authorized scanning + report export" + RESET)
    print(YELLOW + "-" * 58 + RESET)


def section(title):
    print()
    print(CYAN + "== " + title + " " + "=" * (50 - len(title)) + RESET)


def menu():
    clear()
    header()
    section("MAIN MENU")
    print(WHITE + " [1] " + RESET + "Recon      " + DIM + "- find subdomains (passive, no target contact)" + RESET)
    print(WHITE + " [2] " + RESET + "Scan       " + DIM + "- check headers/TLS/exposed files (needs permission)" + RESET)
    print(WHITE + " [3] " + RESET + "Report     " + DIM + "- turn scan findings into a BugHunt import file" + RESET)
    print(WHITE + " [4] " + RESET + "Help       " + DIM + "- what each option does, and the rules" + RESET)
    print(GREEN + " [5] " + RESET + "Full Workflow " + DIM + "- Recon -> pick target -> Scan -> Report, all in one go" + RESET)
    print(WHITE + " [6] " + RESET + "History    " + DIM + "- view saved findings/report files in this folder" + RESET)
    print(WHITE + " [7] " + RESET + "Settings   " + DIM + "- change timeout and output folder" + RESET)
    print(WHITE + " [8] " + RESET + "Multi-Scan " + DIM + "- scan several targets from a list (needs permission)" + RESET)
    print(WHITE + " [9] " + RESET + "Nmap Scan  " + DIM + "- fast port scan via nmap (needs permission)" + RESET)
    print(WHITE + " [0] " + RESET + "Exit")
    print(YELLOW + "-" * 58 + RESET)
    return input(GREEN + "Choose an option: " + RESET).strip()


def run(cmd_args):
    print(DIM + "\n> python bughunt_cli.py " + " ".join(cmd_args) + "\n" + RESET)
    try:
        subprocess.run([sys.executable, CLI] + cmd_args)
    except FileNotFoundError:
        print(RED + f"Could not find {CLI}. Keep this file in the same folder as bughunt_cli.py." + RESET)
    input(DIM + "\nPress Enter to go back to the menu..." + RESET)


def do_recon():
    section("RECON")
    print(WHITE + "This only queries public certificate-transparency logs (crt.sh)." + RESET)
    print(WHITE + "It never sends any request to the target itself. Safe to run on anything." + RESET)
    domain = input(CYAN + "\nDomain (e.g. example.com): " + RESET).strip()
    if not domain:
        print(RED + "No domain entered." + RESET)
        return
    save = input(CYAN + "Save subdomain list to a file? (y/N): " + RESET).strip().lower()
    args = ["recon", domain]
    if save == "y":
        fname = input(CYAN + "File name (default subs.txt): " + RESET).strip() or "subs.txt"
        args += ["--out", fname]
    run(args)


def do_scan():
    section("SCAN")
    print(YELLOW + "WARNING: this sends real requests to the target." + RESET)
    print(YELLOW + "Only use this on a domain you own or are authorized to test" + RESET)
    print(YELLOW + "(e.g. in-scope for a bug bounty program)." + RESET)
    url = input(CYAN + "\nTarget URL (e.g. https://example.com): " + RESET).strip()
    if not url:
        print(RED + "No URL entered." + RESET)
        return
    skip_paths = input(CYAN + "Skip the exposed-file checks (.git/.env/etc)? (y/N): " + RESET).strip().lower()
    out = input(CYAN + "Save findings as (default findings.json): " + RESET).strip() or "findings.json"
    args = ["scan", url, "--out", out]
    if skip_paths == "y":
        args.append("--no-paths")
    run(args)


def do_report():
    section("REPORT")
    print(WHITE + "Turns a findings.json (from Scan) into a file you can import" + RESET)
    print(WHITE + "into BugHunt Report Master via Settings -> Import Data." + RESET)
    src = input(CYAN + "\nFindings file (default findings.json): " + RESET).strip() or "findings.json"
    if not os.path.isfile(src):
        print(RED + f"File not found: {src}" + RESET)
        return
    out = input(CYAN + "Output file (default bughunt_import.json): " + RESET).strip() or "bughunt_import.json"
    run(["report", src, "--out", out])


def do_full_workflow():
    section("FULL WORKFLOW")
    print(WHITE + "This will:" + RESET)
    print("  1. Find subdomains for a root domain (passive, safe)")
    print("  2. Let you pick one (or type your own URL)")
    print(YELLOW + "  3. Scan that ONE target (sends real requests - needs your confirmation)" + RESET)
    print("  4. Auto-build a BugHunt-importable report file")
    go = input(CYAN + "\nContinue? (y/N): " + RESET).strip().lower()
    if go != "y":
        return

    domain = input(CYAN + "\nRoot domain for recon (e.g. example.com): " + RESET).strip()
    if not domain:
        print(RED + "No domain entered." + RESET)
        return

    subs_file = "workflow_subs.txt"
    print(DIM + f"\n> python bughunt_cli.py recon {domain} --out {subs_file}\n" + RESET)
    r = subprocess.run([sys.executable, CLI, "recon", domain, "--out", subs_file])
    if r.returncode != 0:
        print(RED + "Recon failed (crt.sh may be down). Try again later, or pick option 2 to scan a known URL directly." + RESET)
        input(DIM + "\nPress Enter to go back..." + RESET)
        return

    subs = []
    if os.path.isfile(subs_file):
        with open(subs_file) as f:
            subs = [l.strip() for l in f if l.strip()]

    target_url = None
    if subs:
        print(CYAN + f"\nFound {len(subs)} subdomain(s). Pick one to scan, or 0 to type your own URL:" + RESET)
        shown = subs[:30]
        for i, s in enumerate(shown, 1):
            print(f"  [{i}] {s}")
        if len(subs) > 30:
            print(DIM + f"  ...and {len(subs) - 30} more (see {subs_file})" + RESET)
        choice = input(CYAN + "\nChoice: " + RESET).strip()
        if choice.isdigit() and 1 <= int(choice) <= len(shown):
            target_url = "https://" + shown[int(choice) - 1]

    if not target_url:
        target_url = input(CYAN + "Target URL to scan (e.g. https://example.com): " + RESET).strip()
    if not target_url:
        print(RED + "No target chosen. Stopping." + RESET)
        return

    findings_file = "workflow_findings.json"
    print(DIM + f"\n> python bughunt_cli.py scan {target_url} --out {findings_file}\n" + RESET)
    r = subprocess.run([sys.executable, CLI, "scan", target_url, "--out", findings_file])
    if r.returncode != 0:
        print(RED + "Scan was cancelled or failed." + RESET)
        input(DIM + "\nPress Enter to go back..." + RESET)
        return

    report_file = "workflow_report.json"
    print(DIM + f"\n> python bughunt_cli.py report {findings_file} --out {report_file}\n" + RESET)
    subprocess.run([sys.executable, CLI, "report", findings_file, "--out", report_file])

    print(GREEN + f"\nDone! Import '{report_file}' into BugHunt Report Master: Settings -> Import Data." + RESET)
    input(DIM + "\nPress Enter to go back to the menu..." + RESET)


def do_history():
    section("HISTORY")
    exts = (".json",)
    files = []
    for fn in os.listdir("."):
        if fn.endswith(exts) and fn != "bughunt_config.json":
            files.append(fn)
    files.sort(key=lambda f: os.path.getmtime(f), reverse=True)

    if not files:
        print(DIM + "No saved findings/report files found in this folder yet." + RESET)
        input(DIM + "\nPress Enter to go back..." + RESET)
        return

    print(WHITE + "Saved files (newest first):" + RESET)
    for i, fn in enumerate(files, 1):
        size = os.path.getsize(fn)
        print(f"  [{i}] {fn}  " + DIM + f"({size} bytes)" + RESET)

    choice = input(CYAN + "\nOpen one to see a summary? (number, or Enter to skip): " + RESET).strip()
    if choice.isdigit() and 1 <= int(choice) <= len(files):
        fn = files[int(choice) - 1]
        try:
            import json
            with open(fn) as f:
                data = json.load(f)
        except Exception as e:
            print(RED + f"Could not read {fn}: {e}" + RESET)
            input(DIM + "\nPress Enter to go back..." + RESET)
            return

        if "reports" in data:
            print(GREEN + f"\n{fn}: {len(data['reports'])} report(s) ready to import" + RESET)
            for r in data["reports"][:20]:
                print(f"  [{r.get('severity','?')}] {r.get('title','(no title)')}")
        elif "results" in data:
            print(GREEN + f"\n{fn}: batch scan, {len(data['results'])} target(s)" + RESET)
            for entry in data["results"]:
                print(f"  {entry.get('target')} -> {len(entry.get('findings', []))} finding(s)")
        elif "findings" in data:
            print(GREEN + f"\n{fn}: scan of {data.get('target','?')}, {len(data['findings'])} finding(s)" + RESET)
            for f_ in data["findings"][:20]:
                print(f"  [{f_.get('severity','?')}] {f_.get('title','(no title)')}")
        else:
            print(DIM + "Unrecognized file format, showing raw keys: " + ", ".join(data.keys()) + RESET)
    input(DIM + "\nPress Enter to go back..." + RESET)


def do_settings():
    section("SETTINGS")
    run(["config"])
    change = input(CYAN + "Change a setting? (y/N): " + RESET).strip().lower()
    if change != "y":
        return
    print(WHITE + "Examples: timeout=15   output_dir=results" + RESET)
    kv = input(CYAN + "Enter key=value (space-separated for multiple): " + RESET).strip()
    if not kv:
        return
    run(["config", "--set"] + kv.split())


def do_multiscan():
    section("MULTI-SCAN")
    print(YELLOW + "WARNING: this sends real requests to EVERY target in the list." + RESET)
    print(YELLOW + "Only use this for domains you own or are authorized to test." + RESET)
    print(WHITE + "\nYou can either point to an existing text file (one URL per line)," + RESET)
    print(WHITE + "or paste URLs here now, one per line, then an empty line to finish." + RESET)
    mode = input(CYAN + "\nUse a file? (y/N): " + RESET).strip().lower()

    if mode == "y":
        path = input(CYAN + "File path: " + RESET).strip()
        if not os.path.isfile(path):
            print(RED + "File not found." + RESET)
            return
        urls_file = path
    else:
        print(CYAN + "Paste URLs, one per line. Empty line to finish:" + RESET)
        lines = []
        while True:
            line = input()
            if not line.strip():
                break
            lines.append(line.strip())
        if not lines:
            print(RED + "No URLs entered." + RESET)
            return
        urls_file = "multiscan_targets.txt"
        with open(urls_file, "w") as f:
            f.write("\n".join(lines))

    out = input(CYAN + "Save combined results as (default batch_findings.json): " + RESET).strip() or "batch_findings.json"
    run(["batch", urls_file, "--out", out])
    make_report = input(CYAN + "Generate a BugHunt import file from these results now? (y/N): " + RESET).strip().lower()
    if make_report == "y":
        rep_out = input(CYAN + "Report file name (default bughunt_import.json): " + RESET).strip() or "bughunt_import.json"
        run(["report", out, "--out", rep_out])


def do_portscan():
    section("NMAP PORT SCAN")
    print(YELLOW + "WARNING: this is an ACTIVE scan, more intrusive than header checks." + RESET)
    print(YELLOW + "Only use on targets you own or have written permission to test." + RESET)
    print(DIM + "Requires nmap installed (nmap.org) and available in PATH." + RESET)
    print(DIM + "Safe practice target: scanme.nmap.org" + RESET)
    target = input(CYAN + "\nTarget (IP or domain): " + RESET).strip()
    if not target:
        print(RED + "No target entered." + RESET)
        return
    run(["portscan", target])


def do_help():
    clear()
    header()
    section("HELP")
    print(GREEN + "1) Recon" + RESET)
    print("   Looks up subdomains seen in public SSL certificate logs (crt.sh).")
    print("   100% passive - no packet ever reaches the target. Safe on any domain.\n")
    print(GREEN + "2) Scan" + RESET)
    print("   Sends ONE request to the target URL and checks:")
    print("     - missing security headers (CSP, HSTS, X-Frame-Options...)")
    print("     - cookie flags (Secure / HttpOnly / SameSite)")
    print("     - CORS misconfig, server version leaks")
    print("     - TLS certificate expiry")
    print("     - a few common exposed files (.git/config, .env, phpinfo.php)")
    print(RED + "   You must own the target or have written permission to test it." + RESET)
    print("   It asks you to type the domain name to confirm before scanning.\n")
    print(GREEN + "3) Report" + RESET)
    print("   Converts the raw findings.json into reports.json formatted exactly")
    print("   like BugHunt Report Master's data, ready to Import in Settings.\n")
    print(GREEN + "5) Full Workflow" + RESET)
    print("   Does Recon, then lets you pick a subdomain (or type your own URL),")
    print("   then runs Scan on it, then auto-generates the BugHunt import file.")
    print("   Same permission confirmation as Scan happens in the middle.\n")
    print(GREEN + "6) History" + RESET)
    print("   Lists every findings/report JSON file saved in this folder and")
    print("   shows a quick summary of what's inside one you pick.\n")
    print(GREEN + "7) Settings" + RESET)
    print("   Change the request timeout (seconds) or where output files are saved.\n")
    print(GREEN + "8) Multi-Scan" + RESET)
    print("   Scans several targets in one go, from a file or pasted list.")
    print("   Asks you to type CONFIRM once, listing every target, before sending")
    print("   any requests. Use only for a batch of domains you are all authorized to test.\n")
    print(GREEN + "9) Nmap Scan" + RESET)
    print("   Runs a fast nmap scan (nmap -F, top 100 common ports) on one target.")
    print("   This is an ACTIVE scan. Needs nmap installed and written permission.")
    print("   You must type the target exactly to confirm before it runs.\n")
    print(YELLOW + "This tool never brute-forces or exploits anything." + RESET)
    print(YELLOW + "It is a recon/reporting helper, not an attack tool." + RESET)
    input(DIM + "\nPress Enter to go back..." + RESET)


def main():
    while True:
        choice = menu()
        if choice == "1":
            do_recon()
        elif choice == "2":
            do_scan()
        elif choice == "3":
            do_report()
        elif choice == "4":
            do_help()
        elif choice == "5":
            do_full_workflow()
        elif choice == "6":
            do_history()
        elif choice == "7":
            do_settings()
        elif choice == "8":
            do_multiscan()
        elif choice == "9":
            do_portscan()
        elif choice == "0":
            print(GREEN + "\nHappy (ethical) hunting. Bye!\n" + RESET)
            break
        else:
            input(RED + "Invalid option. Press Enter to try again..." + RESET)


if __name__ == "__main__":
    main()
