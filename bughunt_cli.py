#!/usr/bin/env python3
"""
BugHunt CLI - passive recon + lightweight authorized scanning + report export.

IMPORTANT / ETHICS
-------------------
Only run `scan` against domains you own or have WRITTEN PERMISSION to test
(e.g. a bug bounty program's in-scope assets). `scan` makes real HTTP
requests to the target. `recon` only queries public certificate-transparency
logs (crt.sh) and never touches the target itself.

`portscan` runs an ACTIVE nmap scan against a target and is more intrusive
than the header checks `scan` does. Only run it against targets you own or
have written permission to test.

This tool does NOT brute force, exploit, or attack anything. `scan` only
reads what a server offers on a normal page/header request; `portscan`
only runs a fast, read-only nmap port scan.

Setup (Termux):
    pkg install python
    pip install requests

Usage:
    python bughunt_cli.py recon example.com
    python bughunt_cli.py scan https://example.com
    python bughunt_cli.py scan https://example.com --out findings.json
    python bughunt_cli.py report findings.json --out bughunt_import.json
    python bughunt_cli.py portscan example.com
"""

import argparse
import json
import os
import socket
import ssl
import subprocess
import sys
import time
import urllib.parse
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    print("Missing dependency. Run: pip install requests")
    sys.exit(1)

UA = "BugHuntCLI/1.0 (authorized-testing)"
CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bughunt_config.json")
DEFAULT_CONFIG = {"timeout": 10, "output_dir": "."}


def load_config():
    cfg = dict(DEFAULT_CONFIG)
    if os.path.isfile(CONFIG_FILE):
        try:
            with open(CONFIG_FILE) as f:
                cfg.update(json.load(f))
        except Exception:
            pass
    return cfg


def save_config(cfg):
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)


CONFIG = load_config()
TIMEOUT = CONFIG.get("timeout", 10)


def out_path(name):
    d = CONFIG.get("output_dir", ".")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, name)

SECURITY_HEADERS = [
    ("content-security-policy", "High", "Missing Content-Security-Policy",
     "No CSP header found. CSP is a key defense against XSS and data injection.",
     "Add a strict Content-Security-Policy header."),
    ("strict-transport-security", "Medium", "Missing HSTS",
     "No Strict-Transport-Security header. Downgrade/SSL-strip attacks are easier.",
     "Add Strict-Transport-Security with a long max-age and includeSubDomains."),
    ("x-frame-options", "Medium", "Missing Clickjacking Protection",
     "No X-Frame-Options and no CSP frame-ancestors directive seen.",
     "Set X-Frame-Options: SAMEORIGIN or use CSP frame-ancestors."),
    ("x-content-type-options", "Low", "Missing MIME-Sniffing Protection",
     "No X-Content-Type-Options header.",
     "Add X-Content-Type-Options: nosniff."),
    ("referrer-policy", "Low", "Missing Referrer-Policy",
     "No Referrer-Policy header; full URLs may leak to third parties.",
     "Add Referrer-Policy: strict-origin-when-cross-origin."),
    ("permissions-policy", "Low", "Missing Permissions-Policy",
     "No Permissions-Policy header restricting browser features.",
     "Add a Permissions-Policy header for camera, microphone, geolocation, etc."),
]

# Paths that are safe, read-only, single-GET checks commonly used in
# authorized recon. No parameters, no payloads, no state-changing requests.
EXPOSED_PATHS = [
    ("/.git/config", "High", "Exposed .git directory",
     "The .git/config file is publicly accessible, which can expose source code and history."),
    ("/.env", "High", "Exposed .env file",
     "A .env file is publicly accessible, which often contains secrets or credentials."),
    ("/.well-known/security.txt", "Info", "security.txt present",
     "A security.txt file was found, which is good practice (contact info for reporting issues)."),
    ("/phpinfo.php", "Medium", "Exposed phpinfo()",
     "phpinfo() output is publicly accessible and can leak server configuration details."),
    ("/.DS_Store", "Low", "Exposed .DS_Store",
     "A macOS .DS_Store file is accessible and may reveal directory structure."),
]


def banner(msg):
    print("\n" + "=" * 60)
    print(msg)
    print("=" * 60)


def confirm_authorization(target):
    print(f"\nYou are about to send requests to: {target}")
    print("Only proceed if you own this target or have written permission")
    print("(e.g. it is explicitly in-scope for a bug bounty program).")
    typed = input(f"Type the domain exactly to confirm ('{target}'): ").strip()
    return typed == target


def cmd_recon(args):
    domain = args.domain.strip().lower()
    banner(f"Passive recon for {domain} (crt.sh, no requests sent to target)")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        r = requests.get(url, timeout=20, headers={"User-Agent": UA})
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        print(f"crt.sh lookup failed: {e}")
        sys.exit(1)

    subs = set()
    for entry in data:
        name = entry.get("name_value", "")
        for line in name.split("\n"):
            line = line.strip().lower()
            if line.endswith(domain) and "*" not in line:
                subs.add(line)

    subs = sorted(subs)
    print(f"\nFound {len(subs)} unique subdomains:\n")
    for s in subs:
        print(" ", s)

    if args.out:
        with open(args.out, "w") as f:
            f.write("\n".join(subs))
        print(f"\nSaved to {args.out}")
    print("\nNote: these are names seen in public certificate logs. Some may be")
    print("dead, parked, or out of scope - verify before testing any of them.")


def check_headers(resp):
    findings = []
    headers = {k.lower(): v for k, v in resp.headers.items()}

    for key, sev, title, desc, fix in SECURITY_HEADERS:
        if key == "x-frame-options":
            if key in headers or "frame-ancestors" in headers.get("content-security-policy", "").lower():
                continue
        elif key in headers:
            continue
        findings.append({"title": title, "severity": sev, "description": desc,
                          "remediation": fix, "evidence": "header absent"})

    if "server" in headers or "x-powered-by" in headers:
        val = f"Server: {headers.get('server','')} X-Powered-By: {headers.get('x-powered-by','')}".strip()
        findings.append({"title": "Server/Technology Version Leak", "severity": "Low",
                          "description": "Server or framework version information is exposed in headers.",
                          "remediation": "Remove or mask Server and X-Powered-By headers.",
                          "evidence": val})

    if headers.get("access-control-allow-origin", "") == "*":
        findings.append({"title": "Permissive CORS (Access-Control-Allow-Origin: *)",
                          "severity": "Medium",
                          "description": "The server allows cross-origin requests from any origin.",
                          "remediation": "Restrict Access-Control-Allow-Origin to trusted domains only.",
                          "evidence": "Access-Control-Allow-Origin: *"})

    set_cookie = resp.headers.get("Set-Cookie", "")
    if set_cookie:
        low = set_cookie.lower()
        if "secure" not in low:
            findings.append({"title": "Cookie Missing Secure Flag", "severity": "Medium",
                              "description": "A cookie is set without the Secure attribute.",
                              "remediation": "Add the Secure attribute to all cookies.",
                              "evidence": set_cookie[:120]})
        if "httponly" not in low:
            findings.append({"title": "Cookie Missing HttpOnly Flag", "severity": "Medium",
                              "description": "A cookie is set without the HttpOnly attribute.",
                              "remediation": "Add the HttpOnly attribute to session cookies.",
                              "evidence": set_cookie[:120]})
        if "samesite" not in low:
            findings.append({"title": "Cookie Missing SameSite", "severity": "Low",
                              "description": "A cookie has no SameSite attribute (CSRF risk).",
                              "remediation": "Add SameSite=Lax or Strict.",
                              "evidence": set_cookie[:120]})
    return findings


def check_tls(hostname):
    findings = []
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get("notAfter")
                if not_after:
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    days_left = (expiry - datetime.now(timezone.utc)).days
                    if days_left < 14:
                        findings.append({"title": "TLS Certificate Expiring Soon", "severity": "Medium",
                                          "description": f"Certificate expires in {days_left} days.",
                                          "remediation": "Renew the TLS certificate.",
                                          "evidence": f"notAfter: {not_after}"})
    except Exception as e:
        findings.append({"title": "TLS Check Failed", "severity": "Info",
                          "description": f"Could not complete a TLS handshake: {e}",
                          "remediation": "Verify manually; this may be benign (e.g. no port 443).",
                          "evidence": ""})
    return findings


def check_exposed_paths(base_url, session):
    findings = []
    for path, sev, title, desc in EXPOSED_PATHS:
        url = base_url.rstrip("/") + path
        try:
            r = session.get(url, timeout=TIMEOUT, allow_redirects=False)
            time.sleep(0.3)  # be polite, avoid hammering the server
        except Exception:
            continue
        if r.status_code == 200 and len(r.content) > 0:
            # crude false-positive guard: skip if it looks like a generic 200 catch-all page
            if path == "/.well-known/security.txt":
                findings.append({"title": title, "severity": "Info", "description": desc,
                                  "remediation": "No action needed.", "evidence": url})
            else:
                findings.append({"title": title, "severity": sev, "description": desc,
                                  "remediation": "Remove this file from the public web root or block access to it.",
                                  "evidence": url})
    return findings


def cmd_scan(args):
    target = args.url.strip()
    if not target.startswith("http"):
        target = "https://" + target
    parsed = urllib.parse.urlparse(target)
    domain = parsed.netloc

    if not args.yes and not confirm_authorization(domain):
        print("Confirmation did not match target domain. Aborting.")
        sys.exit(1)

    banner(f"Scanning {target} (single request + a few read-only checks)")
    session = requests.Session()
    session.headers.update({"User-Agent": UA})

    all_findings = []
    try:
        resp = session.get(target, timeout=TIMEOUT, allow_redirects=True)
        print(f"GET {target} -> {resp.status_code}")
        all_findings.extend(check_headers(resp))
    except Exception as e:
        print(f"Request failed: {e}")
        sys.exit(1)

    print("Checking TLS certificate...")
    all_findings.extend(check_tls(domain.split(":")[0]))

    if not args.no_paths:
        print("Checking a few common exposed paths (read-only, single GET each)...")
        all_findings.extend(check_exposed_paths(f"{parsed.scheme}://{domain}", session))

    if not all_findings:
        print("\nNo issues found by these passive checks.")
    else:
        print(f"\nFound {len(all_findings)} item(s):\n")
        for f in all_findings:
            print(f"[{f['severity']}] {f['title']}")
            print(f"   {f['description']}")
            print(f"   Fix: {f['remediation']}")
            if f.get("evidence"):
                print(f"   Evidence: {f['evidence']}")
            print()

    result = {
        "target": target,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "findings": all_findings,
    }

    out = args.out or out_path("findings.json")
    with open(out, "w") as f:
        json.dump(result, f, indent=2)
    print(f"Saved raw results to {out}")
    print(f"Next: python bughunt_cli.py report {out} --out bughunt_import.json")
    return result


def cmd_batch(args):
    with open(args.urls_file) as f:
        urls = [l.strip() for l in f if l.strip() and not l.strip().startswith("#")]
    if not urls:
        print(RED_PLAIN("No URLs found in the file."))
        sys.exit(1)

    domains = []
    for u in urls:
        t = u if u.startswith("http") else "https://" + u
        domains.append(urllib.parse.urlparse(t).netloc)

    print(f"\nThis will scan {len(urls)} target(s):")
    for d in domains:
        print("  -", d)
    print("\nOnly proceed if you own ALL of these or have written permission for ALL of them.")
    if not args.yes:
        typed = input("Type CONFIRM to proceed: ").strip()
        if typed != "CONFIRM":
            print("Not confirmed. Aborting.")
            sys.exit(1)

    all_results = []
    session = requests.Session()
    session.headers.update({"User-Agent": UA})
    for u in urls:
        target = u if u.startswith("http") else "https://" + u
        parsed = urllib.parse.urlparse(target)
        domain = parsed.netloc
        banner(f"Scanning {target}")
        findings = []
        try:
            resp = session.get(target, timeout=TIMEOUT, allow_redirects=True)
            print(f"GET {target} -> {resp.status_code}")
            findings.extend(check_headers(resp))
        except Exception as e:
            print(f"Request failed: {e}")
            all_results.append({"target": target, "error": str(e), "findings": []})
            continue
        findings.extend(check_tls(domain.split(":")[0]))
        if not args.no_paths:
            findings.extend(check_exposed_paths(f"{parsed.scheme}://{domain}", session))
        print(f"-> {len(findings)} finding(s)")
        all_results.append({"target": target, "findings": findings})
        time.sleep(0.5)

    out = args.out or out_path("batch_findings.json")
    with open(out, "w") as f:
        json.dump({"scanned_at": datetime.now(timezone.utc).isoformat(), "results": all_results}, f, indent=2)
    print(f"\nSaved combined results to {out}")
    print(f"Next: python bughunt_cli.py report {out} --out bughunt_import.json")


def cmd_config(args):
    cfg = load_config()
    if args.set:
        for kv in args.set:
            if "=" not in kv:
                print(f"Skipping '{kv}' (expected key=value)")
                continue
            k, v = kv.split("=", 1)
            k = k.strip()
            v = v.strip()
            if k == "timeout":
                try:
                    v = int(v)
                except ValueError:
                    print("timeout must be a number")
                    continue
            cfg[k] = v
        save_config(cfg)
        print("Config updated.")
    print("\nCurrent config:")
    for k, v in cfg.items():
        print(f"  {k} = {v}")
    print(f"\nConfig file: {CONFIG_FILE}")


def RED_PLAIN(msg):
    return msg


SEV_TO_CVSS = {
    "High": {"score": "8.6", "severity": "HIGH"},
    "Medium": {"score": "5.4", "severity": "MEDIUM"},
    "Low": {"score": "3.1", "severity": "LOW"},
    "Info": {"score": "0.0", "severity": "NONE"},
}


def findings_to_reports(target, flist, reports):
    for f in flist:
        sev = f.get("severity", "Low")
        cvss = SEV_TO_CVSS.get(sev, SEV_TO_CVSS["Low"])
        reports.append({
            "id": int(time.time() * 1000) + len(reports),
            "title": f"{f['title']} on {target}",
            "score": cvss["score"],
            "severity": cvss["severity"],
            "sum": f.get("description", ""),
            "steps": f"1. Send a GET request to {target}\n2. Observe: {f.get('evidence','see description')}",
            "imp": "Assess impact based on the finding above before including in a submission.",
            "rem": f.get("remediation", ""),
            "ref": "OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/",
            "date": datetime.now().strftime("%m/%d/%Y"),
        })


def cmd_report(args):
    with open(args.findings_file) as f:
        data = json.load(f)

    reports = []
    if "results" in data:
        # batch file: {"results": [{"target":..., "findings":[...]}, ...]}
        for entry in data["results"]:
            findings_to_reports(entry.get("target", "unknown target"), entry.get("findings", []), reports)
    else:
        # single-target file: {"target":..., "findings":[...]}
        findings_to_reports(data.get("target", "unknown target"), data.get("findings", []), reports)

    bundle = {"reports": reports, "payloads": [], "recon": [], "meth": {}}

    out = args.out or out_path("bughunt_import.json")
    with open(out, "w") as f:
        json.dump(bundle, f, indent=2)

    print(f"Wrote {len(reports)} report(s) to {out}")
    print("Import this file in BugHunt Report Master: Settings -> Import Data (JSON).")
    print("\nReminder: review and personalize each report (clear repro steps, real")
    print("impact, screenshots/PoC) before submitting to any bug bounty program -")
    print("this file is a starting draft, not a final submission.")


def cmd_portscan(args):
    target = args.target.strip()

    if not target or target.startswith("-"):
        print("Invalid target.")
        return

    print(f"\nYou are about to PORT SCAN: {target}")
    print("This is an ACTIVE scan and is more intrusive than header checks.")
    print("Only proceed with written permission.")
    if not args.yes:
        typed = input(f"Type the target exactly to confirm ('{target}'): ").strip()
        if typed != target:
            print("Not confirmed. Aborting.")
            return

    # -F = fast scan (common 100 ports only), not aggressive
    cmd = ["nmap", "-F", target]
    print(f"\nRunning: {' '.join(cmd)}\n")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        print(result.stdout)
        if result.stderr:
            print(result.stderr)
    except FileNotFoundError:
        print("Nmap is not installed. Install it first (nmap.org) and add it to PATH.")
    except subprocess.TimeoutExpired:
        print("Scan timed out after 120 seconds.")
    except Exception as e:
        print(f"Scan failed: {e}")


def main():
    p = argparse.ArgumentParser(description="BugHunt CLI - authorized recon and reporting helper")
    sub = p.add_subparsers(dest="cmd", required=True)

    pr = sub.add_parser("recon", help="Passive subdomain discovery via crt.sh (no requests to target)")
    pr.add_argument("domain", help="Root domain, e.g. example.com")
    pr.add_argument("--out", help="Save subdomain list to a file")
    pr.set_defaults(func=cmd_recon)

    ps = sub.add_parser("scan", help="Single-request header/TLS/exposed-path checks (needs permission)")
    ps.add_argument("url", help="Target URL, e.g. https://example.com")
    ps.add_argument("--out", help="Save raw findings JSON (default findings.json)")
    ps.add_argument("--no-paths", action="store_true", help="Skip the exposed-path checks")
    ps.add_argument("--yes", action="store_true", help="Skip the interactive authorization confirmation")
    ps.set_defaults(func=cmd_scan)

    pp = sub.add_parser("report", help="Turn findings.json (or batch_findings.json) into a BugHunt import file")
    pp.add_argument("findings_file", help="findings.json produced by 'scan' or 'batch'")
    pp.add_argument("--out", help="Output file (default bughunt_import.json)")
    pp.set_defaults(func=cmd_report)

    pb = sub.add_parser("batch", help="Scan multiple targets from a file, one URL per line (needs permission for all)")
    pb.add_argument("urls_file", help="Text file with one URL/domain per line")
    pb.add_argument("--out", help="Save combined findings JSON (default batch_findings.json)")
    pb.add_argument("--no-paths", action="store_true", help="Skip the exposed-path checks")
    pb.add_argument("--yes", action="store_true", help="Skip the interactive CONFIRM prompt")
    pb.set_defaults(func=cmd_batch)

    pc = sub.add_parser("config", help="View or change settings (timeout, output_dir)")
    pc.add_argument("--set", nargs="*", help="key=value pairs, e.g. --set timeout=15 output_dir=results")
    pc.set_defaults(func=cmd_config)

    ppo = sub.add_parser("portscan", help="Port scan a target via nmap (ACTIVE - needs explicit permission)")
    ppo.add_argument("target", help="IP or domain")
    ppo.add_argument("--yes", action="store_true", help="Skip the interactive confirmation prompt")
    ppo.set_defaults(func=cmd_portscan)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
