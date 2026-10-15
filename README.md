# BugHunt CLI

A lightweight command-line toolkit for **authorized** bug bounty recon, scanning, and report generation. Includes a colorful interactive menu (`bughunt_menu.py`) as a friendly front-end to the core CLI (`bughunt_cli.py`).

> ⚠️ **Ethics / Legal Notice**
> Only run `scan`, `batch`, and `portscan` against targets you **own** or have **written permission** to test (e.g. assets explicitly in-scope for a bug bounty program). `recon` only queries public certificate-transparency logs (crt.sh) and never contacts the target. This tool does not brute-force, exploit, or attack anything — it performs read-only checks and respects confirmation prompts before sending any active traffic.

---

## Features

- **Recon** — Passive subdomain discovery via crt.sh (no contact with the target)
- **Scan** — Single-request check for missing security headers, cookie flags, CORS misconfig, server version leaks, TLS certificate expiry, and common exposed files (`.git/config`, `.env`, etc.)
- **Batch** — Run `scan` across a list of targets in one go
- **Report** — Convert raw findings into a BugHunt Report Master-importable JSON file
- **Portscan** — Fast, read-only `nmap -F` scan for common open ports
- **Config** — Persist settings like request timeout and output directory
- **Interactive Menu** — A guided, color-coded front-end so you don't have to remember flags

---

## Requirements

- Python 3.8+
- [Nmap](https://nmap.org/download.html) (only required for the `portscan` command — install and ensure it's on your system `PATH`)

Install Python dependencies:

```bash
pip install requests colorama
```

---

## Installation

```bash
git clone https://github.com/<your-username>/bughunt-project.git
cd bughunt-project
pip install requests colorama
```

---

## Usage

### Interactive menu (recommended for most users)

```bash
python bughunt_menu.py
```

Walks you through Recon, Scan, Report, a Full Workflow, History, Settings, Multi-Scan, and Nmap Scan with prompts — no need to memorize commands.

### Direct CLI commands

**Recon** — passive subdomain discovery:
```bash
python bughunt_cli.py recon example.com
python bughunt_cli.py recon example.com --out subs.txt
```

**Scan** — active header/TLS/exposed-file check (asks for confirmation):
```bash
python bughunt_cli.py scan https://example.com
python bughunt_cli.py scan https://example.com --out findings.json --no-paths
```

**Batch scan** — multiple targets from a file, one per line:
```bash
python bughunt_cli.py batch targets.txt --out batch_findings.json
```

**Report** — convert findings into a BugHunt import file:
```bash
python bughunt_cli.py report findings.json --out bughunt_import.json
```

**Portscan** — fast nmap scan (requires nmap installed, asks for confirmation):
```bash
python bughunt_cli.py portscan example.com
```

**Config** — view or change settings:
```bash
python bughunt_cli.py config
python bughunt_cli.py config --set timeout=15 output_dir=results
```

---

## Example Workflow

```bash
# 1. Passively find subdomains
python bughunt_cli.py recon example.com --out subs.txt

# 2. Scan a chosen subdomain (confirms authorization first)
python bughunt_cli.py scan https://sub.example.com --out findings.json

# 3. Turn findings into a submission-ready report file
python bughunt_cli.py report findings.json --out bughunt_import.json
```

Or just run `python bughunt_menu.py` and pick **Full Workflow** to do all three in one guided flow.

---

## Disclaimer

This project is provided for educational and authorized security-testing purposes only. The authors are not responsible for misuse of this tool. Always obtain explicit permission before testing any system you do not own.

## License

Released under the [MIT License](LICENSE).
