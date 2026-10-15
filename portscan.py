# bughunt_cli.py -er bhitore ei rokom dekhabe:

import subprocess

def cmd_portscan(args):
    target = args.target.strip()
    
    # --- Authorization check, bar bar dekhbe emon tool-e ---
    print(f"\nYou are about to PORT SCAN: {target}")
    print("This is an ACTIVE scan and is more intrusive than header checks.")
    print("Only proceed with written permission.")
    typed = input(f"Type the target exactly to confirm ('{target}'): ").strip()
    if typed != target:
        print("Not confirmed. Aborting.")
        return

    # --- Nmap-ke subprocess hishebe call kora ---
    # -F = fast scan (common 100 ports only), beshi aggressive na
    cmd = ["nmap", "-F", target]
    print(f"\nRunning: {' '.join(cmd)}\n")
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        print(result.stdout)
    except FileNotFoundError:
        print("Nmap is not installed. Install it first (nmap.org).")
    except Exception as e:
        print(f"Scan failed: {e}")

# argparse-e eta register hobe ei vabe:
pp = sub.add_parser("portscan", help="Port scan a target (ACTIVE - needs explicit permission)")
pp.add_argument("target", help="IP or domain")
pp.set_defaults(func=cmd_portscan)