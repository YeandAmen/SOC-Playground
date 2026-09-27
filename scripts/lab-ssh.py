#!/usr/bin/env python3
"""Run a command or copy a file between the Mac host and a lab VM."""

import argparse
import getpass
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", choices=("kali", "windows"))
    parser.add_argument("--ip", required=True, help="VM address on your lab network")
    parser.add_argument("--user", required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--command", help="remote command to run")
    group.add_argument("--put", nargs=2, metavar=("LOCAL", "REMOTE"), help="copy a file from Mac to VM")
    group.add_argument("--get", nargs=2, metavar=("REMOTE", "LOCAL"), help="copy a file from VM to Mac")
    args = parser.parse_args()

    try:
        import paramiko
    except ImportError:
        parser.error("Install dependency: python3 -m pip install -r requirements.txt")

    address = args.ip
    password = getpass.getpass(f"{args.user}@{address} SSH password: ")
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.WarningPolicy())
    try:
        client.connect(address, username=args.user, password=password, timeout=10,
                       look_for_keys=False, allow_agent=False)
        if args.command:
            _, stdout, stderr = client.exec_command(args.command)
            sys.stdout.buffer.write(stdout.read())
            sys.stderr.buffer.write(stderr.read())
            return stdout.channel.recv_exit_status()
        with client.open_sftp() as sftp:
            if args.put:
                sftp.put(*args.put)
                print(f"Copied {args.put[0]} to {args.user}@{address}:{args.put[1]}")
            else:
                sftp.get(*args.get)
                print(f"Copied {args.user}@{address}:{args.get[0]} to {args.get[1]}")
        return 0
    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
