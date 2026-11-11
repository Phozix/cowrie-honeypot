#!/usr/bin/env python3
"""
analyze.py - Summarise a Cowrie honeypot log (cowrie.json).

Usage:
    sudo python3 analyze.py /var/lib/docker/volumes/cowrie_cowrie-var/_data/log/cowrie/cowrie.json
    sudo python3 analyze.py cowrie.json --top 5

Only uses the Python standard library: nothing to install.
"""

import argparse
import json
from collections import Counter


def load_events(path):
    """Read cowrie.json: one JSON event per line. Skip broken lines."""
    events = []
    with open(path, encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                print(f"[!] Line {line_number} is not valid JSON, skipped")
    return events


def analyze(events):
    """Count everything interesting in one pass over the events."""
    stats = {
        "sessions": set(),
        "ips": Counter(),
        "usernames": Counter(),
        "passwords": Counter(),
        "combos": Counter(),
        "commands": Counter(),
        "downloads": Counter(),
        "login_success": 0,
        "login_failed": 0,
    }

    for event in events:
        eventid = event.get("eventid", "")

        if "session" in event:
            stats["sessions"].add(event["session"])

        if eventid == "cowrie.session.connect":
            stats["ips"][event.get("src_ip", "?")] += 1

        elif eventid in ("cowrie.login.success", "cowrie.login.failed"):
            user = event.get("username", "")
            password = event.get("password", "")
            stats["usernames"][user] += 1
            stats["passwords"][password] += 1
            stats["combos"][f"{user} / {password}"] += 1
            if eventid == "cowrie.login.success":
                stats["login_success"] += 1
            else:
                stats["login_failed"] += 1

        elif eventid == "cowrie.command.input":
            command = event.get("input", "").strip()
            if command:  # ignore empty lines (attacker just pressed Enter)
                stats["commands"][command] += 1

        elif eventid == "cowrie.session.file_download":
            stats["downloads"][event.get("url", "?")] += 1

    return stats


def print_top(title, counter, top):
    """Print the N most common items of a Counter as a small table."""
    print(f"\n== {title} ==")
    if not counter:
        print("  (nothing yet)")
        return
    for value, count in counter.most_common(top):
        print(f"  {count:>6}  {value}")


def main():
    parser = argparse.ArgumentParser(description="Summarise a Cowrie cowrie.json log")
    parser.add_argument("logfile", help="path to cowrie.json")
    parser.add_argument("--top", type=int, default=10, help="how many items per list (default: 10)")
    args = parser.parse_args()

    events = load_events(args.logfile)
    stats = analyze(events)

    print("=" * 40)
    print(" COWRIE HONEYPOT REPORT")
    print("=" * 40)
    print(f"  Events read      : {len(events)}")
    print(f"  Sessions         : {len(stats['sessions'])}")
    print(f"  Unique IPs       : {len(stats['ips'])}")
    print(f"  Logins succeeded : {stats['login_success']}")
    print(f"  Logins failed    : {stats['login_failed']}")

    print_top("Top source IPs", stats["ips"], args.top)
    print_top("Top usernames", stats["usernames"], args.top)
    print_top("Top passwords", stats["passwords"], args.top)
    print_top("Top username / password combos", stats["combos"], args.top)
    print_top("Top commands", stats["commands"], args.top)
    print_top("Downloaded files (URLs)", stats["downloads"], args.top)


if __name__ == "__main__":
    main()
