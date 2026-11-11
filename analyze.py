#!/usr/bin/env python3
"""
analyze.py - Summarise a Cowrie honeypot log (cowrie.json).

Basic report (standard library only, nothing to install):
    sudo python3 analyze.py cowrie.json
    sudo python3 analyze.py cowrie.json --top 5

Optional extras:
    --geoip FILE.mmdb   add the country of each attacker IP
                        (needs: sudo apt install python3-maxminddb
                         + a free country database, see README)
    --charts DIR        save PNG charts into DIR
                        (needs: sudo apt install python3-matplotlib)
"""

import argparse
import ipaddress
import json
from collections import Counter
from datetime import datetime


# ---------------------------------------------------------------------------
# 1. Reading the log
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# 2. Counting
# ---------------------------------------------------------------------------

def analyze(events):
    """Count everything interesting in one pass over the events."""
    stats = {
        "sessions": set(),
        "ips": Counter(),          # connections per source IP
        "usernames": Counter(),
        "passwords": Counter(),
        "combos": Counter(),
        "commands": Counter(),
        "downloads": Counter(),
        "per_day": Counter(),      # connections per day (YYYY-MM-DD)
        "login_success": 0,
        "login_failed": 0,
    }

    for event in events:
        eventid = event.get("eventid", "")

        if "session" in event:
            stats["sessions"].add(event["session"])

        if eventid == "cowrie.session.connect":
            stats["ips"][event.get("src_ip", "?")] += 1
            day = event.get("timestamp", "")[:10]   # "2026-11-11T14:31:43Z" -> "2026-11-11"
            if day:
                stats["per_day"][day] += 1

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


# ---------------------------------------------------------------------------
# 3. Countries (optional, needs python3-maxminddb + a .mmdb database)
# ---------------------------------------------------------------------------

def count_countries(ip_counter, mmdb_path):
    """Turn {ip: connections} into {country: connections} with an offline database."""
    try:
        import maxminddb
    except ImportError:
        raise SystemExit("[!] --geoip needs the maxminddb module: sudo apt install python3-maxminddb")

    countries = Counter()
    with maxminddb.open_database(mmdb_path) as reader:
        for ip, connections in ip_counter.items():
            countries[lookup_country(reader, ip)] += connections
    return countries


def lookup_country(reader, ip):
    """Return a readable country name for one IP."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return "Unknown"
    if address.is_private or address.is_loopback:
        return "Private network"   # lab traffic (Docker, VM, your Mac)

    record = reader.get(ip) or {}
    country = record.get("country", {})
    name = country.get("names", {}).get("en")
    code = country.get("iso_code")
    if name and code:
        return f"{name} ({code})"
    return "Unknown"


# ---------------------------------------------------------------------------
# 4. Charts (optional, needs python3-matplotlib)
# ---------------------------------------------------------------------------

# Colours: one series per chart, so a single blue; text in neutral inks.
SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK_SOFT = "#52514e"
GRID = "#e4e3df"
BLUE = "#2a78d6"


def make_charts(stats, countries, out_dir, top):
    try:
        import matplotlib
        matplotlib.use("Agg")          # no screen on a server: draw straight to files
        import matplotlib.pyplot as plt
    except ImportError:
        raise SystemExit("[!] --charts needs matplotlib: sudo apt install python3-matplotlib")

    import os
    os.makedirs(out_dir, exist_ok=True)

    plt.rcParams.update({
        "figure.facecolor": SURFACE,
        "axes.facecolor": SURFACE,
        "axes.edgecolor": GRID,
        "axes.labelcolor": INK_SOFT,
        "text.color": INK,
        "xtick.color": INK_SOFT,
        "ytick.color": INK,
        "font.size": 10,
    })

    saved = []
    charts = [
        ("countries.png", "Connections by country", countries),
        ("passwords.png", "Most tried passwords", stats["passwords"]),
        ("usernames.png", "Most tried usernames", stats["usernames"]),
        ("commands.png", "Most typed commands", stats["commands"]),
    ]
    for filename, title, counter in charts:
        if counter:
            path = os.path.join(out_dir, filename)
            bar_chart(plt, counter, title, path, top)
            saved.append(path)

    if stats["per_day"]:
        path = os.path.join(out_dir, "timeline.png")
        timeline_chart(plt, stats["per_day"], path)
        saved.append(path)

    return saved


def shorten(text, limit=45):
    return text if len(text) <= limit else text[: limit - 1] + "…"


def bar_chart(plt, counter, title, path, top):
    """Horizontal bars, biggest at the top, value written at the tip of each bar."""
    items = counter.most_common(top)[::-1]          # reversed so the biggest ends up on top
    labels = [shorten(label) or "(empty)" for label, _ in items]
    values = [value for _, value in items]

    fig, ax = plt.subplots(figsize=(8, 0.4 * len(items) + 1.3), dpi=150)
    bars = ax.barh(labels, values, height=0.55, color=BLUE)

    ax.set_title(title, loc="left", fontsize=13, fontweight="bold", pad=12)
    for side in ("top", "right", "bottom"):
        ax.spines[side].set_visible(False)
    ax.tick_params(axis="y", length=0)
    ax.tick_params(axis="x", length=0)
    ax.xaxis.grid(True, color=GRID, linewidth=1)
    ax.set_axisbelow(True)
    ax.xaxis.get_major_locator().set_params(integer=True)

    biggest = max(values)
    for bar, value in zip(bars, values):
        ax.text(bar.get_width() + biggest * 0.01, bar.get_y() + bar.get_height() / 2,
                f"{value:,}", va="center", ha="left", color=INK_SOFT, fontsize=9)
    ax.set_xlim(0, biggest * 1.12)

    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


def timeline_chart(plt, per_day, path):
    """Connections per day as a line."""
    days = sorted(per_day)
    dates = [datetime.strptime(d, "%Y-%m-%d") for d in days]
    values = [per_day[d] for d in days]

    fig, ax = plt.subplots(figsize=(8, 3.5), dpi=150)
    ax.plot(dates, values, color=BLUE, linewidth=2, solid_capstyle="round",
            marker="o", markersize=7, markerfacecolor=BLUE,
            markeredgecolor=SURFACE, markeredgewidth=2)

    ax.set_title("Connections per day", loc="left", fontsize=13, fontweight="bold", pad=12)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    ax.yaxis.grid(True, color=GRID, linewidth=1)
    ax.set_axisbelow(True)
    ax.set_ylim(bottom=0)
    ax.yaxis.get_major_locator().set_params(integer=True)
    fig.autofmt_xdate()

    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


# ---------------------------------------------------------------------------
# 5. Printing the report
# ---------------------------------------------------------------------------

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
    parser.add_argument("--geoip", metavar="MMDB", help="country database (.mmdb) to locate IPs")
    parser.add_argument("--charts", metavar="DIR", help="folder where PNG charts are saved")
    args = parser.parse_args()

    events = load_events(args.logfile)
    stats = analyze(events)
    countries = count_countries(stats["ips"], args.geoip) if args.geoip else Counter()

    print("=" * 40)
    print(" COWRIE HONEYPOT REPORT")
    print("=" * 40)
    print(f"  Events read      : {len(events)}")
    print(f"  Sessions         : {len(stats['sessions'])}")
    print(f"  Unique IPs       : {len(stats['ips'])}")
    print(f"  Logins succeeded : {stats['login_success']}")
    print(f"  Logins failed    : {stats['login_failed']}")

    print_top("Top source IPs", stats["ips"], args.top)
    if args.geoip:
        print_top("Top countries", countries, args.top)
    print_top("Top usernames", stats["usernames"], args.top)
    print_top("Top passwords", stats["passwords"], args.top)
    print_top("Top username / password combos", stats["combos"], args.top)
    print_top("Top commands", stats["commands"], args.top)
    print_top("Downloaded files (URLs)", stats["downloads"], args.top)

    if args.charts:
        saved = make_charts(stats, countries, args.charts, args.top)
        print(f"\n== Charts saved ({len(saved)}) ==")
        for path in saved:
            print(f"  {path}")

    if args.geoip:
        print("\nIP geolocation by DB-IP (https://db-ip.com), CC BY 4.0")


if __name__ == "__main__":
    main()
