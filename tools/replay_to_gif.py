#!/usr/bin/env python3
# replay one ftp_session_*.log as an asciinema cast, then run agg to get a gif.
# usage: python tools/replay_to_gif.py path/to/session.log [out.gif]
#
# needs: agg (https://github.com/asciinema/agg) on PATH.

import json
import sys
import time
import subprocess
import shutil
from pathlib import Path

# bright enough for a small gif, dim enough not to scream at people
CYAN = "\x1b[38;5;81m"
GREEN = "\x1b[38;5;120m"
RED = "\x1b[38;5;203m"
YELLOW = "\x1b[38;5;221m"
DIM = "\x1b[2m"
BOLD = "\x1b[1m"
RESET = "\x1b[0m"

# how long to wait between events when an attacker takes their time
MAX_GAP = 1.2
# the long PASV stall at the end deserves a beat, not a minute
IDLE_HOLD = 1.8


def parse_ts(s):
    # logs are "HH:MM:SS.mmm" — convert to seconds-of-day, good enough for deltas
    h, m, rest = s.split(":")
    sec, ms = rest.split(".")
    return int(h) * 3600 + int(m) * 60 + int(sec) + int(ms) / 1000


def render(ev):
    d = ev["dir"]
    data = ev["data"].replace("\\n", "\n").replace("\\r", "")

    if d == "SERVER":
        # FTP server replies are line-based; some carry embedded \n (FEAT, etc.)
        lines = [l for l in data.split("\n") if l]
        return "\r\n".join(f"{GREEN}{l}{RESET}" for l in lines) + "\r\n"

    if d == "CLIENT":
        return f"{CYAN}ftp> {data}{RESET}\r\n"

    if d == "CRED":
        return f"{BOLD}{RED}  ✱ creds: {data}{RESET}\r\n"

    if d == "PASV":
        return f"{DIM}  [pasv {data}]{RESET}\r\n"

    if d == "SESSION_END":
        return f"{DIM}  ── session closed ──{RESET}\r\n"

    # nav, modify, etc — show but quiet
    return f"{DIM}  [{d.lower()}] {data}{RESET}\r\n"


def write_cast(events, cast_path, title):
    # asciinema v2 cast format
    header = {
        "version": 2,
        "width": 92,
        "height": 26,
        "timestamp": int(time.time()),
        "title": title,
        "env": {"TERM": "xterm-256color"},
    }

    # opening frame so it's clear what you're looking at
    intro = (
        f"{BOLD}{YELLOW}▶ NetWatch session replay{RESET}\r\n"
        f"{DIM}  source: {title}{RESET}\r\n"
        f"{DIM}  watching FTP honeypot interactions...{RESET}\r\n\r\n"
    )

    with cast_path.open("w") as f:
        f.write(json.dumps(header) + "\n")

        t = 0.0
        f.write(json.dumps([t, "o", intro]) + "\n")
        t += 1.4  # let the intro breathe

        last_event_t = None
        for ev in events:
            ev_t = parse_ts(ev["ts"])
            if last_event_t is not None:
                gap = ev_t - last_event_t
                # real cadence up to a point — then snap shorter so the gif stays watchable
                gap = max(0.08, min(gap, MAX_GAP))
                # idle stretches (PASV stalls) get a hold beat, not a full wait
                if ev_t - last_event_t > 5:
                    gap = IDLE_HOLD
                t += gap
            last_event_t = ev_t

            out = render(ev)
            if out:
                f.write(json.dumps([t, "o", out]) + "\n")

        # tail pause so the last frame doesn't flash by
        t += 1.6
        f.write(json.dumps([t, "o", ""]) + "\n")


def main():
    if len(sys.argv) < 2:
        print("usage: replay_to_gif.py <session.log> [out.gif]", file=sys.stderr)
        sys.exit(1)

    log_path = Path(sys.argv[1])
    if not log_path.exists():
        print(f"no such log: {log_path}", file=sys.stderr)
        sys.exit(1)

    out_gif = Path(sys.argv[2]) if len(sys.argv) > 2 else log_path.with_suffix(".gif")

    events = []
    for line in log_path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue  # skip a malformed line rather than die on it

    if not events:
        print("no events to replay", file=sys.stderr)
        sys.exit(1)

    cast_path = out_gif.with_suffix(".cast")
    write_cast(events, cast_path, log_path.name)
    print(f"wrote cast: {cast_path}")

    if shutil.which("agg") is None:
        print("agg not on PATH — install from https://github.com/asciinema/agg")
        print(f"once installed: agg {cast_path} {out_gif}")
        return

    # default theme reads well; tweak --speed if you want it faster
    subprocess.run(
        ["agg", "--theme", "monokai", "--font-size", "16", str(cast_path), str(out_gif)],
        check=True,
    )
    print(f"wrote gif: {out_gif}")


if __name__ == "__main__":
    main()
