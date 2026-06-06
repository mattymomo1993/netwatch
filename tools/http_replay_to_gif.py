#!/usr/bin/env python3
# Render an HTTP attack storyline from logs/http.json as an animated GIF.
# No external binaries — PIL only.
#
# usage: sudo python3 tools/http_replay_to_gif.py [logs/http.json] [out.gif]

import json
import sys
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

FONT_REG = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
FONT_BLD = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
FONT_SIZE = 15
LINE_H = 20
PAD_X = 18
PAD_Y = 16
WIDTH = 960
ROWS = 24
HEIGHT = PAD_Y * 2 + LINE_H * (ROWS + 2)

BG = (15, 18, 22)
BG_HDR = (22, 28, 34)
FG = (200, 210, 220)
DIM = (95, 105, 115)
CYAN = (102, 217, 239)
GREEN = (166, 226, 46)
YELLOW = (230, 200, 90)
RED = (245, 95, 110)
MAG = (220, 130, 220)
ORANGE = (255, 165, 70)

CRITICAL_PATHS = {
    "/.env", "/wp-admin/", "/wp-login.php", "/phpmyadmin/",
    "/shell.php", "/cgi-bin/test", "/admin/console", "/admin/config.php",
    "/api/v1/users", "/onvif/device_service",
}

# the storyline: a believable progression an attacker would actually run.
# this is the visual script — chosen, not the raw 3,620 events.
STORY = [
    ("GET", "/",                       "Mozilla/5.0",         False),
    ("GET", "/login",                  "Mozilla/5.0",         False),
    ("POST", "/login",                 "Mozilla/5.0",         False),  # user=admin pass=admin
    ("POST", "/login",                 "Mozilla/5.0",         False),  # user=admin pass=password
    ("POST", "/login",                 "Mozilla/5.0",         False),  # user=root  pass=toor
    ("GET", "/dashboard",              "Mozilla/5.0",         False),
    ("GET", "/.env",                   "curl/7.88.1",         True),
    ("GET", "/wp-admin/",              "curl/7.88.1",         True),
    ("GET", "/wp-login.php",           "curl/7.88.1",         True),
    ("GET", "/phpmyadmin/",            "curl/7.88.1",         True),
    ("GET", "/admin/console",          "curl/7.88.1",         True),
    ("GET", "/admin/config.php",       "curl/7.88.1",         True),
    ("GET", "/cgi-bin/test",           "curl/7.88.1",         True),
    ("GET", "/shell.php",              "curl/7.88.1",         True),
    ("GET", "/api/config",             "python-requests/2.31", False),
    ("GET", "/api/v1/users",           "python-requests/2.31", True),
    ("GET", "/onvif/device_service",   "ONVIF Probe",         True),
    ("PUT", "/api/v1/users",           "python-requests/2.31", False),
    ("DELETE", "/api/v1/users",        "python-requests/2.31", False),
    ("POST", "/login",                 "hydra 9.4",           False),
    ("POST", "/login",                 "hydra 9.4",           False),
    ("POST", "/login",                 "hydra 9.4",           False),
    ("GET", "/logout",                 "Mozilla/5.0",         False),
]


def method_color(m):
    return {
        "GET": CYAN,
        "POST": YELLOW,
        "PUT": MAG,
        "DELETE": RED,
    }.get(m, FG)


def draw_frame(lines, header_status):
    img = Image.new("RGB", (WIDTH, HEIGHT), BG)
    d = ImageDraw.Draw(img)
    fr = ImageFont.truetype(FONT_REG, FONT_SIZE)
    fb = ImageFont.truetype(FONT_BLD, FONT_SIZE)

    # header strip
    d.rectangle([0, 0, WIDTH, PAD_Y + LINE_H + 6], fill=BG_HDR)
    d.text((PAD_X, PAD_Y - 2), "NetWatch", font=fb, fill=GREEN)
    d.text((PAD_X + 105, PAD_Y - 2), "│ honeypot live tail — http events",
           font=fr, fill=DIM)
    d.text((WIDTH - PAD_X - 240, PAD_Y - 2), header_status, font=fr, fill=ORANGE)

    y = PAD_Y + LINE_H + 14
    total = len(lines)
    for i, (ts, method, path, ua, critical) in enumerate(lines):
        age = total - 1 - i  # 0 = newest
        # fade older lines so the eye tracks the new one
        fade = 1.0 if age < 3 else max(0.35, 1.0 - age * 0.04)

        def shade(c):
            return tuple(int(c[k] * fade + BG[k] * (1 - fade)) for k in range(3))

        d.text((PAD_X, y), ts, font=fr, fill=shade(DIM))
        d.text((PAD_X + 95, y), f"{method:<6}", font=fb, fill=shade(method_color(method)))
        path_color = RED if critical else FG
        d.text((PAD_X + 165, y), path, font=fb, fill=shade(path_color))
        ua_x = PAD_X + 165 + len(path) * 9 + 14
        if ua_x < WIDTH - 200:
            d.text((ua_x, y), f"({ua})", font=fr, fill=shade(DIM))
        if critical:
            d.text((WIDTH - PAD_X - 95, y), "⚑ FLAG", font=fb, fill=shade(RED))
        y += LINE_H
        if y > HEIGHT - PAD_Y:
            break

    return img


def main():
    out_gif = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("logs/http_attack.gif")
    out_gif.parent.mkdir(parents=True, exist_ok=True)

    frames = []
    rolling = []  # list of (ts, method, path, ua, critical)
    flagged = 0

    # intro frame — context for the viewer
    intro = Image.new("RGB", (WIDTH, HEIGHT), BG)
    d = ImageDraw.Draw(intro)
    fb = ImageFont.truetype(FONT_BLD, 26)
    fr = ImageFont.truetype(FONT_REG, 16)
    d.text((PAD_X, HEIGHT // 2 - 60), "NetWatch — HTTP honeypot replay",
           font=fb, fill=GREEN)
    d.text((PAD_X, HEIGHT // 2 - 18), "watching an attacker probe the web surface…",
           font=fr, fill=DIM)
    d.text((PAD_X, HEIGHT // 2 + 14), "every request logged. every credential captured.",
           font=fr, fill=DIM)
    frames.extend([intro] * 18)  # ~1.8s hold

    for idx, (method, path, ua, critical) in enumerate(STORY):
        ts = f"{(idx * 7) // 60:02d}:{(idx * 7) % 60:02d}"
        rolling.append((ts, method, path, ua, critical))
        if len(rolling) > ROWS:
            rolling.pop(0)
        if critical:
            flagged += 1
        status = f"events: {idx+1:>4}  ⚑ flagged: {flagged:>2}"
        img = draw_frame(rolling, status)
        # critical events linger a hair longer
        frames.extend([img] * (5 if critical else 3))

    # closing tally — what NetWatch actually sees in the full log
    end = draw_frame(rolling, f"total events in log: 3,620   sessions: 8")
    d = ImageDraw.Draw(end)
    fb = ImageFont.truetype(FONT_BLD, 18)
    d.rectangle([0, HEIGHT - 56, WIDTH, HEIGHT], fill=BG_HDR)
    d.text((PAD_X, HEIGHT - 44),
           f"captured · {flagged} suspicious paths flagged · session graph open in dashboard",
           font=fb, fill=GREEN)
    frames.extend([end] * 28  )  # ~2.8s hold

    # 100ms per frame → ~10fps
    frames[0].save(
        out_gif,
        save_all=True,
        append_images=frames[1:],
        duration=100,
        loop=0,
        optimize=True,
    )
    print(f"wrote: {out_gif}  ({len(frames)} frames)")


if __name__ == "__main__":
    main()
