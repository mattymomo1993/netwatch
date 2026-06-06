#!/usr/bin/env python3
"""
NetWatch v2.0 - Unified Network Security Dashboard
════════════════════════════════════════════════════
Modules:
  HONEYPOT  - Fake NVR panel, DVR telnet, RTSP camera, FTP bait
              (defaults :8080/:2323/:2121/:8554, override via NETWATCH_*_PORT env)
  TRAFFIC   - Live packet capture via tshark + raw sockets
  SCANNER   - On-demand nmap scans from dashboard
  CAPTURE   - tcpdump pcap recording
  OSINT     - Reverse DNS, service ID, threat scoring

Run: sudo python3 netwatch.py [interface]
"""

import os
import re
import sys
import ssl
import time
import json
import socket
import select
import struct
import signal
import random
import secrets
import ipaddress
import threading
import subprocess
from datetime import datetime, timezone
from collections import defaultdict, deque
from flask import Flask, request, render_template_string, redirect, jsonify
from markupsafe import escape as _escape

try:
    import requests as req_lib
except ImportError:
    req_lib = None
try:
    import whois as whois_lib
except ImportError:
    whois_lib = None
try:
    import dns.resolver
    import dns.reversename
except ImportError:
    dns = None

import replay  # session-replay data layer (replay.py)

# ─── Config ──────────────────────────────────────────────

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, "logs")
PCAP_DIR = os.path.join(LOG_DIR, "pcaps")
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(PCAP_DIR, exist_ok=True)
try:
    os.chmod(LOG_DIR, 0o700)
    os.chmod(PCAP_DIR, 0o700)
except PermissionError:
    pass

SERIAL = random.randint(1000, 9999)
IFACE = sys.argv[1] if len(sys.argv) > 1 else "wlan0"
_cli_token = None
for _i, _a in enumerate(sys.argv):
    if _a == "--token" and _i + 1 < len(sys.argv):
        _cli_token = sys.argv[_i + 1]
        break
VERSION = "1.1.0"

# Honeypot listener ports — overridable via env so deployments can move to
# standard ports (80/23/21/554) without local sed against the repo.
# CAP_NET_BIND_SERVICE or root required for ports <1024.
HTTP_PORT   = int(os.environ.get("NETWATCH_HTTP_PORT",   "8080"))
TELNET_PORT = int(os.environ.get("NETWATCH_TELNET_PORT", "2323"))
FTP_PORT    = int(os.environ.get("NETWATCH_FTP_PORT",    "2121"))
RTSP_PORT   = int(os.environ.get("NETWATCH_RTSP_PORT",   "8554"))

# ─── Colors ──────────────────────────────────────────────

RED = "\033[91m"; GREEN = "\033[92m"; YELLOW = "\033[93m"
BLUE = "\033[94m"; MAGENTA = "\033[95m"; CYAN = "\033[96m"
WHITE = "\033[97m"; DIM = "\033[2m"; BOLD = "\033[1m"
RESET = "\033[0m"; BG_RED = "\033[41m"; BG_GREEN = "\033[42m"

# ─── Shared State ────────────────────────────────────────

lock = threading.RLock()

# Traffic
hosts = defaultdict(lambda: {
    "bytes_in": 0, "bytes_out": 0, "packets": 0,
    "ports": set(), "protocols": set(), "first_seen": None, "last_seen": None,
    "hostname": "", "resolved": False, "threat_score": 0, "tags": set(),
})
dns_queries = []
alerts = []
total_packets = 0
total_bytes = 0
start_time = time.time()

# Environment detection — Termux (Android) cannot use raw sockets or iptables
# without root. Run in "passive" mode: honeypots + OSINT + web only.
IS_TERMUX = bool(os.environ.get("TERMUX_VERSION") or
                 os.environ.get("PREFIX", "").startswith("/data/data/com.termux"))
try:
    IS_ROOT = (os.geteuid() == 0)
except AttributeError:
    IS_ROOT = False
HAS_RAW_NET = IS_ROOT and not IS_TERMUX  # raw sockets, tcpdump, tshark, iptables

MAX_ALERTS = 500
MAX_HOSTS = 2000
MAX_DNS_CACHE = 1000
MAX_RECON = 200

def _capped_append(lst, item, cap):
    lst.append(item)
    if len(lst) > cap:
        del lst[:len(lst) - cap]

# Honeypot
honeypot_events = []
MAX_EVENTS = 100
MAX_CONNS_PER_SERVICE = 50
_service_conns = defaultdict(int)

def _ansi_strip(s):
    s = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', s)       # ANSI CSI sequences
    s = re.sub(r'\x1b\][^\x07]*\x07', '', s)           # OSC sequences (title set etc)
    s = re.sub(r'\x1b[^[\]][^\x1b]{0,2}', '', s)       # Other ESC sequences
    s = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', s)  # C0 control chars (keep \t \n \r)
    s = s.replace('\r', '')                              # Strip carriage returns (log forgery)
    return s

# tshark protocol stats
proto_stats = defaultdict(int)

# nmap results
nmap_results = []
nmap_running = False

# tcpdump state
tcpdump_proc = None
tcpdump_file = ""

# Suspicious ports
SUS_PORTS = {4444, 5555, 1337, 31337, 6667, 6697, 12345, 54321, 4443}
SCAN_THRESHOLD = 50
TOR_PORTS = {9001, 9002, 9003, 9030, 9050, 9051, 9150}

# Whitelist
WHITELIST_SCAN = {
    "127.0.0.1", "10.0.1.1", "100.66.15.102", "100.85.81.110",
    "160.79.104.10", "142.251.211.91", "172.253.62.188",
    "149.154.166.110", "209.177.145.120",
    "207.251.86.235",  # webcams.nyctmc.org - LocalTipoff
}
WHITELIST_PREFIXES = (
    "216.239.", "104.16.", "104.17.", "104.18.", "199.232.",
    "151.101.", "142.250.", "142.251.", "172.253.", "172.217.",
    "207.251.",  # NYC DOT camera range
    "18.238.",   # CloudFront
    "18.155.",   # CloudFront
    "108.138.",  # CloudFront
)

# Known services for OSINT enrichment
KNOWN_SERVICES = {
    "webcams.nyctmc.org": ("NYC DOT Cameras", "infra"),
    "511ny.org": ("NY 511 Traffic", "infra"),
    "cmn-trffc.pulse.weatherbug.net": ("WeatherBug CDN", "telemetry"),
    "check.torproject.org": ("Tor Check", "privacy"),
}

def is_whitelisted(ip):
    return ip in WHITELIST_SCAN or ip.startswith(WHITELIST_PREFIXES)

def get_local_ips():
    ips = set()
    try:
        out = subprocess.check_output(["ip", "addr"], text=True)
        for line in out.split("\n"):
            if "inet " in line:
                ips.add(line.strip().split()[1].split("/")[0])
    except Exception:
        ips.add("10.0.1.9")
    return ips

LOCAL_IPS = get_local_ips()

# ─── OSINT Enrichment ───────────────────────────────────

dns_cache = {}

def resolve_host(ip):
    if ip in dns_cache:
        return dns_cache[ip]
    try:
        name = _ansi_strip(socket.gethostbyaddr(ip)[0])[:35]
    except Exception:
        name = ""
    if len(dns_cache) > MAX_DNS_CACHE:
        for k in list(dns_cache)[:len(dns_cache) - MAX_DNS_CACHE]:
            del dns_cache[k]
    dns_cache[ip] = name
    return name

KNOWN_INFRA = ("cloudfront", "google", "amazon", "aws", "telegram",
               "microsoft", "apple", "akamai", "fastly",
               "cloudflare", "github", "facebook", "meta", "netflix")

def enrich_host(ip):
    h = hosts[ip]
    if h.get("_enriched"):
        return
    hostname = resolve_host(ip)
    h["hostname"] = hostname
    h["resolved"] = True
    h["tags"] = set()

    is_known = any(k in hostname.lower() for k in KNOWN_INFRA) if hostname else False
    is_local = ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16.") or ip in LOCAL_IPS

    if "cloudfront" in hostname:
        h["tags"].add("CDN")
    elif "google" in hostname:
        h["tags"].add("Google")
    elif "amazon" in hostname or "aws" in hostname:
        h["tags"].add("AWS")
    elif "telegram" in hostname:
        h["tags"].add("Telegram")

    # NOTE: is_known is based on reverse DNS which is attacker-controllable.
    # We still tag for DISPLAY, but NEVER skip threat scoring based on PTR alone.
    # Only truly local IPs and hardcoded whitelisted IPs skip scoring.
    if is_local or is_whitelisted(ip):
        h["_enriched"] = True
        return

    port_count = len(h["ports"])
    if port_count > SCAN_THRESHOLD:
        h["tags"].add("SCANNER")
        h["threat_score"] += 30
    if h["ports"] & SUS_PORTS:
        h["tags"].add("SUS-PORT")
        h["threat_score"] += 20
    if h["ports"] & {23, 3389}:
        h["tags"].add("REMOTE-ACCESS")

    h["_enriched"] = True

# ─── Logging ─────────────────────────────────────────────

_log_lock = threading.Lock()
MAX_LOG_FIELD = 256
MAX_LOG_FILE_SIZE = 50 * 1024 * 1024  # 50MB

def _truncate_data(data, max_len=MAX_LOG_FIELD):
    if isinstance(data, dict):
        return {k: _truncate_data(v, max_len) for k, v in data.items()}
    if isinstance(data, str):
        return data[:max_len] if len(data) > max_len else data
    if isinstance(data, list):
        return [_truncate_data(v, max_len) for v in data[:50]]
    return data

def _rotate_log(filepath):
    try:
        if os.path.exists(filepath) and os.path.getsize(filepath) > MAX_LOG_FILE_SIZE:
            for i in range(2, 0, -1):
                src = f"{filepath}.{i}" if i > 0 else filepath
                dst = f"{filepath}.{i+1}"
                if os.path.exists(src):
                    os.rename(src, dst)
            os.rename(filepath, f"{filepath}.1")
    except OSError:
        pass

def log_event(service, ip, data):
    truncated = _truncate_data(data)
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": service,
        "source_ip": ip,
        "source_port": truncated.get("port", ""),
        "data": truncated,
    }
    line = json.dumps(entry) + "\n"
    logfile = os.path.join(LOG_DIR, f"{service}.json")
    all_log = os.path.join(LOG_DIR, "all_events.json")
    with _log_lock:
        _rotate_log(logfile)
        with open(logfile, "a") as f:
            f.write(line)
        _rotate_log(all_log)
        with open(all_log, "a") as f:
            f.write(line)

    short = _short_summary(service, ip, data)
    with lock:
        honeypot_events.append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "service": service, "ip": ip, "summary": short,
        })
        if len(honeypot_events) > MAX_EVENTS:
            honeypot_events.pop(0)
    if mesh_alert_fwd and mesh_interface and service in ("credential", "malware_attempt", "ftp_upload"):
        threading.Thread(target=_mesh_forward_alert, args=(f"{service} from {ip}: {short}",), daemon=True).start()

    # CrowdSec hand-off (no-op if cscli missing). Runs OUTSIDE both locks.
    if os.environ.get("NETWATCH_AUTODEFEND", "1") == "1":
        try:
            from netwatch_crowdsec import maybe_defend as _cs_defend
            threading.Thread(target=_cs_defend, args=(service, ip), daemon=True).start()
        except ImportError:
            pass

def _short_summary(service, ip, data):
    if service == "credential":
        pw = data.get('password') or ''
        s = f"{data.get('username','')}:{'*' * min(len(pw), 8)}"
    elif service == "telnet":
        pw = data.get('password') or ''
        s = f"login {data.get('username','')}/{'*' * min(len(pw), 8)}"
    elif service == "telnet_cmd":
        s = f"cmd: {data.get('command','')[:40]}"
    elif service == "malware_attempt":
        s = f"MALWARE: {data.get('command','')[:40]}"
    elif service in ("rtsp", "rtsp_auth"):
        s = "RTSP probe"
    elif service == "api_probe":
        s = f"API probe {data.get('method','')}"
    elif service == "onvif_probe":
        s = "ONVIF probe"
    elif service == "scan_probe":
        s = f"{data.get('method','')} {data.get('path','')[:30]}"
    elif service == "dashboard_access":
        s = "viewed dashboard"
    elif service == "http":
        s = f"{data.get('method','')} {data.get('path','')}"
    else:
        s = service
    return _ansi_strip(s)

# -- HONEYPOT - Flask HTTP (NVR Panel)

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
import logging

# Bounded session store with TTL (replaces unbounded app.config abuse)
_session_store = {}  # ip -> {"attempts": int, "threshold": int, "authed": bool, "ts": float}
MAX_SESSIONS = 10000
SESSION_TTL = 3600  # 1 hour

def _get_session(ip):
    now = time.time()
    if ip in _session_store:
        sess = _session_store[ip]
        if now - sess["ts"] > SESSION_TTL:
            del _session_store[ip]
        else:
            return sess
    # Evict oldest if at capacity
    if len(_session_store) >= MAX_SESSIONS:
        oldest_ip = min(_session_store, key=lambda k: _session_store[k]["ts"])
        del _session_store[oldest_ip]
    _session_store[ip] = {
        "attempts": 0, "threshold": random.randint(3, 7),
        "authed": False, "ts": now,
    }
    return _session_store[ip]
import termios
import tty
logging.getLogger("werkzeug").setLevel(logging.ERROR)

LOGIN_PAGE = """<!DOCTYPE html><html><head><title>Network Video Recorder - Login</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:Arial,Helvetica,sans-serif;background:#1a1a2e;display:flex;justify-content:center;align-items:center;min-height:100vh}.login-container{background:#16213e;border:1px solid #0f3460;border-radius:4px;padding:40px;width:380px;box-shadow:0 4px 20px rgba(0,0,0,.5)}.logo{text-align:center;margin-bottom:30px}.logo h1{color:#e94560;font-size:18px;letter-spacing:2px}.logo p{color:#666;font-size:11px;margin-top:5px}.form-group{margin-bottom:15px}.form-group label{display:block;color:#999;font-size:12px;margin-bottom:5px}.form-group input{width:100%;padding:10px;background:#0f3460;border:1px solid #1a1a4e;border-radius:3px;color:#fff;font-size:14px}.form-group input:focus{outline:none;border-color:#e94560}.login-btn{width:100%;padding:12px;background:#e94560;color:#fff;border:none;border-radius:3px;font-size:14px;cursor:pointer;margin-top:10px}.login-btn:hover{background:#c73550}.error{color:#e94560;font-size:12px;text-align:center;margin-top:10px}.footer{text-align:center;margin-top:20px;color:#444;font-size:10px}.device-info{background:#0f3460;border-radius:3px;padding:8px 12px;margin-bottom:20px}.device-info span{color:#4ecca3;font-size:11px}</style></head><body>
<div class="login-container"><div class="logo"><h1>NVR PRO 4200</h1><p>Network Video Recorder Management System</p></div>
<div class="device-info"><span>Device: NVR-4200-PRO | Firmware: v4.3.2.187 | Channels: 16</span></div>
<form method="POST" action="/login"><div class="form-group"><label>Username</label><input type="text" name="username" placeholder="admin" autocomplete="off"></div>
<div class="form-group"><label>Password</label><input type="password" name="password" placeholder="Password"></div>
<button type="submit" class="login-btn">Sign In</button>{% if error %}<div class="error">{{ error }}</div>{% endif %}</form>
<div class="footer">Copyright 2024 NVR Systems Inc. All Rights Reserved.<br>Serial: NVR4200-2024-00{{ serial }}</div></div></body></html>"""

DASHBOARD_PAGE = """<!DOCTYPE html><html><head><title>NVR PRO 4200 - Dashboard</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:Arial,sans-serif;background:#0a0a1a;color:#ccc}.header{background:#16213e;padding:12px 20px;display:flex;justify-content:space-between;align-items:center;border-bottom:2px solid #e94560}.header h1{color:#e94560;font-size:16px}.header .status{color:#4ecca3;font-size:12px}.nav{background:#0f3460;padding:8px 20px;display:flex;gap:20px}.nav a{color:#999;text-decoration:none;font-size:13px}.nav a:hover{color:#e94560}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:2px;padding:10px}.cam-cell{background:#111;aspect-ratio:16/9;display:flex;align-items:center;justify-content:center;position:relative;border:1px solid #222}.cam-cell .label{position:absolute;top:5px;left:8px;font-size:10px;color:#4ecca3;background:rgba(0,0,0,.7);padding:2px 6px;border-radius:2px}.cam-cell .time{position:absolute;bottom:5px;right:8px;font-size:9px;color:#666}.cam-cell .offline{color:#e94560;font-size:11px}.cam-cell .connecting{color:#f0a500;font-size:11px}.sidebar{position:fixed;right:0;top:80px;background:#16213e;width:200px;padding:15px;border-left:1px solid #0f3460;height:calc(100vh - 80px)}.sidebar h3{color:#e94560;font-size:12px;margin-bottom:10px}.sidebar .stat{font-size:11px;margin-bottom:8px}.sidebar .stat span{color:#4ecca3}.loading-bar{width:100%;height:3px;background:#0f3460;margin-top:5px}.loading-bar .fill{height:100%;background:#4ecca3;animation:load 2s ease-in-out infinite}@keyframes load{0%{width:0}50%{width:70%}100%{width:100%}}</style></head><body>
<div class="header"><h1>NVR PRO 4200</h1><div class="status">RECORDING | 12/16 Channels Active | HDD: 2.1TB / 4TB</div></div>
<div class="nav"><a href="#">Live View</a><a href="#">Playback</a><a href="#">Alerts</a><a href="#">Settings</a><a href="/logout">Logout</a></div>
<div class="grid" style="margin-right:210px">{% for cam in cams %}<div class="cam-cell"><span class="label">{{ cam.label }}</span><div class="{{ cam.cls }}">{{ cam.status }}</div><span class="time">{{ cam.time }}</span></div>{% endfor %}</div>
<div class="sidebar"><h3>System Status</h3><div class="stat">CPU: <span>34%</span></div><div class="stat">RAM: <span>1.8GB / 4GB</span></div><div class="stat">HDD: <span>2.1TB / 4TB</span></div><div class="stat">Temp: <span>42C</span></div><div class="stat">Uptime: <span>14d 7h 23m</span></div><div class="stat">Firmware: <span>v4.3.2.187</span></div><h3 style="margin-top:15px">Network</h3><div class="stat">IP: <span>{{ client_ip }}</span></div><div class="stat">Gateway: <span>10.0.1.1</span></div><div class="loading-bar"><div class="fill"></div></div></div></body></html>"""

CAM_DATA = [
    ("CAM 01 - Front Gate", True), ("CAM 02 - Parking Lot A", True),
    ("CAM 03 - Rear Entrance", True), ("CAM 04 - Loading Dock", True),
    ("CAM 05 - Lobby", True), ("CAM 06 - Server Room", True),
    ("CAM 07 - Hallway B2", False), ("CAM 08 - Stairwell", True),
    ("CAM 09 - Parking Lot B", True), ("CAM 10 - East Perimeter", False),
    ("CAM 11 - West Perimeter", True), ("CAM 12 - Main Office", True),
    ("CAM 13 - Warehouse", False), ("CAM 14 - Break Room", False),
    ("CAM 15 - Roof Access", True), ("CAM 16 - Generator", True),
]

@app.before_request
def log_all_requests():
    log_event("http", request.remote_addr, {
        "method": request.method, "path": request.path,
        "user_agent": request.headers.get("User-Agent", ""),
        "headers": dict(request.headers),
    })

@app.route("/")
def index():
    return redirect("/login")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        log_event("credential", request.remote_addr, {
            "username": username, "password": password,
            "user_agent": request.headers.get("User-Agent", ""),
        })
        sess = _get_session(request.remote_addr)
        sess["attempts"] += 1
        sess["ts"] = time.time()
        if sess["attempts"] >= sess["threshold"]:
            sess["authed"] = True
            return redirect("/dashboard")
        return render_template_string(LOGIN_PAGE, error="Invalid credentials. Please try again.", serial=SERIAL)
    return render_template_string(LOGIN_PAGE, error=None, serial=SERIAL)

@app.route("/dashboard")
def dashboard():
    sess = _get_session(request.remote_addr)
    if not sess.get("authed"):
        return redirect("/login")
    now = datetime.now().strftime("%H:%M:%S")
    log_event("dashboard_access", request.remote_addr, {
        "action": "viewed_dashboard",
        "user_agent": request.headers.get("User-Agent", ""),
    })
    cams = []
    for label, online in CAM_DATA:
        if online:
            cams.append({"label": label, "cls": "connecting", "status": "Buffering stream...", "time": now})
        else:
            cams.append({"label": label, "cls": "offline", "status": "OFFLINE", "time": "--:--:--"})
    return render_template_string(DASHBOARD_PAGE, cams=cams, client_ip=str(_escape(request.remote_addr)))

@app.route("/api/config", methods=["GET", "POST"])
def api_config():
    log_event("api_probe", request.remote_addr, {
        "method": request.method, "body": request.get_data(as_text=True),
    })
    return jsonify({"device": "NVR-4200-PRO", "firmware": "4.3.2.187", "channels": 16,
        "rtsp_port": 554, "onvif_port": 8899, "admin_enabled": True, "upnp": True})

@app.route("/onvif/device_service", methods=["GET", "POST"])
def onvif():
    log_event("onvif_probe", request.remote_addr, {
        "method": request.method, "body": request.get_data(as_text=True),
    })
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope">
<SOAP-ENV:Body><tds:GetDeviceInformationResponse>
<tds:Manufacturer>NVR Systems Inc</tds:Manufacturer>
<tds:Model>NVR-4200-PRO</tds:Model>
<tds:FirmwareVersion>4.3.2.187</tds:FirmwareVersion>
<tds:SerialNumber>NVR4200-2024-{SERIAL:04d}</tds:SerialNumber>
</tds:GetDeviceInformationResponse></SOAP-ENV:Body>
</SOAP-ENV:Envelope>""", 200, {"Content-Type": "application/xml"}

@app.route("/logout")
def logout():
    ip = request.remote_addr
    if ip in _session_store:
        del _session_store[ip]
    return redirect("/login")

@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE"])
def catch_all(path):
    log_event("scan_probe", request.remote_addr, {
        "method": request.method, "path": f"/{path}",
        "body": request.get_data(as_text=True)[:500],
        "user_agent": request.headers.get("User-Agent", ""),
    })
    return "404 Not Found", 404

# -- HONEYPOT - Telnet

def _honeypot_listener(service, port, handler):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.listen(5)
    while True:
        try:
            client, addr = sock.accept()
            with lock:
                if _service_conns[service] >= MAX_CONNS_PER_SERVICE:
                    client.close()
                    continue
                _service_conns[service] += 1
            threading.Thread(target=handler, args=(client, addr), daemon=True).start()
        except Exception:
            pass

def telnet_honeypot(port=None):
    if port is None: port = TELNET_PORT
    _honeypot_listener("telnet", port, handle_telnet)

def handle_telnet(client, addr):
    try:
        client.settimeout(30)
        client.send(b"\r\nDVR-4200 login: ")
        username = _ansi_strip(client.recv(256).decode(errors="replace").strip())
        client.send(b"Password: ")
        password = _ansi_strip(client.recv(256).decode(errors="replace").strip())
        log_event("telnet", addr[0], {"port": addr[1], "username": username, "password": password})
        time.sleep(random.uniform(0.5, 2.5))  # Randomized delay to avoid timing fingerprint
        client.send(b"\r\nLogin incorrect\r\n\r\nDVR-4200 login: ")
        username2 = _ansi_strip(client.recv(256).decode(errors="replace").strip())
        client.send(b"Password: ")
        password2 = _ansi_strip(client.recv(256).decode(errors="replace").strip())
        log_event("telnet", addr[0], {"port": addr[1], "username": username2, "password": password2, "attempt": 2})
        client.send(b"\r\n\r\nBusyBox v1.29.3 () built-in shell (ash)\r\n\r\n# ")
        _telnet_idle_timeout = time.time() + 120  # 120s idle timeout
        for _ in range(100):  # 100 commands max (not 20) to avoid fingerprinting
            cmd = _ansi_strip(client.recv(1024).decode(errors="replace").strip())
            if not cmd:
                break
            log_event("telnet_cmd", addr[0], {"command": _ansi_strip(cmd)})
            responses = {
                "id": b"uid=0(root) gid=0(root)\r\n# ",
                "ls": b"bin  etc  lib  mnt  proc  sys  tmp  usr  var\r\n# ",
                "dir": b"bin  etc  lib  mnt  proc  sys  tmp  usr  var\r\n# ",
                "ls -la": b"drwxr-xr-x  12 root root  4096 Jan  5  2024 .\r\ndrwxr-xr-x  12 root root  4096 Jan  5  2024 ..\r\ndrwxr-xr-x   2 root root  4096 Jan  5  2024 bin\r\ndrwxr-xr-x   3 root root  4096 Jan  5  2024 etc\r\n# ",
                "uname -a": b"Linux DVR4200 3.10.14 #1 SMP Fri Jan 5 10:23:41 UTC 2024 armv7l GNU/Linux\r\n# ",
                "uname -r": b"3.10.14\r\n# ",
                "whoami": b"root\r\n# ",
                "pwd": b"/root\r\n# ",
                "hostname": b"DVR4200\r\n# ",
                "uptime": b" 14:23:01 up 42 days,  3:15,  1 user,  load average: 0.08, 0.03, 0.01\r\n# ",
                "ps": b"  PID TTY      STAT   TIME COMMAND\r\n    1 ?        Ss     0:03 init\r\n  127 ?        S      0:00 /usr/sbin/dvr_main\r\n  189 ?        S      0:00 /usr/sbin/httpd\r\n  201 ?        S      0:00 /usr/sbin/telnetd\r\n# ",
                "ifconfig": b"eth0  Link encap:Ethernet  HWaddr 28:D2:44:7A:B3:1F\r\n      inet addr:10.0.1.50  Bcast:10.0.1.255  Mask:255.255.255.0\r\n      UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1\r\n# ",
                "cat /proc/cpuinfo": b"processor\t: 0\r\nmodel name\t: ARMv7 Processor rev 4 (v7l)\r\nBogoMIPS\t: 38.40\r\nFeatures\t: half thumb fastmult vfp edsp neon vfpv3 tls vfpv4\r\n# ",
                "cat /proc/version": b"Linux version 3.10.14 (gcc version 4.8.3) #1 SMP Fri Jan 5 10:23:41 UTC 2024\r\n# ",
                "free": b"              total        used        free\r\nMem:        256000      187000       69000\r\n# ",
                "mount": b"/dev/mtdblock3 on / type squashfs (ro,relatime)\r\ntmpfs on /tmp type tmpfs (rw,nosuid,nodev)\r\n# ",
                "df": b"Filesystem     1K-blocks  Used Available Use% Mounted on\r\n/dev/mtdblock3     15360 12288      3072  80% /\r\ntmpfs              64000   120     63880   1% /tmp\r\n# ",
                "netstat -tlnp": b"Active Internet connections (only servers)\r\nProto Local Address   Foreign Address  State   PID/Program\r\ntcp   0.0.0.0:80      0.0.0.0:*        LISTEN  189/httpd\r\ntcp   0.0.0.0:554     0.0.0.0:*        LISTEN  127/dvr_main\r\ntcp   0.0.0.0:23      0.0.0.0:*        LISTEN  201/telnetd\r\n# ",
            }
            if cmd.startswith("cat /etc/passwd"):
                client.send(b"root:x:0:0:root:/root:/bin/ash\r\nadmin:x:1000:1000::/home/admin:/bin/ash\r\nnobody:x:65534:65534:nobody:/nonexistent:/bin/false\r\n# ")
            elif cmd.startswith("cat /etc/shadow"):
                client.send(b"cat: /etc/shadow: Permission denied\r\n# ")
            elif cmd.startswith("echo "):
                val = cmd[5:].strip().strip('"').strip("'")
                client.send(f"{val}\r\n# ".encode())
            elif cmd in responses:
                client.send(responses[cmd])
            elif any(x in cmd for x in ("wget", "curl", "tftp", "chmod", "busybox")):
                log_event("malware_attempt", addr[0], {"command": cmd})
                if "wget" in cmd or "curl" in cmd:
                    client.send(b"Connecting to remote host... Connection timed out\r\n# ")
                elif "tftp" in cmd:
                    client.send(b"tftp: server error\r\n# ")
                else:
                    client.send(b"-ash: permission denied\r\n# ")
            elif cmd in ("exit", "quit", "logout"):
                break
            else:
                first_word = cmd.split()[0] if cmd.split() else cmd
                client.send(f"-ash: {first_word}: not found\r\n# ".encode())
    except Exception:
        pass
    finally:
        with lock:
            _service_conns["telnet"] = max(0, _service_conns["telnet"] - 1)
        client.close()

# -- HONEYPOT - RTSP

def rtsp_honeypot(port=None):
    if port is None: port = RTSP_PORT
    _honeypot_listener("rtsp", port, handle_rtsp)

def handle_rtsp(client, addr):
    try:
        client.settimeout(10)
        data = client.recv(4096).decode(errors="replace")
        log_event("rtsp", addr[0], {"port": addr[1], "request": data[:500]})
        client.send(("RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\n"
            "WWW-Authenticate: Basic realm=\"NVR-4200\"\r\n"
            "Server: NVR-RTSP/4.3\r\n\r\n").encode())
        data2 = client.recv(4096).decode(errors="replace")
        if data2:
            log_event("rtsp_auth", addr[0], {"port": addr[1], "auth_request": data2[:500]})
    except Exception:
        pass
    finally:
        with lock:
            _service_conns["rtsp"] = max(0, _service_conns["rtsp"] - 1)
        client.close()

# -- HONEYPOT - FTP (full keystroke capture + bait files)

FTP_ROOT = os.path.join(BASE_DIR, "ftp_root")
FTP_UPLOAD_DIR = os.path.join(LOG_DIR, "ftp_uploads")
os.makedirs(FTP_ROOT, exist_ok=True)
os.makedirs(FTP_UPLOAD_DIR, exist_ok=True)
try:
    os.chmod(FTP_UPLOAD_DIR, 0o700)
except PermissionError:
    pass

# Bait file listing
FTP_FILES = {
    "/": ["backup/", "config/", "firmware/", "logs/"],
    "/backup": ["db_dump_2024.sql", "camera_config_bak.tar.gz"],
    "/config": ["network.conf", "camera_keys.pem", "users.db"],
    "/firmware": ["NVR4200_fw_4.3.2.187.bin", "RELEASE_NOTES.txt"],
    "/logs": ["access.log", "auth.log", "system.log"],
}

def ftp_honeypot(port=None):
    if port is None: port = FTP_PORT
    _honeypot_listener("ftp", port, handle_ftp)

def handle_ftp(client, addr):
    client.settimeout(60)
    ip = addr[0]
    # microsecond suffix so back-to-back connects from one IP don't share a log file
    session_id = f"{ip}_{datetime.now().strftime('%H%M%S_%f')}"
    session_log = os.path.join(LOG_DIR, f"ftp_session_{session_id}.log")
    cwd = "/"
    username = ""
    authenticated = False
    data_sock = None
    passive_sock = None
    _pasv_accept_thread = None
    _pasv_ready = threading.Event()
    _pasv_count = 0
    MAX_PASV_PER_SESSION = 5

    log_event("ftp_connect", ip, {"port": addr[1]})

    # Auto-recon on connecting IP
    threading.Thread(target=_ftp_auto_recon, args=(ip,), daemon=True).start()

    def send(msg):
        sent_ok = True
        try:
            client.send((msg + "\r\n").encode())
        except Exception:
            sent_ok = False
        ftp_log("SERVER" if sent_ok else "SERVER_FAIL", msg)

    def ftp_log(direction, data):
        """Log every single byte exchanged — JSON-safe, truncated, newline-escaped"""
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        safe_data = _ansi_strip(str(data)[:MAX_LOG_FIELD]).replace("\r", "\\r").replace("\n", "\\n")
        entry = json.dumps({"ts": ts, "dir": direction, "data": safe_data})
        with _log_lock:
            with open(session_log, "a") as f:
                f.write(entry + "\n")
        log_event("ftp_keystroke", ip, {
            "session": session_id, "direction": direction,
            "data": safe_data[:500], "username": username[:MAX_LOG_FIELD],
        })

    try:
        send("220 NVR-4200 FTP Service v4.3 Ready.")
        _ftp_cmd_count = 0

        while True:
            try:
                _ftp_cmd_count += 1
                if _ftp_cmd_count > 200:
                    send("421 Too many commands, closing.")
                    break
                raw = client.recv(4096)
                if not raw:
                    break
                # if the first few bytes aren't printable ASCII it's almost certainly
                # a TLS ClientHello or other binary probe — log it as hex instead of
                # decoding to mojibake. handshake bytes 0x16 0x03 0x0X are the giveaway.
                head = raw[:4]
                if any(b < 0x09 or (0x0e <= b < 0x20) or b >= 0x80 for b in head):
                    preview = raw[:64].hex()
                    ftp_log("CLIENT_BINARY", f"{len(raw)} bytes hex={preview}")
                    send("502 Command not implemented.")
                    continue
                cmd_line = raw.decode("ascii", errors="replace").strip()
            except Exception:
                break

            if not cmd_line:
                continue

            ftp_log("CLIENT", cmd_line)

            parts = cmd_line.split(" ", 1)
            cmd = parts[0].upper()
            arg = parts[1] if len(parts) > 1 else ""

            # ── Authentication ──
            if cmd == "USER":
                username = arg
                log_event("ftp_credential", ip, {"username": username, "stage": "USER"})
                send(f"331 Password required for {username}.")

            elif cmd == "PASS":
                log_event("ftp_credential", ip, {
                    "username": username, "password": arg,
                    "user_agent": "", "stage": "PASS",
                })
                ftp_log("CRED", f"USER={username} PASS={arg}")
                # Let them in to collect more intel
                authenticated = True
                send("230 Login successful.")

                with lock:
                    alerts.append({"time": datetime.now().strftime("%H:%M:%S"),
                                   "msg": f"FTP LOGIN: {ip} as {username}:{'*' * min(len(arg), 8)}"})

            elif cmd == "SYST":
                send("215 UNIX Type: L8")

            elif cmd == "FEAT":
                send("211-Features:\r\n PASV\r\n UTF8\r\n SIZE\r\n211 End")

            elif cmd == "TYPE":
                send(f"200 Type set to {arg}.")

            elif cmd == "PWD" or cmd == "XPWD":
                send(f'257 "{cwd}" is current directory.')

            elif cmd == "CWD" or cmd == "XCWD":
                target = arg if arg.startswith("/") else (cwd.rstrip("/") + "/" + arg)
                target = target.replace("//", "/")
                ftp_log("NAV", f"CWD to {target}")
                if target.rstrip("/") in FTP_FILES or target == "/":
                    cwd = target if target.endswith("/") else target + "/"
                    cwd = cwd.replace("//", "/")
                    send(f"250 Directory changed to {cwd}")
                else:
                    send("550 Directory not found.")

            elif cmd == "LIST" or cmd == "NLST":
                if not authenticated:
                    send("530 Not logged in.")
                    continue
                listing_path = cwd.rstrip("/") or "/"
                files = FTP_FILES.get(listing_path, FTP_FILES.get(listing_path.rstrip("/"), []))
                ftp_log("LIST", f"listing {listing_path}: {files}")

                send("150 Opening data connection.")
                listing = ""
                for f in files:
                    if f.endswith("/"):
                        listing += f"drwxr-xr-x 2 root root 4096 Aug 15 2024 {f.rstrip('/')}\r\n"
                    else:
                        real_path = os.path.realpath(os.path.join(FTP_ROOT, listing_path.lstrip("/"), f))
                        if real_path.startswith(os.path.realpath(FTP_ROOT)) and os.path.exists(real_path):
                            size = os.path.getsize(real_path)
                        else:
                            size = random.randint(1024, 524288)
                        listing += f"-rw-r--r-- 1 root root {size} Aug 15 2024 {f}\r\n"

                _pasv_ready.wait(timeout=5)
                if data_sock:
                    try:
                        data_sock.sendall(listing.encode())
                        ftp_log("DATA_SEND", f"LIST {len(listing)} bytes: {listing[:500]}")
                        data_sock.close()
                    except Exception:
                        pass
                    data_sock = None
                send("226 Transfer complete.")

            elif cmd == "RETR":
                if not authenticated:
                    send("530 Not logged in.")
                    continue
                filename = arg
                ftp_log("DOWNLOAD", f"RETR {filename}")
                log_event("ftp_download", ip, {
                    "username": username, "file": filename, "cwd": cwd,
                })

                with lock:
                    alerts.append({"time": datetime.now().strftime("%H:%M:%S"),
                                   "msg": f"FTP DOWNLOAD: {ip} grabbed {cwd}{filename}"})

                # Serve the bait file if it exists
                real_path = os.path.realpath(os.path.join(FTP_ROOT, cwd.lstrip("/"), filename))
                if not real_path.startswith(os.path.realpath(FTP_ROOT)):
                    send("550 Access denied.")
                    continue
                if os.path.exists(real_path):
                    send("150 Opening BINARY mode data connection.")
                    _pasv_ready.wait(timeout=5)
                    if data_sock:
                        try:
                            with open(real_path, "rb") as rf:
                                file_data = rf.read()
                            data_sock.sendall(file_data)
                            ftp_log("DATA_SEND", f"RETR {filename} {len(file_data)} bytes from {real_path}")
                            data_sock.close()
                        except Exception:
                            pass
                        data_sock = None
                    send("226 Transfer complete.")
                else:
                    send("550 File not found.")

            elif cmd == "STOR":
                if not authenticated:
                    send("530 Not logged in.")
                    continue
                filename = arg
                ftp_log("UPLOAD", f"STOR {filename}")
                log_event("ftp_upload", ip, {
                    "username": username, "file": filename, "cwd": cwd,
                })

                with lock:
                    alerts.append({"time": datetime.now().strftime("%H:%M:%S"),
                                   "msg": f"FTP UPLOAD: {ip} uploading {filename}"})

                # Capture everything they upload
                send("150 Ready for data.")
                safe_name = os.path.basename(filename.replace('/', '_').replace('\\', '_'))
                safe_name = re.sub(r'[^\w.\-]', '_', safe_name)[:100]
                if not safe_name or safe_name.startswith('.'):
                    safe_name = f"upload_{int(time.time())}"
                upload_path = os.path.join(FTP_UPLOAD_DIR,
                    f"{ip}_{datetime.now().strftime('%H%M%S')}_{safe_name}")
                MAX_UPLOAD_SIZE = 10 * 1024 * 1024
                _pasv_ready.wait(timeout=5)
                if data_sock:
                    try:
                        received = b""
                        while True:
                            chunk = data_sock.recv(65536)
                            if not chunk:
                                break
                            received += chunk
                            if len(received) > MAX_UPLOAD_SIZE:
                                ftp_log("UPLOAD_REJECTED", f"too large: >{MAX_UPLOAD_SIZE}")
                                break
                        if len(received) > MAX_UPLOAD_SIZE:
                            send("552 Exceeded storage allocation.")
                            data_sock.close()
                            data_sock = None
                            continue
                        with open(upload_path, "wb") as uf:
                            uf.write(received)
                        data_sock.close()
                        ftp_log("UPLOAD_SAVED", f"{len(received)} bytes -> {upload_path}")
                        log_event("ftp_upload_complete", ip, {
                            "username": username, "file": filename,
                            "size": len(received), "saved_to": upload_path,
                        })
                    except Exception:
                        pass
                    data_sock = None
                send("226 Transfer complete.")

            elif cmd == "PASV":
                # Rate limit PASV per session to prevent socket exhaustion
                _pasv_count += 1
                if _pasv_count > MAX_PASV_PER_SESSION:
                    send("421 Too many PASV requests.")
                    ftp_log("PASV_REJECTED", f"exceeded {MAX_PASV_PER_SESSION} limit")
                    continue
                # Close old passive socket and wait for old accept thread
                if data_sock:
                    try:
                        data_sock.close()
                    except Exception:
                        pass
                    data_sock = None
                if passive_sock:
                    try:
                        passive_sock.close()
                    except Exception:
                        pass
                if _pasv_accept_thread and _pasv_accept_thread.is_alive():
                    _pasv_accept_thread.join(timeout=2)
                passive_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                passive_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                passive_sock.bind(("0.0.0.0", 0))
                passive_sock.listen(1)
                passive_sock.settimeout(5)
                _, pasv_port = passive_sock.getsockname()
                p1 = pasv_port >> 8
                p2 = pasv_port & 0xFF
                # Get our IP for the response
                try:
                    our_ip = [x for x in LOCAL_IPS if not x.startswith("127") and ":" not in x][0]
                except IndexError:
                    our_ip = "10.0.1.9"
                ip_parts = our_ip.replace(".", ",")
                send(f"227 Entering Passive Mode ({ip_parts},{p1},{p2}).")
                ftp_log("PASV", f"port {pasv_port}")
                # Accept data connection in background — validate source IP
                _pasv_ready.clear()
                def accept_data():
                    nonlocal data_sock
                    try:
                        conn, data_addr = passive_sock.accept()
                        if data_addr[0] != ip:
                            ftp_log("PASV_REJECT_IP", f"data conn from {data_addr[0]}, expected {ip}")
                            conn.close()
                            data_sock = None
                        else:
                            data_sock = conn
                    except socket.timeout:
                        # attacker requested PASV but never opened the data channel
                        ftp_log("PASV_TIMEOUT", f"no data conn within 5s on port {pasv_port}")
                        data_sock = None
                    except Exception:
                        data_sock = None
                    finally:
                        _pasv_ready.set()
                _pasv_accept_thread = threading.Thread(target=accept_data, daemon=True)
                _pasv_accept_thread.start()

            elif cmd == "SIZE":
                real_path = os.path.realpath(os.path.join(FTP_ROOT, cwd.lstrip("/"), arg))
                if not real_path.startswith(os.path.realpath(FTP_ROOT)):
                    send("550 Access denied.")
                    continue
                if os.path.exists(real_path):
                    send(f"213 {os.path.getsize(real_path)}")
                else:
                    send(f"213 {random.randint(1024, 524288)}")

            elif cmd == "DELE" or cmd == "RMD" or cmd == "MKD" or cmd == "RNFR" or cmd == "RNTO":
                ftp_log("MODIFY", f"{cmd} {arg}")
                log_event("ftp_modify", ip, {"command": cmd, "arg": arg, "username": username})
                send("550 Permission denied.")

            elif cmd == "QUIT":
                send("221 Goodbye.")
                ftp_log("QUIT", "session ended")
                break

            elif cmd == "NOOP":
                send("200 OK")

            elif cmd == "SITE":
                ftp_log("SITE_CMD", arg)
                log_event("ftp_site_cmd", ip, {"command": arg, "username": username})
                site_sub = arg.split()[0].upper() if arg.strip() else ""
                if site_sub == "CHMOD":
                    send("200 CHMOD command successful.")
                elif site_sub == "EXEC":
                    log_event("ftp_exploit_attempt", ip, {"command": f"SITE {arg}", "username": username})
                    send("500 SITE EXEC not supported.")
                elif site_sub in ("CPFR", "CPTO"):
                    log_event("ftp_exploit_attempt", ip, {"command": f"SITE {arg}", "username": username})
                    send("500 Unknown SITE command.")
                else:
                    send(f"500 Unknown SITE command '{site_sub}'.")

            else:
                # CLIENT line already captured cmd_line; SERVER 502 below documents the reject.
                # no need for a duplicate UNKNOWN entry.
                send("502 Command not implemented.")

    except Exception as e:
        ftp_log("ERROR", str(e))
    finally:
        client.close()
        if passive_sock:
            try:
                passive_sock.close()
            except Exception:
                pass
        if data_sock:
            try:
                data_sock.close()
            except Exception:
                pass
        ftp_log("SESSION_END", f"total session logged to {session_log}")

        with lock:
            _service_conns["ftp"] = max(0, _service_conns["ftp"] - 1)
            alerts.append({"time": datetime.now().strftime("%H:%M:%S"),
                           "msg": f"FTP SESSION END: {ip} ({username}) — log: {session_log}"})

_recon_cooldown = {}
_recon_active = 0
MAX_CONCURRENT_RECON = 3
RECON_COOLDOWN_SECS = 3600

def _ftp_auto_recon(ip):
    global _recon_active
    if is_whitelisted(ip) or ip in LOCAL_IPS:
        return
    now = time.time()
    with lock:
        if ip in _recon_cooldown and now - _recon_cooldown[ip] < RECON_COOLDOWN_SECS:
            return
        if _recon_active >= MAX_CONCURRENT_RECON:
            return
        _recon_cooldown[ip] = now
        _recon_active += 1

    with lock:
        alerts.append({"time": datetime.now().strftime("%H:%M:%S"),
                       "msg": f"AUTO-RECON: scanning FTP attacker {ip}..."})

    try:
        # Quick scan — check if THEY have FTP/SSH/HTTP open
        result = subprocess.run(
            ["nmap", "-sV", "-T4", "-p", "21,22,23,80,443,445,3389,5900,8080,8443",
             "--open", "-oN", "-", ip],
            capture_output=True, text=True, timeout=60
        )
        open_ports = []
        for line in result.stdout.split("\n"):
            if "open" in line and "/" in line:
                open_ports.append(line.strip())

        # Log their open services
        report_file = os.path.join(LOG_DIR, f"attacker_{ip.replace('.','_')}.txt")
        with open(report_file, "a") as f:
            f.write(f"\n{'='*50}\n")
            f.write(f"Auto-recon at {datetime.now().isoformat()}\n")
            f.write(result.stdout)

        with lock:
            alerts.append({"time": datetime.now().strftime("%H:%M:%S"),
                           "msg": f"RECON DONE: {ip} has {len(open_ports)} open ports"})
            for p in open_ports[:3]:
                alerts.append({"time": datetime.now().strftime("%H:%M:%S"),
                               "msg": f"  {ip}: {p}"})

        # Banner grab their FTP if open
        for line in open_ports:
            if "21/" in line:
                banner = banner_grab(ip, 21)
                with open(report_file, "a") as f:
                    f.write(f"\nFTP Banner: {banner}\n")
                log_event("attacker_ftp_banner", ip, {"banner": banner})
                with lock:
                    alerts.append({"time": datetime.now().strftime("%H:%M:%S"),
                                   "msg": f"ATTACKER FTP: {ip}:21 — {banner[:60]}"})

    except Exception as e:
        with lock:
            alerts.append({"time": datetime.now().strftime("%H:%M:%S"),
                           "msg": f"Auto-recon failed for {ip}: {e}"})
    finally:
        with lock:
            _recon_active = max(0, _recon_active - 1)

# -- TSHARK - Protocol Analysis

tshark_conversations = []

def tshark_monitor():
    try:
        proc = subprocess.Popen(
            ["tshark", "-i", IFACE, "-l", "-T", "fields",
             "-e", "ip.src", "-e", "ip.dst", "-e", "ip.proto",
             "-e", "tcp.srcport", "-e", "tcp.dstport",
             "-e", "udp.srcport", "-e", "udp.dstport",
             "-e", "frame.len", "-e", "_ws.col.Protocol",
             "-e", "_ws.col.Info",
             "-E", "separator=|", "-E", "quote=n"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
        )
    except FileNotFoundError:
        with lock:
            alerts.append({"time": datetime.now().strftime("%H:%M:%S"),
                           "msg": "tshark not found - install wireshark-common"})
        return

    for line in proc.stdout:
        line = line.strip()
        if not line:
            continue
        parts = line.split("|")
        if len(parts) < 9:
            continue
        try:
            src_ip, dst_ip = parts[0], parts[1]
            proto_name = _ansi_strip(parts[8]) if len(parts) > 8 else "?"
            info = _ansi_strip(parts[9][:60]) if len(parts) > 9 else ""
            frame_len = int(parts[7]) if parts[7] else 0

            with lock:
                proto_stats[proto_name] += 1
                tshark_conversations.append({
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "src": src_ip, "dst": dst_ip,
                    "proto": proto_name, "info": info, "len": frame_len,
                })
                if len(tshark_conversations) > 200:
                    tshark_conversations.pop(0)
        except (ValueError, IndexError):
            continue

# -- TCPDUMP - Packet Capture

def start_tcpdump():
    global tcpdump_proc, tcpdump_file
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    tcpdump_file = os.path.join(PCAP_DIR, f"capture_{ts}.pcap")
    try:
        tcpdump_proc = subprocess.Popen(
            ["tcpdump", "-i", IFACE, "-w", tcpdump_file,
             "-C", "50",  # rotate at 50MB
             "-W", "5",   # keep 5 files max
             "-q"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    except FileNotFoundError:
        with lock:
            alerts.append({"time": datetime.now().strftime("%H:%M:%S"),
                           "msg": "tcpdump not found"})

def stop_tcpdump():
    global tcpdump_proc
    if tcpdump_proc:
        tcpdump_proc.terminate()
        tcpdump_proc = None

# -- NMAP - On-Demand Scanner

ALLOWED_NMAP_FLAGS = {
    "-sV", "-sS", "-sT", "-sU", "-sn", "-sC", "-O", "-A",
    "-T1", "-T2", "-T3", "-T4", "-T5",
    "-p-", "-p", "--top-ports", "--open", "--traceroute",
    "100", "1000",
}
_NMAP_OUTPUT_FLAGS = {"-oN", "-oX", "-oG", "-oA", "-oS"}

def _validate_nmap_flags(scan_type):
    flags = scan_type.split()
    sanitized = []
    skip_next = False
    for f in flags:
        if skip_next:
            skip_next = False
            continue
        if f in _NMAP_OUTPUT_FLAGS or any(f.startswith(flag) for flag in _NMAP_OUTPUT_FLAGS):
            skip_next = True
            with lock:
                alerts.append({"time": datetime.now().strftime("%H:%M:%S"),
                               "msg": f"NMAP: blocked output flag '{f}'"})
            continue
        if f in ALLOWED_NMAP_FLAGS or f.isdigit() or re.match(r'^[\d,-]+$', f):
            sanitized.append(f)
        else:
            with lock:
                alerts.append({"time": datetime.now().strftime("%H:%M:%S"),
                               "msg": f"NMAP: blocked flag '{f}'"})
    return sanitized

def nmap_scan(target, scan_type="-sV -T4"):
    global nmap_running
    if not re.match(r'^[\d./a-fA-F:\-a-zA-Z]+$', target):
        add_console(f"{RED}Invalid nmap target: {target}{RESET}"); return
    nmap_running = True

    validated_flags = _validate_nmap_flags(scan_type)
    with lock:
        alerts.append({"time": datetime.now().strftime("%H:%M:%S"),
                       "msg": f"NMAP: scanning {target}..."})
    try:
        result = subprocess.run(
            ["nmap"] + validated_flags + [target, "-oN", "-"],
            capture_output=True, text=True, timeout=300
        )
        output = result.stdout
        # Parse key findings
        lines = []
        for line in output.split("\n"):
            line = line.strip()
            if line and not line.startswith("#") and not line.startswith("Starting"):
                if any(k in line for k in ("open", "filtered", "closed", "Host is", "MAC", "OS", "Service")):
                    lines.append(line)

        ts = datetime.now().strftime("%H:%M:%S")
        with lock:
            nmap_results.clear()
            for l in lines[:20]:
                nmap_results.append({"time": ts, "line": l})
            alerts.append({"time": ts, "msg": f"NMAP: scan of {target} complete ({len(lines)} findings)"})

        # Save full output
        scan_file = os.path.join(LOG_DIR, f"nmap_{target.replace('/','_')}_{ts.replace(':','')}.txt")
        with open(scan_file, "w") as f:
            f.write(output)

    except subprocess.TimeoutExpired:
        with lock:
            alerts.append({"time": datetime.now().strftime("%H:%M:%S"),
                           "msg": f"NMAP: scan of {target} timed out"})
    except FileNotFoundError:
        with lock:
            alerts.append({"time": datetime.now().strftime("%H:%M:%S"),
                           "msg": "nmap not found"})
    finally:
        nmap_running = False

def nmap_scan_thread(target, scan_type="-sV -T4"):
    threading.Thread(target=nmap_scan, args=(target, scan_type), daemon=True).start()

# -- IP TRACKER - Live data movement for a target IP

tracked_ips = {}       # ip -> list of packet records
tracking_active = {}   # ip -> True/False (tshark subprocess alive)

def track_ip(target_ip, duration=0):
    """
    Live-capture all traffic to/from target_ip using tshark.
    Shows: timestamps, direction, protocol, port, payload size, info.
    duration=0 means until stopped.
    """
    tracking_active[target_ip] = True
    tracked_ips.setdefault(target_ip, [])

    with lock:
        alerts.append({"time": datetime.now().strftime("%H:%M:%S"),
                       "msg": f"TRACKING: {target_ip} — all data movement"})

    pcap_file = os.path.join(PCAP_DIR, f"track_{target_ip.replace('.','_')}_{datetime.now().strftime('%H%M%S')}.pcap")

    try:
        # tshark: capture + display simultaneously
        cmd = [
            "tshark", "-i", IFACE,
            "-f", f"host {target_ip}",
            "-l", "-T", "fields",
            "-e", "frame.time_relative",
            "-e", "ip.src", "-e", "ip.dst",
            "-e", "_ws.col.Protocol",
            "-e", "tcp.srcport", "-e", "tcp.dstport",
            "-e", "udp.srcport", "-e", "udp.dstport",
            "-e", "frame.len",
            "-e", "_ws.col.Info",
            "-E", "separator=|",
            "-w", pcap_file,  # also save pcap
        ]
        if duration > 0:
            cmd += ["-a", f"duration:{duration}"]

        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)

        for line in proc.stdout:
            if not tracking_active.get(target_ip):
                proc.terminate()
                break
            line = line.strip()
            if not line:
                continue
            parts = line.split("|")
            if len(parts) < 9:
                continue

            ts_rel = parts[0][:8]
            src = parts[1]
            dst = parts[2]
            proto = parts[3]
            # pick whichever port pair is populated
            sport = parts[4] or parts[6] or "?"
            dport = parts[5] or parts[7] or "?"
            size = parts[8]
            info = parts[9][:60] if len(parts) > 9 else ""

            if src == target_ip:
                direction = "OUT"
                dir_color = RED
            else:
                direction = "IN"
                dir_color = GREEN

            record = {
                "time": datetime.now().strftime("%H:%M:%S"),
                "ts_rel": ts_rel,
                "direction": direction,
                "src": src, "dst": dst,
                "proto": proto,
                "sport": sport, "dport": dport,
                "size": size,
                "info": info,
            }

            with lock:
                tracked_ips[target_ip].append(record)
                if len(tracked_ips[target_ip]) > 500:
                    tracked_ips[target_ip].pop(0)

            add_console(f"  {dir_color}{direction:<3}{RESET} {DIM}{record['time']}{RESET} "
                        f"{proto:<6} {src}:{sport} -> {dst}:{dport}  "
                        f"{size:>5}B  {DIM}{info}{RESET}")

        proc.wait()

    except FileNotFoundError:
        add_console(f"{RED}tshark not found{RESET}")
    except Exception as e:
        add_console(f"{RED}Track error: {e}{RESET}")
    finally:
        tracking_active[target_ip] = False
        with lock:
            alerts.append({"time": datetime.now().strftime("%H:%M:%S"),
                           "msg": f"TRACKING STOPPED: {target_ip} — pcap: {pcap_file}"})

def track_connections(target_ip):
    try:
        result = subprocess.run(
            ["tshark", "-i", IFACE, "-f", f"host {target_ip}",
             "-a", "duration:10", "-q", "-z", "conv,tcp"],
            capture_output=True, text=True, timeout=20
        )
        add_console(f"{BOLD}{CYAN}TCP CONNECTIONS for {target_ip} (10s sample):{RESET}")
        for line in result.stdout.split("\n"):
            line = line.strip()
            if line and ("<->" in line or "Frames" in line):
                add_console(f"  {line}")
    except Exception as e:
        add_console(f"{RED}Connection tracking error: {e}{RESET}")

def track_dns_for(target_ip):
    try:
        result = subprocess.run(
            ["tshark", "-i", IFACE,
             "-f", f"src host {target_ip} and udp port 53",
             "-a", "duration:30", "-T", "fields",
             "-e", "frame.time_relative", "-e", "dns.qry.name",
             "-E", "separator=|"],
            capture_output=True, text=True, timeout=40
        )
        add_console(f"{BOLD}{MAGENTA}DNS from {target_ip} (30s capture):{RESET}")
        seen = set()
        for line in result.stdout.split("\n"):
            parts = line.strip().split("|")
            if len(parts) >= 2 and parts[1] and parts[1] not in seen:
                seen.add(parts[1])
                add_console(f"  {MAGENTA}{parts[1]}{RESET}")
        if not seen:
            add_console(f"  {DIM}No DNS queries captured.{RESET}")
    except Exception as e:
        add_console(f"{RED}DNS tracking error: {e}{RESET}")

def track_payload(target_ip, duration=15):
    try:
        result = subprocess.run(
            ["tshark", "-i", IFACE,
             "-f", f"host {target_ip}",
             "-a", f"duration:{duration}",
             "-T", "fields",
             "-e", "ip.src", "-e", "ip.dst",
             "-e", "tcp.dstport",
             "-e", "data.text",
             "-Y", "data.text",
             "-E", "separator=|"],
            capture_output=True, text=True, timeout=duration + 10
        )
        add_console(f"{BOLD}{YELLOW}PAYLOAD from/to {target_ip} ({duration}s):{RESET}")
        count = 0
        for line in result.stdout.split("\n"):
            parts = line.strip().split("|")
            if len(parts) >= 4 and parts[3]:
                payload = parts[3][:100]
                add_console(f"  {parts[0]} -> {parts[1]}:{parts[2]}  {YELLOW}{payload}{RESET}")
                count += 1
        if count == 0:
            add_console(f"  {DIM}No plaintext payload captured (likely encrypted).{RESET}")
    except Exception as e:
        add_console(f"{RED}Payload capture error: {e}{RESET}")

def track_summary(target_ip):
    records = tracked_ips.get(target_ip, [])
    if not records:
        add_console(f"{DIM}No tracked data for {target_ip}. Start with: track {target_ip}{RESET}")
        return

    in_bytes = sum(int(r["size"]) for r in records if r["direction"] == "IN")
    out_bytes = sum(int(r["size"]) for r in records if r["direction"] == "OUT")
    in_count = sum(1 for r in records if r["direction"] == "IN")
    out_count = sum(1 for r in records if r["direction"] == "OUT")
    protos = set(r["proto"] for r in records)
    dst_ports = set(r["dport"] for r in records if r["direction"] == "OUT")
    src_ports = set(r["sport"] for r in records if r["direction"] == "OUT")
    first = records[0]["time"]
    last = records[-1]["time"]

    add_console(f"{BOLD}{CYAN}TRACK SUMMARY: {target_ip}{RESET}")
    add_console(f"  Period: {first} - {last}  ({len(records)} packets)")
    add_console(f"  {GREEN}IN:  {in_count} pkts, {format_bytes(in_bytes)}{RESET}")
    add_console(f"  {RED}OUT: {out_count} pkts, {format_bytes(out_bytes)}{RESET}")
    add_console(f"  Protocols: {', '.join(protos)}")
    add_console(f"  Ports targeted: {sorted(dst_ports)}")
    add_console(f"  Ports used: {sorted(src_ports)}")

# -- ARP MONITOR - Device Discovery

arp_table = {}

def arp_monitor():
    while True:
        try:
            out = subprocess.check_output(["ip", "neigh"], text=True)
            for line in out.split("\n"):
                parts = line.split()
                if len(parts) >= 5 and "lladdr" in parts:
                    ip = parts[0]
                    mac_idx = parts.index("lladdr") + 1
                    mac = parts[mac_idx] if mac_idx < len(parts) else "?"
                    state = parts[-1]
                    if ip not in arp_table:
                        with lock:
                            alerts.append({"time": datetime.now().strftime("%H:%M:%S"),
                                           "msg": f"NEW DEVICE: {ip} ({mac})"})
                    arp_table[ip] = {"mac": mac, "state": state,
                                     "last_seen": datetime.now().strftime("%H:%M:%S")}
        except Exception:
            pass
        time.sleep(30)

# -- TRAFFIC MONITOR - Raw Sockets

def parse_ethernet(data):
    return struct.unpack("!6s6sH", data[:14])[2], data[14:]

def parse_ip(data):
    ihl = (data[0] & 0xF) * 4
    total_length = struct.unpack("!H", data[2:4])[0]
    protocol = data[9]
    src_ip = socket.inet_ntoa(data[12:16])
    dst_ip = socket.inet_ntoa(data[16:20])
    return protocol, src_ip, dst_ip, total_length, data[ihl:]

def parse_ports(data):
    if len(data) < 4:
        return 0, 0
    return struct.unpack("!HH", data[:4])

def parse_dns(data):
    try:
        dns_data = data[12:] if len(data) > 12 else data
        labels = []
        i = 0
        while i < len(dns_data):
            length = dns_data[i]
            if length == 0:
                break
            i += 1
            labels.append(dns_data[i:i+length].decode(errors="replace"))
            i += length
        return ".".join(labels) if labels else None
    except Exception:
        return None

def _is_benign(ip):
    if ip in LOCAL_IPS or is_whitelisted(ip):
        return True
    if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16."):
        return True
    if ip.startswith("100."):
        try:
            if ipaddress.ip_address(ip) in ipaddress.ip_network("100.64.0.0/10"):
                return True
        except ValueError:
            pass
    return False

def check_suspicious(src_ip, dst_ip, src_port, dst_port):
    if _is_benign(src_ip) and _is_benign(dst_ip):
        return
    now_str = datetime.now().strftime("%H:%M:%S")
    with lock:
        for port in (src_port, dst_port):
            if port in SUS_PORTS and port not in TOR_PORTS:
                alert = f"SUS PORT {port}: {src_ip} <-> {dst_ip}"
                if alert not in [a["msg"] for a in alerts[-20:]]:
                    alerts.append({"time": now_str, "msg": alert})
        for ip in (src_ip, dst_ip):
            if not _is_benign(ip) and len(hosts[ip]["ports"]) > SCAN_THRESHOLD:
                alert = f"PORT SCAN: {ip} ({len(hosts[ip]['ports'])} ports)"
                if alert not in [a["msg"] for a in alerts[-20:]]:
                    alerts.append({"time": now_str, "msg": alert})

def traffic_monitor():
    global total_packets, total_bytes
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        sock.bind((IFACE, 0))
        sock.settimeout(1.0)
    except (PermissionError, OSError) as e:
        with lock:
            alerts.append({"time": datetime.now().strftime("%H:%M:%S"),
                           "msg": f"Sniffer error: {e}"})
        return

    while True:
        try:
            data, _ = sock.recvfrom(65535)
        except socket.timeout:
            continue

        eth_proto, eth_payload = parse_ethernet(data)
        if eth_proto != 0x0800:
            with lock:
                total_packets += 1
            continue

        protocol, src_ip, dst_ip, pkt_len, ip_payload = parse_ip(eth_payload)
        now_str = datetime.now().strftime("%H:%M:%S")

        src_port = dst_port = 0
        dns_domain = None
        if protocol in (6, 17):
            src_port, dst_port = parse_ports(ip_payload)
            if protocol == 17 and dst_port == 53 and len(ip_payload) > 20:
                dns_domain = parse_dns(ip_payload[8:])
                if dns_domain and len(dns_domain) <= 3:
                    dns_domain = None

        with lock:
            total_packets += 1
            total_bytes += pkt_len

            if dns_domain:
                dns_queries.append({"time": now_str, "ip": src_ip, "domain": _ansi_strip(dns_domain)})
                if len(dns_queries) > 200:
                    dns_queries.pop(0)

            if src_ip in LOCAL_IPS:
                hosts[dst_ip]["bytes_out"] += pkt_len
            else:
                hosts[src_ip]["bytes_in"] += pkt_len
            for ip in (src_ip, dst_ip):
                if ip not in LOCAL_IPS:
                    hosts[ip]["packets"] += 1
                    hosts[ip]["last_seen"] = now_str
                    if not hosts[ip]["first_seen"]:
                        hosts[ip]["first_seen"] = now_str
                    if len(hosts[ip]["ports"]) < 500:
                        if src_port:
                            hosts[ip]["ports"].add(src_port)
                        if dst_port:
                            hosts[ip]["ports"].add(dst_port)

        check_suspicious(src_ip, dst_ip, src_port, dst_port)

# -- DASHBOARD - Terminal UI v2

def format_bytes(b):
    for unit in ["B", "KB", "MB", "GB"]:
        if b < 1024:
            return f"{b:.1f}{unit}"
        b /= 1024
    return f"{b:.1f}TB"

def threat_color(score):
    if score >= 30: return RED
    if score >= 10: return YELLOW
    return WHITE

# -- OSINT TOOLS

def osint_geolocate(target):
    try:
        addr = ipaddress.ip_address(target)
        if addr.is_loopback or addr.is_link_local or any(addr in n for n in (
            ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"))):
            return {"error": "private IP — no geolocation"}
    except ValueError:
        pass
    r = _proxied_get(f"http://ip-api.com/json/{urllib.parse.quote(target, safe='')}", timeout=10)
    if not r:
        return {"error": "request failed (install requests or check proxy)"}
    try:
        return r.json()
    except Exception as e:
        return {"error": str(e)}


def osint_whois(target):
    try:
        ipaddress.ip_address(target)
        is_ip = True
    except ValueError:
        is_ip = False
    if is_ip:
        try:
            r = subprocess.run(["whois", target], capture_output=True, text=True, timeout=15)
            result = {}
            for line in r.stdout.split("\n"):
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("%"):
                    continue
                if ":" in line:
                    k, _, v = line.partition(":")
                    k, v = k.strip().lower(), v.strip()
                    if k in ("orgname", "org-name", "organisation"):
                        result["org"] = v
                    elif k in ("country",):
                        result["country"] = v
                    elif k in ("netname",):
                        result["netname"] = v
                    elif k in ("netrange", "inetnum"):
                        result["range"] = v
                    elif k in ("cidr", "route"):
                        result.setdefault("cidr", v)
                    elif k in ("descr", "orgref"):
                        result.setdefault("descr", v)
                    elif k in ("abuse-mailbox", "orgabuseemail"):
                        result.setdefault("abuse", v)
            return result if result else {"raw": r.stdout[:500]}
        except FileNotFoundError:
            return {"error": "whois not installed: apt install whois"}
        except Exception as e:
            return {"error": str(e)}
    if not whois_lib:
        return {"error": "python-whois not installed: pip3 install python-whois"}
    try:
        w = whois_lib.whois(target)
        result = {}
        for field in ("domain_name", "registrar", "whois_server", "creation_date",
                       "expiration_date", "name_servers", "org", "country",
                       "state", "city", "emails", "dnssec"):
            val = getattr(w, field, None)
            if val:
                if isinstance(val, list):
                    val = ", ".join(str(v) for v in val)
                result[field] = str(val)
        return result
    except Exception as e:
        return {"error": str(e)}


def osint_dns_enum(target):
    if not dns:
        return {"error": "dnspython not installed: pip3 install dnspython"}
    results = {}
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV"):
        try:
            answers = dns.resolver.resolve(target, rtype)
            results[rtype] = [str(r) for r in answers]
        except Exception:
            pass
    return results


def osint_reverse_dns(target):
    if not dns:
        try:
            return {"PTR": socket.gethostbyaddr(target)[0]}
        except Exception:
            return {"error": "no PTR record"}
    try:
        rev = dns.reversename.from_address(target)
        answers = dns.resolver.resolve(rev, "PTR")
        return {"PTR": [str(r) for r in answers]}
    except Exception as e:
        return {"error": str(e)}


def osint_port_scan(target, max_ports=1000):
    TOP_PORTS = [
        21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,
        1433,1521,1723,2049,3306,3389,5432,5900,5985,6379,8000,
        8080,8443,8888,9090,9200,27017,
        1,5,7,9,11,13,17,18,19,20,37,42,49,50,63,67,68,69,70,79,
        81,82,83,84,85,88,89,90,99,100,106,109,113,119,125,144,
        146,161,162,174,177,179,191,194,199,209,210,211,212,222,
        254,255,256,259,264,280,311,389,401,402,406,407,416,417,
        425,427,444,458,464,465,475,497,500,502,512,513,514,515,
        520,524,541,543,544,545,548,554,555,563,587,593,616,617,
        625,631,636,646,648,666,667,668,683,687,691,700,705,711,
        714,720,722,726,749,765,777,783,787,800,801,808,843,873,
        880,888,898,900,901,902,903,911,912,981,987,990,992,999,
        1000,1010,1080,1099,1100,1110,1111,1234,1300,1311,1352,
        1434,1443,1494,1500,1503,1524,1556,1580,1583,1594,1600,
        1641,1658,1666,1687,1700,1717,1720,1755,1761,1801,1812,
        1900,1935,1998,1999,2000,2001,2002,2003,2010,2020,2021,
        2030,2040,2065,2100,2121,2160,2170,2200,2222,2288,2301,
        2323,2366,2381,2399,2401,2500,2601,2604,2638,2701,2717,
        2800,2809,2869,2998,3000,3001,3005,3006,3052,3128,3260,
        3268,3269,3283,3300,3301,3322,3333,3367,3369,3370,3371,
        3372,3390,3476,3493,3517,3527,3546,3551,3580,3659,3689,
        3690,3784,3800,3809,3814,3826,3827,3869,3871,3878,3880,
        3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000,
        4001,4002,4003,4004,4005,4006,4045,4111,4125,4224,4242,
        4321,4343,4443,4444,4445,4446,4449,4550,4567,4662,4848,
        4899,4900,4998,5000,5001,5002,5003,5009,5050,5051,5060,
        5080,5100,5190,5200,5222,5269,5357,5405,5414,5431,5440,
        5500,5510,5544,5550,5555,5560,5631,5633,5666,5678,5718,
        5800,5801,5810,5822,5850,5859,5901,5902,5903,5904,5906,
        5915,5922,5950,5960,5987,5988,5998,5999,6000,6001,6002,
        6003,6009,6025,6059,6100,6106,6112,6123,6129,6346,6389,
        6502,6510,6543,6565,6566,6580,6646,6666,6667,6668,6669,
        6689,6692,6779,6789,6881,6901,6969,7000,7001,7002,7004,
        7007,7019,7025,7070,7100,7200,7402,7443,7496,7512,7625,
        7676,7741,7777,7778,7800,7911,7920,7937,7999,8001,8002,
        8007,8008,8009,8010,8021,8031,8042,8045,8081,8082,8083,
        8084,8085,8086,8087,8088,8089,8090,8093,8099,8100,8180,
        8181,8192,8222,8254,8290,8291,8300,8333,8383,8400,8402,
        8500,8600,8649,8651,8652,8654,8701,8800,8873,8899,8994,
        9000,9001,9002,9003,9009,9010,9040,9050,9071,9080,9081,
        9091,9099,9100,9101,9110,9111,9200,9207,9290,9415,9418,
        9443,9500,9535,9575,9593,9595,9618,9666,9876,9878,9898,
        9900,9917,9943,9968,9998,9999,10000,10001,10009,10010,
        10025,10082,10180,10243,10566,10616,10621,10626,10778,
        11110,11111,12000,12345,13456,13722,14000,14238,14441,
        15000,15002,15004,15660,16000,16012,16080,16992,17877,
        18040,18101,19101,19283,19315,19780,19842,20000,20005,
        20031,20221,20222,21571,22939,23502,24444,24800,25734,
        26214,27000,27352,27355,27715,28201,30000,30718,31337,
        32768,32769,32770,32771,32772,32773,32774,32775,32776,
        32777,32778,33354,33899,34571,35500,38292,40193,40911,
        41511,42510,44176,44442,44443,45100,48080,49152,49153,
        49154,49155,49156,49157,49158,49159,49160,49163,49165,
        49175,49400,49999,50000,50001,50002,50003,50006,50300,
        50389,50500,50636,50800,51103,51493,52673,52848,52869,
        54045,55055,55555,55600,56737,57294,58080,60020,60443,
        61532,61900,62078,63331,64623,64680,65000,65129,65389,
    ]
    SERVICES = {
        21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",
        110:"POP3",111:"RPC",135:"MSRPC",139:"NetBIOS",143:"IMAP",
        443:"HTTPS",445:"SMB",993:"IMAPS",995:"POP3S",1433:"MSSQL",
        1521:"Oracle",3306:"MySQL",3389:"RDP",5432:"PostgreSQL",
        5900:"VNC",6379:"Redis",8080:"HTTP-Proxy",8443:"HTTPS-Alt",
        9200:"Elasticsearch",27017:"MongoDB",
    }
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        return []

    ports_to_scan = sorted(set(TOP_PORTS))[:max_ports]
    open_ports = []

    def _check(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            if s.connect_ex((ip, port)) == 0:
                banner = ""
                try:
                    s.settimeout(2)
                    if port in (80, 8080, 8443):
                        s.sendall(b"HEAD / HTTP/1.0\r\nHost: x\r\n\r\n")
                    elif port not in (22, 21, 25, 110, 143):
                        s.sendall(b"\r\n")
                    banner = s.recv(1024).decode("utf-8", errors="replace").strip()[:200]
                except Exception:
                    pass
                s.close()
                return (port, SERVICES.get(port, "unknown"), banner)
            s.close()
        except Exception:
            pass
        return None

    from concurrent.futures import ThreadPoolExecutor, as_completed
    with ThreadPoolExecutor(max_workers=200) as pool:
        futures = {pool.submit(_check, p): p for p in ports_to_scan}
        for f in as_completed(futures):
            r = f.result()
            if r:
                open_ports.append(r)

    return sorted(open_ports, key=lambda x: x[0])


def osint_subnet_ping(cidr):
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return []

    hosts_list = list(network.hosts())
    if len(hosts_list) > 1024:
        return [("error", "", "Network too large, max /22")]

    alive = []
    def _ping(ip):
        try:
            r = subprocess.run(
                ["ping", "-c", "1", "-W", "1", str(ip)],
                capture_output=True, text=True, timeout=2,
            )
            if r.returncode == 0:
                ms = ""
                for line in r.stdout.split("\n"):
                    if "time=" in line:
                        ms = line.split("time=")[1].split()[0]
                        break
                hostname = ""
                try:
                    hostname = socket.gethostbyaddr(str(ip))[0]
                except Exception:
                    pass
                return (str(ip), ms, hostname)
        except Exception:
            pass
        return None

    from concurrent.futures import ThreadPoolExecutor, as_completed
    with ThreadPoolExecutor(max_workers=100) as pool:
        futures = {pool.submit(_ping, ip): ip for ip in hosts_list}
        for f in as_completed(futures):
            r = f.result()
            if r:
                alive.append(r)

    return sorted(alive, key=lambda x: ipaddress.ip_address(x[0]))


# ─── Enhanced OSINT ───────────────────────────────────────

def osint_crt(domain):
    r = _proxied_get(f"https://crt.sh/?q=%25.{urllib.parse.quote(domain, safe='')}&output=json", timeout=15)
    if not r:
        return {"error": "request failed (install requests or check proxy)"}
    try:
        data = r.json()
        seen = set()
        results = []
        for entry in data[:100]:
            cn = entry.get("common_name", "")
            if cn not in seen:
                seen.add(cn)
                results.append({
                    "cn": cn,
                    "issuer": entry.get("issuer_name", "")[:60],
                    "not_after": entry.get("not_after", ""),
                })
        return results
    except Exception as e:
        return {"error": str(e)}

def osint_headers(url):
    if not url.startswith("http"):
        url = "http://" + url
    from urllib.parse import urlparse
    parsed = urlparse(url)
    try:
        resolved = socket.getaddrinfo(parsed.hostname, None)[0][4][0]
        if ipaddress.ip_address(resolved).is_private:
            return {"error": "refused: target resolves to private IP"}
    except Exception:
        pass
    r = _proxied_get(url, timeout=10)
    if not r:
        return {"error": "request failed"}
    try:
        headers = dict(r.headers)
        tech = []
        if "X-Powered-By" in headers:
            tech.append(headers["X-Powered-By"])
        if "Server" in headers:
            tech.append(headers["Server"])
        if "X-AspNet-Version" in headers:
            tech.append("ASP.NET " + headers["X-AspNet-Version"])
        return {"headers": headers, "tech": tech, "status": r.status_code}
    except Exception as e:
        return {"error": str(e)}


def _validate_target_url(url):
    from urllib.parse import urlparse
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        return False, "no hostname"
    blocked = {"localhost", "127.0.0.1", "0.0.0.0", "::1", "metadata.google.internal",
               "metadata", "instance-data"}
    if hostname in blocked:
        return False, "blocked internal host"
    try:
        resolved = socket.getaddrinfo(hostname, None)[0][4][0]
        addr = ipaddress.ip_address(resolved)
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
            return False, "refused: resolves to private IP"
    except Exception:
        return False, "DNS resolution failed"
    return True, ""


def _validate_target_host(target):
    try:
        resolved = socket.getaddrinfo(target, None)[0][4][0]
        addr = ipaddress.ip_address(resolved)
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return False, "refused: target resolves to private IP"
    except Exception:
        return False, "DNS resolution failed"
    return True, ""


def _safe_error(e):
    error_type = type(e).__name__
    generic = {
        "ConnectionRefusedError": "connection refused",
        "TimeoutError": "connection timed out",
        "timeout": "connection timed out",
        "gaierror": "DNS resolution failed",
        "SSLError": "TLS handshake failed",
        "SSLCertVerificationError": "certificate verification failed",
        "FileNotFoundError": "required tool not installed",
    }
    return generic.get(error_type, f"{error_type}: operation failed")


_osint_semaphore = threading.Semaphore(5)


def osint_ssl(target, port=443):
    if not re.match(r'^[a-zA-Z0-9.\-:]+$', target):
        return {"error": "invalid target format"}
    if not (1 <= port <= 65535):
        return {"error": "invalid port"}
    ok, reason = _validate_target_host(target)
    if not ok:
        return {"error": reason}
    try:
        hostname = target if not target.replace(".", "").isdigit() else target
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((target, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cipher = ssock.cipher()
                proto = ssock.version()
                der_cert = ssock.getpeercert(binary_form=True)
        result = {"protocol": proto, "cipher": cipher[0] if cipher else "unknown", "bits": cipher[2] if cipher else 0}
        if der_cert:
            result["cert_size"] = len(der_cert)
            try:
                ctx2 = ssl.create_default_context()
                with socket.create_connection((target, port), timeout=5) as sock2:
                    with ctx2.wrap_socket(sock2, server_hostname=hostname) as ssock2:
                        cert = ssock2.getpeercert()
                        if cert:
                            subj = dict(x[0] for x in cert.get("subject", []))
                            issuer = dict(x[0] for x in cert.get("issuer", []))
                            result["subject"] = subj.get("commonName", "")
                            result["issuer"] = issuer.get("organizationName", issuer.get("commonName", ""))
                            result["not_before"] = cert.get("notBefore", "")
                            result["not_after"] = cert.get("notAfter", "")
                            san = cert.get("subjectAltName", [])
                            result["alt_names"] = [v for _, v in san][:10]
                            try:
                                fmt = "%b %d %H:%M:%S %Y %Z"
                                not_after = datetime.strptime(cert["notAfter"], fmt)
                                result["days_left"] = (not_after - datetime.utcnow()).days
                            except Exception:
                                pass
            except ssl.SSLCertVerificationError:
                result["note"] = "certificate failed validation (self-signed/expired)"
        return result
    except Exception as e:
        return {"error": _safe_error(e)}


def osint_secheaders(url):
    if not url.startswith("http"):
        url = "http://" + url
    ok, reason = _validate_target_url(url)
    if not ok:
        return {"error": reason}
    r = _proxied_get(url, timeout=10)
    if not r:
        return {"error": "request failed"}
    try:
        hdrs = {k.lower(): v for k, v in r.headers.items()}
        checks = [
            ("strict-transport-security", "HSTS"),
            ("content-security-policy", "CSP"),
            ("x-frame-options", "X-Frame-Options"),
            ("x-content-type-options", "X-Content-Type-Options"),
            ("x-xss-protection", "X-XSS-Protection"),
            ("referrer-policy", "Referrer-Policy"),
            ("permissions-policy", "Permissions-Policy"),
        ]
        results = {}
        score = 0
        for header_key, label in checks:
            present = header_key in hdrs
            results[label] = {"present": present, "value": hdrs.get(header_key, "")}
            if present:
                score += 1
        grade = "A" if score >= 6 else "B" if score >= 4 else "C" if score >= 2 else "F"
        return {"headers": results, "score": f"{score}/{len(checks)}", "grade": grade}
    except Exception as e:
        return {"error": str(e)}


def osint_techstack(url):
    if not url.startswith("http"):
        url = "http://" + url
    ok, reason = _validate_target_url(url)
    if not ok:
        return {"error": reason}
    r = _proxied_get(url, timeout=10)
    if not r:
        return {"error": "request failed"}
    try:
        body = r.text[:8192].lower()
        hdrs = {k.lower(): v.lower() for k, v in r.headers.items()}
        techs = []
        sigs = {
            "wp-content": "WordPress", "wp-includes": "WordPress",
            "drupal": "Drupal", "joomla": "Joomla",
            "shopify": "Shopify", "woocommerce": "WooCommerce",
            "next/static": "Next.js", "_next/": "Next.js",
            "nuxt": "Nuxt.js", "__nuxt": "Nuxt.js",
            "react": "React", "vue.js": "Vue.js", "angular": "Angular",
            "laravel": "Laravel", "django": "Django",
            "bootstrap": "Bootstrap", "tailwind": "Tailwind CSS",
        }
        for keyword, label in sigs.items():
            if keyword in body and label not in techs:
                techs.append(label)
        server = hdrs.get("server", "")
        if "nginx" in server: techs.append(f"nginx ({server})")
        elif "apache" in server: techs.append(f"Apache ({server})")
        elif "cloudflare" in server: techs.append("Cloudflare")
        elif "iis" in server: techs.append(f"IIS ({server})")
        powered = hdrs.get("x-powered-by", "")
        if powered:
            techs.append(powered)
        if "cf-ray" in hdrs: techs.append("Cloudflare CDN") if "Cloudflare" not in str(techs) else None
        if "x-vercel" in hdrs or "x-vercel-id" in hdrs: techs.append("Vercel")
        if "x-amz" in str(hdrs): techs.append("AWS")
        return {"technologies": techs, "server": server, "powered_by": powered}
    except Exception as e:
        return {"error": str(e)}


def osint_ping_analyze(target, count=5):
    if not re.match(r'^[a-zA-Z0-9.\-:]+$', target):
        return {"error": "invalid target format"}
    count = max(1, min(count, 20))
    try:
        r = subprocess.run(
            ["ping", "-c", str(count), "-W", "2", target],
            capture_output=True, text=True, timeout=count * 3 + 5
        )
        output = r.stdout
        times = []
        ttl = None
        for line in output.split("\n"):
            if "time=" in line:
                t = float(line.split("time=")[1].split()[0])
                times.append(t)
            if "ttl=" in line.lower():
                ttl = int(re.search(r'ttl=(\d+)', line.lower()).group(1))
        result = {"target": target, "packets_sent": count, "raw": output}
        if times:
            result["min"] = round(min(times), 2)
            result["max"] = round(max(times), 2)
            result["avg"] = round(sum(times) / len(times), 2)
            result["loss"] = round((1 - len(times) / count) * 100, 1)
            if len(times) > 1:
                diffs = [abs(times[i] - times[i-1]) for i in range(1, len(times))]
                result["jitter"] = round(sum(diffs) / len(diffs), 2)
        if ttl:
            result["ttl"] = ttl
            if ttl <= 64:
                result["os_guess"] = "Linux/Unix/macOS"
            elif ttl <= 128:
                result["os_guess"] = "Windows"
            else:
                result["os_guess"] = "Network device (router/switch)"
        return result
    except subprocess.TimeoutExpired:
        return {"error": "ping timed out"}
    except Exception as e:
        return {"error": str(e)}


def osint_trace_enriched(target):
    if not re.match(r'^[a-zA-Z0-9.\-:]+$', target):
        return [{"error": "invalid target format"}]
    try:
        r = subprocess.run(
            ["traceroute", "-m", "20", "-w", "2", target],
            capture_output=True, text=True, timeout=45
        )
        if r.returncode != 0:
            r = subprocess.run(
                ["tracepath", target],
                capture_output=True, text=True, timeout=45
            )
        hops = []
        geo_count = 0
        max_geo = 10
        for line in r.stdout.split("\n"):
            ip_match = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', line)
            if ip_match:
                ip = ip_match.group(1)
                hop = {"ip": ip, "raw": line.strip()}
                try:
                    hop["rdns"] = socket.gethostbyaddr(ip)[0]
                except Exception:
                    hop["rdns"] = ""
                try:
                    addr = ipaddress.ip_address(ip)
                    if not addr.is_private and geo_count < max_geo:
                        geo = _proxied_get(f"http://ip-api.com/json/{ip}?fields=city,country,isp,as", timeout=3)
                        geo_count += 1
                        if geo:
                            gdata = geo.json()
                            hop["city"] = gdata.get("city", "")
                            hop["country"] = gdata.get("country", "")
                            hop["isp"] = gdata.get("isp", "")
                            hop["asn"] = gdata.get("as", "")
                except Exception:
                    pass
                hops.append(hop)
        return hops
    except Exception as e:
        return [{"error": _safe_error(e)}]


def osint_health(target):
    if not re.match(r'^[a-zA-Z0-9.\-]+$', target):
        return {"error": "invalid target format"}
    if not _osint_semaphore.acquire(blocking=False):
        return {"error": "too many concurrent health checks — try again later"}
    try:
        results = {"target": target, "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        results["ping"] = osint_ping_analyze(target, count=3)
        is_domain = not target.replace(".", "").isdigit()
        if is_domain:
            results["dns"] = osint_dns_enum(target)
        results["ssl"] = osint_ssl(target)
        url = f"https://{target}" if is_domain else f"http://{target}"
        results["secheaders"] = osint_secheaders(url)
        results["techstack"] = osint_techstack(url)
        results["geo"] = osint_geolocate(target)
        return results
    finally:
        _osint_semaphore.release()


def osint_asn(ip):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {"error": "invalid IP address"}
    r = _proxied_get(f"http://ip-api.com/json/{ip}?fields=as,org,isp,query,country,city", timeout=10)
    if not r:
        return {"error": "request failed"}
    try:
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def osint_abuse(ip):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {"error": "invalid IP address"}
    result = {"ip": ip}
    r = _proxied_get(f"https://api.blocklist.de/api.php?ip={ip}", timeout=8)
    if r:
        attacks = r.text.strip()
        result["blocklist_de"] = attacks if attacks else "clean"
    r2 = _proxied_get(f"http://ip-api.com/json/{ip}?fields=proxy,hosting,mobile,query", timeout=8)
    if r2:
        try:
            d = r2.json()
            result["is_proxy"] = d.get("proxy", False)
            result["is_hosting"] = d.get("hosting", False)
            result["is_mobile"] = d.get("mobile", False)
        except Exception:
            pass
    return result

# ─── Attack Analysis ──────────────────────────────────────

import base64
import binascii
import urllib.parse

def decode_payload(data):
    results = {"raw": data[:500]}
    try:
        results["base64"] = base64.b64decode(data).decode(errors="replace")[:500]
    except Exception:
        pass
    try:
        results["hex"] = binascii.unhexlify(data.replace(" ", "")).decode(errors="replace")[:500]
    except Exception:
        pass
    try:
        results["url"] = urllib.parse.unquote(data)[:500]
    except Exception:
        pass
    return results

def analyze_attacker(ip):
    with lock:
        events = [e for e in honeypot_events if e["ip"] == ip]
    if not events:
        return None
    services_hit = set()
    summaries = []
    for e in events:
        services_hit.add(e["service"])
        summaries.append(f"[{e['time']}] {e['service']}: {e['summary'][:100]}")
    hostname = resolve_host(ip)
    geo = osint_geolocate(ip) if req_lib else {}
    return {
        "ip": ip,
        "hostname": hostname,
        "total_events": len(events),
        "services_targeted": sorted(services_hit),
        "first_seen": events[0]["time"],
        "last_seen": events[-1]["time"],
        "geo": f"{geo.get('city','?')}, {geo.get('country','?')}" if geo.get("status") != "fail" else "unknown",
        "isp": geo.get("isp", "unknown"),
        "timeline": summaries[-20:],
    }


# -- RECON ENGINE - Attacker Intelligence

recon_reports = {}

def recon_target(target_ip):
    report = {
        "ip": target_ip,
        "timestamp": datetime.now().isoformat(),
        "hostname": "", "ports": [], "os_guess": "",
        "traceroute": [], "services": [], "whois_org": "",
        "geo": "", "honeypot_activity": [],
    }

    with lock:
        alerts.append({"time": datetime.now().strftime("%H:%M:%S"),
                       "msg": f"RECON: profiling {target_ip}..."})

    # 1. Reverse DNS
    try:
        report["hostname"] = socket.gethostbyaddr(target_ip)[0]
    except Exception:
        report["hostname"] = "NO-PTR"

    # 2. Aggressive nmap: ports + services + OS + traceroute
    try:
        result = subprocess.run(
            ["nmap", "-sV", "-O", "--traceroute", "-T4", "--top-ports", "1000",
             "-oN", "-", target_ip],
            capture_output=True, text=True, timeout=300
        )
        output = result.stdout
        for line in output.split("\n"):
            line = line.strip()
            if "/tcp" in line or "/udp" in line:
                report["ports"].append(line)
            if "OS details:" in line or "Running:" in line:
                report["os_guess"] = line
            if "Service Info:" in line:
                report["services"].append(line)
            if line and line[0].isdigit() and "ms" in line:
                report["traceroute"].append(line)

        # Save full nmap output
        scan_file = os.path.join(LOG_DIR, f"recon_{target_ip.replace('.','_')}.txt")
        with open(scan_file, "w") as f:
            f.write(output)
        report["nmap_file"] = scan_file

    except subprocess.TimeoutExpired:
        report["ports"] = ["SCAN TIMED OUT"]
    except Exception as e:
        report["ports"] = [f"ERROR: {e}"]

    # 3. Grab any honeypot activity from this IP
    with lock:
        report["honeypot_activity"] = [
            e for e in honeypot_events if e["ip"] == target_ip
        ][-20:]

    # 4. Check what we saw in traffic
    with lock:
        if target_ip in hosts:
            h = hosts[target_ip]
            report["traffic"] = {
                "bytes_in": h["bytes_in"], "bytes_out": h["bytes_out"],
                "packets": h["packets"], "ports_seen": sorted(h["ports"]),
                "first_seen": h["first_seen"], "last_seen": h["last_seen"],
            }

    # Save report
    if len(recon_reports) > MAX_RECON:
        oldest_key = next(iter(recon_reports))
        del recon_reports[oldest_key]
    recon_reports[target_ip] = report
    report_file = os.path.join(LOG_DIR, f"recon_{target_ip.replace('.','_')}.json")
    with open(report_file, "w") as f:
        json.dump(report, f, indent=2, default=str)

    with lock:
        alerts.append({"time": datetime.now().strftime("%H:%M:%S"),
                       "msg": f"RECON: {target_ip} profiled — {len(report['ports'])} ports, OS: {report['os_guess'][:40]}"})

    return report

def quick_scan(target, flags="-sV -T4 --top-ports 100"):
    nmap_scan_thread(target, flags)

def deep_scan(target):
    nmap_scan_thread(target, "-sV -sC -O -p- -T4 --script vuln")

def stealth_scan(target):
    global nmap_running
    nmap_running = True
    with lock:
        alerts.append({"time": datetime.now().strftime("%H:%M:%S"),
                       "msg": f"STEALTH SCAN: {target} (via Tor)..."})
    try:
        result = subprocess.run(
            ["proxychains4", "-f", "/home/mrrobot/agents/honeypot/proxychains-strict.conf",
             "nmap", "-sT", "-T3", "--top-ports", "100", "-oN", "-", target],
            capture_output=True, text=True, timeout=600
        )
        ts = datetime.now().strftime("%H:%M:%S")
        with lock:
            nmap_results.clear()
            for line in result.stdout.split("\n"):
                line = line.strip()
                if line and any(k in line for k in ("open", "filtered", "closed", "Host is", "MAC", "OS")):
                    nmap_results.append({"time": ts, "line": line})
            alerts.append({"time": ts, "msg": f"STEALTH SCAN: {target} complete"})
    except Exception as e:
        with lock:
            alerts.append({"time": datetime.now().strftime("%H:%M:%S"),
                           "msg": f"STEALTH SCAN failed: {e}"})
    finally:
        nmap_running = False

def banner_grab(target, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((target, int(port)))
        s.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = s.recv(1024).decode(errors="replace")
        s.close()
        return banner.strip()[:200]
    except Exception as e:
        return f"ERROR: {e}"

def traceroute(target):
    try:
        result = subprocess.run(
            ["traceroute", "-m", "20", "-w", "2", target],
            capture_output=True, text=True, timeout=60
        )
        return result.stdout
    except FileNotFoundError:
        # Fallback to nmap traceroute
        try:
            result = subprocess.run(
                ["nmap", "--traceroute", "-sn", target],
                capture_output=True, text=True, timeout=30
            )
            return result.stdout
        except Exception:
            return "traceroute not available"
    except Exception as e:
        return f"ERROR: {e}"

# -- INTERACTIVE COMMAND CONSOLE

MAX_CONSOLE = 5000  # bounded buffer across all screens (deque maxlen)
console_output = deque(maxlen=MAX_CONSOLE)
console_mode = False
_input_active = False
_redraw_event = threading.Event()
_render_lock = threading.Lock()
current_tab = "all"
TABS = ["all", "hosts", "proto", "dns", "honeypot", "nmap", "arp", "alerts", "osint", "proxy", "mesh"]
show_help_overlay = False
osint_results = []
MAX_OSINT = 50
_proxy_circuit_cache = {}
_proxy_cache_time = 0
ip_tags = {}       # {ip: "label"}
ip_notes = {}      # {ip: ["note1", ...]}
watchlist = set()  # IPs on watchlist

# Time-series for charts
_ts_lock = threading.Lock()
_ts_samples = []
_TS_MAX = 360  # 30 min at 5s intervals

# Meshtastic mesh radio
try:
    import meshtastic as _meshtastic_lib
    import meshtastic.serial_interface as _mesh_serial
    _HAS_MESH = True
except ImportError:
    _HAS_MESH = False

mesh_interface = None
mesh_messages = []
mesh_nodes = {}
mesh_alert_fwd = True
_MESH_MAX_MSGS = 200
_MESH_MAX_NODES = 500

_CMD_HISTORY_MAX = 5000
_cmd_history = deque(maxlen=_CMD_HISTORY_MAX)
_output_scroll = 0
_OUTPUT_PANEL_MIN = 6
_tunnel_url = ""  # populated when cloudflared trycloudflare URL is captured

# ─── Screen State (AppState dataclass) ───────────────────
#
# Three screens mounted once: dashboard (tabs+OUTPUT panel), command_line
# (full-screen prompt+history), console (full-screen tool output log).
# Switching = dispatch in _render_frame(); per-screen state (tab, scroll,
# focus, help overlay) persists in AppState so returning to dashboard
# restores exact prior state. F1/F2/F3 or commands `dashboard`/`cli`/`console`.
from dataclasses import dataclass

SCREEN_DASHBOARD = "dashboard"
SCREEN_CLI = "cli"
SCREEN_CONSOLE = "console"
SCREEN_REPLAY = "replay"
SCREENS = (SCREEN_DASHBOARD, SCREEN_CLI, SCREEN_CONSOLE, SCREEN_REPLAY)


def _get_terminal_dims():
    """Return (cols, rows). Falls back to 80x40 if not a TTY."""
    try:
        return os.get_terminal_size()
    except Exception:
        return (80, 40)


def _write_frame(buf):
    """Best-effort write to stdout. Swallow OSError (terminal gone)."""
    try:
        os.write(1, buf.encode('utf-8', errors='replace') if isinstance(buf, str) else buf)
    except OSError:
        pass


@dataclass
class AppState:
    """Centralized TUI state. One instance lives at module scope.

    Screens mount once; switching toggles which paint function runs.
    Per-screen scroll and the dashboard's active tab survive transitions.
    """
    current_screen: str = SCREEN_DASHBOARD
    current_tab: str = "all"
    dash_scroll: int = 0       # OUTPUT-panel scroll within dashboard
    cli_scroll: int = 0        # scrollback offset for CLI screen
    console_scroll: int = 0    # scrollback offset for console screen
    # Per-screen "focus" / cursor row hints — for restore on return.
    dash_focus: int = 0
    last_screen: str = SCREEN_DASHBOARD  # toggle-back target
    needs_clear: bool = False  # one-shot \033[2J before next paint
    # Replay screen state (None until a session is loaded)
    replay_session_id: str = ""
    replay_protocol: str = "ftp"          # "ftp" | "telnet"
    replay_timeline: dict = None          # dict from replay.replay_loader(); intel attached under 'intel'
    replay_cursor_ms: int = 0
    replay_playing: bool = False
    replay_speed: float = 1.0             # 0.25 / 0.5 / 1 / 2 / 4 / 8
    replay_last_tick: float = 0.0         # time.monotonic() of last advance

    def switch(self, target: str) -> None:
        if target not in SCREENS or target == self.current_screen:
            return
        self.last_screen = self.current_screen
        self.current_screen = target
        self.needs_clear = True

    def scroll_for(self, screen: str = "") -> int:
        s = screen or self.current_screen
        return {SCREEN_DASHBOARD: self.dash_scroll,
                SCREEN_CLI: self.cli_scroll,
                SCREEN_CONSOLE: self.console_scroll}.get(s, 0)

    def set_scroll(self, screen: str, value: int) -> None:
        if screen == SCREEN_DASHBOARD:
            self.dash_scroll = value
        elif screen == SCREEN_CLI:
            self.cli_scroll = value
        elif screen == SCREEN_CONSOLE:
            self.console_scroll = value


app_state = AppState()

_HELP_SECTIONS = [
    ("@N References", None, [("", "use @1 @2 etc to target IPs from current list"),
                              ("", "Example: scan @3  |  geo @1  |  fullrecon @5")]),
    ("OSINT", None, [
        ("geo <ip>", "IP geolocation"), ("whois <ip/dom>", "WHOIS lookup"),
        ("dnsinfo <dom>", "DNS enumeration"), ("rdns <ip>", "Reverse DNS"),
        ("portscan <ip>", "Top 1000 ports"), ("subnet [cidr]", "Ping sweep"),
        ("crt <domain>", "Cert transparency"), ("headers <url>", "HTTP fingerprint"),
        ("asn <ip>", "ASN/BGP info"), ("abuse <ip>", "IP reputation"),
        ("ssl <host> [port]", "TLS inspection"), ("secheaders <url>", "Security header audit"),
        ("techstack <url>", "Web tech detect"), ("ping <ip> [n]", "Jitter + OS guess"),
        ("health <target>", "Full profile"), ("etrace <ip>", "Enriched traceroute"),
        ("speed", "Network speedtest"), ("ifinfo", "Local interface info"),
    ]),
    ("Scanning", None, [
        ("scan <ip>", "Quick nmap"), ("deep <ip>", "Full + vulns"),
        ("stealth <ip>", "Tor scan"), ("recon <ip>", "Full OSINT profile"),
        ("banner <ip> <p>", "Grab banner"), ("trace <ip>", "Traceroute"),
        ("fullrecon <ip>", "7-phase chain"), ("sweep [cidr]", "ARP+ping+scan"),
    ]),
    ("Batch Ops", "target = hosts|attackers|arp|nmap|watchlist", [
        ("scanall [list]", "Scan all IPs"), ("geoall [list]", "Geolocate all"),
        ("whoisall [list]", "WHOIS all"), ("reconall [list]", "Full recon all"),
        ("blockall attackers", "Block all honeypot IPs"),
    ]),
    ("Smart Filters", None, [
        ("ips [list]", "Show numbered IPs"), ("top [n]", "Top N talkers"),
        ("new [mins]", "Recently appeared"), ("sus", "Suspicious hosts"),
        ("loud", "Most ports"), ("quiet", "Least traffic"),
        ("find <pattern>", "Search everything"), ("ports <port>", "Hosts by port"),
        ("services", "All detected svcs"), ("country <CC>", "Filter by country"),
        ("whowatch", "Active attackers"), ("summary", "Network overview"),
    ]),
    ("Attack Analysis", None, [
        ("inspect [n]", "Honeypot event"), ("analyze <ip>", "Attacker profile"),
        ("decode <data>", "Decode payload"), ("sessions", "Attacker IPs"),
        ("attackers", "Honeypot IPs"), ("profile <ip>", "Recon report"),
        ("timeline <ip>", "Event history"), ("report <ip>", "Save report"),
    ]),
    ("Tracking", None, [
        ("track <ip> [s]", "Live packet tail"), ("untrack <ip>", "Stop tracking"),
        ("conns <ip>", "TCP connections"), ("sniff <ip> [s]", "Payload capture"),
        ("trackdns <ip>", "DNS queries"), ("tracked <ip>", "Summary"),
    ]),
    ("Defense", None, [
        ("block <ip>", "iptables DROP"), ("unblock <ip>", "Remove rule"),
        ("blocked", "List rules"), ("mac <addr>", "MAC lookup"),
        ("diffarp", "ARP table changes"),
    ]),
    ("Tags & Notes", None, [
        ("tag <ip> <label>", "Label an IP"), ("tag list", "Show all tags"),
        ("tag rm <ip>", "Remove tag"), ("note <ip> <text>", "Add note"),
        ("note show <ip>", "View notes"), ("watch <ip>", "Add to watchlist"),
        ("watch list", "Show watchlist"), ("watch rm <ip>", "Remove from list"),
    ]),
    ("Export", None, [
        ("exportips [list]", "Save IPs to file"), ("report <ip>", "Full text report"),
        ("pcap start|stop", "PCAP capture"), ("export", "Save JSON"),
    ]),
    ("Proxy", None, [
        ("proxy add <t> <h:p>", "Add proxy"), ("proxy rm <n>", "Remove proxy"),
        ("proxy list", "Show all"), ("proxy test [n]", "Test proxy"),
        ("proxy rotate", "Toggle rotation"), ("proxy start", "Boot Tor circuits"),
    ]),
    ("Mesh Radio", None, [
        ("mesh send <text>", "Send message"), ("mesh status", "Connection info"),
        ("mesh nodes", "List nodes"), ("mesh alert on/off", "Toggle forwarding"),
    ]),
    ("System", None, [
        ("status", "Service info"), ("dashboard / d", "Return to TUI"),
        ("clear", "Clear screen"), ("help", "This reference"),
        ("rotate-key", "New Fernet key (invalidate sessions)"),
        ("rotate-token", "New web auth token"),
        ("show-token", "Print current web auth token + file path"),
    ]),
]


def _help_to_console():
    global show_help_overlay, _output_scroll
    show_help_overlay = True
    _output_scroll = 10**9  # clamps to max_scroll → render from top
    add_console(f"NETWATCH v{VERSION} — COMMAND REFERENCE")
    add_console(f"{'='*56}")
    for cat, subtitle, cmds in _HELP_SECTIONS:
        add_console("")
        hdr = f"{cat}:"
        if subtitle:
            hdr += f"  {subtitle}"
        add_console(hdr)
        for cmd, desc in cmds:
            if cmd:
                add_console(f"  {cmd:<20s} {desc}")
            else:
                add_console(f"  {desc}")


def _help_to_print():
    print(f"\n{BOLD}{CYAN}  COMMANDS{RESET}  {DIM}(use @N to pick IPs from current list){RESET}")
    for cat, subtitle, cmds in _HELP_SECTIONS:
        if cat == "@N References":
            continue
        hdr = f"  {BOLD}{cat}:{RESET}"
        if subtitle:
            hdr += f"  {DIM}{subtitle}{RESET}"
        print(hdr)
        pairs = [(c, d) for c, d in cmds if c]
        for i in range(0, len(pairs), 2):
            left_cmd, left_desc = pairs[i]
            line = f"    {GREEN}{left_cmd}{RESET}{' '*(17-len(left_cmd))}{left_desc}"
            if i + 1 < len(pairs):
                right_cmd, right_desc = pairs[i + 1]
                line += f"  {GREEN}{right_cmd}{RESET}{' '*(14-len(right_cmd))}{right_desc}"
            print(line)
    print()


def add_console(text):
    with lock:
        console_output.append(text)  # deque(maxlen=MAX_CONSOLE) self-trims
    _redraw_event.set()


def _get_ip_list(which="auto"):
    if which == "hosts" or (which == "auto" and current_tab == "hosts"):
        with lock:
            return sorted(hosts.keys(), key=lambda ip: hosts[ip].get("bytes_in", 0) + hosts[ip].get("bytes_out", 0), reverse=True)
    elif which == "attackers" or (which == "auto" and current_tab == "honeypot"):
        with lock:
            ips = set()
            for e in honeypot_events:
                ips.add(e["ip"])
            return sorted(ips)
    elif which == "arp" or (which == "auto" and current_tab == "arp"):
        with lock:
            return sorted(arp_table.keys())
    elif which == "nmap" or (which == "auto" and current_tab == "nmap"):
        with lock:
            ips = set()
            for r in nmap_results:
                m = re.search(r'(\d+\.\d+\.\d+\.\d+)', r.get("line", ""))
                if m:
                    ips.add(m.group(1))
            return sorted(ips)
    elif which == "watchlist":
        return sorted(watchlist)
    elif which == "tracked":
        return sorted(ip for ip, v in tracking_active.items() if v)
    elif which == "blocked":
        result = subprocess.run(["iptables", "-L", "INPUT", "-n"], capture_output=True, text=True)
        ips = re.findall(r'DROP\s+all\s+--\s+([\d.]+)', result.stdout)
        return ips
    else:
        with lock:
            return sorted(hosts.keys(), key=lambda ip: hosts[ip].get("bytes_in", 0) + hosts[ip].get("bytes_out", 0), reverse=True)


def _resolve_target(token):
    if token.startswith("@") or token.startswith("#"):
        try:
            idx = int(token[1:]) - 1
            ip_list = _get_ip_list()
            if 0 <= idx < len(ip_list):
                resolved = ip_list[idx]
                add_console(f"{DIM}  → resolved {token} to {resolved}{RESET}")
                return resolved
            else:
                add_console(f"{RED}Index {token} out of range (have {len(ip_list)} IPs){RESET}")
                return None
        except ValueError:
            return token[1:]
    return token


_replay_last_index = []


def _disp_replay(parts):
    global _replay_last_index
    sub = parts[1].lower() if len(parts) >= 2 else "list"

    if sub == "list" or len(parts) < 2:
        try:
            rows = replay.replay_index()
        except Exception as e:
            add_console(f"{RED}replay: index failed: {e}{RESET}")
            return
        if not rows:
            add_console(f"{DIM}No captured sessions yet. Run the honeypots and wait for traffic.{RESET}")
            _replay_last_index = []
            return
        top = rows[:20]
        _replay_last_index = top
        add_console(f"{BOLD}{CYAN}CAPTURED SESSIONS — top {len(top)} of {len(rows)}{RESET}")
        add_console(f"  {DIM}#   session_id                        proto  ip               events   started_at{RESET}")
        for i, r in enumerate(top, 1):
            sid = (r.get("session_id") or "")[:34]
            proto = (r.get("protocol") or "")[:6]
            ip = (r.get("ip") or "")[:15]
            evc = str(r.get("event_count", ""))[:7]
            started = (r.get("started_at_mtime") or "")[:19]
            add_console(f"  {i:<3} {sid:<34} {proto:<6} {ip:<15} {evc:<8} {started}")
        add_console(f"{DIM}  → `replay <#>` or `replay <session_id> [ftp|telnet]` to load{RESET}")
        return

    raw = parts[1]
    proto = parts[2].lower() if len(parts) >= 3 else None

    sid = None
    chosen_proto = proto or "ftp"
    if raw.isdigit():
        idx = int(raw) - 1
        if not (0 <= idx < len(_replay_last_index)):
            add_console(f"{RED}replay: index {raw} out of range — run `replay list` first{RESET}")
            return
        row = _replay_last_index[idx]
        sid = row.get("session_id")
        if not proto:
            chosen_proto = row.get("protocol") or "ftp"
    else:
        sid = raw

    try:
        timeline = replay.replay_loader(sid, protocol=chosen_proto)
        timeline["intel"] = replay.load_intel(timeline.get("ip", ""))
    except FileNotFoundError as e:
        add_console(f"{RED}replay: session not found: {e}{RESET}")
        return
    except ValueError as e:
        add_console(f"{RED}replay: {e}{RESET}")
        return
    except Exception as e:
        add_console(f"{RED}replay: load failed: {e}{RESET}")
        return

    app_state.replay_session_id = sid
    app_state.replay_protocol = chosen_proto
    app_state.replay_timeline = timeline
    app_state.replay_cursor_ms = 0
    app_state.replay_playing = False
    app_state.replay_speed = 1.0
    app_state.replay_last_tick = time.monotonic()
    app_state.switch(SCREEN_REPLAY)
    add_console(f"{GREEN}replay: loaded {sid} ({chosen_proto}) — {len(timeline.get('events', []))} events, "
                f"{timeline.get('duration_ms', 0)/1000:.1f}s{RESET}")
    _redraw_event.set()


def handle_command(cmd):
    global current_tab, console_mode, proxy_rotation
    parts = cmd.strip().split()
    if not parts:
        return

    action = parts[0].lower()

    # Resolve @N references in all arguments
    resolved_parts = [parts[0]]
    for p in parts[1:]:
        if p.startswith("@") or p.startswith("#"):
            r = _resolve_target(p)
            if r is None:
                return
            resolved_parts.append(r)
        else:
            resolved_parts.append(p)
    parts = resolved_parts

    _SIMPLE_THREAD_CMDS = {
        "deep":       (2, r'^[\d./a-fA-F:]+$',    _cmd_deep,         f"{RED}DEEP SCAN: {{}} — all ports, scripts, vulns...{RESET}"),
        "stealth":    (2, r'^[\d./a-fA-F:]+$',    stealth_scan,      f"{MAGENTA}STEALTH SCAN: {{}} via Tor...{RESET}"),
        "recon":      (2, r'^[\d./a-fA-F:]+$',    _cmd_recon,        f"{RED}RECON: full profile on {{}}...{RESET}"),
        "trace":      (2, r'^[\d./a-fA-F:]+$',    _cmd_trace,        f"{CYAN}Traceroute to {{}}...{RESET}"),
        "geo":        (2, None,                    _cmd_geo,          f"{CYAN}Geolocating {{}}...{RESET}"),
        "dnsinfo":    (2, None,                    _cmd_dnsinfo,      f"{CYAN}DNS enumeration: {{}}...{RESET}"),
        "portscan":   (2, r'^[\d.a-zA-Z\-]+$',    _cmd_portscan,     f"{CYAN}Port scanning {{}} (top 1000)...{RESET}"),
        "conns":      (2, r'^[\d./a-fA-F:]+$',    track_connections, f"{CYAN}Capturing TCP connections for {{}} (10s)...{RESET}"),
        "trackdns":   (2, r'^[\d./a-fA-F:]+$',    track_dns_for,     f"{MAGENTA}Capturing DNS from {{}} (30s)...{RESET}"),
        "crt":        (2, None,                    _cmd_crt,          f"{CYAN}Cert transparency: {{}}...{RESET}"),
        "headers":    (2, None,                    _cmd_headers,      f"{CYAN}HTTP headers: {{}}...{RESET}"),
        "asn":        (2, None,                    _cmd_asn,          f"{CYAN}ASN lookup: {{}}...{RESET}"),
        "abuse":      (2, None,                    _cmd_abuse,        f"{CYAN}Abuse check: {{}}...{RESET}"),
        "secheaders": (2, r'^[a-zA-Z0-9.\-/:]+$', _cmd_secheaders,   f"{CYAN}Security header audit: {{}}...{RESET}"),
        "techstack":  (2, r'^[a-zA-Z0-9.\-/:]+$', _cmd_techstack,    f"{CYAN}Tech fingerprint: {{}}...{RESET}"),
        "etrace":     (2, r'^[\d./a-fA-F:a-zA-Z\-]+$', _cmd_etrace,  f"{CYAN}Enriched traceroute: {{}}...{RESET}"),
        "health":     (2, r'^[a-zA-Z0-9.\-]+$',   _cmd_health,       f"{BOLD}{RED}HEALTH CHECK: {{}} — running full profile...{RESET}"),
        "analyze":    (2, None,                    _cmd_analyze,      f"{RED}Analyzing attacker {{}}...{RESET}"),
        "rdns":       (2, None,                    _cmd_rdns,         f"{CYAN}Reverse DNS: {{}}...{RESET}"),
        "fullrecon":  (2, r'^[\d./a-fA-F:a-zA-Z\-]+$', _cmd_fullrecon, f"{BOLD}{RED}FULL RECON: {{}} — geo+whois+dns+ssl+headers+ports+trace...{RESET}"),
        "country":    (2, None,                    _cmd_country,      f"{BOLD}{CYAN}HOSTS IN {{}}:{RESET}"),
        "diffarp":    (1, None,                    _cmd_diffarp,      f"{BOLD}{YELLOW}ARP TABLE DIFF — checking for changes...{RESET}"),
        "sweep":      (1, None,                    _cmd_sweep,        f"{BOLD}{RED}NETWORK SWEEP — ARP + ping + scan...{RESET}"),
        "speed":      (1, None,                    _cmd_speed,        ""),
    }
    if action in _SIMPLE_THREAD_CMDS and len(parts) >= _SIMPLE_THREAD_CMDS[action][0]:
        min_args, pattern, func, msg = _SIMPLE_THREAD_CMDS[action]
        target = parts[1] if len(parts) >= 2 else None
        if target and pattern and not re.match(pattern, target):
            add_console(f"{RED}Invalid target: {target}{RESET}"); return
        if msg:
            add_console(msg.format(target or ""))
        threading.Thread(target=func, args=((target,) if target else ()), daemon=True).start()
        return

    _DIRECT_CMDS = {
        "scan": (2, _disp_scan), "banner": (3, _disp_banner), "whois": (2, _disp_whois),
        "attackers": (1, _disp_attackers), "profile": (2, _disp_profile),
        "block": (2, _disp_block), "unblock": (2, _disp_unblock), "blocked": (1, _disp_blocked),
        "mac": (1, _disp_mac), "inspect": (1, _disp_inspect), "decode": (2, _disp_decode),
        "sessions": (1, _disp_sessions), "ips": (1, _disp_ips), "top": (1, _disp_top),
        "new": (1, _disp_new), "sus": (1, _disp_sus), "loud": (1, _disp_loud),
        "quiet": (1, _disp_quiet), "services": (1, _disp_services),
        "tracking": (1, _disp_tracking), "whowatch": (1, _disp_whowatch),
        "summary": (1, _disp_summary), "timeline": (2, _disp_timeline),
        "report": (2, _disp_report), "exportips": (1, _disp_exportips),
        "ports": (2, _disp_ports), "find": (1, _disp_find),
        "ssl": (2, _disp_ssl), "ping": (2, _disp_ping),
        "track": (2, _disp_track), "untrack": (2, _disp_untrack),
        "sniff": (2, _disp_sniff), "tracked": (2, _disp_tracked),
        "subnet": (1, _disp_subnet), "pcap": (1, _disp_pcap),
        "blockall": (1, _disp_blockall), "tag": (1, _disp_tag), "note": (1, _disp_note),
        "watch": (1, _disp_watch), "mesh": (1, _disp_mesh), "ifinfo": (1, _disp_ifinfo),
        "proxy": (1, _disp_proxy), "replay": (1, _disp_replay),
    }

    if action in _DIRECT_CMDS:
        min_args, handler = _DIRECT_CMDS[action]
        if len(parts) >= min_args:
            handler(parts)
            return

    # Batch operations
    if action in ("scanall", "geoall", "whoisall", "reconall"):
        which = parts[1].lower() if len(parts) >= 2 else "attackers"
        _BATCH_CFG = {
            "scanall":  (20, RED,  "SCAN",  _batch_scan_worker),
            "geoall":   (30, CYAN, "GEO",   _batch_geo_worker),
            "whoisall": (20, CYAN, "WHOIS", _batch_whois_worker),
            "reconall": (10, RED,  "RECON", _batch_recon_worker),
        }
        cap, color, label, worker = _BATCH_CFG[action]
        ip_list = _get_ip_list(which)
        if not ip_list:
            add_console(f"{DIM}No IPs in '{which}' list.{RESET}"); return
        if action in ("geoall", "whoisall"):
            ip_list = [ip for ip in ip_list if not ipaddress.ip_address(ip).is_private]
            if not ip_list:
                add_console(f"{YELLOW}No external IPs.{RESET}"); return
        actual = min(len(ip_list), cap)
        add_console(f"{BOLD}{color}BATCH {label}: {actual} IPs from '{which}'...{RESET}")
        def _run_batch(ips=ip_list[:actual], n=actual):
            for i, ip in enumerate(ips):
                worker(i, n, ip)
                time.sleep(0.5)
            add_console(f"{GREEN}Batch {label.lower()} complete.{RESET}")
        threading.Thread(target=_run_batch, daemon=True).start()
        return

    # Tab switching
    _TAB_NAMES = {"hosts", "alerts", "dns", "proto", "honeypot", "nmap", "arp", "all", "osint"}
    if action in _TAB_NAMES:
        current_tab = action
        add_console(f"{CYAN}Switched to [{action.upper()}] view{RESET}")
        return

    # Simple one-liners
    if action == "export":
        save_logs()
        add_console(f"{GREEN}Exported to {LOG_DIR}/traffic.json{RESET}")
    elif action in ("dashboard", "dash", "d"):
        console_mode = False
        app_state.switch(SCREEN_DASHBOARD)
        _redraw_event.set()
    elif action in ("cli", "commandline", "command-line"):
        app_state.switch(SCREEN_CLI)
        _redraw_event.set()
    elif action == "console":
        app_state.switch(SCREEN_CONSOLE)
        _redraw_event.set()
    elif action == "clear":
        with lock:
            console_output.clear()
        app_state.dash_scroll = 0
        app_state.cli_scroll = 0
        app_state.console_scroll = 0
    elif action == "help":
        _help_to_console()
    elif action == "status":
        _disp_summary(parts)
    elif action in ("rotate-key", "rotatekey"):
        _disp_rotate_key()
    elif action in ("rotate-token", "rotatetoken"):
        _disp_rotate_token()
    elif action in ("show-token", "showtoken", "token"):
        _disp_show_token()
    else:
        add_console(f"{RED}Unknown: '{action}'. Type 'help' for commands.{RESET}")


def _disp_rotate_key():
    """Generate fresh Fernet key. All web sessions invalidated."""
    global WEB_ENCRYPTION_KEY, _fernet
    try:
        new_key = rotate_key()
        WEB_ENCRYPTION_KEY = new_key
        _fernet = _Fernet(new_key)
        add_console(f"{GREEN}Web encryption key rotated — all sessions invalidated.{RESET}")
    except Exception as e:
        add_console(f"{RED}Key rotation failed: {_safe_error(e)}{RESET}")


def _disp_show_token():
    """Print the current full WEB_TOKEN and its on-disk path."""
    add_console(f"{YELLOW}Web Token : {WEB_TOKEN}{RESET}")
    add_console(f"{DIM}File      : {_TOKEN_PATH} (0600){RESET}")
    add_console(f"{DIM}Use this token to log into the web dashboard.{RESET}")


def _disp_rotate_token():
    """Generate fresh WEB_TOKEN and persist. All web sessions invalidated."""
    global WEB_TOKEN
    try:
        new_token = secrets.token_hex(24)
        WEB_TOKEN = new_token
        _persist_web_token(new_token, _TOKEN_PATH)
        redacted = f"{new_token[:6]}…{new_token[-4:]}"
        add_console(f"{GREEN}Web token rotated: {redacted}  (full token in {_TOKEN_PATH}){RESET}")
    except Exception as e:
        add_console(f"{RED}Token rotation failed: {_safe_error(e)}{RESET}")

# ─── OSINT command-handler helpers ───────────────────────
# Most _cmd_* handlers follow the same shape: call OSINT fn → check error →
# emit results → record to osint_results. Helpers fold the boilerplate.

def _osint_err(data) -> bool:
    """Emit and return True if data is an error dict; caller returns early."""
    if isinstance(data, dict) and "error" in data:
        add_console(f"  {RED}{data['error']}{RESET}")
        return True
    return False

def _osint_record(type_: str, target: str, result_str: str) -> None:
    with lock:
        _capped_append(osint_results, {
            "time": datetime.now().strftime("%H:%M:%S"),
            "type": type_, "target": target, "result": result_str,
        }, MAX_OSINT)

def _cmd_crt(target):
    data = osint_crt(target)
    if _osint_err(data): return
    if not data:
        add_console(f"  {YELLOW}No certs found.{RESET}"); return
    add_console(f"  {GREEN}{len(data)} subdomains:{RESET}")
    for e in data[:25]:
        add_console(f"  {CYAN}{e['cn']}{RESET}  {DIM}{e['not_after']}{RESET}")
    _osint_record("CRT", target, f"{len(data)} subdomains")

def _cmd_headers(target):
    data = osint_headers(target)
    if _osint_err(data): return
    add_console(f"  {GREEN}Status: {data['status']}{RESET}")
    if data.get("tech"):
        add_console(f"  {YELLOW}Tech: {', '.join(data['tech'])}{RESET}")
    for k, v in list(data.get("headers", {}).items())[:15]:
        add_console(f"  {DIM}{k}:{RESET} {str(v)[:80]}")

def _cmd_asn(target):
    data = osint_asn(target)
    if _osint_err(data): return
    for k, v in data.items():
        add_console(f"  {WHITE}{k}:{RESET} {v}")

def _cmd_abuse(target):
    for k, v in osint_abuse(target).items():
        color = RED if v and k != "ip" else GREEN
        add_console(f"  {color}{k}:{RESET} {v}")

def _cmd_ssl(target):
    if ":" in target and not target.startswith("[") and target.rsplit(":", 1)[1].isdigit():
        host, port = target.rsplit(":", 1)
        port = int(port)
    else:
        host, port = target, 443
    data = osint_ssl(host, port)
    if _osint_err(data): return
    for label, key in (("Protocol", "protocol"), ("Cipher", "cipher"),
                       ("Subject", "subject"), ("Issuer", "issuer")):
        v = data.get(key, "?")
        extra = f" ({data.get('bits','?')} bit)" if key == "cipher" else ""
        add_console(f"  {GREEN}{label}:{RESET} {v}{extra}")
    add_console(f"  {GREEN}Valid:{RESET}    {data.get('not_before','?')} → {data.get('not_after','?')}")
    days = data.get("days_left")
    if days is not None:
        color = GREEN if days > 30 else YELLOW if days > 7 else RED
        add_console(f"  {color}Expires:{RESET}  {days} days")
    if data.get("alt_names"):
        add_console(f"  {DIM}SANs: {', '.join(data['alt_names'][:5])}{RESET}")
    _osint_record("SSL", target,
        f"{data.get('protocol','?')} | {data.get('subject','?')} | {data.get('days_left','?')}d left")

def _cmd_secheaders(target):
    data = osint_secheaders(target)
    if _osint_err(data): return
    add_console(f"  {BOLD}Grade: {data['grade']}  ({data['score']}){RESET}")
    for label, info in data.get("headers", {}).items():
        if info["present"]:
            add_console(f"  {GREEN}+ {label}{RESET} {DIM}{info['value'][:60]}{RESET}")
        else:
            add_console(f"  {RED}x {label}{RESET} {DIM}MISSING{RESET}")
    _osint_record("SECHDR", target, f"Grade {data['grade']} ({data['score']})")

def _cmd_techstack(target):
    data = osint_techstack(target)
    if _osint_err(data): return
    techs = data.get("technologies", [])
    if techs:
        add_console(f"  {GREEN}Technologies detected:{RESET}")
        for t in techs:
            add_console(f"    {CYAN}* {t}{RESET}")
    else:
        add_console(f"  {YELLOW}No frameworks detected{RESET}")
    if data.get("server"):
        add_console(f"  {DIM}Server: {data['server']}{RESET}")
    _osint_record("TECH", target, ", ".join(techs[:5]) or "none detected")

def _cmd_ping(target, count=5):
    data = osint_ping_analyze(target, count)
    if _osint_err(data): return
    add_console(f"  {GREEN}RTT:{RESET}  min={data.get('min','?')}ms  avg={data.get('avg','?')}ms  max={data.get('max','?')}ms")
    if "jitter" in data:
        add_console(f"  {GREEN}Jitter:{RESET} {data['jitter']}ms")
    add_console(f"  {GREEN}Loss:{RESET}  {data.get('loss', '?')}%")
    if "ttl" in data:
        add_console(f"  {GREEN}TTL:{RESET}   {data['ttl']} -> {YELLOW}{data.get('os_guess', '?')}{RESET}")
    _osint_record("PING", target,
        f"avg={data.get('avg','?')}ms jitter={data.get('jitter','?')}ms TTL={data.get('ttl','?')} ({data.get('os_guess','?')})")

def _cmd_etrace(target):
    hops = osint_trace_enriched(target)
    if not hops:
        add_console(f"  {YELLOW}No hops returned.{RESET}"); return
    if _osint_err(hops[0]): return
    for i, hop in enumerate(hops, 1):
        loc = f"{hop.get('city','')}, {hop.get('country','')}" if hop.get("city") else ""
        add_console(f"  {DIM}{i:>2}{RESET} {CYAN}{hop['ip']:<16}{RESET} {hop.get('rdns','')[:30]:<32}{GREEN}{loc:<20}{RESET}{DIM}{hop.get('isp','')[:25]}{RESET}")
    _osint_record("ETRACE", target, f"{len(hops)} hops")

def _cmd_analyze(target):
    profile = analyze_attacker(target)
    if not profile:
        add_console(f"  {DIM}No honeypot events from {target}{RESET}"); return
    add_console(f"{BOLD}{RED}ATTACKER PROFILE: {target}{RESET}")
    add_console(f"  Hostname:  {profile['hostname'] or 'N/A'}")
    add_console(f"  Location:  {profile['geo']}")
    add_console(f"  ISP:       {profile['isp']}")
    add_console(f"  Events:    {profile['total_events']}")
    add_console(f"  Services:  {', '.join(profile['services_targeted'])}")
    add_console(f"  First:     {profile['first_seen']}")
    add_console(f"  Last:      {profile['last_seen']}")
    add_console(f"  {YELLOW}Timeline:{RESET}")
    for line in profile['timeline']:
        add_console(f"    {DIM}{line}{RESET}")

def _cmd_rdns(target):
    data = osint_reverse_dns(target)
    if "error" in data:
        add_console(f"  {YELLOW}{data['error']}{RESET}")
    else:
        for k, v in data.items():
            if isinstance(v, list):
                for item in v:
                    add_console(f"  {GREEN}PTR: {item}{RESET}")
            else:
                add_console(f"  {GREEN}PTR: {v}{RESET}")

def _cmd_health(target):
    data = osint_health(target)
    add_console(f"\n  {BOLD}{CYAN}=== HEALTH REPORT: {target} ==={RESET}")
    p, s, sh = data.get("ping", {}), data.get("ssl", {}), data.get("secheaders", {})
    ts, g, d = data.get("techstack", {}), data.get("geo", {}), data.get("dns", {})
    if "error" not in p:
        add_console(f"  {GREEN}PING:{RESET} avg={p.get('avg','?')}ms jitter={p.get('jitter','?')}ms loss={p.get('loss','?')}% TTL={p.get('ttl','?')} ({p.get('os_guess','?')})")
    if "error" not in s:
        add_console(f"  {GREEN}TLS:{RESET}  {s.get('protocol','?')} | {s.get('cipher','?')} | subj={s.get('subject','?')} | {s.get('days_left','?')}d left")
    else:
        add_console(f"  {RED}TLS:{RESET}  {s.get('error','no connection')}")
    if "error" not in sh:
        add_console(f"  {GREEN}HDRS:{RESET} Grade {sh.get('grade','?')} ({sh.get('score','?')})")
    if "error" not in ts:
        add_console(f"  {GREEN}TECH:{RESET} {', '.join(ts.get('technologies', [])[:6]) or 'none detected'}")
    if "error" not in g and g.get("status") != "fail":
        add_console(f"  {GREEN}GEO:{RESET}  {g.get('city','?')}, {g.get('country','?')} | {g.get('isp','?')} | {g.get('as','?')}")
    if d and "error" not in d:
        add_console(f"  {GREEN}DNS:{RESET}  {sum(len(v) for v in d.values())} records ({', '.join(d.keys())})")
    add_console(f"  {BOLD}{CYAN}{'=' * 40}{RESET}\n")
    _osint_record("HEALTH", target,
        f"Grade {sh.get('grade','?')} | {s.get('protocol','?')} | {', '.join(ts.get('technologies',[])[:3])}")

def _cmd_country(cc):
    with lock:
        ext_ips = [ip for ip in hosts if not ipaddress.ip_address(ip).is_private]
    found = 0
    for ip in ext_ips[:50]:
        data = osint_geolocate(ip)
        if data.get("countryCode", "").upper() == cc.upper():
            add_console(f"  {CYAN}{ip:<18}{RESET} {data.get('city','?')}, {data.get('country','?')} — {data.get('isp','?')[:30]}")
            found += 1
        time.sleep(0.3)
    add_console(f"{DIM}Found {found} hosts in {cc.upper()}.{RESET}")

def _cmd_speed(_target=None):
    add_console(f"{CYAN}Running speedtest...{RESET}")
    try:
        r = subprocess.run(["speedtest-cli", "--simple"], capture_output=True, text=True, timeout=60)
        if r.returncode == 0:
            for line in r.stdout.strip().split("\n"):
                add_console(f"  {GREEN}{line}{RESET}")
        else:
            add_console(f"  {RED}speedtest failed: {r.stderr.strip()}{RESET}")
    except FileNotFoundError:
        add_console(f"  {RED}speedtest-cli not installed. pip install speedtest-cli{RESET}")
    except subprocess.TimeoutExpired:
        add_console(f"  {RED}speedtest timed out (60s){RESET}")
    except Exception as e:
        add_console(f"  {RED}speedtest error: {e}{RESET}")

def _cmd_fullrecon(target):
    add_console(f"  {CYAN}[1/7] Geolocation...{RESET}")
    geo = osint_geolocate(target)
    if "error" not in geo and geo.get("status") != "fail":
        add_console(f"    {GREEN}Location:{RESET} {geo.get('city','?')}, {geo.get('country','?')}")
        add_console(f"    {GREEN}ISP:{RESET} {geo.get('isp','?')}")
        add_console(f"    {GREEN}AS:{RESET} {geo.get('as','?')}")
    add_console(f"  {CYAN}[2/7] WHOIS...{RESET}")
    w = osint_whois(target)
    if "error" not in w:
        for k, v in list(w.items())[:5]:
            add_console(f"    {GREEN}{k}:{RESET} {v}")
    add_console(f"  {CYAN}[3/7] DNS...{RESET}")
    d = osint_dns_enum(target)
    if d and "error" not in d:
        total = sum(len(v) for v in d.values())
        add_console(f"    {GREEN}{total} records:{RESET} {', '.join(f'{k}={len(v)}' for k,v in d.items())}")
    add_console(f"  {CYAN}[4/7] SSL/TLS...{RESET}")
    s = osint_ssl(target, 443)
    if "error" not in s:
        add_console(f"    {GREEN}TLS:{RESET} {s.get('protocol','?')} | {s.get('cipher','?')} | {s.get('days_left','?')}d left")
    add_console(f"  {CYAN}[5/7] HTTP headers...{RESET}")
    h = osint_headers(target)
    if "error" not in h:
        add_console(f"    {GREEN}Status:{RESET} {h.get('status','?')}")
        if h.get("tech"):
            add_console(f"    {GREEN}Tech:{RESET} {', '.join(h['tech'])}")
    add_console(f"  {CYAN}[6/7] Port scan...{RESET}")
    try:
        result = subprocess.run(["nmap", "-sV", "-T4", "--top-ports", "200", target, "-oN", "-"],
            capture_output=True, text=True, timeout=90)
        open_lines = [l.strip() for l in result.stdout.split("\n") if "open" in l]
        for p in open_lines[:10]:
            add_console(f"    {GREEN}{p}{RESET}")
    except Exception:
        add_console(f"    {RED}nmap failed{RESET}")
    add_console(f"  {CYAN}[7/7] Traceroute...{RESET}")
    tr = traceroute(target)
    hops = [l.strip() for l in tr.split("\n") if l.strip()]
    for hop in hops[:8]:
        add_console(f"    {DIM}{hop}{RESET}")
    add_console(f"\n  {BOLD}{GREEN}=== FULL RECON COMPLETE: {target} ==={RESET}")
    _osint_record("FULLRECON", target, "7-phase recon complete")

def _cmd_sweep(cidr=None):
    cidr = cidr or "10.0.1.0/24"
    add_console(f"  {CYAN}[1/3] ARP scan...{RESET}")
    try:
        result = subprocess.run(["arp-scan", "-l", "-I", IFACE], capture_output=True, text=True, timeout=30)
        arp_lines = [l for l in result.stdout.split("\n") if re.match(r'^\d+\.\d+\.\d+\.\d+', l)]
        for l in arp_lines:
            add_console(f"    {GREEN}{l}{RESET}")
        add_console(f"    {DIM}{len(arp_lines)} devices found via ARP{RESET}")
    except Exception:
        add_console(f"    {DIM}arp-scan not available, using ping sweep{RESET}")
    add_console(f"  {CYAN}[2/3] Ping sweep {cidr}...{RESET}")
    try:
        result = subprocess.run(["nmap", "-sn", "-T4", cidr], capture_output=True, text=True, timeout=60)
        up_hosts = re.findall(r'Nmap scan report for (\S+)', result.stdout)
        for h in up_hosts:
            add_console(f"    {GREEN}UP: {h}{RESET}")
        add_console(f"    {DIM}{len(up_hosts)} hosts up{RESET}")
    except Exception as e:
        add_console(f"    {RED}ping sweep failed: {e}{RESET}")
    add_console(f"  {CYAN}[3/3] Quick port scan on live hosts...{RESET}")
    try:
        result = subprocess.run(["nmap", "-sV", "-T4", "--top-ports", "50", cidr],
            capture_output=True, text=True, timeout=120)
        for line in result.stdout.split("\n"):
            if "open" in line:
                add_console(f"    {GREEN}{line.strip()}{RESET}")
    except Exception:
        pass
    add_console(f"{GREEN}Network sweep complete.{RESET}")

def _cmd_diffarp(_target=None):
    result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
    current_arp = {}
    for line in result.stdout.split("\n"):
        m = re.search(r'\(([\d.]+)\)\s+at\s+([\w:]+)', line)
        if m:
            current_arp[m.group(1)] = m.group(2)
    with lock:
        known = {ip: info.get("mac", "") for ip, info in arp_table.items()}
    for ip, mac in current_arp.items():
        if ip not in known:
            hostname = resolve_host(ip)
            add_console(f"  {GREEN}[NEW]{RESET}  {ip:<16} {mac}  {hostname[:25]}")
        elif known[ip] != mac and known[ip]:
            add_console(f"  {RED}[CHG]{RESET}  {ip:<16} {known[ip]} -> {mac}  {YELLOW}MAC CHANGED!{RESET}")
    for ip in known:
        if ip not in current_arp:
            add_console(f"  {DIM}[GONE] {ip:<16} {known.get(ip,'')}{RESET}")
    add_console(f"{DIM}ARP diff complete.{RESET}")

def _disp_banner(parts):
    if not re.match(r'^[\d./a-fA-F:]+$', parts[1]):
        add_console(f"{RED}Invalid target{RESET}"); return
    if not parts[2].isdigit():
        add_console(f"{RED}Invalid port{RESET}"); return
    add_console(f"Grabbing banner {parts[1]}:{parts[2]}...")
    result = banner_grab(parts[1], parts[2])
    add_console(f"{GREEN}{result}{RESET}")

def _disp_whois(parts):
    target = parts[1]
    add_console(f"{CYAN}WHOIS: {target}{RESET}")
    hostname = resolve_host(target)
    add_console(f"  Hostname: {hostname or 'NO PTR'}")
    data = osint_whois(target)
    if "error" in data:
        add_console(f"  {YELLOW}{data['error']}{RESET}")
    else:
        for k, v in data.items():
            add_console(f"  {WHITE}{k}:{RESET} {v}")
    if target in hosts:
        h = hosts[target]
        add_console(f"  {DIM}Traffic: {format_bytes(h['bytes_in'])} in / {format_bytes(h['bytes_out'])} out{RESET}")
        add_console(f"  {DIM}Ports: {sorted(h['ports'])}{RESET}")
    if target in recon_reports:
        r = recon_reports[target]
        add_console(f"  OS: {r.get('os_guess', '?')}")

def _disp_attackers(parts):
    with lock:
        attacker_ips = set()
        for e in honeypot_events:
            if e["service"] in ("credential", "telnet", "telnet_cmd", "malware_attempt",
                                 "rtsp", "rtsp_auth", "scan_probe", "api_probe", "onvif_probe"):
                attacker_ips.add(e["ip"])
    if attacker_ips:
        add_console(f"{RED}ATTACKERS ({len(attacker_ips)} unique IPs):{RESET}")
        for ip in sorted(attacker_ips):
            events = [e for e in honeypot_events if e["ip"] == ip]
            hostname = resolve_host(ip)
            add_console(f"  {RED}{ip:<18}{RESET} {hostname:<25} {len(events)} events")
    else:
        add_console(f"{DIM}No honeypot attackers yet.{RESET}")

def _disp_profile(parts):
    ip = parts[1]
    if ip in recon_reports:
        r = recon_reports[ip]
        add_console(f"{BOLD}{CYAN}RECON REPORT: {ip}{RESET}")
        add_console(f"  Hostname: {r['hostname']}")
        add_console(f"  OS: {r.get('os_guess', '?')}")
        add_console(f"  Scanned: {r['timestamp']}")
        for p in r.get("ports", [])[:15]:
            add_console(f"  {GREEN}{p}{RESET}")
        if r.get("traceroute"):
            add_console(f"  {CYAN}Traceroute:{RESET}")
            for hop in r["traceroute"][:10]:
                add_console(f"    {hop}")
        if r.get("honeypot_activity"):
            add_console(f"  {RED}Honeypot hits: {len(r['honeypot_activity'])}{RESET}")
    else:
        add_console(f"{DIM}No recon report for {ip}. Run: recon {ip}{RESET}")

def _iptables_rule(action: str, ip: str) -> None:
    """action ∈ {'-A', '-D'} — add or delete DROP for src/dst."""
    if not HAS_RAW_NET:
        add_console(f"{YELLOW}iptables unavailable (Termux or non-root){RESET}")
        return
    for chain, flag in (("INPUT", "-s"), ("OUTPUT", "-d")):
        subprocess.run(["iptables", action, chain, flag, ip, "-j", "DROP"], capture_output=True)

def _validate_ip_or_error(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip); return True
    except ValueError:
        add_console(f"{RED}Invalid IP: {ip}{RESET}"); return False

def _disp_block(parts):
    ip = parts[1]
    if not _validate_ip_or_error(ip): return
    _iptables_rule("-A", ip)
    add_console(f"{RED}BLOCKED: {ip} (iptables DROP in+out){RESET}")
    with lock:
        alerts.append({"time": datetime.now().strftime("%H:%M:%S"), "msg": f"BLOCKED: {ip}"})

def _disp_unblock(parts):
    ip = parts[1]
    if not _validate_ip_or_error(ip): return
    _iptables_rule("-D", ip)
    add_console(f"{GREEN}UNBLOCKED: {ip}{RESET}")

def _disp_blocked(parts):
    result = subprocess.run(["iptables", "-L", "-n", "--line-numbers"], capture_output=True, text=True)
    for line in result.stdout.split("\n"):
        if "DROP" in line:
            add_console(f"  {RED}{line.strip()}{RESET}")

def _disp_mac(parts):
    if len(parts) < 2:
        add_console(f"{DIM}Usage: mac <address>  (e.g. mac f4:34:f0:83:b8:f9){RESET}"); return
    mac_query = parts[1].lower().replace("-", ":").replace(".", ":")
    found = False
    with lock:
        arp_copy = dict(arp_table)
    for ip, info in arp_copy.items():
        if mac_query in info.get("mac", "").lower():
            hostname = resolve_host(ip)
            add_console(f"  {CYAN}{info['mac']}{RESET}  {ip:<16} {hostname}  {DIM}{info['state']}{RESET}")
            found = True
    if not found:
        add_console(f"{DIM}MAC {mac_query} not found in ARP table.{RESET}")
        add_console(f"{DIM}Try: subnet  or  arp -a  to refresh.{RESET}")

def _disp_inspect(parts):
    idx = int(parts[1]) - 1 if len(parts) >= 2 and parts[1].isdigit() else -1
    with lock:
        events = list(honeypot_events)
    if idx < 0 or idx >= len(events):
        add_console(f"{YELLOW}Last 10 honeypot events:{RESET}")
        for i, e in enumerate(events[-10:]):
            real_idx = len(events) - 10 + i
            add_console(f"  {DIM}{real_idx+1}.{RESET} [{e['time']}] {_honeypot_color(e['service'])}{e['service']:<14}{RESET} {e['ip']}  {e['summary'][:60]}")
        add_console(f"{DIM}Usage: inspect <number>{RESET}")
    else:
        e = events[idx]
        add_console(f"{BOLD}{RED}EVENT #{idx+1}{RESET}")
        add_console(f"  Time:    {e['time']}")
        add_console(f"  Service: {e['service']}")
        add_console(f"  IP:      {e['ip']}")
        add_console(f"  Summary: {e['summary']}")
        if e.get("data"):
            add_console(f"  {YELLOW}Raw Data:{RESET}")
            for line in _ansi_strip(str(e['data'])[:500]).split("\n")[:10]:
                add_console(f"    {DIM}{line}{RESET}")

def _disp_decode(parts):
    data = " ".join(parts[1:])
    results = decode_payload(data)
    add_console(f"{YELLOW}Decode results:{RESET}")
    for method, decoded in results.items():
        if decoded and decoded != data:
            add_console(f"  {GREEN}{method}:{RESET} {decoded[:200]}")

def _disp_sessions(parts):
    with lock:
        attacker_ips = {}
        for e in honeypot_events:
            ip = e["ip"]
            if ip not in attacker_ips:
                attacker_ips[ip] = {"count": 0, "services": set(), "first": e["time"], "last": e["time"]}
            attacker_ips[ip]["count"] += 1
            attacker_ips[ip]["services"].add(e["service"])
            attacker_ips[ip]["last"] = e["time"]
    if not attacker_ips:
        add_console(f"{DIM}No honeypot sessions yet.{RESET}"); return
    add_console(f"{BOLD}{YELLOW}HONEYPOT SESSIONS ({len(attacker_ips)} attackers):{RESET}")
    add_console(f"  {DIM}{'IP':<18}{'Events':<8}{'Services':<30}{'First':<10}{'Last'}{RESET}")
    for ip, info in sorted(attacker_ips.items(), key=lambda x: x[1]["count"], reverse=True)[:20]:
        svcs = ",".join(sorted(info["services"]))[:28]
        add_console(f"  {RED}{ip:<18}{RESET}{info['count']:<8}{svcs:<30}{info['first']:<10}{info['last']}")

def _disp_ips(parts):
    which = parts[1].lower() if len(parts) >= 2 else "auto"
    ip_list = _get_ip_list(which)
    label = which if which != "auto" else current_tab
    if not ip_list:
        add_console(f"{DIM}No IPs in '{label}' list.{RESET}"); return
    add_console(f"{BOLD}{CYAN}IPs — {label.upper()} ({len(ip_list)}):{RESET}")
    for i, ip in enumerate(ip_list[:40]):
        hostname = resolve_host(ip)
        tag = f" {YELLOW}[{ip_tags[ip]}]{RESET}" if ip in ip_tags else ""
        watch = f" {RED}★{RESET}" if ip in watchlist else ""
        add_console(f"  {DIM}@{i+1:<3}{RESET} {CYAN}{ip:<18}{RESET} {hostname[:30]}{tag}{watch}")
    if len(ip_list) > 40:
        add_console(f"  {DIM}... and {len(ip_list)-40} more{RESET}")

def _disp_top(parts):
    n = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 10
    with lock:
        ranked = sorted(hosts.items(), key=lambda x: x[1].get("bytes_in", 0) + x[1].get("bytes_out", 0), reverse=True)
    add_console(f"{BOLD}{CYAN}TOP {n} TALKERS:{RESET}")
    add_console(f"  {DIM}{'#':>3}  {'IP':<18}{'In':>10}{'Out':>10}{'Ports':>8}  Host{RESET}")
    for i, (ip, h) in enumerate(ranked[:n]):
        hostname = resolve_host(ip)
        add_console(f"  {DIM}@{i+1:<2}{RESET}  {CYAN}{ip:<18}{RESET}{GREEN}{format_bytes(h.get('bytes_in',0)):>10}{RESET}{RED}{format_bytes(h.get('bytes_out',0)):>10}{RESET}{len(h.get('ports',set())):>8}  {hostname[:25]}")

def _disp_new(parts):
    mins = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 5
    with lock:
        recent = [(ip, h) for ip, h in hosts.items() if h.get("first_seen")]
    recent.sort(key=lambda x: x[1]["first_seen"], reverse=True)
    recent = recent[:20]
    add_console(f"{BOLD}{YELLOW}NEW HOSTS (last {mins}min): {len(recent)}{RESET}")
    for i, (ip, h) in enumerate(recent):
        hostname = resolve_host(ip)
        add_console(f"  {DIM}@{i+1:<2}{RESET}  {YELLOW}{ip:<18}{RESET} {h['first_seen']}  {hostname[:30]}")

def _disp_sus(parts):
    with lock:
        suspicious = [(ip, h) for ip, h in hosts.items() if h.get("threat_score", 0) > 0]
    suspicious.sort(key=lambda x: x[1].get("threat_score", 0), reverse=True)
    if not suspicious:
        attacker_ips = set()
        with lock:
            for e in honeypot_events:
                attacker_ips.add(e["ip"])
        if attacker_ips:
            add_console(f"{BOLD}{RED}SUSPICIOUS — {len(attacker_ips)} honeypot attackers:{RESET}")
            for i, ip in enumerate(sorted(attacker_ips)):
                hostname = resolve_host(ip)
                add_console(f"  {DIM}@{i+1:<2}{RESET}  {RED}{ip:<18}{RESET} {hostname[:30]}")
        else:
            add_console(f"{DIM}No suspicious hosts detected yet.{RESET}")
    else:
        add_console(f"{BOLD}{RED}SUSPICIOUS HOSTS ({len(suspicious)}):{RESET}")
        for i, (ip, h) in enumerate(suspicious[:20]):
            hostname = resolve_host(ip)
            score = h.get("threat_score", 0)
            tags_str = ", ".join(h.get("tags", set()))
            add_console(f"  {DIM}@{i+1:<2}{RESET}  {RED}{ip:<18}{RESET} score={score:<4} {YELLOW}{tags_str[:30]}{RESET}  {hostname[:20]}")

def _disp_loud(parts):
    with lock:
        by_packets = sorted(hosts.items(), key=lambda x: len(x[1].get("ports", set())), reverse=True)
    add_console(f"{BOLD}{RED}LOUDEST HOSTS (most ports):{RESET}")
    for i, (ip, h) in enumerate(by_packets[:15]):
        hostname = resolve_host(ip)
        ports = sorted(h.get("ports", set()))[:8]
        add_console(f"  {DIM}@{i+1:<2}{RESET}  {RED}{ip:<18}{RESET} {len(h.get('ports',set()))} ports: {', '.join(str(p) for p in ports)}  {hostname[:20]}")

def _disp_quiet(parts):
    with lock:
        by_bytes = sorted(hosts.items(), key=lambda x: x[1].get("bytes_in", 0) + x[1].get("bytes_out", 0))
    add_console(f"{BOLD}{DIM}QUIETEST HOSTS:{RESET}")
    for i, (ip, h) in enumerate(by_bytes[:15]):
        hostname = resolve_host(ip)
        total = h.get("bytes_in", 0) + h.get("bytes_out", 0)
        add_console(f"  {DIM}@{i+1:<2}  {ip:<18} {format_bytes(total):>10}  {hostname[:30]}{RESET}")

def _disp_services(parts):
    add_console(f"{BOLD}{CYAN}DETECTED SERVICES:{RESET}")
    svc_map = {}
    with lock:
        for ip, h in hosts.items():
            for port in h.get("ports", set()):
                svc_map.setdefault(port, []).append(ip)
    for port in sorted(svc_map.keys()):
        ips = svc_map[port]
        add_console(f"  {GREEN}{port:>6}{RESET}  {len(ips)} hosts: {', '.join(ips[:5])}{' ...' if len(ips) > 5 else ''}")

def _disp_tracking(parts):
    active = {ip for ip, v in tracking_active.items() if v}
    if active:
        add_console(f"{CYAN}Active tracks:{RESET}")
        for ip in sorted(active):
            count = len(tracked_ips.get(ip, []))
            add_console(f"  {ip} — {count} packets captured")
    else:
        add_console(f"{DIM}No active tracks. Use: track <ip>{RESET}")

def _disp_whowatch(parts):
    add_console(f"{BOLD}{CYAN}WHO'S WATCHING — IPs hitting honeypots RIGHT NOW:{RESET}")
    with lock:
        recent_attackers = {}
        for e in honeypot_events:
            recent_attackers.setdefault(e.get("ip", ""), []).append(e)
    for ip, evts in sorted(recent_attackers.items(), key=lambda x: len(x[1]), reverse=True)[:15]:
        hostname = resolve_host(ip)
        svcs = set(e["service"] for e in evts)
        last = evts[-1]["time"]
        add_console(f"  {RED}{ip:<18}{RESET} {len(evts)} events  last={last}  {', '.join(svcs)[:30]}  {hostname[:20]}")

def _disp_summary(parts):
    add_console(f"{BOLD}{CYAN}{'='*50}{RESET}")
    add_console(f"{BOLD}{CYAN}  NETWORK SUMMARY{RESET}")
    add_console(f"{BOLD}{CYAN}{'='*50}{RESET}")
    with lock:
        total_hosts = len(hosts)
        external = sum(1 for ip in hosts if not ipaddress.ip_address(ip).is_private)
        internal = total_hosts - external
        total_dns = len(dns_queries)
        total_hp = len(honeypot_events)
        attacker_count = len(set(e["ip"] for e in honeypot_events))
        proto_count = len(proto_stats)
        arp_count = len(arp_table)
        nmap_count = len(nmap_results)
    add_console(f"  {GREEN}Hosts:{RESET}      {total_hosts} ({internal} internal, {external} external)")
    add_console(f"  {GREEN}Protocols:{RESET}  {proto_count}")
    add_console(f"  {GREEN}DNS:{RESET}        {total_dns} queries")
    add_console(f"  {GREEN}ARP:{RESET}        {arp_count} devices")
    add_console(f"  {GREEN}Honeypot:{RESET}   {total_hp} events from {attacker_count} attackers")
    add_console(f"  {GREEN}Scans:{RESET}      {nmap_count} nmap results")
    add_console(f"  {GREEN}Watchlist:{RESET}  {len(watchlist)} IPs")
    add_console(f"  {GREEN}Tags:{RESET}       {len(ip_tags)}")
    add_console(f"  {GREEN}Packets:{RESET}    {total_packets:,}")
    add_console(f"  {GREEN}Bandwidth:{RESET}  {format_bytes(total_bytes)}")
    add_console(f"  {GREEN}Uptime:{RESET}     {int(time.time()-start_time)}s")
    active_tracks = sum(1 for v in tracking_active.values() if v)
    if active_tracks:
        add_console(f"  {GREEN}Tracking:{RESET}   {active_tracks} active")
    add_console(f"{BOLD}{CYAN}{'='*50}{RESET}")

def _disp_timeline(parts):
    target = parts[1]
    add_console(f"{BOLD}{CYAN}TIMELINE — {target}:{RESET}")
    events = []
    with lock:
        for e in honeypot_events:
            if e["ip"] == target:
                events.append(("honeypot", e["time"], e["service"], e["summary"][:60]))
        if target in hosts:
            h = hosts[target]
            if h.get("first_seen"):
                events.append(("seen", h["first_seen"], "first_seen", f"ports: {sorted(h.get('ports', set()))[:5]}"))
    events.sort(key=lambda x: x[1])
    if not events:
        add_console(f"  {DIM}No events for {target}{RESET}"); return
    for src, ts, svc, detail in events[-25:]:
        color = RED if src == "honeypot" else GREEN
        add_console(f"  {DIM}{ts}{RESET}  {color}{svc:<14}{RESET} {detail}")
    if target in ip_notes:
        add_console(f"  {YELLOW}Notes:{RESET}")
        for n in ip_notes[target]:
            add_console(f"    {DIM}{n}{RESET}")

def _disp_report(parts):
    target = parts[1]
    add_console(f"{BOLD}{RED}GENERATING REPORT: {target}...{RESET}")
    def _run():
        lines = [f"{'='*50}", f"NETWATCH REPORT: {target}", f"Generated: {datetime.now().isoformat()}", f"{'='*50}"]
        with lock:
            h = hosts.get(target, {})
        if h:
            lines += ["\nHOST DATA:", f"  Hostname: {resolve_host(target)}",
                f"  First seen: {h.get('first_seen', '?')}", f"  Last seen: {h.get('last_seen', '?')}",
                f"  Bytes in: {format_bytes(h.get('bytes_in', 0))}", f"  Bytes out: {format_bytes(h.get('bytes_out', 0))}",
                f"  Ports: {sorted(h.get('ports', set()))}", f"  Protocols: {sorted(h.get('protocols', set()))}"]
        if target in recon_reports:
            r = recon_reports[target]
            lines += ["\nRECON:", f"  OS: {r.get('os_guess', '?')}", f"  Open ports: {len(r.get('ports', []))}"]
            lines += [f"    {p}" for p in r.get("ports", [])[:20]]
        with lock:
            hp = [e for e in honeypot_events if e["ip"] == target]
        if hp:
            lines.append(f"\nHONEYPOT EVENTS ({len(hp)}):")
            lines += [f"  [{e['time']}] {e['service']}: {e['summary'][:70]}" for e in hp[-15:]]
        if target in ip_tags:
            lines.append(f"\nTAG: {ip_tags[target]}")
        if target in ip_notes:
            lines.append("\nNOTES:")
            lines += [f"  {n}" for n in ip_notes[target]]
        report_file = os.path.join(LOG_DIR, f"report_{target.replace('.','_')}.txt")
        with open(report_file, "w") as f:
            f.write("\n".join(lines))
        add_console(f"{GREEN}Report saved: {report_file}{RESET}")
        add_console(f"{DIM}({len(lines)} lines){RESET}")
    threading.Thread(target=_run, daemon=True).start()

def _disp_exportips(parts):
    which = parts[1].lower() if len(parts) >= 2 else "all"
    if which == "all":
        with lock:
            ip_list = sorted(hosts.keys())
    else:
        ip_list = _get_ip_list(which)
    if not ip_list:
        add_console(f"{DIM}No IPs to export.{RESET}"); return
    export_file = os.path.join(LOG_DIR, f"ips_{which}_{int(time.time())}.txt")
    with open(export_file, "w") as f:
        for ip in ip_list:
            hostname = resolve_host(ip)
            tag = ip_tags.get(ip, "")
            f.write(f"{ip}\t{hostname}\t{tag}\n")
    add_console(f"{GREEN}Exported {len(ip_list)} IPs -> {export_file}{RESET}")

def _disp_ports(parts):
    target_port = parts[1]
    if not target_port.isdigit():
        add_console(f"{RED}Usage: ports <port_number>{RESET}"); return
    port = int(target_port)
    add_console(f"{BOLD}{CYAN}HOSTS WITH PORT {port}:{RESET}")
    found = 0
    with lock:
        for ip, h in hosts.items():
            if port in h.get("ports", set()):
                hostname = resolve_host(ip)
                add_console(f"  {CYAN}{ip:<18}{RESET} {hostname[:30]}")
                found += 1
    with lock:
        for r in nmap_results:
            line = r.get("line", "")
            if f"{port}/" in line and "open" in line:
                add_console(f"  {GREEN}[nmap]{RESET} {line.strip()}")
                found += 1
    if found == 0:
        add_console(f"  {DIM}No hosts found with port {port}{RESET}")

def _disp_find(parts):
    if len(parts) < 2:
        add_console(f"{DIM}Usage: find <pattern>  — search across all data{RESET}"); return
    pattern = " ".join(parts[1:]).lower()
    results_found = 0
    add_console(f"{CYAN}Searching for '{pattern}'...{RESET}")
    with lock:
        for ip, h in hosts.items():
            hostname = resolve_host(ip)
            if pattern in ip.lower() or pattern in hostname.lower():
                add_console(f"  {GREEN}[HOST]{RESET} {ip} — {hostname}")
                results_found += 1
    with lock:
        for e in honeypot_events:
            if pattern in str(e.get("summary", "")).lower() or pattern in e.get("ip", ""):
                add_console(f"  {RED}[HONEY]{RESET} {e['ip']} — {e['service']} — {e['summary'][:50]}")
                results_found += 1
                if results_found > 30:
                    break
    with lock:
        for entry in dns_queries:
            if pattern in entry.get("domain", "").lower():
                add_console(f"  {CYAN}[DNS]{RESET} {entry['domain']} — {entry.get('ip', '')}")
                results_found += 1
    for ip, label in ip_tags.items():
        if pattern in label.lower() or pattern in ip:
            add_console(f"  {YELLOW}[TAG]{RESET} {ip} — {label}")
            results_found += 1
    add_console(f"{DIM}Found {results_found} matches for '{pattern}'.{RESET}")

def _disp_scan(parts):
    target = parts[1]
    if not re.match(r'^[\d./a-fA-F:]+$', target):
        add_console(f"{RED}Invalid target: {target}{RESET}"); return
    SCAN_PRESETS = {"quick": "-sV -T4 --top-ports 100", "syn": "-sS -T4",
        "udp": "-sU -T4 --top-ports 50", "ping": "-sn -T4", "full": "-sV -T4 -p-"}
    preset = parts[2].lower() if len(parts) > 2 else "quick"
    flags = SCAN_PRESETS.get(preset, SCAN_PRESETS["quick"])
    add_console(f"{YELLOW}Scanning {target} [{preset}] ({flags})...{RESET}")
    threading.Thread(target=_cmd_scan, args=(target, flags), daemon=True).start()

def _disp_ssl(parts):
    target = parts[1]
    if not re.match(r'^[a-zA-Z0-9.\-:]+$', target):
        add_console(f"{RED}Invalid target: {target}{RESET}"); return
    port = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 443
    if not (1 <= port <= 65535):
        add_console(f"{RED}Invalid port{RESET}"); return
    add_console(f"{CYAN}SSL/TLS inspection: {target}:{port}...{RESET}")
    threading.Thread(target=_cmd_ssl, args=(f"{target}:{port}",), daemon=True).start()

def _disp_ping(parts):
    target = parts[1]
    if not re.match(r'^[a-zA-Z0-9.\-:]+$', target):
        add_console(f"{RED}Invalid target: {target}{RESET}"); return
    count = min(int(parts[2]), 20) if len(parts) > 2 and parts[2].isdigit() else 5
    add_console(f"{CYAN}Ping analysis: {target} ({count} packets)...{RESET}")
    threading.Thread(target=_cmd_ping, args=(target, count), daemon=True).start()

def _disp_track(parts):
    ip = parts[1]
    if not re.match(r'^[\d./a-fA-F:]+$', ip):
        add_console(f"{RED}Invalid target{RESET}"); return
    dur = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0
    dur = min(dur, 3600)
    if tracking_active.get(ip):
        add_console(f"{YELLOW}Already tracking {ip}. Use: untrack {ip}{RESET}")
    else:
        add_console(f"{CYAN}TRACKING {ip} — live packet stream {'(' + str(dur) + 's)' if dur else '(until untrack)'}...{RESET}")
        threading.Thread(target=track_ip, args=(ip, dur), daemon=True).start()

def _disp_untrack(parts):
    ip = parts[1]
    if tracking_active.get(ip):
        tracking_active[ip] = False
        add_console(f"{GREEN}Stopped tracking {ip}{RESET}")
    else:
        add_console(f"{DIM}Not currently tracking {ip}{RESET}")

def _disp_sniff(parts):
    if not re.match(r'^[\d./a-fA-F:]+$', parts[1]):
        add_console(f"{RED}Invalid target{RESET}"); return
    dur = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 15
    dur = min(dur, 300)
    add_console(f"{YELLOW}Sniffing payload from {parts[1]} ({dur}s)...{RESET}")
    threading.Thread(target=track_payload, args=(parts[1], dur), daemon=True).start()

def _disp_tracked(parts):
    if not re.match(r'^[\d./a-fA-F:]+$', parts[1]):
        add_console(f"{RED}Invalid target{RESET}"); return
    track_summary(parts[1])

def _disp_subnet(parts):
    cidr = parts[1] if len(parts) >= 2 else "10.0.1.0/24"
    add_console(f"{CYAN}Ping sweeping {cidr}...{RESET}")
    threading.Thread(target=_cmd_subnet_sweep, args=(cidr,), daemon=True).start()

def _disp_pcap(parts):
    if len(parts) >= 2 and parts[1] == "stop":
        stop_tcpdump()
        add_console(f"{GREEN}PCAP capture stopped.{RESET}")
    else:
        start_tcpdump()
        add_console(f"{GREEN}PCAP capture started: {tcpdump_file}{RESET}")

def _disp_blockall(parts):
    which = parts[1].lower() if len(parts) >= 2 else "attackers"
    if which != "attackers":
        add_console(f"{RED}Safety: blockall only works on 'attackers' list.{RESET}"); return
    ip_list = _get_ip_list("attackers")
    if not ip_list:
        add_console(f"{DIM}No attackers to block.{RESET}"); return
    add_console(f"{BOLD}{RED}BLOCKING {len(ip_list)} ATTACKER IPs...{RESET}")
    blocked = 0
    for ip in ip_list:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        _iptables_rule("-A", ip)
        add_console(f"  {RED}x {ip}{RESET}")
        blocked += 1
    add_console(f"{RED}Blocked {blocked} IPs.{RESET}")
    with lock:
        alerts.append({"time": datetime.now().strftime("%H:%M:%S"), "msg": f"BLOCKALL: {blocked} attacker IPs blocked"})

def _disp_tag(parts):
    if len(parts) < 2:
        add_console(f"{DIM}Usage: tag <ip/@N> <label>  |  tag list  |  tag rm <ip>{RESET}"); return
    if parts[1] == "list":
        if not ip_tags:
            add_console(f"{DIM}No tags set.{RESET}"); return
        add_console(f"{BOLD}{YELLOW}IP TAGS:{RESET}")
        for ip, label in sorted(ip_tags.items()):
            add_console(f"  {CYAN}{ip:<18}{RESET} {YELLOW}{label}{RESET}")
    elif parts[1] == "rm" and len(parts) >= 3:
        t = parts[2]
        if t in ip_tags:
            del ip_tags[t]
            add_console(f"{GREEN}Tag removed from {t}{RESET}")
        else:
            add_console(f"{DIM}No tag on {t}{RESET}")
    else:
        if len(parts) < 3:
            add_console(f"{DIM}Usage: tag <ip/@N> <label>{RESET}"); return
        ip_tags[parts[1]] = " ".join(parts[2:])
        add_console(f"{GREEN}Tagged {parts[1]} -> {YELLOW}{' '.join(parts[2:])}{RESET}")

def _disp_note(parts):
    if len(parts) < 2:
        add_console(f"{DIM}Usage: note <ip/@N> <text>  |  note show <ip>{RESET}"); return
    if parts[1] == "show" and len(parts) >= 3:
        notes = ip_notes.get(parts[2], [])
        if not notes:
            add_console(f"{DIM}No notes on {parts[2]}{RESET}"); return
        add_console(f"{BOLD}{YELLOW}NOTES — {parts[2]}:{RESET}")
        for i, n in enumerate(notes):
            add_console(f"  {DIM}{i+1}.{RESET} {n}")
    else:
        if len(parts) < 3:
            add_console(f"{DIM}Usage: note <ip/@N> <text>{RESET}"); return
        ip_notes.setdefault(parts[1], []).append(f"[{datetime.now().strftime('%H:%M')}] {' '.join(parts[2:])}")
        add_console(f"{GREEN}Note added to {parts[1]}{RESET}")

def _disp_watch(parts):
    if len(parts) < 2:
        add_console(f"{DIM}Usage: watch <ip/@N>  |  watch rm <ip>  |  watch list{RESET}"); return
    sub = parts[1]
    if sub == "list":
        if not watchlist:
            add_console(f"{DIM}Watchlist empty.{RESET}"); return
        add_console(f"{BOLD}{RED}* WATCHLIST ({len(watchlist)}):{RESET}")
        for i, ip in enumerate(sorted(watchlist)):
            hostname = resolve_host(ip)
            tag = f" {YELLOW}[{ip_tags[ip]}]{RESET}" if ip in ip_tags else ""
            add_console(f"  {DIM}@{i+1:<2}{RESET}  {RED}{ip:<18}{RESET} {hostname[:30]}{tag}")
    elif sub == "rm" and len(parts) >= 3:
        watchlist.discard(parts[2])
        add_console(f"{GREEN}Removed {parts[2]} from watchlist{RESET}")
    else:
        watchlist.add(sub)
        add_console(f"{RED}* Added {sub} to watchlist{RESET}")

def _disp_mesh(parts):
    global mesh_alert_fwd, current_tab
    if len(parts) < 2:
        current_tab = "mesh"
        add_console(f"{CYAN}Switched to [MESH] view{RESET}")
        return
    sub = parts[1].lower()
    if sub == "send" and len(parts) >= 3:
        text = " ".join(parts[2:])
        if len(text) > 200:
            add_console(f"{RED}Message too long (200 char max for LoRa){RESET}"); return
        if mesh_send(text):
            add_console(f"{GREEN}Sent: {text}{RESET}")
        else:
            add_console(f"{RED}Mesh not connected{RESET}")
    elif sub == "status":
        if mesh_interface:
            add_console(f"  {GREEN}Mesh: connected{RESET}")
            add_console(f"  Nodes: {len(mesh_nodes)}  Messages: {len(mesh_messages)}")
            add_console(f"  Alert forwarding: {'ON' if mesh_alert_fwd else 'OFF'}")
        else:
            add_console(f"  {YELLOW}Mesh: not connected{RESET}")
            if not _HAS_MESH:
                add_console(f"  {DIM}Install: pip3 install meshtastic{RESET}")
    elif sub == "nodes":
        if not mesh_nodes:
            add_console(f"  {DIM}No mesh nodes seen yet{RESET}")
        else:
            for nid, info in mesh_nodes.items():
                add_console(f"  {CYAN}{info.get('name', nid):<20}{RESET} SNR:{info.get('snr', '?'):>6}  Last:{info.get('last_heard', '?')}")
    elif sub == "alert":
        if len(parts) >= 3 and parts[2].lower() in ("on", "off"):
            mesh_alert_fwd = parts[2].lower() == "on"
            add_console(f"  Alert forwarding: {'ON' if mesh_alert_fwd else 'OFF'}")
        else:
            add_console(f"  {DIM}Usage: mesh alert on/off{RESET}")
    else:
        add_console(f"  {DIM}mesh send <text> | mesh status | mesh nodes | mesh alert on/off{RESET}")

def _disp_ifinfo(parts):
    try:
        hostname = socket.gethostname()
        add_console(f"  {CYAN}Hostname  : {GREEN}{hostname}{RESET}")
        try:
            primary_ip = socket.gethostbyname(hostname)
            add_console(f"  {CYAN}Primary IP: {GREEN}{primary_ip}{RESET}")
        except Exception:
            add_console(f"  {CYAN}Primary IP: {DIM}unavailable{RESET}")
        add_console(f"  {CYAN}Interface : {GREEN}{IFACE}{RESET}")
        r = subprocess.run(["ip", "addr", "show", IFACE], capture_output=True, text=True, timeout=5)
        for line in r.stdout.strip().split("\n"):
            line = line.strip()
            if "inet " in line or "link/ether" in line:
                add_console(f"  {DIM}{line}{RESET}")
        add_console(f"  {CYAN}Routes:{RESET}")
        r2 = subprocess.run(["ip", "route"], capture_output=True, text=True, timeout=5)
        for line in r2.stdout.strip().split("\n")[:10]:
            add_console(f"  {DIM}{line.strip()}{RESET}")
    except Exception as e:
        add_console(f"  {RED}ifinfo error: {e}{RESET}")

def _disp_proxy(parts):
    global proxy_rotation, current_tab
    if len(parts) == 1:
        current_tab = "proxy"
        add_console(f"{CYAN}Switched to [PROXY] view{RESET}")
        return
    sub = parts[1].lower()
    if sub == "add" and len(parts) >= 4:
        ptype = parts[2].lower()
        if ptype not in ("socks4", "socks5", "http", "https"):
            add_console(f"{RED}Type must be: socks4, socks5, http, https{RESET}"); return
        hostport = parts[3]
        if ":" not in hostport:
            add_console(f"{RED}Format: proxy add <type> <host:port>{RESET}"); return
        h, p = hostport.rsplit(":", 1)
        if not p.isdigit() or not (1 <= int(p) <= 65535):
            add_console(f"{RED}Invalid port (1-65535){RESET}"); return
        proxy_pool.append({"type": ptype, "host": h, "port": p, "label": f"{ptype}://{h}:{p}"})
        add_console(f"{GREEN}Added proxy #{len(proxy_pool)}: {ptype}://{h}:{p}{RESET}")
    elif sub == "rm" and len(parts) >= 3 and parts[2].isdigit():
        idx = int(parts[2]) - 1
        if 0 <= idx < len(proxy_pool):
            removed = proxy_pool.pop(idx)
            add_console(f"{YELLOW}Removed: {removed['label']}{RESET}")
        else:
            add_console(f"{RED}Invalid index{RESET}")
    elif sub == "list":
        if not proxy_pool:
            add_console(f"{DIM}No proxies configured. Use: proxy add <type> <host:port>{RESET}")
        else:
            add_console(f"{MAGENTA}Configured Proxies ({len(proxy_pool)}):{RESET}")
            for i, p in enumerate(proxy_pool):
                add_console(f"  {i+1}. {p['label']}")
            add_console(f"  Rotation: {GREEN}ON{RESET}" if proxy_rotation else f"  Rotation: {RED}OFF{RESET}")
    elif sub == "rotate":
        proxy_rotation = not proxy_rotation
        add_console(f"{GREEN}Proxy rotation: {'ON' if proxy_rotation else 'OFF'}{RESET}")
    elif sub == "test":
        idx = int(parts[2]) - 1 if len(parts) >= 3 and parts[2].isdigit() else -1
        entries = [proxy_pool[idx]] if 0 <= idx < len(proxy_pool) else proxy_pool
        if not entries:
            add_console(f"{DIM}No proxies to test. Use: proxy add ...{RESET}"); return
        def _test_all():
            for p in entries:
                ok, ip, ms = _test_proxy(p)
                if ok:
                    add_console(f"  {GREEN}o {p['label']}{RESET} -> {ip} ({ms}ms)")
                else:
                    add_console(f"  {RED}o {p['label']}{RESET} -> FAILED")
        threading.Thread(target=_test_all, daemon=True).start()
    else:
        threading.Thread(target=_cmd_proxy, args=(sub,), daemon=True).start()

def _batch_scan_worker(i, n, ip):
    add_console(f"  {DIM}[{i+1}/{n}]{RESET} Scanning {ip}...")
    try:
        result = subprocess.run(["nmap", "-sV", "-T4", "--top-ports", "100", ip, "-oN", "-"],
            capture_output=True, text=True, timeout=60)
        open_ports = [l.strip() for l in result.stdout.split("\n") if "open" in l]
        for p in open_ports[:5]:
            add_console(f"    {GREEN}{p}{RESET}")
        if not open_ports:
            add_console(f"    {DIM}no open ports{RESET}")
    except Exception as e:
        add_console(f"    {RED}error: {e}{RESET}")

def _batch_geo_worker(_i, _n, ip):
    data = osint_geolocate(ip)
    if "error" not in data and data.get("status") != "fail":
        add_console(f"  {CYAN}{ip:<18}{RESET} {data.get('city','?')}, {data.get('country','?'):<20} {DIM}{data.get('isp','?')[:30]}{RESET}")
    else:
        add_console(f"  {ip:<18} {RED}lookup failed{RESET}")

def _batch_whois_worker(_i, _n, ip):
    data = osint_whois(ip)
    if "error" not in data:
        add_console(f"  {CYAN}{ip:<18}{RESET} {data.get('org', data.get('name', '?'))[:50]}")
    else:
        add_console(f"  {ip:<18} {RED}{data.get('error','failed')[:40]}{RESET}")

def _batch_recon_worker(i, n, ip):
    add_console(f"  {DIM}[{i+1}/{n}]{RESET} {RED}Recon: {ip}...{RESET}")
    try:
        report = recon_target(ip)
        add_console(f"    {GREEN}Hostname:{RESET} {report.get('hostname','?')}")
        add_console(f"    {GREEN}OS:{RESET} {report.get('os_guess','?')}")
        add_console(f"    {GREEN}Ports:{RESET} {len(report.get('ports',[]))}")
    except Exception as e:
        add_console(f"    {RED}error: {e}{RESET}")

def _cmd_scan(target, flags):
    try:
        validated = _validate_nmap_flags(flags)
        result = subprocess.run(
            ["nmap"] + validated + [target, "-oN", "-"],
            capture_output=True, text=True, timeout=120
        )
        for line in result.stdout.split("\n"):
            line = line.strip()
            if line and any(k in line for k in ("open", "filtered", "Host is", "MAC", "OS", "Service", "Running")):
                add_console(f"  {GREEN}{line}{RESET}")
        add_console(f"{GREEN}Scan complete.{RESET}")
    except Exception as e:
        add_console(f"{RED}Scan error: {e}{RESET}")

def _cmd_deep(target):
    try:
        result = subprocess.run(
            ["nmap", "-sV", "-sC", "-O", "-p-", "-T4", "--script", "vuln",
             target, "-oN", "-"],
            capture_output=True, text=True, timeout=600
        )
        scan_file = os.path.join(LOG_DIR, f"deep_{target.replace('.','_')}.txt")
        with open(scan_file, "w") as f:
            f.write(result.stdout)
        for line in result.stdout.split("\n"):
            line = line.strip()
            if line and any(k in line for k in ("open", "filtered", "VULNERABLE", "Host is", "OS", "Service", "Running", "CVE")):
                add_console(f"  {RED if 'VULNERABLE' in line or 'CVE' in line else GREEN}{line}{RESET}")
        add_console(f"{GREEN}Deep scan saved: {scan_file}{RESET}")
    except Exception as e:
        add_console(f"{RED}Deep scan error: {e}{RESET}")

def _cmd_recon(target):
    report = recon_target(target)
    add_console(f"{BOLD}{CYAN}RECON COMPLETE: {target}{RESET}")
    add_console(f"  Hostname: {report['hostname']}")
    add_console(f"  OS: {report.get('os_guess', '?')}")
    add_console(f"  Open ports: {len(report['ports'])}")
    for p in report["ports"][:10]:
        add_console(f"    {GREEN}{p}{RESET}")
    if report.get("honeypot_activity"):
        add_console(f"  {RED}Honeypot hits: {len(report['honeypot_activity'])}{RESET}")
    add_console(f"  Report: {report.get('nmap_file', 'N/A')}")

def _cmd_trace(target):
    result = traceroute(target)
    for line in result.split("\n"):
        if line.strip():
            add_console(f"  {line.strip()}")


def _cmd_geo(target):
    data = osint_geolocate(target)
    if "error" in data:
        add_console(f"  {RED}{data['error']}{RESET}")
        return
    if data.get("status") == "fail":
        add_console(f"  {RED}Failed: {data.get('message', 'unknown')}{RESET}")
        return
    fields = [
        ("IP", data.get("query")), ("Country", f"{data.get('country')} ({data.get('countryCode')})"),
        ("Region", data.get("regionName")), ("City", data.get("city")),
        ("ZIP", data.get("zip")), ("Lat/Lon", f"{data.get('lat')}, {data.get('lon')}"),
        ("ISP", data.get("isp")), ("Org", data.get("org")), ("AS", data.get("as")),
    ]
    for name, val in fields:
        if val:
            add_console(f"  {WHITE}{name}:{RESET} {val}")
    _osint_record("GEO", target,
        f"{data.get('city','?')}, {data.get('country','?')} ({data.get('isp','?')})")


def _cmd_dnsinfo(target):
    data = osint_dns_enum(target)
    if _osint_err(data): return
    if not data:
        add_console(f"  {YELLOW}No DNS records found.{RESET}"); return
    for rtype, records in data.items():
        for rec in records:
            add_console(f"  {YELLOW}{rtype:<6}{RESET} {rec}")
    total = sum(len(v) for v in data.values())
    _osint_record("DNS", target, f"{total} records ({', '.join(data.keys())})")


def _cmd_portscan(target):
    results = osint_port_scan(target)
    if not results:
        add_console(f"  {YELLOW}No open ports found.{RESET}"); return
    add_console(f"  {GREEN}{len(results)} open ports:{RESET}")
    for port, svc, banner in results:
        b = banner.split("\n")[0][:60] if banner else ""
        add_console(f"  {GREEN}{port:<7}{RESET}{svc:<15}{DIM}{b}{RESET}")
    _osint_record("SCAN", target, f"{len(results)} open ports")


def _cmd_subnet_sweep(cidr):
    alive = osint_subnet_ping(cidr)
    if not alive:
        add_console(f"  {YELLOW}No hosts responded.{RESET}"); return
    if alive[0][0] == "error":
        add_console(f"  {RED}{alive[0][2]}{RESET}"); return
    add_console(f"  {GREEN}{len(alive)} hosts alive:{RESET}")
    for ip, ms, hostname in alive:
        add_console(f"  {GREEN}{ip:<18}{RESET}{ms + 'ms':<10}{DIM}{hostname}{RESET}")
    _osint_record("SWEEP", cidr, f"{len(alive)} hosts alive")


PROXYCHAIN_SCRIPT = "/home/mrrobot/scripts/proxychain.sh"
_TOR_SOCKS_PORTS = [9050, 9052, 9054]

# ─── Multi-Proxy System ──────────────────────────────────
proxy_pool = []
proxy_rotate_idx = 0
proxy_rotation = False

def _proxy_session(proxy_entry=None):
    if not req_lib:
        return None
    s = req_lib.Session()
    s.headers["User-Agent"] = "Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36"
    if proxy_entry:
        ptype = proxy_entry["type"]
        host = proxy_entry["host"]
        port = proxy_entry["port"]
        url = f"{ptype}://{host}:{port}"
        s.proxies = {"http": url, "https": url}
        s.timeout = 15
    elif os.environ.get("HTTP_PROXY") or os.environ.get("HTTPS_PROXY"):
        s.proxies = {
            "http": os.environ.get("HTTP_PROXY", ""),
            "https": os.environ.get("HTTPS_PROXY", ""),
        }
    return s

def _get_proxy():
    global proxy_rotate_idx
    with lock:
        if not proxy_pool:
            return None
        if proxy_rotation:
            p = proxy_pool[proxy_rotate_idx % len(proxy_pool)]
            proxy_rotate_idx += 1
            return p
        return proxy_pool[0]

def _proxied_get(url, timeout=10):
    if not req_lib:
        return None
    proxy = _get_proxy()
    sess = _proxy_session(proxy)
    if not sess:
        return None
    try:
        return sess.get(url, timeout=timeout)
    except Exception:
        return None

def _test_proxy(entry):
    if not req_lib:
        return False, "", 0
    sess = _proxy_session(entry)
    if not sess:
        return False, "", 0
    t0 = time.time()
    try:
        r = sess.get("http://httpbin.org/ip", timeout=10)
        ms = int((time.time() - t0) * 1000)
        ip = r.json().get("origin", "?")
        return True, ip, ms
    except Exception:
        return False, "", 0

def _cmd_proxy(sub):
    if sub == "start":
        add_console(f"{MAGENTA}Starting Tor circuits...{RESET}")
        try:
            r = subprocess.run(["sudo", "bash", PROXYCHAIN_SCRIPT, "start"],
                               capture_output=True, text=True, timeout=30)
            for line in r.stdout.split("\n"):
                line = line.strip()
                if line and not line.startswith("╔") and not line.startswith("╚") and not line.startswith("║"):
                    clean = re.sub(r'\033\[[0-9;]*m', '', line)
                    if clean.strip():
                        add_console(f"  {GREEN}{clean}{RESET}")
            if r.returncode != 0 and r.stderr.strip():
                add_console(f"  {RED}{r.stderr.strip()[:200]}{RESET}")
        except Exception as e:
            add_console(f"  {RED}Error: {e}{RESET}")

    elif sub == "stop":
        add_console(f"{MAGENTA}Stopping extra Tor circuits...{RESET}")
        try:
            r = subprocess.run(["sudo", "bash", PROXYCHAIN_SCRIPT, "stop"],
                               capture_output=True, text=True, timeout=10)
            for line in r.stdout.split("\n"):
                clean = re.sub(r'\033\[[0-9;]*m', '', line).strip()
                if clean:
                    add_console(f"  {GREEN}{clean}{RESET}")
        except Exception as e:
            add_console(f"  {RED}Error: {e}{RESET}")

    elif sub == "check":
        add_console(f"{CYAN}Testing Tor circuits...{RESET}")
        for port in _TOR_SOCKS_PORTS:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                result = s.connect_ex(("127.0.0.1", port))
                s.close()
                if result == 0:
                    add_console(f"  {GREEN}● Circuit :{port} LIVE{RESET}")
                else:
                    add_console(f"  {RED}● Circuit :{port} DOWN{RESET}")
            except Exception:
                add_console(f"  {RED}● Circuit :{port} DOWN{RESET}")

    else:  # status (default)
        add_console(f"{MAGENTA}Proxy Status:{RESET}")
        proxy_on = os.environ.get("PROXYCHAINS_CONF_FILE") or "proxychains" in os.environ.get("LD_PRELOAD", "")
        add_console(f"  Session: {GREEN}PROXIED{RESET}" if proxy_on else f"  Session: {YELLOW}DIRECT{RESET}")
        alive = 0
        for port in _TOR_SOCKS_PORTS:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                up = s.connect_ex(("127.0.0.1", port)) == 0
                s.close()
                status = f"{GREEN}● UP{RESET}" if up else f"{RED}● DOWN{RESET}"
                add_console(f"  Tor :{port} {status}")
                if up:
                    alive += 1
            except Exception:
                add_console(f"  Tor :{port} {RED}● DOWN{RESET}")
        add_console(f"  {alive}/3 circuits available")
        if not proxy_on:
            add_console(f"  {DIM}To proxy: proxy start, then relaunch with PROXY=1{RESET}")


# -- CONSOLE UI - Interactive Terminal

def _tab_bar(cols, active=None):
    active = active or current_tab
    parts = []
    for i, t in enumerate(TABS):
        num = str(i + 1) if i < 9 else "0"
        if t == active:
            parts.append(f"{BOLD}{BG_RED}{WHITE} {num}:{t.upper()} {RESET}")
        else:
            parts.append(f"{DIM}{num}:{t.upper()}{RESET}")
    return "  " + "  ".join(parts)


def _host_line(ip, data):
    hostname = data.get("hostname") or dns_cache.get(ip, "")
    if len(hostname) > 23:
        hostname = hostname[:21] + ".."
    port_count = len(data["ports"])
    tags = data.get("tags", set())
    tag_str = " ".join(f"[{t}]" for t in sorted(tags)) if tags else ""
    if ip in LOCAL_IPS:
        color = GREEN
    elif data.get("threat_score", 0) >= 30:
        color = RED
    elif data.get("threat_score", 0) >= 10:
        color = YELLOW
    elif data["bytes_in"] + data["bytes_out"] > 1_000_000:
        color = CYAN
    else:
        color = WHITE
    return f"  {color}{ip:<18}{hostname:<24}{format_bytes(data['bytes_in']):<9}{format_bytes(data['bytes_out']):<9}{data['packets']:<7}{port_count:<6}{DIM}{tag_str}{RESET}"


def _honeypot_color(svc):
    if svc in ("credential", "malware_attempt", "ftp_upload", "ftp_upload_complete"):
        return RED
    elif svc in ("telnet", "telnet_cmd"):
        return YELLOW
    elif svc in ("ftp_credential", "ftp_connect", "ftp_download", "ftp_keystroke"):
        return MAGENTA
    elif svc in ("rtsp", "rtsp_auth"):
        return BLUE
    return DIM


def _section_simple(title, color, data_fn, format_fn, empty_msg, limit=5, col_header=None):
    lines = []
    with lock:
        items = data_fn()
    count = len(items) if hasattr(items, '__len__') else 0
    lines.append(f"{BOLD}{color}  {title}{RESET}  {DIM}({count}){RESET}")
    items = items[-limit:] if isinstance(items, list) else list(items)[:limit]
    if items:
        if col_header:
            lines.append(col_header)
        for item in items:
            lines.append(format_fn(item))
    else:
        lines.append(f"  {DIM}({empty_msg}){RESET}")
    return lines

def _section_hosts(limit=10):
    lines = []
    with lock:
        sorted_hosts = sorted(hosts.items(),
            key=lambda x: x[1]["bytes_in"] + x[1]["bytes_out"], reverse=True)[:limit]
    lines.append(f"{BOLD}{CYAN}  HOSTS{RESET}  {DIM}({len(hosts)} total, top by traffic){RESET}")
    lines.append(f"  {DIM}{'IP':<18}{'Hostname':<24}{'In':<9}{'Out':<9}{'Pkts':<7}{'Ports':<6}{'Tags'}{RESET}")
    lines.append(f"  {DIM}{'─'*74}{RESET}")
    for ip, data in sorted_hosts:
        lines.append(_host_line(ip, data))
    if not sorted_hosts:
        lines.append(f"  {DIM}(no hosts yet){RESET}")
    return lines

def _section_protocols(limit=8, expanded=False):
    lines = []
    with lock:
        top_protos = sorted(proto_stats.items(), key=lambda x: x[1], reverse=True)[:limit]
    lines.append(f"{BOLD}{BLUE}  PROTOCOLS{RESET}  {DIM}(tshark, {len(proto_stats)} types){RESET}")
    if top_protos:
        if expanded:
            lines.append(f"  {DIM}{'Protocol':<20}{'Count':<10}{'Bar'}{RESET}")
            lines.append(f"  {DIM}{'─'*55}{RESET}")
            max_count = top_protos[0][1] if top_protos else 1
            for proto, count in top_protos:
                bar_len = int((count / max_count) * 30) if max_count else 0
                lines.append(f"  {BLUE}{proto:<20}{RESET}{count:<10}{BLUE}{'█' * bar_len}{RESET}")
        else:
            proto_line = "  "
            for proto, count in top_protos:
                proto_line += f"{BLUE}{proto}{RESET}:{count}  "
            lines.append(proto_line)
    else:
        lines.append(f"  {DIM}(waiting for tshark...){RESET}")
    return lines

def _section_dns(limit=5):
    return _section_simple("DNS", MAGENTA,
        lambda: dns_queries,
        lambda e: f"  {DIM}{e['time']}{RESET}  {e['ip']:<16} {MAGENTA}{e['domain']}{RESET}" +
            next((f" {DIM}({sn}){RESET}" for d, (sn, _) in KNOWN_SERVICES.items() if d in e["domain"]), ""),
        "waiting...", limit)

def _section_honeypot(limit=6, show_http=False):
    def _data():
        if show_http:
            return list(honeypot_events[-limit:])
        return [e for e in honeypot_events if e["service"] not in ("http",)][-limit:]
    return _section_simple("HONEYPOT", YELLOW, _data,
        lambda ev: f"  {DIM}{ev['time']}{RESET} {_honeypot_color(ev['service'])}{ev['service']:<14}{RESET} {ev['ip']:<16} {ev['summary']}",
        "waiting for visitors...", limit)

def _section_nmap(limit=5):
    status = f"{YELLOW}SCANNING...{RESET}" if nmap_running else f"{DIM}idle{RESET}"
    return _section_simple(f"NMAP{RESET}  {status}", GREEN,
        lambda: list(nmap_results[-limit:]),
        lambda r: f"  {DIM}{r['time']}{RESET}  {r['line']}",
        "no scans yet", limit)

def _section_arp(limit=6):
    lines = []
    with lock:
        arp_copy = dict(arp_table)
    lines.append(f"{BOLD}{CYAN}  DEVICES (ARP){RESET}  {DIM}({len(arp_copy)} found){RESET}")
    if arp_copy:
        lines.append(f"  {DIM}{'MAC':<20}{'IP':<18}{'State'}{RESET}")
        for ip, info in sorted(arp_copy.items())[:limit]:
            lines.append(f"  {CYAN}{info['mac']:<20}{RESET}{ip:<18}{DIM}{info['state']}{RESET}")
    else:
        lines.append(f"  {DIM}(no ARP entries yet){RESET}")
    return lines

def _section_alerts(limit=5):
    return _section_simple("ALERTS", RED,
        lambda: alerts,
        lambda a: f"  {RED}[!] {a['time']} {a['msg']}{RESET}",
        "no alerts", limit)


def _section_proxy(max_lines=20):
    lines = []
    proxy_on = os.environ.get("PROXYCHAINS_CONF_FILE") or "proxychains" in os.environ.get("LD_PRELOAD", "")
    conf = os.environ.get("PROXYCHAINS_CONF_FILE", "")
    has_custom = len(proxy_pool) > 0

    if not proxy_on and not has_custom:
        lines.append(f"{BOLD}{MAGENTA}  PROXY{RESET}  {DIM}(not active){RESET}")
        lines.append(f"  {DIM}Options:{RESET}")
        lines.append(f"  {GREEN}proxy add socks5 127.0.0.1:9050{RESET}   {DIM}— add SOCKS5 proxy{RESET}")
        lines.append(f"  {GREEN}proxy add http 1.2.3.4:8080{RESET}      {DIM}— add HTTP proxy{RESET}")
        lines.append(f"  {GREEN}proxy add socks4 host:port{RESET}       {DIM}— add SOCKS4 proxy{RESET}")
        lines.append(f"  {DIM}Or launch with proxychains:{RESET}")
        lines.append(f"  {GREEN}sudo proxychains4 -f proxychains-strict.conf python3 netwatch.py{RESET}")
        lines.append("")
        try:
            r = subprocess.run(["systemctl", "is-active", "tor"], capture_output=True, text=True, timeout=3)
            tor_status = r.stdout.strip()
            color = GREEN if tor_status == "active" else RED
            lines.append(f"  Tor service: {color}{tor_status}{RESET}")
        except Exception:
            pass
        return lines

    lines.append(f"{BOLD}{MAGENTA}  PROXY{RESET}  {GREEN}ACTIVE{RESET}")
    lines.append("")

    # Custom proxy pool
    if has_custom:
        rot_status = f"{GREEN}ROTATING{RESET}" if proxy_rotation else f"{DIM}sequential{RESET}"
        lines.append(f"  {BOLD}{WHITE}Custom Proxies ({len(proxy_pool)}){RESET}  {rot_status}")
        lines.append(f"  {DIM}{'─'*50}{RESET}")
        for i, p in enumerate(proxy_pool):
            marker = f"{CYAN}►{RESET}" if i == (proxy_rotate_idx - 1) % len(proxy_pool) and proxy_rotation else " "
            lines.append(f"  {marker} {i+1}. {GREEN}{p['label']}{RESET}")
        lines.append("")

    # Proxychains/Tor
    if proxy_on:
        chain_type = "dynamic"
        tor_ports = []
        if conf and os.path.isfile(conf):
            lines.append(f"  {DIM}Config:{RESET} {conf}")
            with open(conf) as f:
                for line in f:
                    line = line.strip()
                    if line in ("dynamic_chain", "strict_chain", "random_chain", "round_robin_chain"):
                        chain_type = line.replace("_", " ").title()
                    if line.startswith("socks") and "127.0.0.1" in line:
                        tor_ports.append(line.split()[-1])
        lines.append(f"  {DIM}Chain:{RESET}  {YELLOW}{chain_type}{RESET}")
        lines.append("")

        tor_ports = [p for p in tor_ports if p.isdigit()]
        global _proxy_circuit_cache, _proxy_cache_time
        now = time.time()
        if now - _proxy_cache_time > 10:
            def _check_circuits():
                global _proxy_circuit_cache, _proxy_cache_time
                results = {}
                for p in tor_ports:
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(2)
                        s.connect(("127.0.0.1", int(p)))
                        s.close()
                        results[p] = True
                    except Exception:
                        results[p] = False
                with lock:
                    _proxy_circuit_cache = results
                    _proxy_cache_time = time.time()
            threading.Thread(target=_check_circuits, daemon=True).start()

        lines.append(f"  {BOLD}{WHITE}Tor Circuits ({len(tor_ports)}){RESET}")
        lines.append(f"  {DIM}{'─'*50}{RESET}")
        with lock:
            cache_snap = dict(_proxy_circuit_cache)
        for i, port in enumerate(tor_ports):
            up = cache_snap.get(port, False)
            status = f"{GREEN}● LIVE{RESET}" if up else f"{RED}● DOWN{RESET}"
            lines.append(f"  {status}  socks5://127.0.0.1:{port}  {DIM}(circuit {i+1}){RESET}")

    lines.append("")
    lines.append(f"  {BOLD}{WHITE}Routing{RESET}")
    lines.append(f"  {DIM}{'─'*50}{RESET}")
    lines.append(f"  {GREEN}✓{RESET} OSINT requests    {DIM}(geo, whois, crt, headers, abuse){RESET}")
    lines.append(f"  {GREEN}✓{RESET} nmap scans        {DIM}(scan/deep/stealth){RESET}")
    lines.append(f"  {GREEN}✓{RESET} DNS lookups       {DIM}(proxy_dns if proxychains){RESET}")
    lines.append(f"  {RED}✗{RESET} packet sniffing   {DIM}(raw sockets, local only){RESET}")
    lines.append(f"  {RED}✗{RESET} honeypot listeners {DIM}(bound to 0.0.0.0){RESET}")
    lines.append(f"  {RED}✗{RESET} ARP monitor       {DIM}(layer 2, local only){RESET}")
    lines.append("")
    lines.append(f"  {DIM}Commands:{RESET} {GREEN}proxy add{RESET} {GREEN}proxy rm{RESET} {GREEN}proxy list{RESET} {GREEN}proxy test{RESET} {GREEN}proxy rotate{RESET}")
    return lines


def _section_osint(limit=20):
    lines = []
    with lock:
        recent = list(osint_results[-limit:])
    lines.append(f"{BOLD}{MAGENTA}  OSINT{RESET}  {DIM}({len(osint_results)} results){RESET}")
    lines.append(f"  {DIM}{'Time':<10}{'Type':<7}{'Target':<25}{'Result'}{RESET}")
    lines.append(f"  {DIM}{'─'*65}{RESET}")
    if recent:
        for r in reversed(recent):
            color = {
                "GEO": CYAN, "DNS": MAGENTA, "SCAN": GREEN,
                "SWEEP": YELLOW, "WHOIS": BLUE, "CRT": CYAN,
                "HDR": GREEN, "ASN": BLUE, "ABUSE": RED,
            }.get(r["type"], WHITE)
            lines.append(f"  {DIM}{r['time']}{RESET}  {color}{r['type']:<6}{RESET} {r['target']:<24} {r['result']}")
    else:
        lines.append(f"  {DIM}(no results yet){RESET}")
    lines.append("")
    lines.append(f"  {DIM}Commands:{RESET}  {GREEN}geo{RESET} {GREEN}whois{RESET} {GREEN}dnsinfo{RESET} {GREEN}rdns{RESET} {GREEN}portscan{RESET} {GREEN}subnet{RESET} {GREEN}crt{RESET} {GREEN}headers{RESET} {GREEN}asn{RESET} {GREEN}abuse{RESET} {GREEN}ssl{RESET} {GREEN}secheaders{RESET} {GREEN}techstack{RESET} {GREEN}ping{RESET} {GREEN}health{RESET} {GREEN}etrace{RESET} <target>")
    return lines


def _build_help_overlay(cols, rows):
    lines = []
    w = min(cols - 4, 78)
    pad = "  "
    lines.append(f"{pad}{BOLD}{RED}{'═'*w}{RESET}")
    lines.append(f"{pad}{BOLD}{RED}  NETWATCH v{VERSION} — COMMAND REFERENCE{RESET}  {DIM}(ESC to close){RESET}")
    lines.append(f"{pad}{BOLD}{RED}{'═'*w}{RESET}")
    lines.append("")
    lines.append(f"{pad}{BOLD}Tabs:{RESET}  {DIM}type name or 1-9/0 to switch{RESET}")
    lines.append(f"{pad}  {GREEN}all{RESET}  {GREEN}hosts{RESET}  {GREEN}proto{RESET}  {GREEN}dns{RESET}  {GREEN}honeypot{RESET}  {GREEN}nmap{RESET}  {GREEN}arp{RESET}  {GREEN}alerts{RESET}  {GREEN}osint{RESET}  {GREEN}proxy{RESET}")
    lines.append("")
    for cat, subtitle, cmds in _HELP_SECTIONS:
        hdr = f"{pad}{BOLD}{cat}:{RESET}"
        if subtitle:
            hdr += f"  {DIM}{subtitle}{RESET}"
        lines.append(hdr)
        pairs = [(c, d) for c, d in cmds if c]
        notes = [(c, d) for c, d in cmds if not c]
        for n_cmd, n_desc in notes:
            lines.append(f"{pad}  {DIM}{n_desc}{RESET}")
        for i in range(0, len(pairs), 2):
            left_cmd, left_desc = pairs[i]
            line = f"{pad}  {GREEN}{left_cmd}{RESET}{' '*(18-len(left_cmd))}{left_desc}"
            if i + 1 < len(pairs):
                right_cmd, right_desc = pairs[i + 1]
                line += f"  {GREEN}{right_cmd}{RESET}{' '*(16-len(right_cmd))}{right_desc}"
            lines.append(line)
        lines.append("")
    lines.append(f"{pad}{DIM}Navigation: 1-0=tab  type name=switch  ESC=close  @N=target from list{RESET}")
    return lines


def _section_console():
    lines = []
    with lock:
        snap = list(console_output)
    recent_console = snap[-8:]
    if recent_console:
        lines.append(f"{BOLD}{WHITE}  OUTPUT{RESET}")
        for line in recent_console:
            lines.append(f"  {line}")
    return lines


def _build_frame(cols=80, max_content=35, active_tab=None):
    global current_tab
    tab = active_tab or current_tab
    lines = []
    now = datetime.now().strftime("%H:%M:%S")
    uptime = int(time.time() - start_time)
    up_h, up_m, up_s = uptime // 3600, (uptime % 3600) // 60, uptime % 60

    # Header
    w = min(cols, 78)
    lines.append(f"{BOLD}{RED}{'═'*w}{RESET}")
    lines.append(f"{BOLD}{RED}  NETWATCH v{VERSION}{RESET}  {DIM}Network Security Dashboard{RESET}")
    lines.append(f"  {DIM}{now}  |  Up: {up_h}h{up_m}m{up_s}s  |  {IFACE}  |  Pkts: {total_packets:,}  |  {format_bytes(total_bytes)}{RESET}")
    lines.append(f"{BOLD}{RED}{'═'*w}{RESET}")

    # Services
    svcs = [
        (f"HTTP:{HTTP_PORT}", GREEN), (f"TELNET:{TELNET_PORT}", GREEN),
        (f"FTP:{FTP_PORT}", GREEN), (f"RTSP:{RTSP_PORT}", GREEN),
        (f"SNIFF:{IFACE}", GREEN),
    ]
    tshark_ok = len(tshark_conversations) > 0
    svcs.append(("TSHARK", GREEN if tshark_ok else YELLOW))
    svcs.append(("TCPDUMP", GREEN if tcpdump_proc else RED))
    svcs.append(("NMAP", YELLOW if nmap_running else DIM))
    proxy_on = os.environ.get("PROXYCHAINS_CONF_FILE") or "proxychains" in os.environ.get("LD_PRELOAD", "")
    svcs.append(("TOR-PROXY", GREEN if proxy_on else DIM))
    svc_line = "  "
    for name, color in svcs:
        svc_line += f"{color}{name}{RESET} "
    lines.append(svc_line)

    # Tab bar
    lines.append(_tab_bar(cols, active=tab))
    lines.append(f"{DIM}  {'─'*min(76, w)}{RESET}")

    # Content based on active tab
    if tab == "all":
        if _tunnel_url:
            lines.append(f"  {GREEN}Tunnel:{RESET} {_tunnel_url}")
            lines.append("")
        lines.extend(_section_hosts(8))
        lines.append("")
        p = _section_protocols(6)
        if len(p) > 1:
            lines.extend(p)
            lines.append("")
        lines.extend(_section_dns(4))
        lines.append("")
        lines.extend(_section_honeypot(5))
        with lock:
            show_nmap = bool(nmap_results) or nmap_running
            show_arp = bool(arp_table)
            show_alerts = bool(alerts)
        if show_nmap:
            lines.append("")
            lines.extend(_section_nmap(3))
        if show_arp:
            lines.append("")
            lines.extend(_section_arp(4))
        if show_alerts:
            lines.append("")
            lines.extend(_section_alerts(3))
    elif tab == "hosts":
        lines.extend(_section_hosts(max_content))
    elif tab == "proto":
        lines.extend(_section_protocols(max_content, expanded=True))
    elif tab == "dns":
        lines.extend(_section_dns(max_content))
    elif tab == "honeypot":
        lines.extend(_section_honeypot(max_content, show_http=True))
    elif tab == "nmap":
        lines.extend(_section_nmap(max_content))
        lines.append("")
        lines.append(f"  {DIM}Quick:{RESET}  {GREEN}scan <ip>{RESET}  {GREEN}deep <ip>{RESET}  {GREEN}stealth <ip>{RESET}  {GREEN}subnet{RESET}")
    elif tab == "arp":
        lines.extend(_section_arp(max_content))
        lines.append("")
        lines.append(f"  {DIM}Quick:{RESET}  {GREEN}mac <addr>{RESET}  {GREEN}scan <ip>{RESET}  {GREEN}whois <ip>{RESET}")
    elif tab == "alerts":
        lines.extend(_section_alerts(max_content))
    elif tab == "osint":
        lines.extend(_section_osint(max_content))
    elif tab == "proxy":
        lines.extend(_section_proxy(max_content))
    elif tab == "mesh":
        lines.extend(_section_mesh(max_content))
    else:
        current_tab = "all"
        lines.append(f"  {DIM}(reset to all view){RESET}")

    return lines


def _section_mesh(limit=20):
    lines = []
    if not _HAS_MESH:
        lines.append(f"  {DIM}Meshtastic not installed: pip3 install meshtastic{RESET}")
        return lines
    if mesh_interface is None:
        lines.append(f"  {YELLOW}No mesh radio detected. Connect a LoRa device via USB.{RESET}")
        lines.append(f"  {DIM}Supported: T-Beam, Heltec, RAK, LilyGo{RESET}")
        return lines
    lines.append(f"  {BOLD}{GREEN}MESH RADIO CONNECTED{RESET}")
    lines.append(f"  {DIM}Nodes: {len(mesh_nodes)}  |  Messages: {len(mesh_messages)}  |  Alert fwd: {'ON' if mesh_alert_fwd else 'OFF'}{RESET}")
    lines.append("")
    if mesh_nodes:
        lines.append(f"  {BOLD}{WHITE}NODES{RESET}")
        for nid, info in list(mesh_nodes.items())[:8]:
            name = info.get("name", nid)
            snr = info.get("snr", "?")
            last = info.get("last_heard", "?")
            lines.append(f"  {CYAN}{name:<20}{RESET} SNR:{snr:>6}  Last:{last}")
    if mesh_messages:
        lines.append("")
        lines.append(f"  {BOLD}{WHITE}MESSAGES{RESET}")
        for msg in mesh_messages[-min(limit - len(lines), 12):]:
            color = GREEN if msg["type"] == "sent" else CYAN
            lines.append(f"  {DIM}{msg['ts']}{RESET}  {color}{msg['from']:<12}{RESET} {msg['text']}")
    lines.append("")
    lines.append(f"  {DIM}Commands:{RESET}  {GREEN}mesh send <text>{RESET}  {GREEN}mesh status{RESET}  {GREEN}mesh nodes{RESET}  {GREEN}mesh alert on/off{RESET}")
    return lines


def _paint_dashboard():
    global _output_scroll
    cols, rows = _get_terminal_dims()

    # Fixed layout: row 1..top_end = dashboard, divider, output panel, separator, prompt
    output_panel = max(_OUTPUT_PANEL_MIN, (rows - 9) // 2)
    top_end = rows - output_panel - 3  # 3 = divider + separator + prompt
    top_end = max(8, top_end)
    output_panel = rows - top_end - 3

    if show_help_overlay:
        # Use full screen for help (rows - 2: leave room for separator + prompt).
        # Scroll semantics for help: scroll=0 → top, scroll=max_scroll → bottom.
        help_rows = max(8, rows - 2)
        all_help = _build_help_overlay(cols, rows)
        total_help = len(all_help)
        max_scroll = max(0, total_help - help_rows)
        scroll = min(_output_scroll, max_scroll)
        start_idx = scroll
        end_idx = min(total_help, start_idx + help_rows)
        top_lines = all_help[start_idx:end_idx]
        if total_help > help_rows:
            top_lines = top_lines + [f"  {DIM}── {start_idx+1}-{end_idx}/{total_help}  PgUp/PgDn scroll · ESC close{RESET}"]
        top_end = rows - 2
        output_panel = 0
    else:
        top_lines = _build_frame(cols, max(3, top_end - 7))
        top_lines = top_lines[:top_end]

    # Output panel content
    with lock:
        all_output = list(console_output)
    total = len(all_output)
    if total > 0:
        _output_scroll = min(_output_scroll, max(0, total - 1))
        end_idx = total - _output_scroll
        start_idx = max(0, end_idx - output_panel)
        end_idx = max(start_idx, end_idx)
        visible = all_output[start_idx:end_idx]
        if total > output_panel:
            scroll_info = f" {start_idx+1}-{end_idx}/{total} "
        else:
            scroll_info = " "
    else:
        visible = []
        scroll_info = " "

    dw = max(1, cols - 12 - len(scroll_info))
    divider = f"{DIM}  {'─'*3} {BOLD}{WHITE}OUTPUT{RESET}{DIM}{scroll_info}{'─'*dw}{RESET}"

    # Build full screen buffer
    buf = "\033[?25l\033[H"

    for line in top_lines:
        buf += line + "\033[K\n"
    for _ in range(top_end - len(top_lines)):
        buf += "\033[K\n"

    if output_panel > 0:
        buf += divider + "\033[K\n"
        for line in visible:
            text = str(line).replace('\n', ' ').replace('\r', '')
            buf += f"  {text}\033[K\n"
        for _ in range(output_panel - len(visible)):
            buf += "\033[K\n"

    buf += f"{DIM}{'─'*cols}{RESET}\033[K\n"
    buf += f"{BOLD}{RED}nw>{RESET} \033[K"
    buf += "\033[?25h"

    _write_frame(buf)


def _paint_cli():
    """Full-screen Command Line: history + interleaved output, prompt at bottom.
    State (cli_scroll) persists in app_state; returning to dashboard restores it."""
    cols, rows = _get_terminal_dims()
    with lock:
        out_snap = list(console_output)
        hist_snap = list(_cmd_history)
    # Interleave: show last N output lines; prompt below. Scroll = lines from bottom.
    body_rows = max(3, rows - 4)
    scroll = max(0, min(app_state.cli_scroll, max(0, len(out_snap) - body_rows)))
    end = len(out_snap) - scroll
    start = max(0, end - body_rows)
    visible = out_snap[start:end]

    buf = "\033[?25l\033[H"
    title = f"{BOLD}{RED}  NETWATCH — COMMAND LINE{RESET}  {DIM}(F1 dashboard · F3 console · PgUp/PgDn scroll){RESET}"
    buf += title + "\033[K\n"
    buf += f"{DIM}{'─'*min(cols, 78)}{RESET}\033[K\n"
    for line in visible:
        text = str(line).replace('\n', ' ').replace('\r', '')
        buf += f"  {text}\033[K\n"
    for _ in range(body_rows - len(visible)):
        buf += "\033[K\n"
    info = f" {start+1}-{end}/{len(out_snap)} · hist {len(hist_snap)}/{_cmd_history.maxlen} " if out_snap else " "
    buf += f"{DIM}{'─'*3} {BOLD}{WHITE}CLI{RESET}{DIM}{info}{'─'*max(1, cols-12-len(info))}{RESET}\033[K\n"
    buf += f"{BOLD}{RED}nw>{RESET} \033[K"
    buf += "\033[?25h"
    _write_frame(buf)


def _paint_console():
    """Full-screen Console: tool output log only, scrollable, read-only."""
    cols, rows = _get_terminal_dims()
    with lock:
        snap = list(console_output)
    body_rows = max(3, rows - 3)
    scroll = max(0, min(app_state.console_scroll, max(0, len(snap) - body_rows)))
    end = len(snap) - scroll
    start = max(0, end - body_rows)
    visible = snap[start:end]

    buf = "\033[?25l\033[H"
    title = f"{BOLD}{RED}  NETWATCH — CONSOLE{RESET}  {DIM}(F1 dashboard · F2 cli · PgUp/PgDn · `clear` to wipe){RESET}"
    buf += title + "\033[K\n"
    buf += f"{DIM}{'─'*min(cols, 78)}{RESET}\033[K\n"
    for line in visible:
        text = str(line).replace('\n', ' ').replace('\r', '')
        buf += f"  {text}\033[K\n"
    for _ in range(body_rows - len(visible)):
        buf += "\033[K\n"
    info = f" {start+1}-{end}/{len(snap)} " if snap else " (empty) "
    buf += f"{DIM}{'─'*3} {BOLD}{WHITE}LOG{RESET}{DIM}{info}{'─'*max(1, cols-12-len(info))}{RESET}\033[K"
    _write_frame(buf)


_REPLAY_SPEED_STEPS = (0.25, 0.5, 1.0, 2.0, 4.0, 8.0)


def _replay_fmt_ms(ms):
    if ms is None or ms < 0:
        ms = 0
    s, msr = divmod(int(ms), 1000)
    m, s = divmod(s, 60)
    return f"{m:02d}:{s:02d}.{msr:03d}"


def _replay_event_color(kind):
    k = (kind or "").lower()
    if k in ("client", "cmd", "login"):
        return CYAN
    if k == "server":
        return GREEN
    if k in ("cred", "credential"):
        return RED
    if k == "malware":
        return YELLOW
    if k == "connect":
        return BLUE
    return ""


def _replay_advance_cursor():
    now = time.monotonic()
    last = app_state.replay_last_tick or now
    app_state.replay_last_tick = now
    if not app_state.replay_playing:
        return
    tl = app_state.replay_timeline
    if not tl:
        return
    dur = int(tl.get("duration_ms") or 0)
    if dur <= 0:
        app_state.replay_playing = False
        return
    delta = (now - last) * 1000.0 * float(app_state.replay_speed)
    app_state.replay_cursor_ms = int(app_state.replay_cursor_ms + delta)
    if app_state.replay_cursor_ms >= dur:
        app_state.replay_cursor_ms = dur
        app_state.replay_playing = False


def _paint_replay():
    _replay_advance_cursor()
    cols, rows = _get_terminal_dims()
    cols = max(60, cols)
    rows = max(12, rows)

    tl = app_state.replay_timeline
    buf = "\033[?25l\033[H"

    if not tl:
        title = f"{BOLD}{RED}  NETWATCH — REPLAY{RESET}  {DIM}(no session loaded){RESET}"
        buf += title + "\033[K\n"
        buf += f"{DIM}{'─'*min(cols, 78)}{RESET}\033[K\n"
        msg = [
            "",
            f"  {DIM}No replay session loaded.{RESET}",
            "",
            f"  Type {GREEN}replay list{RESET} to see captured sessions,",
            f"  then {GREEN}replay <#>{RESET} or {GREEN}replay <session_id>{RESET} to load one.",
            "",
            f"  {DIM}[q] back to dashboard{RESET}",
        ]
        for line in msg:
            buf += line + "\033[K\n"
        for _ in range(rows - 2 - len(msg)):
            buf += "\033[K\n"
        _write_frame(buf)
        return

    sid = tl.get("session_id", "")
    proto = tl.get("protocol", app_state.replay_protocol)
    ip = tl.get("ip", "")
    dur = int(tl.get("duration_ms") or 0)
    cur = max(0, min(int(app_state.replay_cursor_ms), dur))
    events = tl.get("events") or []
    intel = tl.get("intel") or {}

    side_w = 22 if cols >= 80 else 0
    main_w = cols - side_w - (1 if side_w else 0)

    end_tag = f"  {BOLD}{YELLOW}[END]{RESET}" if (not app_state.replay_playing and cur >= dur and dur > 0) else ""
    title = f"{BOLD}{RED}  NETWATCH — REPLAY{RESET}  {DIM}{sid}{RESET}{end_tag}"
    buf += title + "\033[K\n"
    buf += f"{DIM}{'─'*min(cols, 78)}{RESET}\033[K\n"

    meta = (f"  {DIM}proto:{RESET} {proto}   {DIM}ip:{RESET} {ip}   "
            f"{DIM}duration:{RESET} {_replay_fmt_ms(dur)}   "
            f"{DIM}events:{RESET} {len(events)}")
    buf += meta + "\033[K\n"

    body_rows = max(4, rows - 6)

    cur_idx = -1
    for i, e in enumerate(events):
        if int(e.get("t_ms", 0)) <= cur:
            cur_idx = i
        else:
            break

    show = body_rows
    if len(events) <= show:
        start = 0
    else:
        anchor = max(0, cur_idx - (show * 2 // 3))
        start = min(anchor, len(events) - show)
        start = max(0, start)
    end = min(len(events), start + show)
    window = events[start:end]

    side_lines = []
    if side_w:
        def _pad(label, val):
            v = ("" if val is None else str(val))[:side_w - len(label) - 2]
            return f"{DIM}{label}{RESET}{v}"
        if intel:
            side_lines.append(f"{BOLD}{WHITE}INTEL{RESET}")
            side_lines.append(_pad("Country: ", intel.get("country") or "—"))
            side_lines.append(_pad("ASN:     ", intel.get("asn") or "—"))
            side_lines.append(_pad("Org:     ", intel.get("org") or "—"))
            side_lines.append(_pad("Abuse:   ", intel.get("abuse_score") or "—"))
            tags = intel.get("tags") or []
            side_lines.append(_pad("Tags:    ", ", ".join(tags)[:side_w - 10] if tags else "—"))
            host = intel.get("hostname") or ""
            if host:
                side_lines.append(_pad("Host:    ", host))
            notes = intel.get("notes") or ""
            if notes:
                side_lines.append("")
                side_lines.append(f"{DIM}Notes:{RESET}")
                s = str(notes)
                while s and len(side_lines) < body_rows:
                    side_lines.append(s[:side_w])
                    s = s[side_w:]
        else:
            side_lines.append(f"{BOLD}{WHITE}INTEL{RESET}")
            side_lines.append(f"{DIM}(no recon data){RESET}")
            side_lines.append("")
            side_lines.append(f"{DIM}Run `recon {ip}`")
            side_lines.append(f"{DIM}from dashboard.{RESET}")
        side_lines = side_lines[:body_rows]
        while len(side_lines) < body_rows:
            side_lines.append("")

    for row in range(body_rows):
        if row < len(window):
            e = window[row]
            ev_idx = start + row
            t_ms = int(e.get("t_ms", 0))
            kind = (e.get("kind") or "").upper()[:8]
            text = (e.get("text") or "").replace("\n", " ").replace("\r", "")
            future = t_ms > cur
            color = _replay_event_color(e.get("kind"))
            ts = _replay_fmt_ms(t_ms)
            line = f"[{ts}] {kind:<8} {text}"
            max_text = main_w - 4
            if len(line) > max_text:
                line = line[:max_text - 1] + "…"
            marker = " "
            if ev_idx == cur_idx:
                marker = f"{BOLD}{WHITE}▶{RESET}"
            if future:
                rendered = f" {marker} {DIM}{line}{RESET}"
            elif ev_idx == cur_idx:
                rendered = f" {marker} {BOLD}{color}{line}{RESET}"
            else:
                rendered = f" {marker} {color}{line}{RESET}"
            left_cell = rendered
        elif row == 0 and not window:
            left_cell = f"  {DIM}(no events captured){RESET}"
        else:
            left_cell = ""

        visible_len = len(re.sub(r"\033\[[0-9;]*m", "", left_cell))
        pad = max(0, main_w - visible_len)
        out_line = left_cell + (" " * pad)

        if side_w:
            side_cell = side_lines[row]
            s_vis = len(re.sub(r"\033\[[0-9;]*m", "", side_cell))
            s_pad = max(0, side_w - s_vis)
            out_line += f"{DIM}│{RESET}" + side_cell + (" " * s_pad)

        buf += out_line + "\033[K\n"

    bar_w = max(10, cols - 30)
    filled = int(bar_w * (cur / dur)) if dur > 0 else bar_w
    filled = max(0, min(filled, bar_w))
    bar = ("█" * filled) + ("─" * (bar_w - filled))
    play_tag = f"{GREEN}▶{RESET}" if app_state.replay_playing else f"{YELLOW}❚❚{RESET}"
    spd_s = f"{app_state.replay_speed:g}x"
    footer1 = f" {play_tag} {bar} {_replay_fmt_ms(cur)}/{_replay_fmt_ms(dur)}  {DIM}speed:{RESET} {spd_s}"
    footer2 = (f" {DIM}[SPACE] play  [←→] ±1s  [</>] ±10s  [+-] speed  "
               f"[Home/End] jump  [q] back{RESET}")
    buf += footer1 + "\033[K\n"
    buf += footer2 + "\033[K\n"

    rendered_rows = 4 + body_rows + 2
    for _ in range(max(0, rows - rendered_rows)):
        buf += "\033[K\n"

    _write_frame(buf)


def _render_frame():
    # console_mode (legacy) suppresses all paint — caller owns the terminal.
    if console_mode or _input_active:
        return
    if not _render_lock.acquire(blocking=False):
        return
    try:
        if console_mode or _input_active:
            return
        if app_state.needs_clear:
            try:
                os.write(1, b"\033[2J\033[H")
            except OSError:
                pass
            app_state.needs_clear = False
        screen = app_state.current_screen
        if screen == SCREEN_CLI:
            _paint_cli()
        elif screen == SCREEN_CONSOLE:
            _paint_console()
        elif screen == SCREEN_REPLAY:
            _paint_replay()
        else:
            _paint_dashboard()
    finally:
        _render_lock.release()


def draw_dashboard():
    enrich_counter = 0
    _write_frame(b"\033[2J\033[H")

    while True:
      try:
        _redraw_event.wait(timeout=0.3)

        if _input_active:
            _redraw_event.clear()
            continue

        _redraw_event.clear()

        enrich_counter += 1
        if enrich_counter % 5 == 0:
            try:
                with lock:
                    if len(alerts) > MAX_ALERTS:
                        del alerts[:len(alerts) - MAX_ALERTS]
                    if len(hosts) > MAX_HOSTS:
                        oldest = sorted(hosts.keys(), key=lambda k: hosts[k].get("last_seen") or "")[:len(hosts) - MAX_HOSTS]
                        for k in oldest:
                            del hosts[k]
                    for ip in list(hosts.keys())[:20]:
                        if not hosts[ip].get("_enriched"):
                            threading.Thread(target=enrich_host, args=(ip,), daemon=True).start()
            except Exception:
                pass

        _render_frame()
      except KeyboardInterrupt:
        raise
      except Exception:
        pass

def _exec_console_cmd(cmd):
    a = cmd.strip().lower()
    if a == "status":
        now = datetime.now().strftime("%H:%M:%S")
        uptime = int(time.time() - start_time)
        up_h, up_m, up_s = uptime // 3600, (uptime % 3600) // 60, uptime % 60
        print(f"\n{BOLD}{CYAN}  STATUS{RESET}")
        print(f"  Time:    {now}")
        print(f"  Uptime:  {up_h}h{up_m}m{up_s}s")
        print(f"  Iface:   {IFACE}")
        print(f"  Packets: {total_packets:,}")
        print(f"  Traffic: {format_bytes(total_bytes)}")
        print(f"  Hosts:   {len(hosts)}")
        print(f"  Alerts:  {len(alerts)}")
        print(f"  Honeypot: {len(honeypot_events)} events")
        print(f"  ARP:     {len(arp_table)} devices")
        print(f"  PCAP:    {'Recording: ' + tcpdump_file if tcpdump_proc else 'Not recording'}")
        print(f"  NMAP:    {'RUNNING' if nmap_running else 'idle'}")
        print(f"  Tags:    {len(ip_tags)}  |  Watchlist: {len(watchlist)}")
        print()
    elif a == "help":
        _help_to_print()
    else:
        with lock:
            start_idx = len(console_output)
        handle_command(cmd)
        time.sleep(0.15)
        with lock:
            snap = list(console_output)
        new_output = snap[start_idx:] if start_idx < len(snap) else []
        for line in new_output:
            print(f"  {line}")
        if new_output:
            print()


# -- WEB DASHBOARD - Real-time browser UI (:9090)

WEB_PORT = 9090
WEB_TOKEN = _cli_token or os.environ.get("NETWATCH_TOKEN", "") or secrets.token_hex(24)
from cryptography.fernet import Fernet as _Fernet, InvalidToken as _InvalidToken

# Persistent Fernet key at ~/.config/netwatch/web.key (dir 0700, file 0600).
# Key never logged. rotate_key() generates fresh material; load_or_create_key()
# reads existing or seeds new. Survives restarts so sessions don't die on reboot.
_KEY_DIR = os.path.join(os.path.expanduser("~"), ".config", "netwatch")
_KEY_PATH = os.path.join(_KEY_DIR, "web.key")
_TOKEN_PATH = os.path.join(_KEY_DIR, "token")

def _persist_web_token(token: str, path: str = _TOKEN_PATH) -> None:
    """Write token to disk with 0600 perms. Idempotent — overwrites on rotation."""
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        try:
            os.chmod(os.path.dirname(path), 0o700)
        except OSError:
            pass
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            f.write(token + "\n")
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, path)
    except OSError:
        pass

def load_or_create_key(path=_KEY_PATH):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    try:
        os.chmod(os.path.dirname(path), 0o700)
    except OSError:
        pass
    if os.path.exists(path):
        try:
            data = open(path, "rb").read().strip()
            _Fernet(data)  # validate
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            return data
        except (ValueError, _InvalidToken, OSError):
            pass  # invalid/corrupt — regenerate
    key = _Fernet.generate_key()
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(key)
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, path)
    return key

def rotate_key(path=_KEY_PATH):
    """Atomically replace web.key with fresh material. Invalidates sessions."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    key = _Fernet.generate_key()
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(key)
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, path)
    return key

def get_cipher(key=None):
    return _Fernet(key if key is not None else WEB_ENCRYPTION_KEY)

WEB_ENCRYPTION_KEY = load_or_create_key()
_fernet = _Fernet(WEB_ENCRYPTION_KEY)
_ALLOWED_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),  # tailscale
]

web_app = Flask("netwatch_web")
web_app.secret_key = secrets.token_hex(32)
web_log = logging.getLogger("netwatch_web")
web_log.setLevel(logging.ERROR)

import hmac as _hmac

_sse_count = 0
_SSE_MAX = 5
_sse_lock = threading.Lock()

_LOGIN_HTML = """<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetWatch — Login</title><style>
*{margin:0;padding:0;box-sizing:border-box}body{background:#080a0e;color:#c8ccd4;font-family:'JetBrains Mono','Fira Code',monospace;
display:flex;justify-content:center;align-items:center;min-height:100vh}
.box{background:#0d1117;border:1px solid #1a1f2b;border-radius:8px;padding:40px;width:340px;text-align:center}
h1{color:#ff3333;font-size:22px;margin-bottom:8px;letter-spacing:2px}
.sub{color:#555;font-size:11px;margin-bottom:24px}
input{width:100%;background:#080a0e;border:1px solid #1a1f2b;color:#c8ccd4;font-family:inherit;
font-size:14px;padding:10px 14px;border-radius:4px;outline:none;margin-bottom:12px;text-align:center}
input:focus{border-color:#ff3333}
button{width:100%;background:#ff3333;color:#080a0e;border:none;padding:10px;border-radius:4px;
font-family:inherit;font-size:13px;font-weight:700;cursor:pointer;letter-spacing:1px}
button:hover{background:#ff5555}
.err{color:#ff3333;font-size:11px;margin-top:8px;min-height:16px}
</style></head><body><div class="box"><h1>NETWATCH</h1><div class="sub">Enter access token to continue</div>
<input id="tok" type="password" placeholder="Token" autocomplete="off" autofocus>
<button onclick="go()">AUTHENTICATE</button><div class="err" id="err"></div></div>
<script>
document.getElementById("tok").addEventListener("keydown",e=>{if(e.key==="Enter")go()});
async function go(){const t=document.getElementById("tok").value.trim();if(!t)return;
try{const r=await fetch("/auth",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({token:t})});
if(r.ok){location.reload()}else{document.getElementById("err").textContent="Invalid token"}}
catch(e){document.getElementById("err").textContent="Connection error"}}
</script></body></html>"""

def _verify_web_cookie(cookie_val):
    if not cookie_val:
        return False
    try:
        decrypted = _fernet.decrypt(cookie_val.encode()).decode()
        return _hmac.compare_digest(decrypted, WEB_TOKEN)
    except Exception:
        return False

@web_app.before_request
def _web_auth():
    client = ipaddress.ip_address(request.remote_addr)
    if not any(client in net for net in _ALLOWED_NETS):
        return "Forbidden", 403
    if request.path == "/auth" and request.method == "POST":
        return None
    if WEB_TOKEN:
        if not _verify_web_cookie(request.cookies.get("nw_token", "")):
            return _LOGIN_HTML, 401
    if request.method == "POST":
        origin = request.headers.get("Origin", "")
        if not origin:
            return "CSRF rejected — Origin header required", 403
        _allowed_origins = {f"http://127.0.0.1:{WEB_PORT}", f"http://localhost:{WEB_PORT}"}
        for _lip in LOCAL_IPS:
            _allowed_origins.add(f"http://{_lip}:{WEB_PORT}")
        _cf_origin = os.environ.get("NETWATCH_CF_ORIGIN", "")
        # Loopback on any port — SSH tunnels remap ports (e.g. -L 9091:127.0.0.1:9090)
        # and the same-origin policy already prevents foreign sites from issuing these.
        _origin_lc = origin.lower()
        _loopback_any_port = (_origin_lc.startswith("http://localhost:")
                              or _origin_lc.startswith("http://127.0.0.1:"))
        if _cf_origin and origin == f"https://{_cf_origin}":
            pass
        elif origin.startswith("https://") and origin.endswith(".trycloudflare.com") and _verify_web_cookie(request.cookies.get("nw_token", "")):
            pass
        elif _loopback_any_port and _verify_web_cookie(request.cookies.get("nw_token", "")):
            pass
        elif origin not in _allowed_origins:
            return "CSRF rejected", 403

@web_app.after_request
def _security_headers(resp):
    # SAMEORIGIN allows the dashboard to embed /replay/<sid> in an iframe
    # while still blocking cross-site framing (clickjacking protection).
    resp.headers["X-Frame-Options"] = "SAMEORIGIN"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if request.is_secure:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp

_auth_attempts = {}

@web_app.route("/auth", methods=["POST"])
def web_auth():
    ip = request.remote_addr
    now = time.time()
    if len(_auth_attempts) > 1000:
        stale = [k for k, (_, ts) in _auth_attempts.items() if now - ts > 300]
        for k in stale:
            del _auth_attempts[k]
    if ip in _auth_attempts:
        count, first_ts = _auth_attempts[ip]
        if now - first_ts < 60:
            if count >= 10:
                return "Too many attempts", 429
            _auth_attempts[ip] = (count + 1, first_ts)
        else:
            _auth_attempts[ip] = (1, now)
    else:
        _auth_attempts[ip] = (1, now)
    token = request.json.get("token", "")
    if _hmac.compare_digest(token, WEB_TOKEN):
        resp = jsonify({"ok": True})
        encrypted = _fernet.encrypt(WEB_TOKEN.encode()).decode()
        resp.set_cookie("nw_token", encrypted, httponly=True, samesite="Lax", secure=request.is_secure, path="/")
        return resp
    return "Unauthorized", 401

def _state_snapshot():
    with lock:
        sorted_hosts = sorted(hosts.items(),
            key=lambda x: x[1]["bytes_in"] + x[1]["bytes_out"], reverse=True)[:100]
        host_list = []
        for ip, d in sorted_hosts:
            host_list.append({
                "ip": ip,
                "hostname": d.get("hostname") or dns_cache.get(ip, ""),
                "bytes_in": d["bytes_in"], "bytes_out": d["bytes_out"],
                "packets": d["packets"],
                "ports": len(d["ports"]),
                "threat_score": d.get("threat_score", 0),
                "tags": sorted(d.get("tags", set())),
                "local": ip in LOCAL_IPS,
            })
        proto_list = sorted(proto_stats.items(), key=lambda x: x[1], reverse=True)[:20]
        dns_list = [{"time": e["time"], "ip": e["ip"], "domain": e["domain"]}
                    for e in dns_queries[-50:]]
        hp_list = [{"time": e["time"], "service": e["service"], "ip": e["ip"],
                     "summary": e["summary"]} for e in honeypot_events[-50:]]
        nm_list = [{"time": r["time"], "line": r["line"]} for r in nmap_results[-30:]]
        arp_list = [{"ip": ip, "mac": info["mac"], "state": info["state"]}
                    for ip, info in sorted(arp_table.items())]
        alert_list = [{"time": a["time"], "msg": a["msg"]} for a in alerts[-50:]]
        osint_list = list(osint_results[-30:])
        proxy_on = bool(os.environ.get("PROXYCHAINS_CONF_FILE") or
                        "proxychains" in os.environ.get("LD_PRELOAD", ""))
        threat_dist = {"clean": 0, "low": 0, "medium": 0, "high": 0}
        for _ip, _d in hosts.items():
            _ts = _d.get("threat_score", 0)
            if _ts >= 30: threat_dist["high"] += 1
            elif _ts >= 10: threat_dist["medium"] += 1
            elif _ts > 0: threat_dist["low"] += 1
            else: threat_dist["clean"] += 1
    uptime = int(time.time() - start_time)
    return {
        "time": datetime.now().strftime("%H:%M:%S"),
        "uptime": f"{uptime//3600}h{(uptime%3600)//60}m{uptime%60}s",
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "total_bytes_fmt": format_bytes(total_bytes),
        "iface": IFACE,
        "hosts": host_list,
        "host_count": len(hosts),
        "protocols": [{"name": p, "count": c} for p, c in proto_list],
        "dns": dns_list,
        "honeypot": hp_list,
        "nmap": nm_list,
        "nmap_running": nmap_running,
        "arp": arp_list,
        "alerts": alert_list,
        "osint": osint_list,
        "proxy_active": proxy_on,
        "tcpdump_active": tcpdump_proc is not None,
        "mesh_connected": mesh_interface is not None,
        "mesh_msgs": len(mesh_messages),
        "mesh_nodes": len(mesh_nodes),
        "threat_dist": threat_dist,
    }

@web_app.route("/")
def web_index():
    return render_template_string(WEB_DASHBOARD_HTML)

_snapshot_cache = {"data": None, "ts": 0}
_SNAPSHOT_TTL = 2.0

def _cached_snapshot():
    now = time.time()
    if now - _snapshot_cache["ts"] > _SNAPSHOT_TTL or _snapshot_cache["data"] is None:
        _snapshot_cache["data"] = json.dumps(_state_snapshot(), default=str)
        _snapshot_cache["ts"] = now
    return _snapshot_cache["data"]

@web_app.route("/api/state")
def web_state():
    return web_app.response_class(_cached_snapshot(), mimetype="application/json")

@web_app.route("/api/stream")
def web_stream():
    global _sse_count
    with _sse_lock:
        if _sse_count >= _SSE_MAX:
            return "Too many streams", 429
        _sse_count += 1
    cookie_val = request.cookies.get("nw_token", "")
    def generate():
        global _sse_count
        _iter = 0
        try:
            while True:
                _iter += 1
                if _iter % 15 == 0 and WEB_TOKEN and not _verify_web_cookie(cookie_val):
                    break
                yield f"data: {_cached_snapshot()}\n\n"
                time.sleep(2)
        finally:
            with _sse_lock:
                _sse_count = max(0, _sse_count - 1)
    return web_app.response_class(generate(), mimetype="text/event-stream",
                                   headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

_WEB_SAFE_CMDS = {
    "scan", "deep", "recon", "trace", "banner", "whois", "geo",
    "dnsinfo", "portscan", "rdns", "attackers", "profile", "ping", "ssl",
    "secheaders", "techstack", "health", "etrace", "crt", "headers", "asn",
    "abuse", "subnet", "status", "blocked", "inspect", "analyze", "sessions",
    "decode", "tracked", "mac", "proxy",
    "ips", "top", "new", "sus", "loud", "quiet", "find", "ports", "services",
    "country", "timeline", "summary", "whowatch", "fullrecon",
    "tag", "note", "watch", "report", "exportips", "diffarp", "mesh",
    "scanall", "geoall", "whoisall", "reconall", "blockall", "sweep",
    "speed", "ifinfo", "help",
    "block", "unblock", "pcap", "track", "untrack", "conns", "sniff",
    "trackdns", "tracking", "stealth", "clear", "export",
}

_OUTBOUND_CMDS = {"geo", "whois", "dnsinfo", "crt", "headers", "asn", "abuse",
                   "ssl", "secheaders", "techstack", "health", "etrace", "ping",
                   "fullrecon", "scan", "deep", "recon", "trace", "banner",
                   "portscan", "sweep", "conns", "track", "sniff", "trackdns"}

def _is_internal_target(target):
    try:
        ip = ipaddress.ip_address(target)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return True
    except ValueError:
        pass
    try:
        for info in socket.getaddrinfo(target, None, socket.AF_INET):
            ip = ipaddress.ip_address(info[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return True
    except Exception:
        return True
    return False

_cmd_rate = {}  # ip -> (count, expensive_count, window_start)
_web_cmd_lock = threading.Lock()
_CMD_RATE_LIMIT = 20
_CMD_RATE_WINDOW = 60
_EXPENSIVE_CMDS = {"fullrecon", "scanall", "reconall", "blockall", "sweep", "geoall", "whoisall", "deep",
                    "block", "unblock", "stealth", "pcap"}
_EXPENSIVE_RATE_LIMIT = 3

@web_app.route("/api/cmd", methods=["POST"])
def web_cmd():
    rip = request.remote_addr
    now = time.time()
    if len(_cmd_rate) > 1000:
        stale = [k for k, (_, _, ws) in _cmd_rate.items() if now - ws > _CMD_RATE_WINDOW * 2]
        for k in stale:
            del _cmd_rate[k]
    if rip in _cmd_rate:
        cnt, ecnt, wstart = _cmd_rate[rip]
        if now - wstart >= _CMD_RATE_WINDOW:
            cnt, ecnt, wstart = 0, 0, now
    else:
        cnt, ecnt, wstart = 0, 0, now
    if cnt >= _CMD_RATE_LIMIT:
        return jsonify({"error": "rate limited — try again later"}), 429
    cmd = request.json.get("cmd", "").strip()
    if not cmd:
        return jsonify({"error": "empty command"})
    parts = cmd.split()
    action = parts[0].lower()
    if action in _EXPENSIVE_CMDS and ecnt >= _EXPENSIVE_RATE_LIMIT:
        return jsonify({"error": f"'{action}' rate limited — max {_EXPENSIVE_RATE_LIMIT}/{_CMD_RATE_WINDOW}s"}), 429
    _cmd_rate[rip] = (cnt + 1, ecnt + (1 if action in _EXPENSIVE_CMDS else 0), wstart)
    if action not in _WEB_SAFE_CMDS:
        return jsonify({"error": f"command '{action}' not recognized — type 'help' for available commands"})
    if action in _OUTBOUND_CMDS and len(parts) >= 2:
        target = parts[1]
        if _is_internal_target(target):
            return jsonify({"error": f"target '{target}' resolves to internal/metadata IP — blocked"})
    if action in ("scan", "deep", "recon", "portscan", "fullrecon", "sweep", "subnet") and len(parts) >= 2:
        target = parts[1]
        if "/" in target:
            try:
                net = ipaddress.ip_network(target, strict=False)
                if net.prefixlen < 20:
                    return jsonify({"error": f"CIDR range too large (/{net.prefixlen}) — max /20 via web"})
            except ValueError:
                pass
    with _web_cmd_lock:
        with lock:
            start_idx = len(console_output)
        handle_command(cmd)
        time.sleep(0.5)
        with lock:
            snap = list(console_output)
        output = snap[start_idx:] if start_idx < len(snap) else []
    clean = [re.sub(r'\033\[[0-9;]*[a-zA-Z]', '', line) for line in output]
    return jsonify({"output": clean})

WEB_DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetWatch</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js" integrity="sha384-jb8JQMbMoBUzgWatfe6COACi2ljcDdZQ2OxczGA3bGNeWe+6DChMTBJemed7ZnvJ" crossorigin="anonymous"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#080a0e;--surface:#0d1117;--border:#1a1f2b;--red:#ff3333;--green:#00ff88;
--cyan:#00d4ff;--yellow:#ffcc00;--magenta:#ff66ff;--blue:#4488ff;--dim:#555;--text:#c8ccd4;
--panel-h:40vh;
/* semantic aliases — components read these; theme switches still hit the literal vars */
--accent:var(--red);--fg:var(--text);--muted:var(--dim);
--threat-high:var(--red);--threat-med:var(--yellow);--threat-low:var(--green);
--warn:var(--yellow);--info:var(--cyan);--good:var(--green);
--svc-on-bg:#0a2a15;--svc-on-bd:#0f3d1e;
--svc-warn-bg:#2a2a0a;--svc-warn-bd:#3d3d0f;
--svc-off-bg:#1a0a0a;--svc-off-bd:#2a1515;--svc-off-fg:#663333;
--header-grad-from:#12060a}
.theme-matrix{--bg:#000;--surface:#001100;--border:#003300;--red:#00ff41;--green:#00ff41;
--cyan:#00ff41;--yellow:#33ff33;--magenta:#00ff41;--blue:#00ff41;--dim:#005500;--text:#00ff41;
--svc-on-bg:#002200;--svc-on-bd:#004400;--svc-warn-bg:#002200;--svc-warn-bd:#004400;
--svc-off-bg:#001100;--svc-off-bd:#002200;--svc-off-fg:#005500;--header-grad-from:#001100}
.theme-midnight{--bg:#020617;--surface:#0f172a;--border:#1e3a5f;--red:#f43f5e;--green:#34d399;
--cyan:#38bdf8;--yellow:#fbbf24;--magenta:#a78bfa;--blue:#60a5fa;--dim:#475569;--text:#e0f2fe;
--svc-on-bg:#053024;--svc-on-bd:#0a4a3a;--svc-warn-bg:#3a2a05;--svc-warn-bd:#5a420a;
--svc-off-bg:#1a0a14;--svc-off-bd:#2a1525;--svc-off-fg:#6b3d4d;--header-grad-from:#1e0a16}
.theme-cyberpunk{--bg:#050014;--surface:#111827;--border:#f97316;--red:#f97316;--green:#22d3ee;
--cyan:#22d3ee;--yellow:#f9a8d4;--magenta:#f9a8d4;--blue:#818cf8;--dim:#6b21a8;--text:#f9a8d4;
--svc-on-bg:#0a2030;--svc-on-bd:#1a3050;--svc-warn-bg:#301a30;--svc-warn-bd:#502a50;
--svc-off-bg:#1a0a1a;--svc-off-bd:#2a152a;--svc-off-fg:#6b3d6b;--header-grad-from:#1a0530}
.theme-light{--bg:#f9fafb;--surface:#ffffff;--border:#d1d5db;--red:#dc2626;--green:#047857;
--cyan:#0e7490;--yellow:#b45309;--magenta:#7e22ce;--blue:#1d4ed8;--dim:#6b7280;--text:#111827;
--svc-on-bg:#d1fae5;--svc-on-bd:#a7f3d0;--svc-warn-bg:#fef3c7;--svc-warn-bd:#fcd34d;
--svc-off-bg:#fee2e2;--svc-off-bd:#fca5a5;--svc-off-fg:#991b1b;--header-grad-from:#fee2e2}
#scanline-overlay{position:fixed;top:0;left:0;width:100%;height:100%;pointer-events:none;z-index:50;opacity:0}
#scanline-overlay.soft{opacity:1;background:repeating-linear-gradient(0deg,transparent,transparent 3px,rgba(0,0,0,.03) 3px,rgba(0,0,0,.03) 6px)}
#scanline-overlay.heavy{opacity:1;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,.08) 2px,rgba(0,0,0,.08) 4px)}
@keyframes status-pulse{0%,100%{opacity:1}50%{opacity:.4}}
.pulse{animation:status-pulse 1.5s ease-in-out infinite}
@keyframes row-in{from{opacity:0;transform:translateY(-2px)}to{opacity:1;transform:none}}
.fade-in tr,.fade-in .nw-row{animation:row-in .18s ease-out both}
@keyframes spin{to{transform:rotate(360deg)}}
.spinner{display:inline-block;width:10px;height:10px;border:2px solid var(--muted);
border-top-color:var(--accent);border-radius:50%;animation:spin .9s linear infinite;vertical-align:-1px;margin-right:6px}
.empty-state,.loading-state{padding:24px 12px;color:var(--muted);font-size:12px;
text-align:left;border:1px dashed var(--border);border-radius:6px;background:rgba(255,255,255,.01);
margin-top:4px}
.empty-state .label,.loading-state .label{color:var(--fg);font-size:13px;margin-bottom:4px}
.empty-state .hint{color:var(--muted);font-size:11px}
.loading-state .label{color:var(--info)}
body{background:var(--bg);color:var(--text);font-family:'JetBrains Mono','Fira Code',monospace;
font-size:13px;overflow-x:hidden;min-height:100vh;display:flex;flex-direction:column}
#header{background:linear-gradient(180deg,var(--header-grad-from) 0%,var(--surface) 100%);
border-bottom:2px solid var(--accent);padding:10px 20px;display:flex;align-items:center;gap:16px;flex-shrink:0}
#header h1{color:var(--red);font-size:18px;font-weight:700;letter-spacing:2px}
.stat{color:var(--dim);font-size:11px}
.stat b{color:var(--text)}
.services{display:flex;gap:4px;margin-left:auto;flex-wrap:wrap}
.svc{padding:2px 6px;border-radius:3px;font-size:9px;font-weight:600;text-transform:uppercase}
.svc.on{background:var(--svc-on-bg);color:var(--good);border:1px solid var(--svc-on-bd)}
.svc.warn{background:var(--svc-warn-bg);color:var(--warn);border:1px solid var(--svc-warn-bd)}
.svc.off{background:var(--svc-off-bg);color:var(--svc-off-fg);border:1px solid var(--svc-off-bd)}
#tabs{display:flex;gap:0;background:var(--surface);border-bottom:1px solid var(--border);
padding:0 12px;flex-shrink:0;overflow-x:auto}
.tab{padding:8px 14px;cursor:pointer;color:var(--dim);font-size:11px;font-weight:600;
text-transform:uppercase;letter-spacing:1px;border-bottom:2px solid transparent;transition:all .15s;white-space:nowrap}
.tab:hover{color:var(--text);background:rgba(255,255,255,.03)}
.tab.active{color:var(--red);border-bottom-color:var(--red);background:rgba(255,51,51,.05)}
.tab .n{font-size:9px;color:var(--dim);margin-right:3px}
#content{flex:1;overflow-y:auto;padding:14px 18px;min-height:0}
table{width:100%;border-collapse:collapse}
th{text-align:left;color:var(--dim);font-size:10px;text-transform:uppercase;
letter-spacing:.5px;padding:5px 8px;border-bottom:1px solid var(--border);position:sticky;top:0;background:var(--bg)}
td{padding:4px 8px;border-bottom:1px solid rgba(255,255,255,.03);font-size:12px;
overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
tr:hover td{background:rgba(255,255,255,.02)}
tr.clickable{cursor:pointer}
tr.clickable:hover td{background:rgba(0,212,255,.06)}
.ip{color:var(--cyan)}.ip.local{color:var(--green)}
.ip.threat-high{color:var(--red)}.ip.threat-med{color:var(--yellow)}
.tag{display:inline-block;padding:1px 5px;border-radius:2px;font-size:9px;margin:0 2px;
background:rgba(255,51,51,.15);color:var(--red)}
.bar-wrap{height:12px;background:var(--border);border-radius:2px;overflow:hidden;min-width:40px}
.bar-fill{height:100%;border-radius:2px;transition:width .3s}
.proto-bar{background:var(--blue)}
.alert-row{color:var(--red)}
.hp-cred{color:var(--red)}.hp-telnet{color:var(--yellow)}.hp-ftp{color:var(--magenta)}
.hp-rtsp{color:var(--blue)}.hp-http{color:var(--dim)}
.section-title{color:var(--cyan);font-size:13px;font-weight:700;margin:14px 0 6px;
display:flex;align-items:center;gap:8px}
.section-title:first-child{margin-top:0}
.count{color:var(--dim);font-size:10px;font-weight:400}
#cmd-bar{background:var(--surface);border-top:1px solid var(--border);padding:8px 18px;
display:flex;gap:10px;align-items:center;flex-shrink:0}
#cmd-bar label{color:var(--red);font-weight:700;font-size:14px}
#cmd-input{flex:1;background:var(--bg);border:1px solid var(--border);color:var(--text);
font-family:inherit;font-size:13px;padding:7px 12px;border-radius:4px;outline:none}
#cmd-input:focus{border-color:var(--accent);box-shadow:0 0 8px rgba(255,51,51,.15)}
.tab:focus-visible,button:focus-visible,select:focus-visible,
.ctx-item:focus-visible,.panel-btn:focus-visible,.port-chip:focus-visible{
outline:2px solid var(--accent);outline-offset:2px;border-radius:3px}
[role="dialog"]{outline:none}
#kbd-help{display:none;position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);
background:var(--surface);border:1px solid var(--accent);border-radius:8px;padding:18px 22px;
z-index:1100;min-width:280px;max-width:90vw;box-shadow:0 16px 48px rgba(0,0,0,.7)}
#kbd-help.open{display:block}
#kbd-help h3{color:var(--accent);font-size:12px;text-transform:uppercase;letter-spacing:1px;margin-bottom:10px}
#kbd-help table{width:100%;font-size:12px}
#kbd-help td{padding:3px 8px;border:none}
#kbd-help kbd{background:var(--bg);border:1px solid var(--border);border-radius:3px;
padding:1px 6px;font-family:inherit;font-size:11px;color:var(--info)}
#kbd-help .close-hint{color:var(--muted);font-size:10px;margin-top:10px;text-align:right}
.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;
clip:rect(0,0,0,0);white-space:nowrap;border:0}
.osint-geo{color:var(--cyan)}.osint-dns{color:var(--magenta)}.osint-scan{color:var(--green)}
.osint-abuse{color:var(--red)}.osint-whois{color:var(--blue)}
.ip-click{cursor:pointer;text-decoration:none;border-bottom:1px dashed rgba(0,212,255,.3);transition:all .15s}
.ip-click:hover{border-bottom-color:var(--cyan);text-shadow:0 0 6px rgba(0,212,255,.3)}
#ctx-menu{display:none;position:fixed;background:var(--surface);border:1px solid var(--red);
border-radius:6px;padding:4px 0;z-index:1000;min-width:190px;box-shadow:0 8px 24px rgba(0,0,0,.6)}
.ctx-hdr{padding:8px 14px;color:var(--cyan);font-weight:700;font-size:12px;border-bottom:1px solid var(--border);
letter-spacing:.5px;display:flex;align-items:center;gap:6px}
.ctx-hdr::before{content:">";color:var(--red)}
.ctx-sep{height:1px;background:var(--border);margin:2px 0}
.ctx-item{padding:6px 14px;font-size:12px;cursor:pointer;color:var(--text);display:flex;align-items:center;gap:8px;transition:all .1s}
.ctx-item:hover{background:rgba(255,51,51,.1);color:var(--red)}
.ctx-item .k{color:var(--dim);font-size:10px;margin-left:auto}
#output-panel{display:none;position:fixed;bottom:0;left:0;right:0;background:var(--surface);
border-top:2px solid var(--red);z-index:900;flex-direction:column;height:var(--panel-h);min-height:120px;max-height:85vh}
#output-panel.open{display:flex}
#panel-drag{height:6px;cursor:ns-resize;background:transparent;flex-shrink:0;display:flex;align-items:center;justify-content:center}
#panel-drag::after{content:"";width:40px;height:3px;background:var(--dim);border-radius:2px}
#panel-drag:hover::after{background:var(--red)}
#output-hdr{padding:6px 16px;display:flex;align-items:center;gap:12px;border-bottom:1px solid var(--border);flex-shrink:0}
#output-hdr .title{color:var(--red);font-weight:700;font-size:12px;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.panel-btn{cursor:pointer;color:var(--dim);font-size:14px;padding:2px 6px;border-radius:3px;border:1px solid transparent}
.panel-btn:hover{color:var(--red);border-color:var(--border)}
#output-body{overflow-y:auto;padding:10px 16px;font-size:11px;color:var(--text);flex:1;white-space:pre-wrap;font-family:inherit;line-height:1.6}
#detail-panel{display:none;position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);
background:var(--surface);border:2px solid var(--red);border-radius:8px;z-index:950;
width:700px;max-width:90vw;max-height:80vh;flex-direction:column;box-shadow:0 16px 48px rgba(0,0,0,.8)}
#detail-panel.open{display:flex}
#detail-hdr{padding:10px 16px;display:flex;align-items:center;gap:12px;border-bottom:1px solid var(--border);flex-shrink:0}
#detail-hdr .title{color:var(--cyan);font-weight:700;font-size:14px;flex:1}
#detail-body{overflow-y:auto;padding:14px 16px;font-size:12px;flex:1}
.detail-section{margin-bottom:14px}
.detail-section h3{color:var(--red);font-size:11px;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px}
.detail-row{display:flex;gap:12px;padding:3px 0;border-bottom:1px solid rgba(255,255,255,.03)}
.detail-label{color:var(--dim);min-width:100px;font-size:11px}
.detail-val{color:var(--text);word-break:break-all}
.port-chip{display:inline-block;padding:2px 6px;margin:2px;border-radius:3px;font-size:10px;
background:rgba(0,212,255,.1);color:var(--cyan);border:1px solid rgba(0,212,255,.2)}
.osint-row{cursor:pointer;transition:background .15s}
.osint-row:hover td{background:rgba(0,212,255,.06) !important}
@media(max-width:768px){
  #header{flex-wrap:wrap;gap:8px;padding:8px 12px}
  .services{margin-left:0;width:100%}
  td,th{padding:3px 4px;font-size:11px}
  #content{padding:10px}
  #detail-panel{width:95vw}
  #charts-grid{grid-template-columns:1fr !important}
  #tabs{background:linear-gradient(90deg,var(--surface) 0%,var(--surface) 92%,rgba(0,0,0,.4) 100%)}
  .panel-btn,.tab,.ctx-item{min-height:36px;display:flex;align-items:center}
}
@media(max-width:640px){
  #detail-panel{width:100vw;max-width:100vw;height:100vh;max-height:100vh;
    border-radius:0;border-width:0;top:0;left:0;transform:none}
  #detail-panel.open{display:flex}
  .panel-btn{min-width:44px;min-height:44px;justify-content:center}
  #cmd-input{font-size:14px}
  #kbd-help{width:100vw;max-width:100vw;border-radius:0;top:0;left:0;transform:none;height:100vh;overflow-y:auto}
}
::-webkit-scrollbar{width:6px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:#2a3040}
</style>
</head>
<body>
<div id="header">
  <h1>NETWATCH</h1>
  <span class="stat"><b id="s-pkts">0</b> pkts</span>
  <span class="stat"><b id="s-bytes">0B</b></span>
  <span class="stat"><b id="s-hosts">0</b> hosts</span>
  <span class="stat" style="color:var(--dim)" id="s-time"></span>
  <div class="services" id="svc-bar"></div>
  <span class="sr-only" id="theme-sel-label">Theme</span>
  <select id="theme-sel" aria-labelledby="theme-sel-label" style="background:var(--surface);color:var(--fg);border:1px solid var(--border);padding:3px 6px;font-size:10px;font-family:inherit;border-radius:3px;cursor:pointer" title="Theme">
    <option value="">Terminal</option><option value="theme-matrix">Matrix</option><option value="theme-midnight">Midnight</option><option value="theme-cyberpunk">Cyberpunk</option><option value="theme-light">Light</option>
  </select>
  <span class="sr-only" id="scan-sel-label">CRT scanlines</span>
  <select id="scanline-sel" aria-labelledby="scan-sel-label" style="background:var(--surface);color:var(--fg);border:1px solid var(--border);padding:3px 6px;font-size:10px;font-family:inherit;border-radius:3px;cursor:pointer" title="CRT Scanlines">
    <option value="">CRT Off</option><option value="soft">CRT Soft</option><option value="heavy">CRT Heavy</option>
  </select>
  <button id="kbd-help-btn" title="Keyboard shortcuts (press ?)" aria-label="Show keyboard shortcuts" style="background:var(--surface);color:var(--fg);border:1px solid var(--border);padding:2px 8px;font-size:11px;font-family:inherit;border-radius:3px;cursor:pointer">?</button>
  <span class="pulse" style="width:8px;height:8px;border-radius:50%;background:var(--good);display:inline-block" title="Live updates streaming" aria-label="Live updates streaming"></span>
</div>
<div id="scanline-overlay"></div>
<div id="tabs"></div>
<div id="charts-row" style="display:none;padding:14px 18px 0">
  <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px" id="charts-grid">
    <div style="background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:10px;height:155px"><div style="color:var(--cyan);font-size:10px;font-weight:700;margin-bottom:2px">TRAFFIC</div><canvas id="chart-traffic"></canvas></div>
    <div style="background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:10px;height:155px"><div style="color:var(--cyan);font-size:10px;font-weight:700;margin-bottom:2px">PROTOCOLS</div><canvas id="chart-proto"></canvas></div>
    <div style="background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:10px;height:155px"><div style="color:var(--cyan);font-size:10px;font-weight:700;margin-bottom:2px">THREATS</div><canvas id="chart-threat"></canvas></div>
  </div>
</div>
<div id="content"></div>
<div id="cmd-bar">
  <label>nw&gt;</label>
  <input id="cmd-input" type="text" placeholder="Type command... (scan / geo / whois / recon / deep / help)  Press / to focus" autocomplete="off" spellcheck="false">
</div>
<div id="ctx-menu"></div>
<div id="output-panel" role="region" aria-label="Command output panel">
  <div id="panel-drag" role="separator" aria-orientation="horizontal" aria-label="Resize output panel"></div>
  <div id="output-hdr">
    <span class="title" id="output-title">OUTPUT</span>
    <button class="panel-btn" id="output-max" title="Maximize" aria-label="Maximize output panel">&#9634;</button>
    <button class="panel-btn" id="output-close" title="Close" aria-label="Close output panel">&times;</button>
  </div>
  <div id="output-body"></div>
</div>
<div id="detail-panel" role="dialog" aria-modal="true" aria-labelledby="detail-title">
  <div id="detail-hdr">
    <span class="title" id="detail-title">HOST DETAIL</span>
    <button class="panel-btn" id="detail-close" title="Close" aria-label="Close host detail">&times;</button>
  </div>
  <div id="detail-body"></div>
</div>
<div id="kbd-help" role="dialog" aria-modal="true" aria-labelledby="kbd-help-title">
  <h3 id="kbd-help-title">Keyboard Shortcuts</h3>
  <table>
    <tr><td><kbd>1</kbd>–<kbd>9</kbd></td><td>Jump to tab</td></tr>
    <tr><td><kbd>0</kbd></td><td>Proxy tab</td></tr>
    <tr><td><kbd>Shift</kbd>+<kbd>M</kbd></td><td>Mesh tab</td></tr>
    <tr><td><kbd>Shift</kbd>+<kbd>H</kbd></td><td>Help tab</td></tr>
    <tr><td><kbd>R</kbd></td><td>Replay tab</td></tr>
    <tr><td><kbd>/</kbd></td><td>Focus command bar</td></tr>
    <tr><td><kbd>?</kbd></td><td>Toggle this overlay</td></tr>
    <tr><td><kbd>Esc</kbd></td><td>Close any open panel</td></tr>
  </table>
  <div class="close-hint">Esc to close</div>
</div>
<script>
const TABS=["all","hosts","proto","dns","honeypot","scan","nmap","arp","alerts","osint","proxy","mesh","replay","help"];
let tab="all",D={};
function $(s){return document.querySelector(s)}
function $$(s){return document.querySelectorAll(s)}
function esc(s){const d=document.createElement("div");d.textContent=s;return d.innerHTML}
function fmtBytes(b){for(const u of["B","KB","MB","GB"]){if(b<1024)return b.toFixed(1)+u;b/=1024}return b.toFixed(1)+"TB"}

function initTabs(){
  const c=$("#tabs");
  c.setAttribute("role","tablist");
  TABS.forEach((t,i)=>{
    const d=document.createElement("button");
    d.className="tab"+(t===tab?" active":"");
    d.setAttribute("role","tab");
    d.setAttribute("aria-selected",t===tab?"true":"false");
    d.style.background="transparent";d.style.border="none";d.style.borderBottom="2px solid transparent";
    d.innerHTML=`<span class="n">${i<9?i+1:0}</span>${t.toUpperCase()}`;
    d.onclick=()=>_activateTabIdx(i);
    c.appendChild(d);
  });
}

function ipClass(h){
  if(h.local)return"ip local";
  if(h.threat_score>=30)return"ip threat-high";
  if(h.threat_score>=10)return"ip threat-med";
  return"ip";
}
function hpClass(svc){
  if(["credential","malware_attempt","ftp_upload"].includes(svc))return"hp-cred";
  if(["telnet","telnet_cmd"].includes(svc))return"hp-telnet";
  if(svc.startsWith("ftp"))return"hp-ftp";
  if(svc.startsWith("rtsp"))return"hp-rtsp";
  return"hp-http";
}

function renderHosts(list,limit){
  const h=list||D.hosts||[];
  const show=h.slice(0,limit||h.length);
  let s=`<table><tr><th style="width:140px">IP</th><th style="width:160px">Hostname</th><th style="width:80px">In</th><th style="width:80px">Out</th><th style="width:60px">Pkts</th><th style="width:50px">Ports</th><th style="width:60px">Threat</th><th>Tags</th></tr>`;
  show.forEach(h=>{
    const tags=h.tags.map(t=>`<span class="tag">${esc(t)}</span>`).join("");
    const thr=h.threat_score>0?`<span style="color:${h.threat_score>=30?'var(--red)':h.threat_score>=10?'var(--yellow)':'var(--dim)'}">${h.threat_score}</span>`:`<span style="color:var(--dim)">0</span>`;
    s+=`<tr class="clickable" onclick="showHostDetail('${esc(h.ip)}')"><td class="${ipClass(h)}"><span class="ip-click" data-ip="${esc(h.ip)}">${esc(h.ip)}</span></td><td>${esc(h.hostname)}</td><td>${fmtBytes(h.bytes_in)}</td><td>${fmtBytes(h.bytes_out)}</td><td>${h.packets.toLocaleString()}</td><td>${h.ports}</td><td>${thr}</td><td>${tags}</td></tr>`;
  });
  return s+"</table>";
}
function _empty(label,hint){return`<div class="empty-state"><div class="label">${esc(label)}</div><div class="hint">${esc(hint||"")}</div></div>`}
function _loading(label){return`<div class="loading-state"><div class="label"><span class="spinner"></span>${esc(label)}</div></div>`}
function renderProto(expanded){
  const p=D.protocols||[];
  if(!p.length)return _empty("No protocol data yet","Waiting for tshark to start capturing — check the TSHARK service indicator.");
  const max=p[0]?.count||1;
  let s=`<table><tr><th style="width:200px">Protocol</th><th style="width:100px">Count</th><th>Distribution</th></tr>`;
  p.forEach(x=>{
    const pct=((x.count/max)*100).toFixed(0);
    s+=`<tr><td style="color:var(--blue)">${esc(x.name)}</td><td>${x.count.toLocaleString()}</td><td><div class="bar-wrap"><div class="bar-fill proto-bar" style="width:${pct}%"></div></div></td></tr>`;
  });
  return s+"</table>";
}
function renderDNS(limit){
  const d=(D.dns||[]).slice(-(limit||50)).reverse();
  if(!d.length)return _empty("No DNS queries yet","Run nslookup or wait for traffic with DNS lookups.");
  let s=`<table><tr><th style="width:80px">Time</th><th style="width:140px">IP</th><th>Domain</th></tr>`;
  d.forEach(e=>{s+=`<tr><td style="color:var(--dim)">${esc(e.time)}</td><td class="ip"><span class="ip-click" data-ip="${esc(e.ip)}">${esc(e.ip)}</span></td><td style="color:var(--magenta)">${esc(e.domain)}</td></tr>`});
  return s+"</table>";
}
function renderHP(limit){
  // HTTP events live in the Scan tab (they're high-volume scanner noise that drowns out
  // credential/telnet/ftp/rtsp signal). Mirrors the TUI's _section_honeypot(show_http=False) default.
  const h=(D.honeypot||[]).filter(e=>e.service!=="http").slice(-(limit||50)).reverse();
  if(!h.length)return _empty("No honeypot hits yet","Honeypots are listening on :21 / :23 / :80 / :554 — waiting for attackers.");
  let s=`<table><tr><th style="width:70px">Time</th><th style="width:100px">Service</th><th style="width:130px">IP</th><th>Summary</th></tr>`;
  h.forEach(e=>{s+=`<tr><td style="color:var(--dim)">${esc(e.time)}</td><td class="${hpClass(e.service)}">${esc(e.service)}</td><td class="ip"><span class="ip-click" data-ip="${esc(e.ip)}">${esc(e.ip)}</span></td><td>${esc(e.summary)}</td></tr>`});
  return s+"</table>";
}
function renderScan(limit){
  // HTTP probes split out from the honeypot tab — Mirai/CVE scanners hammer :80 constantly,
  // so this view is its own signal class (path coverage, user agents, scanner identification).
  const h=(D.honeypot||[]).filter(e=>e.service==="http").slice(-(limit||100)).reverse();
  if(!h.length)return _empty("No HTTP probes yet","HTTP scan/probe traffic appears here once attackers hit :80.");
  let s=`<table><tr><th style="width:70px">Time</th><th style="width:130px">IP</th><th>Probe</th></tr>`;
  h.forEach(e=>{s+=`<tr><td style="color:var(--dim)">${esc(e.time)}</td><td class="ip"><span class="ip-click" data-ip="${esc(e.ip)}">${esc(e.ip)}</span></td><td>${esc(e.summary)}</td></tr>`});
  return s+"</table>";
}
function renderNmap(){
  const n=D.nmap||[];
  const status=D.nmap_running?`<span style="color:var(--yellow);animation:pulse 1s infinite">SCANNING...</span>`:`<span style="color:var(--dim)">idle</span>`;
  let s=`<div class="section-title">NMAP ${status} <span class="count">(${n.length} results)</span></div>`;
  if(!n.length)return s+_empty("No scans yet","Type 'scan <ip>' or 'deep <ip>' in the command bar.");
  const ips=new Set();
  n.forEach(r=>{const m=r.line.match(/(\d+\.\d+\.\d+\.\d+)/);if(m)ips.add(m[1])});
  if(ips.size){
    s+=`<div style="margin:8px 0;display:flex;gap:6px;flex-wrap:wrap">`;
    ips.forEach(ip=>{s+=`<span class="ip-click port-chip" data-ip="${esc(ip)}" onclick="showScanDetail('${esc(ip)}')" style="cursor:pointer">${esc(ip)}</span>`});
    s+=`</div>`;
  }
  s+=`<table><tr><th style="width:70px">Time</th><th>Result</th></tr>`;
  n.slice(-30).reverse().forEach(r=>{
    const m=r.line.match(/(\d+\.\d+\.\d+\.\d+)/);
    const click=m?` class="clickable" onclick="showScanDetail('${esc(m[1])}')"`:"";
    s+=`<tr${click}><td style="color:var(--dim)">${esc(r.time)}</td><td>${esc(r.line)}</td></tr>`;
  });
  return s+"</table>";
}
function renderARP(){
  const a=D.arp||[];
  if(!a.length)return _empty("No ARP entries yet","ARP monitor watches your subnet — devices appear as they speak on the wire.");
  let s=`<table><tr><th style="width:180px">MAC</th><th style="width:140px">IP</th><th>State</th></tr>`;
  a.forEach(e=>{s+=`<tr class="clickable" onclick="showHostDetail('${esc(e.ip)}')"><td style="color:var(--cyan)">${esc(e.mac)}</td><td class="ip"><span class="ip-click" data-ip="${esc(e.ip)}">${esc(e.ip)}</span></td><td style="color:var(--dim)">${esc(e.state)}</td></tr>`});
  return s+"</table>";
}
function renderAlerts(){
  const a=(D.alerts||[]).slice(-50).reverse();
  if(!a.length)return _empty("All quiet","No threat alerts yet. Alerts appear here when scoring fires or honeypots see credentials.");
  let s=`<table><tr><th style="width:70px">Time</th><th>Alert</th></tr>`;
  a.forEach(e=>{
    const m=e.msg.match(/(\d+\.\d+\.\d+\.\d+)/);
    const click=m?` class="clickable" onclick="showHostDetail('${esc(m[1])}')"`:"";
    s+=`<tr class="alert-row"${click}><td>${esc(e.time)}</td><td>${esc(e.msg)}</td></tr>`;
  });
  return s+"</table>";
}
function renderOSINT(){
  const o=(D.osint||[]).slice(-50).reverse();
  if(!o.length)return _empty("No OSINT results yet","Run geo, whois, abuse, ssl, recon, etc. — results show here as they finish.");
  let s=`<table><tr><th style="width:70px">Time</th><th style="width:60px">Type</th><th style="width:160px">Target</th><th>Result</th><th style="width:60px">Detail</th></tr>`;
  o.forEach(r=>{
    const cls={"GEO":"osint-geo","DNS":"osint-dns","SCAN":"osint-scan","ABUSE":"osint-abuse","WHOIS":"osint-whois","CRT":"osint-dns","SSL":"osint-geo","PING":"osint-scan","SECHDR":"osint-abuse","TECH":"osint-whois"}[r.type]||"";
    const isIP=/^\d+\.\d+\.\d+\.\d+$/.test(r.target);
    const detailBtn=isIP?`<span class="port-chip" style="cursor:pointer" onclick="showHostDetail('${esc(r.target)}')">View</span>`:"";
    s+=`<tr class="osint-row"><td style="color:var(--dim)">${esc(r.time)}</td><td class="${cls}" style="font-weight:700">${esc(r.type)}</td><td>${isIP?`<span class="ip-click" data-ip="${esc(r.target)}">${esc(r.target)}</span>`:esc(r.target)}</td><td style="white-space:normal;word-break:break-word">${esc(r.result)}</td><td>${detailBtn}</td></tr>`;
  });
  return s+"</table>";
}
function renderProxy(){
  let s="";
  if(D.proxy_active){s+=`<div style="color:var(--green);font-weight:700;margin-bottom:12px">PROXY ACTIVE</div>`}
  else{s+=`<div style="color:var(--dim);margin-bottom:12px">Proxy not active. Use <span style="color:var(--green)">proxy add socks5 127.0.0.1:9050</span> to configure.</div>`}
  return s;
}
let _replayCache=null,_replayCacheAt=0,_replayProto="ftp",_replayFilter="";
function renderReplay(){
  let s=`<div class="section-title">SESSION REPLAY
    <span class="count" id="replay-count">(loading...)</span>
    <span style="margin-left:auto;display:flex;gap:6px;align-items:center;flex-wrap:wrap">
      <input id="replay-filter" placeholder="filter ip / id..." value="${esc(_replayFilter)}"
        style="background:var(--bg);border:1px solid var(--border);color:var(--fg);font:inherit;font-size:11px;padding:3px 8px;border-radius:3px;width:160px;outline:none">
      <button onclick="_replayRefresh(true)" aria-label="Refresh sessions" title="Refresh"
        style="background:var(--surface);color:var(--fg);border:1px solid var(--border);padding:3px 10px;border-radius:3px;cursor:pointer;font:inherit;font-size:11px">&#x21bb; Refresh</button>
    </span>
  </div>`;
  s+=`<div id="replay-body">${_loading("Loading captured sessions...")}</div>`;
  // schedule render after innerHTML flush
  setTimeout(_replayMount,0);
  return s;
}
function _replayMount(){
  const inp=document.getElementById("replay-filter");
  if(inp){
    inp.oninput=()=>{_replayFilter=inp.value.trim().toLowerCase();_replayPaint()};
    inp.focus();const v=inp.value;inp.value="";inp.value=v;
  }
  _replayRefresh(false);
}
async function _replayRefresh(force){
  const fresh=force||!_replayCache||(Date.now()-_replayCacheAt>15000);
  if(fresh){
    try{
      const r=await fetch("/api/replay");
      _replayCache=await r.json();_replayCacheAt=Date.now();
    }catch(e){_replayCache=[]}
  }
  _replayPaint();
}
function _replayPaint(){
  const body=document.getElementById("replay-body");
  const cnt=document.getElementById("replay-count");
  if(!body)return;
  const all=Array.isArray(_replayCache)?_replayCache:[];
  const f=_replayFilter;
  const rows=f?all.filter(s=>(s.session_id||"").toLowerCase().includes(f)||(s.ip||"").toLowerCase().includes(f)):all;
  if(cnt)cnt.textContent=`(${rows.length}${f?` / ${all.length}`:""} sessions)`;
  if(!rows.length){
    body.innerHTML=f?_empty("No sessions match the filter","Clear the filter to see all captured sessions.")
      :_empty("No replay sessions yet","Captured FTP/Telnet sessions land in logs/ — wait for honeypot hits or sync the droplet captures.");
    return;
  }
  let h=`<table class="fade-in"><tr>
    <th style="width:90px">When</th><th style="width:60px">Proto</th><th style="width:140px">IP</th>
    <th>Session ID</th><th style="width:80px;text-align:right">Size</th><th style="width:90px">Action</th></tr>`;
  rows.slice(0,200).forEach(s=>{
    const when=_fmtAgo(s.started_at_mtime);
    const protoCls=s.protocol==="telnet"?"hp-telnet":"hp-ftp";
    h+=`<tr><td style="color:var(--muted)">${esc(when)}</td>`+
       `<td><span class="${protoCls}" style="font-weight:600;text-transform:uppercase">${esc(s.protocol||"?")}</span></td>`+
       `<td class="ip"><span class="ip-click" data-ip="${esc(s.ip||"")}">${esc(s.ip||"")}</span></td>`+
       `<td style="color:var(--fg);font-size:11px">${esc(s.session_id)}</td>`+
       `<td style="text-align:right;color:var(--muted)">${(s.event_count||0).toLocaleString()}</td>`+
       `<td><button onclick="showReplayDetail('${esc(s.session_id)}','${esc(s.protocol||"ftp")}')" `+
       `aria-label="Replay session ${esc(s.session_id)}" `+
       `style="background:var(--accent);color:var(--bg);border:none;padding:3px 10px;border-radius:3px;cursor:pointer;font:inherit;font-size:11px;font-weight:600">&#9658; Play</button></td></tr>`;
  });
  h+=`</table>`;
  if(rows.length>200)h+=`<div style="color:var(--muted);font-size:11px;padding:8px 0">Showing 200 of ${rows.length}. Use the filter to narrow.</div>`;
  body.innerHTML=h;
}
function _fmtAgo(iso){
  if(!iso)return"—";
  const t=new Date(iso).getTime();
  if(!t)return iso;
  const s=Math.max(0,Math.floor((Date.now()-t)/1000));
  if(s<60)return s+"s ago";
  if(s<3600)return Math.floor(s/60)+"m ago";
  if(s<86400)return Math.floor(s/3600)+"h ago";
  return Math.floor(s/86400)+"d ago";
}
function showReplayDetail(sid,proto){
  const p=$("#detail-panel"),b=$("#detail-body"),t=$("#detail-title");
  t.textContent=`Replay: ${sid} (${proto.toUpperCase()})`;
  b.innerHTML=`<iframe src="/replay/${encodeURIComponent(sid)}?proto=${encodeURIComponent(proto)}" `+
    `title="Session replay player for ${esc(sid)}" `+
    `style="width:100%;height:70vh;border:1px solid var(--border);border-radius:4px;background:var(--bg)"></iframe>`;
  p.classList.add("open");
}

function renderMesh(){
  if(!D.mesh_connected)return _empty("Meshtastic not connected","Plug a LoRa radio (T-Beam / Heltec) over USB and restart NetWatch.");
  let s=`<div style="color:var(--green);font-weight:700;margin-bottom:8px">MESH RADIO CONNECTED</div>`;
  s+=`<div style="margin-bottom:12px;color:var(--dim)">Nodes: ${D.mesh_nodes||0} | Messages: ${D.mesh_msgs||0} | Alert forwarding: ${D.mesh_alert_fwd?"ON":"OFF"}</div>`;
  s+=`<div style="margin-bottom:8px"><input id="mesh-input" type="text" placeholder="Send mesh message..." style="background:var(--bg);border:1px solid var(--border);color:var(--text);font-family:inherit;font-size:12px;padding:6px 10px;border-radius:4px;width:60%;outline:none"><button onclick="sendMesh()" style="background:var(--green);color:var(--bg);border:none;padding:6px 14px;margin-left:6px;border-radius:4px;cursor:pointer;font-family:inherit;font-weight:700">SEND</button></div>`;
  return s;
}
function renderHelp(){
  const S="color:var(--cyan);font-size:13px;font-weight:700;margin:16px 0 8px;border-bottom:1px solid var(--border);padding-bottom:4px";
  const C="color:var(--green)";
  const D2="color:var(--dim);font-size:11px";
  let s=`<div style="max-width:800px">`;
  s+=`<div style="color:var(--red);font-size:16px;font-weight:700;margin-bottom:4px">NETWATCH COMMAND REFERENCE</div>`;
  s+=`<div style="${D2};margin-bottom:16px">Type any command in the bar below. Use @N to reference IPs by index from the hosts list.</div>`;
  s+=`<div style="${S}">OSINT (16 tools)</div><table>`;
  s+=`<tr><th style="width:180px">Command</th><th>Description</th></tr>`;
  const osint=[["geo &lt;ip&gt;","IP geolocation"],["whois &lt;ip/domain&gt;","WHOIS lookup"],["dnsinfo &lt;domain&gt;","DNS enumeration (A/AAAA/MX/NS/TXT/SOA/CNAME/SRV)"],
    ["rdns &lt;ip&gt;","Reverse DNS (PTR)"],["ssl &lt;host&gt; [port]","TLS certificate inspection"],["secheaders &lt;url&gt;","Security header audit + grade"],
    ["techstack &lt;url&gt;","Web technology fingerprinting"],["ping &lt;ip&gt; [count]","Jitter analysis + TTL OS guess"],
    ["health &lt;target&gt;","Full profile (ping + SSL + headers + tech + geo + DNS)"],["etrace &lt;target&gt;","Enriched traceroute with per-hop GeoIP"],
    ["portscan &lt;ip&gt;","Socket-based top 1000 port scan"],["subnet [cidr]","Threaded ping sweep"],
    ["crt &lt;domain&gt;","Certificate transparency search"],["headers &lt;url&gt;","HTTP response headers"],
    ["asn &lt;ip&gt;","ASN/BGP info"],["abuse &lt;ip&gt;","IP reputation check"],["speed","Network speed test"],["ifinfo","Local interface + routing info"]];
  osint.forEach(([c,d])=>{s+=`<tr><td style="${C}">${c}</td><td>${d}</td></tr>`});
  s+=`</table>`;
  s+=`<div style="${S}">Scanning</div><table><tr><th style="width:180px">Command</th><th>Description</th></tr>`;
  [["scan &lt;ip&gt; [preset]","Nmap scan (quick/syn/udp/ping/full)"],["deep &lt;ip&gt;","All ports + vuln scripts"],
   ["stealth &lt;ip&gt;","SYN scan through Tor"],["recon &lt;ip&gt;","Full OSINT profile"],["fullrecon &lt;ip&gt;","7-phase recon chain"],
   ["sweep [cidr]","ARP + ping + port scan"],["banner &lt;ip&gt; &lt;port&gt;","Service banner grab"],["trace &lt;ip&gt;","Traceroute"]
  ].forEach(([c,d])=>{s+=`<tr><td style="${C}">${c}</td><td>${d}</td></tr>`});
  s+=`</table>`;
  s+=`<div style="${S}">Tracking &amp; Capture</div><table><tr><th style="width:180px">Command</th><th>Description</th></tr>`;
  [["track &lt;ip&gt; [secs]","Live packet tail (tshark)"],["untrack &lt;ip&gt;","Stop tracking"],
   ["conns &lt;ip&gt;","TCP conversation capture"],["sniff &lt;ip&gt; [secs]","Raw payload capture"],
   ["trackdns &lt;ip&gt;","DNS query capture"],["tracking","List active tracks"],
   ["pcap start/stop","PCAP recording to file"]
  ].forEach(([c,d])=>{s+=`<tr><td style="${C}">${c}</td><td>${d}</td></tr>`});
  s+=`</table>`;
  s+=`<div style="${S}">Smart Filters</div><table><tr><th style="width:180px">Command</th><th>Description</th></tr>`;
  [["top [n]","Top N talkers"],["sus","Suspicious hosts (threat > 0)"],["new [mins]","Recently appeared"],
   ["loud","Most ports touched"],["find &lt;pattern&gt;","Search all data"],["ports &lt;port&gt;","Hosts using port"],
   ["country &lt;CC&gt;","Filter by country"],["whowatch","Active attackers"],["summary","Network overview"]
  ].forEach(([c,d])=>{s+=`<tr><td style="${C}">${c}</td><td>${d}</td></tr>`});
  s+=`</table>`;
  s+=`<div style="${S}">Attack Analysis</div><table><tr><th style="width:180px">Command</th><th>Description</th></tr>`;
  [["inspect [n]","View honeypot event detail"],["analyze &lt;ip&gt;","Attacker profile"],
   ["decode &lt;data&gt;","Decode payload"],["sessions","All attacker IPs"],
   ["attackers","Honeypot IPs"],["profile &lt;ip&gt;","Recon report"],
   ["timeline &lt;ip&gt;","Full event history"],["report &lt;ip&gt;","Save full report"]
  ].forEach(([c,d])=>{s+=`<tr><td style="${C}">${c}</td><td>${d}</td></tr>`});
  s+=`</table>`;
  s+=`<div style="${S}">Defense</div><table><tr><th style="width:180px">Command</th><th>Description</th></tr>`;
  [["block &lt;ip&gt;","iptables DROP"],["unblock &lt;ip&gt;","Remove block"],
   ["blocked","List current rules"],["diffarp","ARP table change detection"]
  ].forEach(([c,d])=>{s+=`<tr><td style="${C}">${c}</td><td>${d}</td></tr>`});
  s+=`</table>`;
  s+=`<div style="${S}">Tags, Notes &amp; Watchlist</div><table><tr><th style="width:180px">Command</th><th>Description</th></tr>`;
  [["tag &lt;ip&gt; &lt;label&gt;","Label an IP"],["tag list","Show all tags"],["note &lt;ip&gt; &lt;text&gt;","Add note"],
   ["watch &lt;ip&gt;","Add to watchlist"],["watch list","Show watchlist"],["watch rm &lt;ip&gt;","Remove from watchlist"]
  ].forEach(([c,d])=>{s+=`<tr><td style="${C}">${c}</td><td>${d}</td></tr>`});
  s+=`</table>`;
  s+=`<div style="${S}">Batch Operations</div><table><tr><th style="width:180px">Command</th><th>Description</th></tr>`;
  [["scanall [list]","Scan all IPs in list"],["reconall [list]","Full recon all"],
   ["geoall [list]","Geolocate all"],["whoisall [list]","WHOIS all"],
   ["blockall attackers","Block all honeypot IPs"]
  ].forEach(([c,d])=>{s+=`<tr><td style="${C}">${c}</td><td>${d}</td></tr>`});
  s+=`</table>`;
  s+=`<div style="${D2};margin-top:8px">Lists: hosts, attackers, arp, nmap, watchlist, tracked, blocked</div>`;
  s+=`<div style="${S}">Proxy / Tor</div><table><tr><th style="width:180px">Command</th><th>Description</th></tr>`;
  [["proxy add &lt;type&gt; &lt;h:p&gt;","Add proxy (socks4/socks5/http)"],["proxy list","Show configured proxies"],
   ["proxy test [n]","Test proxy connection"],["proxy start","Start Tor circuits"],["proxy rotate","Toggle rotation"]
  ].forEach(([c,d])=>{s+=`<tr><td style="${C}">${c}</td><td>${d}</td></tr>`});
  s+=`</table>`;
  s+=`<div style="${S}">Mesh Radio</div><table><tr><th style="width:180px">Command</th><th>Description</th></tr>`;
  [["mesh send &lt;text&gt;","Send mesh message"],["mesh status","Connection info"],
   ["mesh nodes","List mesh nodes"],["mesh alert on/off","Toggle alert forwarding"]
  ].forEach(([c,d])=>{s+=`<tr><td style="${C}">${c}</td><td>${d}</td></tr>`});
  s+=`</table>`;
  s+=`<div style="${S}">Export &amp; System</div><table><tr><th style="width:180px">Command</th><th>Description</th></tr>`;
  [["exportips [list]","Save IPs to file"],["report &lt;ip&gt;","Full text report"],
   ["export","Save traffic JSON"],["clear","Clear output"],
   ["status","Service info"],["help","This page"]
  ].forEach(([c,d])=>{s+=`<tr><td style="${C}">${c}</td><td>${d}</td></tr>`});
  s+=`</table>`;
  s+=`<div style="${D2};margin-top:16px;border-top:1px solid var(--border);padding-top:8px">Keyboard: 1-0 = tab switch &nbsp;|&nbsp; / = focus command bar &nbsp;|&nbsp; ESC = close panels &nbsp;|&nbsp; Click any IP for context menu</div>`;
  s+=`</div>`;
  return s;
}

let _charts={};
function _css(n){return getComputedStyle(document.body).getPropertyValue(n).trim()||"#c8ccd4"}
function _rgba(hex,a){
  const h=hex.replace("#","");
  if(h.length!==3&&h.length!==6)return hex;
  const v=h.length===3?h.split("").map(c=>c+c).join(""):h;
  const r=parseInt(v.slice(0,2),16),g=parseInt(v.slice(2,4),16),b=parseInt(v.slice(4,6),16);
  return`rgba(${r},${g},${b},${a})`;
}
function _chartPalette(){
  return{
    fg:_css("--fg"),muted:_css("--muted"),accent:_css("--accent"),
    info:_css("--info"),good:_css("--good"),warn:_css("--warn"),
    magenta:_css("--magenta"),blue:_css("--blue"),
    threatHigh:_css("--threat-high"),threatMed:_css("--threat-med"),threatLow:_css("--threat-low"),
    grid:_rgba(_css("--fg")||"#fff",.05),gridSubtle:_rgba(_css("--fg")||"#fff",.03)
  };
}
function initCharts(){
  if(typeof Chart==="undefined")return;
  if(_charts.traffic)return;
  const ctx1=document.getElementById("chart-traffic");
  const ctx2=document.getElementById("chart-proto");
  const ctx3=document.getElementById("chart-threat");
  if(!ctx1||!ctx2||!ctx3)return;
  const p=_chartPalette();
  const cfg={responsive:true,maintainAspectRatio:false,animation:{duration:300},
    plugins:{legend:{labels:{color:p.fg,font:{size:10}}}}};
  _charts.traffic=new Chart(ctx1,{type:"line",data:{labels:[],datasets:[
    {label:"Packets",data:[],borderColor:p.info,backgroundColor:_rgba(p.info,.1),fill:true,tension:.3,pointRadius:0},
    {label:"Bytes (KB)",data:[],borderColor:p.accent,backgroundColor:_rgba(p.accent,.1),fill:true,tension:.3,pointRadius:0,yAxisID:"y1"}
  ]},options:{...cfg,scales:{x:{ticks:{color:p.muted,maxTicksLimit:8},grid:{color:p.gridSubtle}},
    y:{ticks:{color:p.info},grid:{color:p.grid}},
    y1:{position:"right",ticks:{color:p.accent},grid:{drawOnChartArea:false}}}}});
  _charts.proto=new Chart(ctx2,{type:"doughnut",data:{labels:[],datasets:[{data:[],
    backgroundColor:[p.info,p.accent,p.good,p.warn,p.magenta,p.blue,p.threatMed,p.threatLow,p.fg,p.muted]}]},
    options:{...cfg,plugins:{...cfg.plugins,legend:{position:"right",labels:{color:p.fg,font:{size:10},padding:8}}}}});
  _charts.threat=new Chart(ctx3,{type:"bar",data:{labels:["Clean","Low","Medium","High"],datasets:[{data:[0,0,0,0],
    backgroundColor:[_rgba(p.good,.15),_rgba(p.warn,.15),_rgba(p.threatMed,.18),_rgba(p.threatHigh,.2)],
    borderColor:[p.good,p.warn,p.threatMed,p.threatHigh],borderWidth:1}]},
    options:{...cfg,plugins:{...cfg.plugins,legend:{display:false}},
    scales:{x:{ticks:{color:p.muted},grid:{color:p.gridSubtle}},
    y:{ticks:{color:p.muted},grid:{color:p.grid}}}}});
}
function _destroyCharts(){
  ["traffic","proto","threat"].forEach(k=>{if(_charts[k]){_charts[k].destroy();delete _charts[k]}});
}

let _tsData=[];
function updateCharts(){
  if(!_charts.traffic)return;
  const td=D.threat_dist||{};
  _charts.threat.data.datasets[0].data=[td.clean||0,td.low||0,td.medium||0,td.high||0];
  _charts.threat.update();
  const p=D.protocols||[];
  _charts.proto.data.labels=p.map(x=>x.name);
  _charts.proto.data.datasets[0].data=p.map(x=>x.count);
  _charts.proto.update();
}
function loadTimeseries(){
  fetch("/api/timeseries").then(r=>r.json()).then(samples=>{
    if(!_charts.traffic||!samples.length)return;
    _tsData=samples;
    const labels=samples.map(s=>{const d=new Date(s.ts*1000);return d.getHours()+":"+String(d.getMinutes()).padStart(2,"0")});
    let prevPkts=samples[0].packets;let prevBytes=samples[0].bytes;
    const pktRates=[];const byteRates=[];
    samples.forEach((s,i)=>{
      if(i===0){pktRates.push(0);byteRates.push(0);return}
      pktRates.push(s.packets-prevPkts);
      byteRates.push(Math.round((s.bytes-prevBytes)/1024));
      prevPkts=s.packets;prevBytes=s.bytes;
    });
    _charts.traffic.data.labels=labels;
    _charts.traffic.data.datasets[0].data=pktRates;
    _charts.traffic.data.datasets[1].data=byteRates;
    _charts.traffic.update();
  }).catch(()=>{});
}

function render(){
  const c=$("#content"),cr=$("#charts-row");
  let html="";
  if(tab==="all"){
    cr.style.display="block";
    html+=`<div class="section-title">HOSTS <span class="count">(${D.host_count||0})</span></div>`;
    html+=renderHosts(null,10);
    html+=`<div class="section-title">PROTOCOLS <span class="count">(${(D.protocols||[]).length})</span></div>`;
    html+=renderProto();
    html+=`<div class="section-title">DNS <span class="count">(${(D.dns||[]).length})</span></div>`;
    html+=renderDNS(5);
    html+=`<div class="section-title">HONEYPOT <span class="count">(${(D.honeypot||[]).filter(e=>e.service!=="http").length})</span></div>`;
    html+=renderHP(5);
    if((D.alerts||[]).length){html+=`<div class="section-title" style="color:var(--red)">ALERTS <span class="count">(${D.alerts.length})</span></div>`;html+=renderAlerts()}
  }else{cr.style.display="none"}
  if(tab==="hosts"){
    html+=`<div class="section-title">HOSTS <span class="count">(${D.host_count||0})</span></div>`;
    html+=renderHosts();
  }else if(tab==="proto"){
    html+=`<div class="section-title">PROTOCOLS</div>`;
    html+=renderProto(true);
  }else if(tab==="dns"){
    html+=`<div class="section-title">DNS QUERIES</div>`;
    html+=renderDNS();
  }else if(tab==="honeypot"){
    html+=`<div class="section-title">HONEYPOT EVENTS</div>`;
    html+=renderHP();
  }else if(tab==="scan"){
    html+=`<div class="section-title">SCAN PROBES <span class="count">(${(D.honeypot||[]).filter(e=>e.service==="http").length})</span></div>`;
    html+=renderScan();
  }else if(tab==="nmap"){
    html+=renderNmap();
  }else if(tab==="arp"){
    html+=`<div class="section-title">DEVICES (ARP) <span class="count">(${(D.arp||[]).length})</span></div>`;
    html+=renderARP();
  }else if(tab==="alerts"){
    html+=`<div class="section-title" style="color:var(--red)">ALERTS <span class="count">(${(D.alerts||[]).length})</span></div>`;
    html+=renderAlerts();
  }else if(tab==="osint"){
    html+=`<div class="section-title">OSINT RESULTS <span class="count">(${(D.osint||[]).length})</span></div>`;
    html+=renderOSINT();
  }else if(tab==="proxy"){
    html+=`<div class="section-title">PROXY / TOR</div>`;
    html+=renderProxy();
  }else if(tab==="mesh"){
    html+=`<div class="section-title">MESH RADIO</div>`;
    html+=renderMesh();
  }else if(tab==="replay"){
    html+=renderReplay();
  }else if(tab==="help"){
    html+=renderHelp();
  }
  c.innerHTML=html;
  if(tab==="all"){initCharts();updateCharts()}
}

function updateHeader(){
  $("#s-time").textContent=D.time||"";
  $("#s-pkts").textContent=(D.total_packets||0).toLocaleString();
  $("#s-bytes").textContent=D.total_bytes_fmt||"0B";
  $("#s-hosts").textContent=D.host_count||0;
  const svcs=[
    ["SNIFF",true],["TSHARK",(D.protocols||[]).length>0],
    ["TCPDUMP",D.tcpdump_active],["NMAP",D.nmap_running],["TOR",D.proxy_active],
    ["MESH",D.mesh_connected]
  ];
  $("#svc-bar").innerHTML=svcs.map(([n,on])=>`<span class="svc ${on?"on":n==="NMAP"?"warn":"off"}">${n}</span>`).join("");
}

let evtSrc,_tsCounter=0;
let _lastCounts="",_renderPending=false;
let _sseBackoff=1000,_sseExpired=false;
function _sseStatus(state){
  const dot=document.querySelector("#header .pulse");
  if(!dot)return;
  if(state==="ok"){dot.style.background="var(--good)";dot.title="Live updates streaming"}
  else if(state==="retry"){dot.style.background="var(--warn)";dot.title="Reconnecting..."}
  else if(state==="expired"){dot.style.background="var(--threat-high)";dot.title="Session expired"}
}
function _showAuthExpired(){
  if(_sseExpired)return;
  _sseExpired=true;
  const wrap=document.createElement("div");
  wrap.id="auth-expired";
  wrap.setAttribute("role","alertdialog");
  wrap.style.cssText="position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.75);z-index:1200;display:flex;align-items:center;justify-content:center;backdrop-filter:blur(2px)";
  wrap.innerHTML=`<div style="background:var(--surface);border:1px solid var(--threat-high);border-radius:8px;padding:22px 28px;max-width:90vw;width:380px;text-align:center">
    <div style="color:var(--threat-high);font-weight:700;font-size:14px;margin-bottom:10px">SESSION EXPIRED</div>
    <div style="color:var(--fg);font-size:12px;margin-bottom:14px;line-height:1.5">Your auth cookie is no longer valid (token rotation or restart).<br>Reload and paste the current token.</div>
    <button onclick="location.reload()" style="background:var(--accent);color:var(--bg);border:none;padding:8px 22px;border-radius:4px;cursor:pointer;font:inherit;font-weight:600">Reload</button>
  </div>`;
  document.body.appendChild(wrap);
}
function connect(){
  if(_sseExpired)return;
  try{evtSrc=new EventSource("/api/stream")}catch(e){console.warn("SSE construct failed:",e);return}
  evtSrc.onopen=()=>{_sseBackoff=1000;_sseStatus("ok")};
  evtSrc.onmessage=e=>{
    try{
      D=JSON.parse(e.data);
      updateHeader();
      const counts=`${D.host_count}|${(D.dns||[]).length}|${(D.honeypot||[]).length}|${(D.nmap||[]).length}|${(D.alerts||[]).length}|${(D.osint||[]).length}|${(D.arp||[]).length}|${D.nmap_running}|${tab}`;
      if(counts!==_lastCounts&&tab!=="replay"){
        _lastCounts=counts;
        if(!_renderPending){
          _renderPending=true;
          requestAnimationFrame(()=>{
            const el=$("#content");
            const scrollY=el?el.scrollTop:0;
            render();
            if(el)el.scrollTop=scrollY;
            _renderPending=false;
          });
        }
      }
      if(tab==="all"&&_charts.traffic){updateCharts();_tsCounter++;if(_tsCounter%10===0)loadTimeseries()}
    }catch(err){console.warn("SSE parse error:",err)}
  };
  evtSrc.onerror=()=>{
    if(evtSrc){evtSrc.close();evtSrc=null}
    // Probe / to detect 401 vs simple disconnect — if 401, prompt re-auth.
    fetch("/api/state",{credentials:"same-origin"}).then(r=>{
      if(r.status===401){_showAuthExpired();_sseStatus("expired");return}
      _sseStatus("retry");
      setTimeout(connect,_sseBackoff);
      _sseBackoff=Math.min(_sseBackoff*2,30000);
    }).catch(()=>{
      _sseStatus("retry");
      setTimeout(connect,_sseBackoff);
      _sseBackoff=Math.min(_sseBackoff*2,30000);
    });
  };
}

async function sendMesh(){
  const inp=document.getElementById("mesh-input");
  if(!inp)return;
  const text=inp.value.trim();
  if(!text)return;
  inp.value="";
  try{
    await fetch("/api/mesh/send",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({text})});
  }catch(e){}
}

const CTX_ACTIONS=[
  {label:"View Detail",cmd:"_detail",k:"v"},
  {sep:true},
  {label:"Scan",cmd:"scan",k:"s"},{label:"Deep Scan",cmd:"deep",k:"d"},
  {label:"Geo",cmd:"geo",k:"g"},{label:"Whois",cmd:"whois",k:"w"},
  {label:"DNS Info",cmd:"dnsinfo",k:""},{label:"Abuse",cmd:"abuse",k:""},
  {label:"ASN",cmd:"asn",k:""},{label:"SSL Cert",cmd:"ssl",k:""},
  {sep:true},
  {label:"Traceroute",cmd:"trace",k:"t"},{label:"Ping",cmd:"ping",k:"p"},
  {label:"Port Scan",cmd:"portscan",k:""},
  {sep:true},
  {label:"Analyze",cmd:"analyze",k:"a"},{label:"Timeline",cmd:"timeline",k:""},
  {label:"Full Recon",cmd:"fullrecon",k:"f"},
  {sep:true},
  {label:"Tag",cmd:"tag",k:"",prompt:true},{label:"Watch",cmd:"watch",k:""},
  {label:"Note",cmd:"note",k:"",prompt:true},
];

function showCtxMenu(ip,x,y){
  const m=$("#ctx-menu");
  let html=`<div class="ctx-hdr">${esc(ip)}</div>`;
  CTX_ACTIONS.forEach(a=>{
    if(a.sep){html+=`<div class="ctx-sep"></div>`;return}
    html+=`<div class="ctx-item" data-cmd="${a.cmd}" data-ip="${esc(ip)}" data-prompt="${a.prompt||false}">${a.label}${a.k?`<span class="k">${a.k}</span>`:""}</div>`;
  });
  m.innerHTML=html;
  m.style.left=Math.min(x,window.innerWidth-200)+"px";
  m.style.top=Math.min(y,window.innerHeight-m.scrollHeight-20)+"px";
  m.style.display="block";
  m.querySelectorAll(".ctx-item").forEach(el=>{
    el.onclick=()=>{
      const cmd=el.dataset.cmd,ip=el.dataset.ip;
      m.style.display="none";
      if(cmd==="_detail"){showHostDetail(ip);return}
      if(el.dataset.prompt==="true"){
        const val=prompt(cmd+" "+ip+" — enter value:");
        if(val)runCmd(cmd+" "+ip+" "+val);
      }else{runCmd(cmd+" "+ip)}
    };
  });
}

function showOutput(title,lines){
  const p=$("#output-panel");
  $("#output-title").textContent=title;
  $("#output-body").innerHTML=lines.map(l=>esc(l)).join("\n");
  p.classList.add("open");
}

async function runCmd(cmd){
  showOutput("Running: "+cmd,["..."]);
  try{
    const r=await fetch("/api/cmd",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({cmd})});
    const d=await r.json();
    if(d.error){showOutput("Error",["Error: "+d.error])}
    else{showOutput(cmd,d.output||["(no output)"])}
  }catch(err){showOutput("Error",["Connection error: "+err.message])}
}

async function showHostDetail(ip){
  const p=$("#detail-panel"),b=$("#detail-body"),t=$("#detail-title");
  t.textContent="Loading "+ip+"...";
  b.innerHTML=`<div style="color:var(--dim)">Fetching...</div>`;
  p.classList.add("open");
  try{
    const r=await fetch("/api/host/"+ip);
    const d=await r.json();
    if(d.error){b.innerHTML=`<div style="color:var(--red)">${esc(d.error)}</div>`;t.textContent=ip;return}
    t.textContent=ip+(d.hostname?` (${d.hostname})`:"");
    let html=`<div class="detail-section"><h3>Overview</h3>`;
    html+=`<div class="detail-row"><span class="detail-label">Traffic In</span><span class="detail-val">${fmtBytes(d.bytes_in)}</span></div>`;
    html+=`<div class="detail-row"><span class="detail-label">Traffic Out</span><span class="detail-val">${fmtBytes(d.bytes_out)}</span></div>`;
    html+=`<div class="detail-row"><span class="detail-label">Packets</span><span class="detail-val">${(d.packets||0).toLocaleString()}</span></div>`;
    html+=`<div class="detail-row"><span class="detail-label">Threat Score</span><span class="detail-val" style="color:${d.threat_score>=30?'var(--red)':d.threat_score>=10?'var(--yellow)':'var(--green)'}">${d.threat_score}</span></div>`;
    html+=`<div class="detail-row"><span class="detail-label">First Seen</span><span class="detail-val">${esc(d.first_seen||"—")}</span></div>`;
    html+=`<div class="detail-row"><span class="detail-label">Last Seen</span><span class="detail-val">${esc(d.last_seen||"—")}</span></div>`;
    if(d.geo)html+=`<div class="detail-row"><span class="detail-label">Geo</span><span class="detail-val">${esc(d.geo)}</span></div>`;
    if(d.asn)html+=`<div class="detail-row"><span class="detail-label">ASN</span><span class="detail-val">${esc(d.asn)}</span></div>`;
    if(d.notes)html+=`<div class="detail-row"><span class="detail-label">Notes</span><span class="detail-val" style="color:var(--yellow)">${esc(d.notes)}</span></div>`;
    if(d.watchlisted)html+=`<div class="detail-row"><span class="detail-label">Status</span><span class="detail-val" style="color:var(--red)">WATCHLISTED</span></div>`;
    html+=`</div>`;
    if(d.ports&&d.ports.length){
      html+=`<div class="detail-section"><h3>Open Ports (${d.ports.length})</h3><div style="display:flex;flex-wrap:wrap;gap:4px">`;
      d.ports.forEach(p=>{html+=`<span class="port-chip">${p}</span>`});
      html+=`</div></div>`;
    }
    if(d.tags&&d.tags.length){
      html+=`<div class="detail-section"><h3>Tags</h3><div style="display:flex;gap:4px;flex-wrap:wrap">`;
      d.tags.forEach(t=>{html+=`<span class="tag">${esc(t)}</span>`});
      html+=`</div></div>`;
    }
    if(d.nmap_results&&d.nmap_results.length){
      html+=`<div class="detail-section"><h3>Scan Results (${d.nmap_results.length})</h3>`;
      d.nmap_results.forEach(r=>{html+=`<div style="padding:2px 0;color:var(--green);font-size:11px">${esc(r.line)}</div>`});
      html+=`</div>`;
    }
    if(d.osint_results&&d.osint_results.length){
      html+=`<div class="detail-section"><h3>OSINT (${d.osint_results.length})</h3>`;
      d.osint_results.forEach(r=>{html+=`<div style="padding:2px 0;font-size:11px"><span style="color:var(--cyan);font-weight:700;margin-right:8px">${esc(r.type)}</span>${esc(r.result)}</div>`});
      html+=`</div>`;
    }
    if(d.honeypot_events&&d.honeypot_events.length){
      html+=`<div class="detail-section"><h3>Honeypot Activity (${d.honeypot_events.length})</h3>`;
      d.honeypot_events.forEach(e=>{html+=`<div style="padding:2px 0;font-size:11px"><span style="color:var(--dim)">${esc(e.time)}</span> <span style="color:var(--red)">${esc(e.service)}</span> ${esc(e.summary)}</div>`});
      html+=`</div>`;
    }
    if(d.dns_queries&&d.dns_queries.length){
      html+=`<div class="detail-section"><h3>DNS Queries (${d.dns_queries.length})</h3>`;
      d.dns_queries.forEach(q=>{html+=`<div style="padding:2px 0;font-size:11px"><span style="color:var(--dim)">${esc(q.time)}</span> <span style="color:var(--magenta)">${esc(q.domain)}</span></div>`});
      html+=`</div>`;
    }
    if(d.has_recon){
      html+=`<div class="detail-section"><h3>Full Recon</h3><button onclick="showReconDetail('${esc(ip)}')" style="background:var(--red);color:white;border:none;padding:6px 14px;border-radius:4px;cursor:pointer;font-family:inherit;font-weight:700">View Recon Report</button></div>`;
    }
    html+=`<div style="margin-top:12px;display:flex;gap:6px;flex-wrap:wrap">`;
    ["scan","deep","geo","whois","abuse","recon","portscan","trace","ping"].forEach(cmd=>{
      html+=`<button onclick="runCmd('${cmd} ${esc(ip)}')" style="background:var(--surface);color:var(--text);border:1px solid var(--border);padding:4px 10px;border-radius:4px;cursor:pointer;font-family:inherit;font-size:11px">${cmd}</button>`;
    });
    html+=`</div>`;
    b.innerHTML=html;
  }catch(err){b.innerHTML=`<div style="color:var(--red)">Error: ${esc(err.message)}</div>`}
}

async function showScanDetail(ip){
  const p=$("#detail-panel"),b=$("#detail-body"),t=$("#detail-title");
  t.textContent="Scan Logs: "+ip;
  b.innerHTML=`<div style="color:var(--dim)">Loading scan data...</div>`;
  p.classList.add("open");
  try{
    const r=await fetch("/api/scan_log/"+ip);
    const d=await r.json();
    let html="";
    if(d.scans&&d.scans.length){
      d.scans.forEach(s=>{
        html+=`<div class="detail-section"><h3>${esc(s.file)}</h3><pre style="background:var(--bg);padding:10px;border-radius:4px;overflow-x:auto;font-size:11px;color:var(--green);border:1px solid var(--border)">${esc(s.content)}</pre></div>`;
      });
    }else{
      html=`<div style="color:var(--dim)">No scan logs found for ${esc(ip)}</div>`;
      html+=`<button onclick="runCmd('scan ${esc(ip)}');$('#detail-panel').classList.remove('open')" style="background:var(--red);color:white;border:none;padding:6px 14px;border-radius:4px;cursor:pointer;font-family:inherit;font-weight:700;margin-top:12px">Run Scan Now</button>`;
    }
    b.innerHTML=html;
  }catch(err){b.innerHTML=`<div style="color:var(--red)">Error: ${esc(err.message)}</div>`}
}

async function showReconDetail(ip){
  const b=$("#detail-body");
  b.innerHTML=`<div style="color:var(--dim)">Loading recon report...</div>`;
  try{
    const r=await fetch("/api/recon/"+ip);
    const d=await r.json();
    if(d.error){b.innerHTML=`<div style="color:var(--red)">${esc(d.error)}</div>`;return}
    let html=`<div class="detail-section"><h3>Recon Report: ${esc(ip)}</h3>`;
    Object.entries(d).forEach(([k,v])=>{
      if(k==="ip"||k==="timestamp")return;
      const val=Array.isArray(v)?v.join(", "):typeof v==="object"?JSON.stringify(v):String(v);
      if(val&&val!=="[]"&&val!=="{}")html+=`<div class="detail-row"><span class="detail-label">${esc(k)}</span><span class="detail-val" style="white-space:normal">${esc(val)}</span></div>`;
    });
    html+=`</div>`;
    b.innerHTML=html;
  }catch(err){b.innerHTML=`<div style="color:var(--red)">Error: ${esc(err.message)}</div>`}
}

// Resizable output panel
(function(){
  const drag=$("#panel-drag"),panel=$("#output-panel");
  let startY,startH;
  drag.addEventListener("mousedown",e=>{
    startY=e.clientY;startH=panel.offsetHeight;
    const onMove=e2=>{
      const h=startH+(startY-e2.clientY);
      panel.style.height=Math.max(120,Math.min(window.innerHeight*.85,h))+"px";
    };
    const onUp=()=>{document.removeEventListener("mousemove",onMove);document.removeEventListener("mouseup",onUp)};
    document.addEventListener("mousemove",onMove);
    document.addEventListener("mouseup",onUp);
    e.preventDefault();
  });
  // Touch support
  drag.addEventListener("touchstart",e=>{
    startY=e.touches[0].clientY;startH=panel.offsetHeight;
    const onMove=e2=>{
      const h=startH+(startY-e2.touches[0].clientY);
      panel.style.height=Math.max(120,Math.min(window.innerHeight*.85,h))+"px";
      e2.preventDefault();
    };
    const onUp=()=>{document.removeEventListener("touchmove",onMove);document.removeEventListener("touchend",onUp)};
    document.addEventListener("touchmove",onMove,{passive:false});
    document.addEventListener("touchend",onUp);
  },{passive:true});
})();

// Maximize/restore output panel
let _panelMaxed=false;
$("#output-max").onclick=()=>{
  const p=$("#output-panel");
  if(_panelMaxed){p.style.height="var(--panel-h)";_panelMaxed=false}
  else{p.style.height="85vh";_panelMaxed=true}
};

document.addEventListener("click",e=>{
  const el=e.target.closest(".ip-click");
  if(el&&!e.target.closest("tr.clickable")){showCtxMenu(el.dataset.ip,e.clientX,e.clientY);e.stopPropagation();return}
  if(!e.target.closest("#ctx-menu"))$("#ctx-menu").style.display="none";
});

$("#output-close").onclick=()=>{$("#output-panel").classList.remove("open");$("#output-panel").style.height=""};
$("#detail-close").onclick=()=>{$("#detail-panel").classList.remove("open");if(_lastFocus)try{_lastFocus.focus()}catch(e){}};

// Focus trap for detail-panel (modal dialog)
let _lastFocus=null;
function _focusable(el){
  return Array.from(el.querySelectorAll('a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),iframe,[tabindex]:not([tabindex="-1"])'));
}
document.addEventListener("keydown",e=>{
  const dp=$("#detail-panel");
  if(!dp.classList.contains("open")||e.key!=="Tab")return;
  const items=_focusable(dp);
  if(!items.length)return;
  const first=items[0],last=items[items.length-1];
  if(e.shiftKey&&document.activeElement===first){last.focus();e.preventDefault()}
  else if(!e.shiftKey&&document.activeElement===last){first.focus();e.preventDefault()}
});
// Remember last focus when opening modal, restore on close
const _origShowDetail=showHostDetail;
showHostDetail=async function(ip){
  _lastFocus=document.activeElement;
  await _origShowDetail(ip);
  const dp=$("#detail-panel"),first=_focusable(dp)[0];
  if(first)first.focus();
};
const _origShowScan=showScanDetail;
showScanDetail=async function(ip){
  _lastFocus=document.activeElement;
  await _origShowScan(ip);
  const dp=$("#detail-panel"),first=_focusable(dp)[0];
  if(first)first.focus();
};
const _origShowReplay=showReplayDetail;
showReplayDetail=function(sid,proto){
  _lastFocus=document.activeElement;
  _origShowReplay(sid,proto);
  const dp=$("#detail-panel"),first=_focusable(dp)[0];
  if(first)first.focus();
};

$("#cmd-input").addEventListener("keydown",async e=>{
  if(e.key!=="Enter")return;
  const cmd=e.target.value.trim();
  if(!cmd)return;
  e.target.value="";
  runCmd(cmd);
});

function _activateTabIdx(i){
  if(i<0||i>=TABS.length)return;
  tab=TABS[i];
  $$(".tab").forEach((t,j)=>{t.classList.toggle("active",j===i);if(j===i)t.setAttribute("aria-selected","true");else t.setAttribute("aria-selected","false")});
  render();
}
function _tabIdx(name){return TABS.indexOf(name)}
document.addEventListener("keydown",e=>{
  if(document.activeElement===$("#cmd-input"))return;
  if(e.key==="Escape"){
    if($("#kbd-help").classList.contains("open")){$("#kbd-help").classList.remove("open");return}
    if($("#detail-panel").classList.contains("open")){$("#detail-panel").classList.remove("open");return}
    $("#ctx-menu").style.display="none";
    if($("#output-panel").classList.contains("open")){$("#output-panel").classList.remove("open");$("#output-panel").style.height="";return}
    return;
  }
  if(e.key==="?"||(e.key==="/"&&e.shiftKey)){
    e.preventDefault();$("#kbd-help").classList.toggle("open");return;
  }
  if(e.shiftKey){
    if(e.key==="M"||e.key==="m"){const i=_tabIdx("mesh");if(i>=0){e.preventDefault();_activateTabIdx(i);return}}
    if(e.key==="H"||e.key==="h"){const i=_tabIdx("help");if(i>=0){e.preventDefault();_activateTabIdx(i);return}}
    return;
  }
  if(e.key==="r"||e.key==="R"){const i=_tabIdx("replay");if(i>=0){e.preventDefault();_activateTabIdx(i);return}}
  const n=parseInt(e.key);
  if(n>=1&&n<=9&&n<=TABS.length){_activateTabIdx(n-1);return}
  if(e.key==="0"&&TABS.length>=10){_activateTabIdx(9);return}
  if(e.key==="/"){e.preventDefault();$("#cmd-input").focus()}
});

// Theme + Scanline persistence
const _themeSel=$("#theme-sel"),_scanSel=$("#scanline-sel"),_scanOverlay=$("#scanline-overlay");
_themeSel.value=localStorage.getItem("nw_theme")||"";
document.body.className=_themeSel.value;
_scanSel.value=localStorage.getItem("nw_scanline")||"";
_scanOverlay.className=_scanSel.value;
_themeSel.onchange=()=>{
  document.body.className=_themeSel.value;
  localStorage.setItem("nw_theme",_themeSel.value);
  _destroyCharts();
  if(tab==="all"){initCharts();updateCharts();loadTimeseries()}
};
_scanSel.onchange=()=>{_scanOverlay.className=_scanSel.value;localStorage.setItem("nw_scanline",_scanSel.value)};

initTabs();
$("#kbd-help-btn").onclick=()=>$("#kbd-help").classList.toggle("open");
$("#kbd-help").onclick=e=>{if(e.target.id==="kbd-help")$("#kbd-help").classList.remove("open")};
connect();
fetch("/api/state").then(r=>r.json()).then(d=>{D=d;updateHeader();render()}).catch(()=>{});
</script>
</body>
</html>"""

@web_app.route("/api/recon/<ip>")
def web_recon_detail(ip):
    if not re.match(r'^[0-9a-fA-F.:]+$', ip):
        return jsonify({"error": "invalid IP"}), 400
    with lock:
        report = recon_reports.get(ip)
    if not report:
        return jsonify({"error": "no recon data — run: recon " + ip}), 404
    safe = {}
    for k, v in report.items():
        if isinstance(v, (str, int, float, bool)):
            safe[k] = v
        elif isinstance(v, list):
            safe[k] = v[:50]
        elif isinstance(v, dict):
            safe[k] = v
    return jsonify(safe)

@web_app.route("/api/host/<ip>")
def web_host_detail(ip):
    if not re.match(r'^[0-9a-fA-F.:]+$', ip):
        return jsonify({"error": "invalid IP"}), 400
    with lock:
        h = hosts.get(ip)
        if not h:
            return jsonify({"error": "host not found"}), 404
        info = {
            "ip": ip,
            "hostname": h.get("hostname") or dns_cache.get(ip, ""),
            "bytes_in": h["bytes_in"], "bytes_out": h["bytes_out"],
            "packets": h["packets"],
            "ports": sorted(h["ports"]),
            "threat_score": h.get("threat_score", 0),
            "tags": sorted(h.get("tags", set())),
            "first_seen": h.get("first_seen", ""),
            "last_seen": h.get("last_seen", ""),
            "geo": h.get("geo", ""),
            "asn": h.get("asn", ""),
            "hostname_rdns": h.get("hostname", ""),
        }
        hp = [e for e in honeypot_events if e.get("ip") == ip][-20:]
        dns_hits = [e for e in dns_queries if e.get("ip") == ip][-20:]
        nmap_hits = [r for r in nmap_results if re.search(r'\b' + re.escape(ip) + r'\b', r.get("line", ""))][-20:]
        osint_hits = [r for r in osint_results if r.get("target") == ip][-20:]
    info["honeypot_events"] = hp
    info["dns_queries"] = dns_hits
    info["nmap_results"] = nmap_hits
    info["osint_results"] = osint_hits
    info["has_recon"] = ip in recon_reports
    info["notes"] = ip_notes.get(ip, "")
    info["watchlisted"] = ip in watchlist
    return jsonify(info)

@web_app.route("/api/scan_log/<ip>")
def web_scan_log(ip):
    if not re.match(r'^[0-9a-fA-F.:]+$', ip):
        return jsonify({"error": "invalid IP"}), 400
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
    results = []
    try:
        for f in sorted(os.listdir(log_dir)):
            ip_slug = ip.replace(".", "_")
            if f.startswith("nmap_") and f.endswith(".txt") and re.search(r'(?:^nmap_|_)' + re.escape(ip_slug) + r'(?:_|\.)', f):
                with open(os.path.join(log_dir, f)) as fh:
                    results.append({"file": f, "content": fh.read()[-4000:]})
    except Exception:
        pass
    return jsonify({"ip": ip, "scans": results})

# -- SESSION REPLAY (uses replay.py data layer)

@web_app.route("/replay")
def web_replay_index():
    return render_template_string(_REPLAY_INDEX_HTML)

def _replay_proto_arg():
    p = (request.args.get("proto") or "ftp").lower()
    return p if p in ("ftp", "telnet") else "ftp"

@web_app.route("/replay/<session_id>")
def web_replay_player(session_id):
    if not replay.SESSION_ID_RE.match(session_id):
        return jsonify({"error": "invalid session_id"}), 400
    return render_template_string(_REPLAY_PLAYER_HTML,
                                  session_id=session_id,
                                  protocol=_replay_proto_arg())

def _replay_extra_dirs():
    """Extra capture dirs to merge into replay listings (e.g. droplet rsync).

    Order: official $NETWATCH_EXTRA_LOG_DIRS (colon-separated), then a couple
    of conventional defaults. Each entry is silently skipped if missing.
    """
    env = os.environ.get("NETWATCH_EXTRA_LOG_DIRS", "")
    dirs = [d.strip() for d in env.split(":") if d.strip()]
    dirs += [
        os.path.expanduser("~/agents/honeypot-captures"),
        "/home/mrrobot/agents/honeypot-captures",
    ]
    seen = set()
    out = []
    for d in dirs:
        rp = os.path.realpath(d) if d else ""
        if rp and rp not in seen and os.path.isdir(rp):
            seen.add(rp)
            out.append(rp)
    return out

@web_app.route("/api/replay")
def web_replay_api_index():
    merged = list(replay.replay_index())
    seen = {s.get("session_id") for s in merged}
    for d in _replay_extra_dirs():
        try:
            for s in replay.replay_index(log_dir=d):
                sid = s.get("session_id")
                if sid and sid not in seen:
                    seen.add(sid)
                    s["source"] = "droplet"
                    merged.append(s)
        except Exception:
            continue
    merged.sort(key=lambda s: s.get("started_at_mtime", ""), reverse=True)
    return jsonify(merged)

@web_app.route("/api/replay/<session_id>")
def web_replay_api_session(session_id):
    if not replay.SESSION_ID_RE.match(session_id):
        return jsonify({"error": "invalid session_id"}), 400
    proto = _replay_proto_arg()
    last_err = None
    for log_dir in [None] + _replay_extra_dirs():
        try:
            timeline = replay.replay_loader(session_id, protocol=proto, log_dir=log_dir)
            timeline["intel"] = replay.load_intel(timeline["ip"], log_dir=log_dir)
            return jsonify(timeline)
        except FileNotFoundError as e:
            last_err = e
            continue
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
    return jsonify({"error": "session not found"}), 404

_REPLAY_INDEX_HTML = r"""<!DOCTYPE html><html><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetWatch · Replay sessions</title>
<style>
 body{background:#0a0e0a;color:#cfe;font:13px/1.4 ui-monospace,Menlo,Consolas,monospace;margin:0;padding:24px}
 h1{color:#7df58a;font-weight:400;letter-spacing:1px;margin:0 0 4px}
 .sub{color:#5a8;margin-bottom:24px;font-size:11px}
 a{color:#7df58a;text-decoration:none}
 a:hover{color:#fff;background:#143}
 table{width:100%;border-collapse:collapse;margin-top:8px}
 th{text-align:left;padding:6px 10px;color:#5a8;font-weight:400;border-bottom:1px solid #143;font-size:11px;text-transform:uppercase;letter-spacing:1px}
 td{padding:6px 10px;border-bottom:1px solid #0f1a10}
 tr:hover td{background:#0e1810}
 .empty{padding:40px;text-align:center;color:#588}
 .nav{margin-bottom:16px}
 .nav a{padding:4px 10px;border:1px solid #2a4;border-radius:3px;margin-right:8px}
 .ip{color:#fff}
 .num{color:#999;text-align:right}
 .proto{font-size:10px;padding:1px 6px;border-radius:2px;text-transform:uppercase;letter-spacing:1px}
 .proto.ftp{background:#143;color:#7df58a}
 .proto.telnet{background:#311;color:#f87}
</style></head><body>
<div class="nav"><a href="/">← dashboard</a><a href="/replay" id="refresh">↻ refresh</a></div>
<h1>SESSION REPLAY</h1>
<div class="sub">Captured honeypot sessions — click any session to scrub the timeline</div>
<div id="content"><div class="empty">loading…</div></div>
<script>
const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function load(){
  let sessions;
  try{
    const r=await fetch('/api/replay');
    if(!r.ok)throw new Error('HTTP '+r.status);
    sessions=await r.json();
  }catch(e){
    document.getElementById('content').innerHTML=`<div class="empty">Failed to load sessions: ${esc(e.message||e)}</div>`;return;
  }
  const el=document.getElementById('content');
  if(!sessions.length){el.innerHTML='<div class="empty">No sessions captured yet — once attackers hit a honeypot, they\'ll appear here.</div>';return}
  let h='<table><thead><tr><th>session id</th><th>proto</th><th>attacker ip</th><th>captured</th><th>events</th></tr></thead><tbody>';
  for(const s of sessions){
    const ts=String(s.started_at_mtime||'').replace('T',' ').replace(/\..*/,'');
    const proto=(s.protocol==='telnet')?'telnet':'ftp';  // whitelist
    const sid=encodeURIComponent(s.session_id);
    h+=`<tr><td><a href="/replay/${sid}?proto=${proto}">${esc(s.session_id)}</a></td>`+
       `<td><span class="proto ${proto}">${proto}</span></td>`+
       `<td class="ip">${esc(s.ip)}</td><td>${esc(ts)} UTC</td><td class="num">${Number(s.event_count)||0}</td></tr>`;
  }
  el.innerHTML=h+'</tbody></table>';
}
load();
document.getElementById('refresh').addEventListener('click',e=>{e.preventDefault();load()});
</script>
</body></html>"""

_REPLAY_PLAYER_HTML = r"""<!DOCTYPE html><html><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetWatch · Replay {{ session_id }}</title>
<style>
 body{background:#0a0e0a;color:#cfe;font:13px/1.4 ui-monospace,Menlo,Consolas,monospace;margin:0}
 header{padding:14px 20px;border-bottom:1px solid #143;display:flex;align-items:center;gap:20px;flex-wrap:wrap}
 header h1{color:#7df58a;font:400 14px/1 inherit;letter-spacing:2px;margin:0}
 header .meta{color:#5a8;font-size:11px}
 header .meta b{color:#fff;font-weight:400}
 header a{color:#7df58a;text-decoration:none;padding:3px 8px;border:1px solid #2a4;border-radius:3px;font-size:11px}
 main{display:grid;grid-template-columns:1fr 280px;height:calc(100vh - 130px)}
 #events{overflow-y:auto;padding:12px 18px}
 .ev{padding:3px 0;display:grid;grid-template-columns:70px 80px 1fr;gap:10px;border-radius:2px}
 .ev .t{color:#588;font-size:11px}
 .ev .k{font-size:11px;text-transform:uppercase;letter-spacing:1px}
 .ev[data-k=server] .k{color:#7df58a}
 .ev[data-k=server_fail] .k{color:#f55}
 .ev[data-k=client] .k{color:#fc7}
 .ev[data-k=cred] .k{color:#f9f}
 .ev[data-k=upload] .k,.ev[data-k=upload_saved] .k,.ev[data-k=data_recv] .k{color:#9cf}
 .ev[data-k=download] .k,.ev[data-k=data_send] .k{color:#9cf}
 .ev[data-k=session_end] .k,.ev[data-k=quit] .k{color:#666}
 .ev .x{color:#cfe;word-break:break-all;white-space:pre-wrap}
 .ev.future{opacity:.18}
 .ev.cursor{background:#143}
 #intel{border-left:1px solid #143;padding:14px 16px;overflow-y:auto;background:#070b07}
 #intel h2{color:#5a8;font:400 11px/1 inherit;letter-spacing:2px;text-transform:uppercase;margin:0 0 12px}
 #intel dt{color:#588;font-size:11px;margin-top:10px;text-transform:uppercase;letter-spacing:1px}
 #intel dd{color:#fff;margin:2px 0 0}
 #intel .empty{color:#588;font-style:italic;font-size:11px}
 footer{border-top:1px solid #143;padding:10px 18px;display:flex;align-items:center;gap:14px;background:#070b07}
 footer button{background:#0a0e0a;color:#7df58a;border:1px solid #2a4;padding:4px 12px;border-radius:3px;cursor:pointer;font:inherit}
 footer button:hover{background:#143;color:#fff}
 footer button.active{background:#143;color:#fff}
 #scrub{flex:1;height:6px;-webkit-appearance:none;background:#143;border-radius:3px;outline:none}
 #scrub::-webkit-slider-thumb{-webkit-appearance:none;width:14px;height:14px;background:#7df58a;border-radius:50%;cursor:pointer}
 #scrub::-moz-range-thumb{width:14px;height:14px;background:#7df58a;border-radius:50%;border:none;cursor:pointer}
 #time{color:#fff;font-variant-numeric:tabular-nums;min-width:120px;text-align:right}
 .err{color:#f55;padding:40px;text-align:center}
</style></head><body>
<header>
 <h1>NETWATCH · REPLAY</h1>
 <div class="meta">session <b id="sid">{{ session_id }}</b></div>
 <div class="meta">ip <b id="ip">…</b></div>
 <div class="meta">duration <b id="dur">…</b></div>
 <a href="/replay">← all sessions</a>
</header>
<main>
 <div id="events"><div class="err">loading…</div></div>
 <div id="intel"><h2>ATTACKER INTEL</h2><div id="intelBody"><div class="empty">loading…</div></div></div>
</main>
<footer>
 <button id="home" title="jump to start (Home)">⏮</button>
 <button id="back10" title="-10s (&lt;)">⏪</button>
 <button id="back1" title="-1s (←)">◀</button>
 <button id="play">▶</button>
 <button id="fwd1" title="+1s (→)">▶|</button>
 <button id="fwd10" title="+10s (&gt;)">⏩</button>
 <button id="end" title="jump to end (End)">⏭</button>
 <button data-speed="0.5">0.5×</button>
 <button data-speed="1" class="active">1×</button>
 <button data-speed="2">2×</button>
 <button data-speed="4">4×</button>
 <input type="range" id="scrub" min="0" max="0" value="0" step="1">
 <span id="time">00:00 / 00:00</span>
</footer>
<script>
const sid={{ session_id|tojson }};
const proto={{ protocol|tojson }};
const SPEEDS=[0.25,0.5,1,2,4,8];
let timeline=null,cursor=0,playing=false,speed=1,timer=null,lastTick=0;
const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function fmt(ms){const s=Math.floor(ms/1000),m=Math.floor(s/60);return `${String(m).padStart(2,'0')}:${String(s%60).padStart(2,'0')}`}
function renderIntel(intel){
 const b=document.getElementById('intelBody');
 if(!intel||!intel.ip){b.innerHTML='<div class="empty">No OSINT recon yet for this IP. Run <code>recon</code> from the dashboard.</div>';return}
 const rows=[['IP',intel.ip],['Country',intel.country],['City',intel.city],['ASN',intel.asn],['Org',intel.org],['Abuse',intel.abuse_score],['Hostname',intel.hostname]];
 let h='<dl>';
 for(const [k,v] of rows)if(v||v===0)h+=`<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`;
 if(intel.tags&&intel.tags.length)h+=`<dt>Tags</dt><dd>${esc(intel.tags.join(', '))}</dd>`;
 if(intel.notes)h+=`<dt>Notes</dt><dd>${esc(intel.notes)}</dd>`;
 b.innerHTML=h+'</dl>';
}
function renderEvents(){
 const el=document.getElementById('events');
 if(!timeline.events.length){el.innerHTML='<div class="err">No events captured in this session (banner-only).</div>';return}
 let h='',lastCursorIdx=-1;
 for(let i=0;i<timeline.events.length;i++){
  const e=timeline.events[i],fut=e.t_ms>cursor;
  if(!fut)lastCursorIdx=i;
  h+=`<div class="ev${fut?' future':''}" data-k="${esc(e.kind)}" data-i="${i}"><span class="t">${fmt(e.t_ms)}</span><span class="k">${esc(e.kind)}</span><span class="x">${esc(e.text)}</span></div>`;
 }
 el.innerHTML=h;
 const cur=el.querySelector(`[data-i="${lastCursorIdx}"]`);
 if(cur){cur.classList.add('cursor');cur.scrollIntoView({block:'nearest'})}
}
function updateScrubber(){
 document.getElementById('scrub').value=cursor;
 document.getElementById('time').textContent=`${fmt(cursor)} / ${fmt(timeline.duration_ms)}`;
}
function setCursor(ms){
 cursor=Math.max(0,Math.min(timeline.duration_ms,ms|0));
 lastTick=performance.now();
 updateScrubber();renderEvents();
}
function setSpeed(v){
 speed=v;lastTick=performance.now();
 document.querySelectorAll('[data-speed]').forEach(x=>x.classList.toggle('active',parseFloat(x.dataset.speed)===v));
}
function stepSpeed(dir){
 const i=SPEEDS.indexOf(speed);
 const ni=Math.max(0,Math.min(SPEEDS.length-1,(i<0?2:i)+dir));
 setSpeed(SPEEDS[ni]);
}
function play(){
 if(!playing && cursor>=timeline.duration_ms) cursor=0;  // restart from end
 playing=!playing;
 document.getElementById('play').textContent=playing?'❚❚':'▶';
 lastTick=performance.now();
 if(playing&&!timer)tick();
}
function tick(){
 if(!playing){timer=null;return}
 const now=performance.now(),dt=(now-lastTick)*speed;lastTick=now;
 cursor=Math.min(timeline.duration_ms,cursor+dt);
 updateScrubber();renderEvents();
 if(cursor>=timeline.duration_ms){playing=false;document.getElementById('play').textContent='▶';timer=null;return}
 timer=requestAnimationFrame(tick);
}
async function load(){
 try{
  const r=await fetch(`/api/replay/${encodeURIComponent(sid)}?proto=${proto}`);
  if(!r.ok){document.getElementById('events').innerHTML=`<div class="err">${esc((await r.json()).error||'load failed')}</div>`;return}
  timeline=await r.json();
  document.getElementById('ip').textContent=timeline.ip;
  document.getElementById('dur').textContent=fmt(timeline.duration_ms);
  document.getElementById('scrub').max=Math.max(timeline.duration_ms,1);
  // Auto-slow sub-2-second captures so playback is actually visible
  // (many FTP probes are sub-100ms TLS handshakes that would flash past).
  if(timeline.duration_ms>0 && timeline.duration_ms<2000){
    setSpeed(0.25);
    document.getElementById('dur').title='Auto-slowed to 0.25× — session is under 2s';
  }
  renderIntel(timeline.intel);renderEvents();updateScrubber();
 }catch(e){document.getElementById('events').innerHTML=`<div class="err">${esc(e)}</div>`}
}
document.getElementById('play').addEventListener('click',play);
document.getElementById('back1').addEventListener('click',()=>setCursor(cursor-1000));
document.getElementById('fwd1').addEventListener('click',()=>setCursor(cursor+1000));
document.getElementById('back10').addEventListener('click',()=>setCursor(cursor-10000));
document.getElementById('fwd10').addEventListener('click',()=>setCursor(cursor+10000));
document.getElementById('home').addEventListener('click',()=>setCursor(0));
document.getElementById('end').addEventListener('click',()=>setCursor(timeline?timeline.duration_ms:0));
document.getElementById('scrub').addEventListener('input',e=>setCursor(parseInt(e.target.value,10)));
document.querySelectorAll('[data-speed]').forEach(b=>b.addEventListener('click',()=>setSpeed(parseFloat(b.dataset.speed))));
document.addEventListener('keydown',e=>{
 if(!timeline)return;
 const tag=(e.target.tagName||'').toLowerCase();
 if(tag==='input'||tag==='textarea')return;
 switch(e.key){
  case ' ':e.preventDefault();play();break;
  case 'ArrowLeft':e.preventDefault();setCursor(cursor-1000);break;
  case 'ArrowRight':e.preventDefault();setCursor(cursor+1000);break;
  case '<':case ',':e.preventDefault();setCursor(cursor-10000);break;
  case '>':case '.':e.preventDefault();setCursor(cursor+10000);break;
  case 'Home':e.preventDefault();setCursor(0);break;
  case 'End':e.preventDefault();setCursor(timeline.duration_ms);break;
  case '+':case '=':e.preventDefault();stepSpeed(1);break;
  case '-':case '_':e.preventDefault();stepSpeed(-1);break;
 }
});
load();
</script>
</body></html>"""

# -- TIME-SERIES SAMPLING

def _sample_timeseries():
    while True:
        time.sleep(5)
        sample = {
            "ts": int(time.time()),
            "packets": total_packets,
            "bytes": total_bytes,
            "protos": dict(list(proto_stats.items())[:10]),
        }
        with _ts_lock:
            _ts_samples.append(sample)
            if len(_ts_samples) > _TS_MAX:
                del _ts_samples[:len(_ts_samples) - _TS_MAX]

@web_app.route("/api/timeseries")
def web_timeseries():
    last = min(int(request.args.get("last", 60)), 120)
    with _ts_lock:
        return jsonify(list(_ts_samples[-last:]))

# -- MESHTASTIC MESH RADIO

def _mesh_connect():
    global mesh_interface
    if not _HAS_MESH:
        return False
    import glob
    ports = glob.glob("/dev/ttyUSB*") + glob.glob("/dev/ttyACM*")
    for port in ports:
        try:
            mesh_interface = _mesh_serial.SerialInterface(port)
            try:
                from pubsub import pub
                pub.subscribe(_on_mesh_recv, "meshtastic.receive")
            except ImportError:
                pass
            return True
        except Exception:
            continue
    return False

def _on_mesh_recv(packet, interface=None):
    decoded = packet.get("decoded", {})
    text = _ansi_strip(decoded.get("text", ""))
    if not text:
        return
    from_id = _ansi_strip(str(packet.get("fromId", "unknown")))
    from_name = _ansi_strip(str(packet.get("from", from_id)))
    with lock:
        mesh_messages.append({
            "ts": datetime.now().strftime("%H:%M:%S"),
            "from": str(from_name),
            "text": text,
            "type": "recv",
        })
        if len(mesh_messages) > _MESH_MAX_MSGS:
            del mesh_messages[:len(mesh_messages) - _MESH_MAX_MSGS]
        snr = packet.get("snr")
        if snr is not None:
            fid = str(from_id)[:32]
            if len(mesh_nodes) >= _MESH_MAX_NODES and fid not in mesh_nodes:
                oldest = min(mesh_nodes, key=lambda k: mesh_nodes[k].get("last_heard", ""))
                del mesh_nodes[oldest]
            mesh_nodes[fid] = {
                "name": str(from_name)[:50],
                "snr": snr,
                "last_heard": datetime.now().strftime("%H:%M:%S"),
            }

def mesh_send(text):
    if not mesh_interface:
        return False
    try:
        mesh_interface.sendText(text)
        with lock:
            mesh_messages.append({
                "ts": datetime.now().strftime("%H:%M:%S"),
                "from": "self",
                "text": text,
                "type": "sent",
            })
        return True
    except Exception:
        return False

def _mesh_forward_alert(msg):
    if mesh_alert_fwd and mesh_interface:
        short = msg[:200]
        mesh_send(f"[NW] {short}")

@web_app.route("/api/mesh")
def web_mesh():
    with lock:
        return jsonify({
            "connected": mesh_interface is not None,
            "messages": list(mesh_messages[-50:]),
            "nodes": dict(mesh_nodes),
            "alert_fwd": mesh_alert_fwd,
        })

@web_app.route("/api/mesh/send", methods=["POST"])
def web_mesh_send():
    text = request.json.get("text", "").strip()
    if not text:
        return jsonify({"error": "empty message"})
    if len(text) > 200:
        return jsonify({"error": "message too long (200 char max for LoRa)"})
    ok = mesh_send(text)
    return jsonify({"ok": ok})

# -- GRAPHQL API (optional)

try:
    import graphene as _graphene
    _HAS_GQL = True
except ImportError:
    _HAS_GQL = False

if _HAS_GQL:
    class _GQL_Host(_graphene.ObjectType):
        ip = _graphene.String()
        hostname = _graphene.String()
        bytes_in = _graphene.Int()
        bytes_out = _graphene.Int()
        packets = _graphene.Int()
        ports = _graphene.Int()
        threat_score = _graphene.Int()
        tags = _graphene.List(_graphene.String)
        local = _graphene.Boolean()

    class _GQL_Protocol(_graphene.ObjectType):
        name = _graphene.String()
        count = _graphene.Int()

    class _GQL_DNS(_graphene.ObjectType):
        time = _graphene.String()
        ip = _graphene.String()
        domain = _graphene.String()

    class _GQL_HoneypotEvent(_graphene.ObjectType):
        time = _graphene.String()
        service = _graphene.String()
        ip = _graphene.String()
        summary = _graphene.String()

    class _GQL_Alert(_graphene.ObjectType):
        time = _graphene.String()
        msg = _graphene.String()

    class _GQL_ARP(_graphene.ObjectType):
        ip = _graphene.String()
        mac = _graphene.String()
        state = _graphene.String()

    class _GQL_Query(_graphene.ObjectType):
        hosts = _graphene.List(_GQL_Host, min_threat=_graphene.Int(), limit=_graphene.Int())
        protocols = _graphene.List(_GQL_Protocol)
        dns_queries = _graphene.List(_GQL_DNS, limit=_graphene.Int())
        honeypot_events = _graphene.List(_GQL_HoneypotEvent, service=_graphene.String(), ip=_graphene.String(), limit=_graphene.Int())
        alerts = _graphene.List(_GQL_Alert, limit=_graphene.Int())
        arp_entries = _graphene.List(_GQL_ARP)

        def resolve_hosts(self, info, min_threat=None, limit=100):
            snap = _state_snapshot()
            h = snap["hosts"]
            if min_threat is not None:
                h = [x for x in h if x.get("threat_score", 0) >= min_threat]
            return [_GQL_Host(**x) for x in h[:min(limit or 100, 200)]]

        def resolve_protocols(self, info):
            snap = _state_snapshot()
            return [_GQL_Protocol(**x) for x in snap["protocols"]]

        def resolve_dns_queries(self, info, limit=50):
            snap = _state_snapshot()
            return [_GQL_DNS(**x) for x in snap["dns"][-limit:]]

        def resolve_honeypot_events(self, info, service=None, ip=None, limit=50):
            snap = _state_snapshot()
            evts = snap["honeypot"]
            if service:
                evts = [e for e in evts if e["service"] == service]
            if ip:
                evts = [e for e in evts if e["ip"] == ip]
            return [_GQL_HoneypotEvent(**e) for e in evts[-limit:]]

        def resolve_alerts(self, info, limit=50):
            snap = _state_snapshot()
            return [_GQL_Alert(**a) for a in snap["alerts"][-limit:]]

        def resolve_arp_entries(self, info):
            snap = _state_snapshot()
            return [_GQL_ARP(**a) for a in snap["arp"]]

    class _GQL_RunCommand(_graphene.Mutation):
        class Arguments:
            cmd = _graphene.String(required=True)
        output = _graphene.List(_graphene.String)
        error = _graphene.String()

        def mutate(self, info, cmd):
            rip = request.remote_addr
            now = time.time()
            if rip in _cmd_rate:
                cnt, ecnt, wstart = _cmd_rate[rip]
                if now - wstart >= _CMD_RATE_WINDOW:
                    cnt, ecnt, wstart = 0, 0, now
            else:
                cnt, ecnt, wstart = 0, 0, now
            if cnt >= _CMD_RATE_LIMIT:
                return _GQL_RunCommand(output=[], error="rate limited")
            parts = cmd.strip().split()
            if not parts:
                return _GQL_RunCommand(output=[], error="empty command")
            action = parts[0].lower()
            if action not in _WEB_SAFE_CMDS:
                return _GQL_RunCommand(output=[], error=f"'{action}' not allowed via API")
            if action in _EXPENSIVE_CMDS and ecnt >= _EXPENSIVE_RATE_LIMIT:
                return _GQL_RunCommand(output=[], error=f"'{action}' rate limited")
            _cmd_rate[rip] = (cnt + 1, ecnt + (1 if action in _EXPENSIVE_CMDS else 0), wstart)
            if action in _OUTBOUND_CMDS and len(parts) >= 2:
                if _is_internal_target(parts[1]):
                    return _GQL_RunCommand(output=[], error="internal target blocked")
            if action in ("scan", "deep", "recon", "portscan", "fullrecon", "sweep", "subnet") and len(parts) >= 2:
                target = parts[1]
                if "/" in target:
                    try:
                        net = ipaddress.ip_network(target, strict=False)
                        if net.prefixlen < 20:
                            return _GQL_RunCommand(output=[], error=f"CIDR range too large (/{net.prefixlen})")
                    except ValueError:
                        pass
            with _web_cmd_lock:
                with lock:
                    start_idx = len(console_output)
                handle_command(cmd)
                time.sleep(0.5)
                with lock:
                    snap = list(console_output)
                out = snap[start_idx:] if start_idx < len(snap) else []
            clean = [re.sub(r'\033\[[0-9;]*[a-zA-Z]', '', l) for l in out]
            return _GQL_RunCommand(output=clean, error=None)

    class _GQL_Mutation(_graphene.ObjectType):
        run_command = _GQL_RunCommand.Field()

    _gql_schema = _graphene.Schema(query=_GQL_Query, mutation=_GQL_Mutation)
    _GQL_MAX_ALIASES = 10

    @web_app.route("/graphql", methods=["GET", "POST"])
    def _gql_endpoint():
        if request.method == "GET":
            return "GraphQL endpoint — POST queries here", 200
        body = request.get_json(silent=True) or {}
        query_str = body.get("query", "")
        if len(query_str) > 4000:
            return jsonify({"errors": [{"message": "Query too long"}]}), 400
        if query_str.count("{") > _GQL_MAX_ALIASES + 2:
            return jsonify({"errors": [{"message": "Query too complex"}]}), 400
        depth, cur = 0, 0
        for ch in query_str:
            if ch == '{':
                cur += 1
                depth = max(depth, cur)
            elif ch == '}':
                cur -= 1
        if depth > 7:
            return jsonify({"errors": [{"message": "Query too deeply nested"}]}), 400
        variables = body.get("variables")
        result = _gql_schema.execute(query_str, variables=variables)
        resp = {}
        if result.data:
            resp["data"] = result.data
        if result.errors:
            resp["errors"] = [{"message": str(e)} for e in result.errors]
        return jsonify(resp), 200 if not result.errors else 400


def start_web_dashboard():
    web_app.run(host="0.0.0.0", port=WEB_PORT, debug=False, use_reloader=False, threaded=True)

# -- MAIN

def save_logs():
    traffic_file = os.path.join(LOG_DIR, "traffic.json")
    with lock:
        stats = {
            "session": {
                "start": datetime.fromtimestamp(start_time).isoformat(),
                "end": datetime.now().isoformat(),
                "total_packets": total_packets, "total_bytes": total_bytes,
                "version": VERSION,
            },
            "hosts": {ip: {
                "bytes_in": d["bytes_in"], "bytes_out": d["bytes_out"],
                "packets": d["packets"], "ports": sorted(d["ports"]),
                "hostname": d.get("hostname", ""),
                "threat_score": d.get("threat_score", 0),
                "tags": sorted(d.get("tags", set())),
                "first_seen": d["first_seen"], "last_seen": d["last_seen"],
            } for ip, d in hosts.items()},
            "protocols": dict(proto_stats),
            "dns_queries": dns_queries[-100:],
            "alerts": alerts,
            "honeypot_events": honeypot_events[-100:],
            "nmap_results": nmap_results,
            "arp_table": arp_table,
        }
    with open(traffic_file, "w") as f:
        json.dump(stats, f, indent=2, default=str)
    print(f"\n{GREEN}[*] Saved to {traffic_file}{RESET}")

def main():
    global IFACE
    if not HAS_RAW_NET:
        if IS_TERMUX:
            print(f"{YELLOW}[!] Termux detected — running passive mode (honeypots + OSINT + web only).{RESET}")
            print(f"{DIM}    Disabled: packet sniff, tshark, tcpdump, iptables (require root).{RESET}")
        elif not IS_ROOT:
            print(f"{YELLOW}[!] Not root — running passive mode. Use sudo for full capture features.{RESET}")
    if not re.match(r'^[a-zA-Z0-9_\-]+$', IFACE):
        print(f"{RED}[!] Invalid interface: {IFACE}{RESET}")
        sys.exit(1)

    print(f"{BOLD}{RED}")
    print("  ╔════════════════════════════════════════════╗")
    print(f"  ║        NETWATCH v{VERSION}                     ║")
    print("  ║   Network Security Dashboard               ║")
    print("  ║   Honeypot + Traffic + tshark + nmap        ║")
    print(f"  ╚════════════════════════════════════════════╝{RESET}")
    print(f"  {GREEN}Honeypot HTTP   : :8080{RESET}")
    print(f"  {GREEN}Honeypot Telnet : :{TELNET_PORT}{RESET}")
    print(f"  {GREEN}Honeypot FTP    : :{FTP_PORT}  (bait files + keystroke log){RESET}")
    print(f"  {GREEN}Honeypot RTSP   : :{RTSP_PORT}{RESET}")
    print(f"  {GREEN}Traffic Sniffer : {IFACE}{RESET}")
    print(f"  {GREEN}tshark Protocol : {IFACE}{RESET}")
    print(f"  {GREEN}tcpdump Capture : {PCAP_DIR}/{RESET}")
    print(f"  {GREEN}ARP Monitor     : active{RESET}")

    # Detect proxychains
    proxy_active = os.environ.get("PROXYCHAINS_CONF_FILE") or os.environ.get("LD_PRELOAD", "").find("proxychains") != -1
    if proxy_active:
        conf = os.environ.get("PROXYCHAINS_CONF_FILE", "")
        tor_ports = []
        if conf and os.path.isfile(conf):
            with open(conf) as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("socks") and "127.0.0.1" in line:
                        tor_ports.append(line.split()[-1])
        tor_ports = [p for p in tor_ports if p.isdigit()]
        circuits = len(tor_ports) if tor_ports else "?"
        print(f"  {GREEN}ProxyChains     : ACTIVE ({circuits} Tor circuits){RESET}")
        for p in tor_ports:
            up = True
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                s.connect(("127.0.0.1", int(p)))
                s.close()
                up = True
            except Exception:
                up = False
            status = f"{GREEN}UP{RESET}" if up else f"{RED}DOWN{RESET}"
            print(f"  {DIM}  └ socks5 127.0.0.1:{p} [{status}{DIM}]{RESET}")
        print(f"  {YELLOW}  Outbound recon routed through Tor — inbound sniffing stays local{RESET}")
    else:
        print(f"  {DIM}ProxyChains     : not active (outbound is direct){RESET}")

    print(f"  {DIM}Logs: {LOG_DIR}/{RESET}")
    print(f"  {DIM}nmap: use 'scan <target>' via API or edit code{RESET}\n")

    _cf_proc = None

    def shutdown(sig, frame):
        print(f"\n{YELLOW}[*] Shutting down NetWatch...{RESET}")
        stop_tcpdump()
        for cmd in ["tshark -i", "tcpdump -i"]:
            subprocess.run(["pkill", "-f", cmd], capture_output=True)
        if mesh_interface:
            try:
                mesh_interface.close()
            except Exception:
                pass
        if _cf_proc:
            try:
                _cf_proc.terminate()
                _cf_proc.wait(timeout=5)
            except Exception:
                pass
        save_logs()
        subprocess.run(["fuser", "-k",
                        f"{TELNET_PORT}/tcp", f"{RTSP_PORT}/tcp",
                        f"{HTTP_PORT}/tcp", f"{FTP_PORT}/tcp",
                        f"{WEB_PORT}/tcp"], capture_output=True)
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # Start all modules
    threading.Thread(target=telnet_honeypot, args=(TELNET_PORT,), daemon=True).start()
    threading.Thread(target=rtsp_honeypot, args=(RTSP_PORT,), daemon=True).start()
    threading.Thread(target=ftp_honeypot, args=(FTP_PORT,), daemon=True).start()
    if HAS_RAW_NET:
        threading.Thread(target=traffic_monitor, daemon=True).start()
        threading.Thread(target=tshark_monitor, daemon=True).start()
        threading.Thread(target=arp_monitor, daemon=True).start()
    threading.Thread(target=draw_dashboard, daemon=True).start()

    # Start packet capture (skipped without raw-net privileges)
    if HAS_RAW_NET:
        start_tcpdump()

    # Auto-scan local subnet on startup
    time.sleep(5)
    nmap_scan_thread("10.0.1.0/24", "-sn -T4")

    # Flask honeypot in background thread (so main thread can do console)
    flask_thread = threading.Thread(
        target=lambda: app.run(host="0.0.0.0", port=HTTP_PORT, debug=False, use_reloader=False),
        daemon=True
    )
    flask_thread.start()

    # Web dashboard on :9090
    web_thread = threading.Thread(target=start_web_dashboard, daemon=True)
    web_thread.start()
    print(f"  {GREEN}Web Dashboard   : http://0.0.0.0:{WEB_PORT}{RESET}")
    _persist_web_token(WEB_TOKEN)
    _redacted = f"{WEB_TOKEN[:6]}…{WEB_TOKEN[-4:]}" if len(WEB_TOKEN) >= 12 else "(short)"
    print(f"  {YELLOW}Web Token       : {_redacted}  (full token in {_TOKEN_PATH}, 0600){RESET}")

    # Time-series sampling for charts
    threading.Thread(target=_sample_timeseries, daemon=True).start()

    # Meshtastic mesh radio
    if _HAS_MESH:
        mesh_ok = _mesh_connect()
        if mesh_ok:
            print(f"  {GREEN}Meshtastic      : connected{RESET}")
        else:
            print(f"  {DIM}Meshtastic      : no device found{RESET}")
    else:
        print(f"  {DIM}Meshtastic      : not installed{RESET}")

    if _HAS_GQL:
        print(f"  {GREEN}GraphQL IDE     : http://0.0.0.0:{WEB_PORT}/graphql{RESET}")

    # Cloudflare tunnel for remote access
    _cf_bin = "/home/mrrobot/agents/agent-office/cloudflared"
    if os.path.isfile(_cf_bin):
        try:
            _cf_proc = subprocess.Popen(
                [_cf_bin, "tunnel", "--url", f"http://localhost:{WEB_PORT}"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
            )
            def _parse_tunnel():
                global _tunnel_url
                for line in _cf_proc.stdout:
                    if "trycloudflare.com" in line:
                        m = re.search(r'https://[a-z0-9-]+\.trycloudflare\.com', line)
                        if m:
                            url = m.group(0)
                            _tunnel_url = url
                            print(f"  {GREEN}Remote Access   : {url}{RESET}")
                            with lock:
                                alerts.append({"time": datetime.now().strftime("%H:%M:%S"),
                                               "msg": f"Tunnel: {url}"})
                            break
            threading.Thread(target=_parse_tunnel, daemon=True).start()
        except Exception as e:
            print(f"  {DIM}Tunnel          : failed ({e}){RESET}")
    else:
        print(f"  {DIM}Tunnel          : cloudflared not found{RESET}")

    def _read_key(fd):
        ch = os.read(fd, 1).decode('utf-8', errors='replace')
        if ch == '\x1b':
            seq = b""
            while select.select([fd], [], [], 0.05)[0]:
                seq += os.read(fd, 1)
            if seq == b"": return "esc"
            if seq == b"[A": return "up"
            if seq == b"[B": return "down"
            if seq == b"[C": return "right"
            if seq == b"[D": return "left"
            if seq == b"[5~": return "pgup"
            if seq == b"[6~": return "pgdn"
            if seq in (b"[H", b"[1~"): return "home"
            if seq in (b"[F", b"[4~"): return "end"
            # Function keys: F1=ESC OP / ESC [11~,  F2=OQ / [12~,  F3=OR / [13~
            if seq in (b"OP", b"[11~"): return "f1"
            if seq in (b"OQ", b"[12~"): return "f2"
            if seq in (b"OR", b"[13~"): return "f3"
            return None
        return ch

    def _command_input(fd, first_ch):
        """Collect a full command with history (up/down arrows)."""
        global current_tab, _input_active, _output_scroll
        _input_active = True
        _render_lock.acquire()
        buf = first_ch
        hist_idx = len(_cmd_history)
        saved_buf = ""
        try:
            cols, rows = os.get_terminal_size()
        except Exception:
            cols, rows = 80, 40
        prompt_row = rows

        def _redraw_prompt():
            try:
                os.write(1, f"\033[{prompt_row};1H\033[K{BOLD}{RED}nw>{RESET} {buf}".encode())
            except OSError:
                pass

        try:
            os.write(1, f"\033[{prompt_row};1H\033[K\033[?25h{BOLD}{RED}nw>{RESET} {buf}".encode())
        except OSError:
            pass
        try:
            while True:
                ch = os.read(fd, 1).decode('utf-8', errors='replace')
                if ch == '\r' or ch == '\n':
                    try:
                        os.write(1, f"\033[{prompt_row};1H\033[K".encode())
                    except OSError:
                        pass
                    if buf.strip():
                        _cmd_history.append(buf)  # deque self-trims
                    return buf
                if ch == '\x7f' or ch == '\x08':
                    if buf:
                        buf = buf[:-1]
                        _redraw_prompt()
                    if not buf:
                        try:
                            os.write(1, f"\033[{prompt_row};1H\033[K".encode())
                        except OSError:
                            pass
                        return ""
                    continue
                if ch == '\x03':
                    raise KeyboardInterrupt
                if ch == '\x1b':
                    seq = b""
                    while select.select([fd], [], [], 0.05)[0]:
                        seq += os.read(fd, 1)
                    if seq == b"[A" and _cmd_history:
                        if hist_idx == len(_cmd_history):
                            saved_buf = buf
                        hist_idx = max(0, hist_idx - 1)
                        buf = _cmd_history[hist_idx]
                        _redraw_prompt()
                    elif seq == b"[B":
                        if hist_idx < len(_cmd_history) - 1:
                            hist_idx += 1
                            buf = _cmd_history[hist_idx]
                        else:
                            hist_idx = len(_cmd_history)
                            buf = saved_buf
                        _redraw_prompt()
                    elif seq in (b"[5~", b"[6~"):
                        if seq == b"[5~":
                            with lock:
                                mx = max(0, len(console_output) - _OUTPUT_PANEL_MIN)
                            _output_scroll = min(_output_scroll + _OUTPUT_PANEL_MIN, mx)
                        else:
                            _output_scroll = max(0, _output_scroll - _OUTPUT_PANEL_MIN)
                        _paint_dashboard()
                        _redraw_prompt()
                    continue
                if ch == '\t':
                    continue
                if 32 <= ord(ch) < 127:
                    buf += ch
                    try:
                        os.write(1, ch.encode())
                    except OSError:
                        pass
        finally:
            _input_active = False
            _render_lock.release()

    # Interactive key listener (main thread)
    global console_mode, current_tab, show_help_overlay, _output_scroll
    time.sleep(1)
    fd = sys.stdin.fileno()
    try:
        old_settings = termios.tcgetattr(fd)
    except termios.error:
        print(f"\n  {YELLOW}No TTY — running headless (web dashboard only on :{WEB_PORT}){RESET}")
        try:
            while True:
                time.sleep(60)
        except KeyboardInterrupt:
            shutdown(None, None)
        return
    import atexit
    atexit.register(lambda: termios.tcsetattr(fd, termios.TCSADRAIN, old_settings))
    try:
        tty.setraw(fd)
        _raw_settings = termios.tcgetattr(fd)
        while True:
          try:
            key = _read_key(fd)
            if key is None:
                if show_help_overlay:
                    show_help_overlay = False
                    _redraw_event.set()
                continue

            if key == '\x03':
                raise KeyboardInterrupt

            # F1/F2/F3 — toggle screens. Mounted-once semantics: per-screen
            # scroll persists in app_state so returning restores prior view.
            if key == "f1":
                app_state.switch(SCREEN_DASHBOARD); _redraw_event.set(); continue
            if key == "f2":
                app_state.switch(SCREEN_CLI); _redraw_event.set(); continue
            if key == "f3":
                app_state.switch(SCREEN_CONSOLE); _redraw_event.set(); continue

            # Replay screen owns its own bindings (space/arrows/</>/+-/home/end/q).
            if app_state.current_screen == SCREEN_REPLAY:
                tl = app_state.replay_timeline
                dur = int((tl or {}).get("duration_ms") or 0)
                if key == "q" or key == "esc":
                    app_state.replay_playing = False
                    app_state.switch(app_state.last_screen or SCREEN_DASHBOARD)
                    _redraw_event.set(); continue
                if key == " ":
                    if dur > 0:
                        if app_state.replay_cursor_ms >= dur:
                            app_state.replay_cursor_ms = 0
                        app_state.replay_playing = not app_state.replay_playing
                        app_state.replay_last_tick = time.monotonic()
                    _redraw_event.set(); continue
                if key == "left":
                    app_state.replay_cursor_ms = max(0, app_state.replay_cursor_ms - 1000)
                    _redraw_event.set(); continue
                if key == "right":
                    app_state.replay_cursor_ms = min(dur, app_state.replay_cursor_ms + 1000)
                    _redraw_event.set(); continue
                if key == "<" or key == ",":
                    app_state.replay_cursor_ms = max(0, app_state.replay_cursor_ms - 10000)
                    _redraw_event.set(); continue
                if key == ">" or key == ".":
                    app_state.replay_cursor_ms = min(dur, app_state.replay_cursor_ms + 10000)
                    _redraw_event.set(); continue
                if key == "home":
                    app_state.replay_cursor_ms = 0
                    _redraw_event.set(); continue
                if key == "end":
                    app_state.replay_cursor_ms = dur
                    app_state.replay_playing = False
                    _redraw_event.set(); continue
                if key in ("+", "="):
                    try:
                        i = _REPLAY_SPEED_STEPS.index(app_state.replay_speed)
                    except ValueError:
                        i = 2
                    app_state.replay_speed = _REPLAY_SPEED_STEPS[min(i + 1, len(_REPLAY_SPEED_STEPS) - 1)]
                    _redraw_event.set(); continue
                if key in ("-", "_"):
                    try:
                        i = _REPLAY_SPEED_STEPS.index(app_state.replay_speed)
                    except ValueError:
                        i = 2
                    app_state.replay_speed = _REPLAY_SPEED_STEPS[max(i - 1, 0)]
                    _redraw_event.set(); continue

            # Scroll keys target the active screen's buffer.
            _scr = app_state.current_screen
            if key in ("up", "down", "pgup", "pgdn", "home", "end"):
                with lock:
                    total = len(console_output)
                if _scr == SCREEN_DASHBOARD:
                    page = _OUTPUT_PANEL_MIN
                    cur = _output_scroll
                elif _scr == SCREEN_CLI:
                    page = max(1, (os.get_terminal_size().lines if hasattr(os, 'get_terminal_size') else 40) - 4)
                    cur = app_state.cli_scroll
                else:
                    page = max(1, (os.get_terminal_size().lines if hasattr(os, 'get_terminal_size') else 40) - 3)
                    cur = app_state.console_scroll
                mx = max(0, total - page)
                if key == "up":   cur = min(cur + 1, mx)
                elif key == "down": cur = max(0, cur - 1)
                elif key == "pgup": cur = min(cur + page, mx)
                elif key == "pgdn": cur = max(0, cur - page)
                elif key == "home": cur = mx
                elif key == "end":  cur = 0
                if _scr == SCREEN_DASHBOARD:
                    _output_scroll = cur
                    app_state.dash_scroll = cur
                else:
                    app_state.set_scroll(_scr, cur)
                _redraw_event.set()
                continue

            # Number keys 1-9, 0 = tab jumps (dashboard only — preserved across
            # screen toggles since current_tab is module-level).
            if key == '0' and len(TABS) >= 10:
                current_tab = TABS[9]
                app_state.current_tab = current_tab
                show_help_overlay = False
                if app_state.current_screen != SCREEN_DASHBOARD:
                    app_state.switch(SCREEN_DASHBOARD)
                _redraw_event.set()
                continue
            if key in "123456789" and int(key) <= len(TABS):
                current_tab = TABS[int(key) - 1]
                app_state.current_tab = current_tab
                show_help_overlay = False
                if app_state.current_screen != SCREEN_DASHBOARD:
                    app_state.switch(SCREEN_DASHBOARD)
                _redraw_event.set()
                continue

            if len(key) == 1 and 32 <= ord(key) < 127 and not key.isdigit():
                show_help_overlay = False
                cmd = _command_input(fd, key)
                if not cmd.strip():
                    _redraw_event.set()
                    continue
                action = cmd.strip().lower().split()[0]

                if action in TABS:
                    current_tab = action
                    _redraw_event.set()
                    continue

                if action == "help":
                    show_help_overlay = True
                    _output_scroll = 10**9  # clamp to max_scroll → render from top
                    _redraw_event.set()
                    continue

                if action == "clear":
                    with lock:
                        console_output.clear()
                    _output_scroll = 0
                    _redraw_event.set()
                    continue

                _output_scroll = 0
                def _run_inline(c):
                    handle_command(c)
                    _redraw_event.set()
                threading.Thread(target=_run_inline, args=(cmd,), daemon=True).start()
          except KeyboardInterrupt:
            raise
          except Exception:
            _redraw_event.set()
    except KeyboardInterrupt:
        pass
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        shutdown(None, None)

if __name__ == "__main__":
    main()
