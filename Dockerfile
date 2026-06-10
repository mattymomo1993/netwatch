# NetWatch — all-in-one network security dashboard (honeypots + capture + OSINT)
# Headless by default: no TTY in a container, so NetWatch runs the web dashboard
# and honeypots without the curses UI.
FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.title="NetWatch" \
      org.opencontainers.image.description="Honeypots, traffic capture, OSINT, scanning, mesh alerts." \
      org.opencontainers.image.source="https://github.com/Mattmorris-dev/netwatch-sec" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later"

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# System tools NetWatch shells out to: scanning, sniffing, OSINT, defense.
# Preseed wireshark-common so tshark installs without the interactive setuid prompt.
RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      nmap tshark tcpdump traceroute iproute2 iptables \
      curl openssl whois dnsutils arp-scan \
      psmisc procps ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY netwatch.py replay.py netwatch_crowdsec.py ./

# Honeypot + dashboard ports (informational — on Linux use --network host).
# Defaults: HTTP 8080, Telnet 2323, FTP 2121, RTSP 8554, dashboard 9090.
# Standard-port honeypot: pass NETWATCH_*_PORT env (23/21/80/554).
EXPOSE 21 23 80 554 2121 2323 8080 8554 9090

# Interface defaults to eth0; override: `docker run ... netwatch-sec <iface>`.
ENTRYPOINT ["python", "netwatch.py"]
CMD ["eth0"]
