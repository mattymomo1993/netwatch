#!/bin/bash
# NetWatch launcher — just run: sudo netwatch
#   --fixed-token : use persistent token instead of random
NETWATCH="/home/mrrobot/agents/honeypot/netwatch.py"
IFACE="${1:-wlan0}"
# Set NETWATCH_FIXED_TOKEN in your environment (e.g., ~/.bashrc) — never commit it
FIXED_TOKEN="${NETWATCH_FIXED_TOKEN:-}"

# Skip iface arg if it's a flag
[[ "$1" == --* ]] && IFACE="wlan0"

# Termux (Android) has no sudo and no root — run in passive mode directly.
# Detection mirrors netwatch.py: TERMUX_VERSION env var OR Termux PREFIX path.
IS_TERMUX=0
if [ -n "${TERMUX_VERSION:-}" ] || [[ "${PREFIX:-}" == /data/data/com.termux* ]]; then
    IS_TERMUX=1
fi

if [ "$EUID" -ne 0 ] && [ "$IS_TERMUX" -ne 1 ]; then
    if command -v sudo >/dev/null 2>&1; then
        exec sudo -E "$0" "$@"
    else
        echo "[!] Not root and sudo not available — running in passive mode (honeypots + web only)." >&2
    fi
fi

# Token: random by default, fixed with --fixed-token
if [[ " $* " == *" --fixed-token "* ]]; then
    if [ -z "$FIXED_TOKEN" ]; then
        echo "ERROR: --fixed-token requested but NETWATCH_FIXED_TOKEN env var is not set." >&2
        echo "Set it in ~/.bashrc:  export NETWATCH_FIXED_TOKEN=\$(openssl rand -hex 24)" >&2
        exit 1
    fi
    TOKEN="$FIXED_TOKEN"
    TOKEN_MODE="FIXED"
else
    TOKEN=$(openssl rand -hex 24)
    TOKEN_MODE="RANDOM"
fi
export NETWATCH_TOKEN="$TOKEN"

# Kill stale ports
fuser -k 2323/tcp 8554/tcp 8080/tcp 2121/tcp 9090/tcp >/dev/null 2>&1
pkill -f "tshark -i" 2>/dev/null
pkill -f "tcpdump -i" 2>/dev/null
sleep 1

echo -e "\033[91;1m"
echo "  ╔══════════════════════════════════════════════════╗"
echo "  ║            NETWATCH — Starting...                ║"
echo "  ╠══════════════════════════════════════════════════╣"
echo -e "  ║  Token: \033[93m${TOKEN}\033[91m  ║"
echo -e "  ║  Mode:  \033[93m${TOKEN_MODE}\033[91m                                       ║"
echo "  ╚══════════════════════════════════════════════════╝"
echo -e "\033[0m"
echo -e "  \033[2mUse --fixed-token for persistent token across launches\033[0m"
echo ""

exec python3 "$NETWATCH" "$IFACE"
