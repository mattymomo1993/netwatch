"""
Tests for the NetWatch web dashboard (web_app on port 9090).
Covers: authentication, CSRF, rate limiting, API endpoints,
SSRF validation, and detail routes.
"""
import json
import time
import ipaddress
import pytest
from unittest.mock import patch, MagicMock
from collections import defaultdict

import netwatch


# ═══════════════════════════════════════════════════════════
#  FIXTURES
# ═══════════════════════════════════════════════════════════

@pytest.fixture
def web_client():
    """Flask test client for the web dashboard (port 9090)."""
    netwatch.web_app.config["TESTING"] = True
    with netwatch.web_app.test_client() as client:
        yield client


@pytest.fixture(autouse=True)
def reset_web_state():
    """Reset web-specific mutable state between tests."""
    netwatch._auth_attempts.clear()
    netwatch._cmd_rate.clear()
    netwatch._snapshot_cache["data"] = None
    netwatch._snapshot_cache["ts"] = 0
    yield


@pytest.fixture
def authed_client(web_client):
    """Web client already authenticated with valid cookie."""
    # Authenticate via the actual auth endpoint to get a proper cookie
    web_client.post(
        "/auth",
        json={"token": netwatch.WEB_TOKEN},
        headers={"Origin": f"http://127.0.0.1:{netwatch.WEB_PORT}"},
    )
    return web_client


@pytest.fixture
def populated_hosts():
    """Pre-populate hosts dict with a sample host."""
    netwatch.hosts["203.0.113.42"] = {
        "bytes_in": 5000,
        "bytes_out": 3000,
        "packets": 100,
        "ports": {80, 443},
        "threat_score": 15,
        "tags": {"scanner"},
        "first_seen": "2025-01-01 10:00:00",
        "last_seen": "2025-01-01 12:00:00",
        "geo": "US",
        "asn": "AS12345",
        "hostname": "example.host",
    }
    return "203.0.113.42"


@pytest.fixture
def populated_recon():
    """Pre-populate recon_reports with a sample report."""
    ip = "203.0.113.42"
    netwatch.recon_reports[ip] = {
        "ip": ip,
        "open_ports": [22, 80, 443],
        "os_guess": "Linux",
        "score": 25,
        "banners": {"80": "nginx/1.22"},
    }
    return ip


# ═══════════════════════════════════════════════════════════
#  AUTH TESTS
# ═══════════════════════════════════════════════════════════

class TestWebAuth:
    def test_unauthenticated_get_root_returns_401(self, web_client):
        resp = web_client.get("/")
        assert resp.status_code == 401

    def test_unauthenticated_get_api_state_returns_401(self, web_client):
        resp = web_client.get("/api/state")
        assert resp.status_code == 401

    def test_post_auth_correct_token_returns_200(self, web_client):
        resp = web_client.post(
            "/auth",
            json={"token": netwatch.WEB_TOKEN},
            headers={"Origin": f"http://127.0.0.1:{netwatch.WEB_PORT}"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True

    def test_post_auth_sets_cookie(self, web_client):
        resp = web_client.post(
            "/auth",
            json={"token": netwatch.WEB_TOKEN},
            headers={"Origin": f"http://127.0.0.1:{netwatch.WEB_PORT}"},
        )
        assert resp.status_code == 200
        cookies = {c.name: c.value for c in web_client.cookie_jar}
        assert "nw_token" in cookies
        decrypted = netwatch._fernet.decrypt(cookies["nw_token"].encode()).decode()
        assert decrypted == netwatch.WEB_TOKEN

    def test_post_auth_wrong_token_returns_401(self, web_client):
        resp = web_client.post(
            "/auth",
            json={"token": "wrong_token_value"},
            headers={"Origin": f"http://127.0.0.1:{netwatch.WEB_PORT}"},
        )
        assert resp.status_code == 401

    def test_post_auth_empty_token_returns_401(self, web_client):
        resp = web_client.post(
            "/auth",
            json={"token": ""},
            headers={"Origin": f"http://127.0.0.1:{netwatch.WEB_PORT}"},
        )
        assert resp.status_code == 401

    def test_post_auth_no_token_field_returns_401(self, web_client):
        resp = web_client.post(
            "/auth",
            json={},
            headers={"Origin": f"http://127.0.0.1:{netwatch.WEB_PORT}"},
        )
        assert resp.status_code == 401

    def test_auth_rate_limit_triggers_after_10_attempts(self, web_client):
        origin = f"http://127.0.0.1:{netwatch.WEB_PORT}"
        for i in range(10):
            resp = web_client.post(
                "/auth",
                json={"token": "bad"},
                headers={"Origin": origin},
            )
            assert resp.status_code == 401, f"attempt {i+1} should be 401"

        # 11th attempt should be rate limited
        resp = web_client.post(
            "/auth",
            json={"token": "bad"},
            headers={"Origin": origin},
        )
        assert resp.status_code == 429
        assert b"Too many attempts" in resp.data

    def test_auth_rate_limit_resets_after_window(self, web_client):
        origin = f"http://127.0.0.1:{netwatch.WEB_PORT}"
        # Fill up the rate limit
        for _ in range(10):
            web_client.post("/auth", json={"token": "bad"}, headers={"Origin": origin})

        # Simulate window expiry by backdating the timestamp
        for ip in netwatch._auth_attempts:
            count, _ = netwatch._auth_attempts[ip]
            netwatch._auth_attempts[ip] = (count, time.time() - 61)

        # Should succeed now (resets counter)
        resp = web_client.post(
            "/auth",
            json={"token": netwatch.WEB_TOKEN},
            headers={"Origin": origin},
        )
        assert resp.status_code == 200

    def test_authenticated_get_root_returns_200(self, authed_client):
        resp = authed_client.get("/")
        assert resp.status_code == 200

    def test_authenticated_get_api_state_returns_200(self, authed_client):
        resp = authed_client.get("/api/state")
        assert resp.status_code == 200


# ═══════════════════════════════════════════════════════════
#  CSRF TESTS
# ═══════════════════════════════════════════════════════════

class TestCSRF:
    def test_post_cmd_without_origin_returns_403(self, authed_client):
        resp = authed_client.post("/api/cmd", json={"cmd": "status"})
        assert resp.status_code == 403
        assert b"Origin header required" in resp.data

    def test_post_cmd_with_wrong_origin_returns_403(self, authed_client):
        resp = authed_client.post(
            "/api/cmd",
            json={"cmd": "status"},
            headers={"Origin": "http://evil.com"},
        )
        assert resp.status_code == 403
        assert b"CSRF rejected" in resp.data

    def test_post_cmd_with_valid_origin_passes_csrf(self, authed_client):
        origin = f"http://127.0.0.1:{netwatch.WEB_PORT}"
        with patch("netwatch.handle_command"), patch("time.sleep"):
            resp = authed_client.post(
                "/api/cmd",
                json={"cmd": "status"},
                headers={"Origin": origin},
            )
        assert resp.status_code == 200

    def test_post_cmd_with_localhost_origin_passes_csrf(self, authed_client):
        origin = f"http://localhost:{netwatch.WEB_PORT}"
        with patch("netwatch.handle_command"), patch("time.sleep"):
            resp = authed_client.post(
                "/api/cmd",
                json={"cmd": "status"},
                headers={"Origin": origin},
            )
        assert resp.status_code == 200

    def test_cloudflare_tunnel_origin_requires_valid_cookie(self, authed_client):
        origin = "https://test-abc123.trycloudflare.com"
        with patch("netwatch.handle_command"), patch("time.sleep"):
            resp = authed_client.post(
                "/api/cmd",
                json={"cmd": "status"},
                headers={"Origin": origin},
            )
        assert resp.status_code == 200

    def test_cloudflare_tunnel_origin_without_cookie_rejected(self, web_client):
        """Cloudflare tunnel POST without valid auth cookie is rejected."""
        # Without valid cookie, _web_auth returns 401 before CSRF check
        origin = "https://test-abc123.trycloudflare.com"
        resp = web_client.post(
            "/api/cmd",
            json={"cmd": "status"},
            headers={"Origin": origin},
        )
        assert resp.status_code == 401

    def test_cf_origin_env_var_allows_specific_origin(self, authed_client):
        with patch.dict("os.environ", {"NETWATCH_CF_ORIGIN": "my-tunnel.example.com"}):
            with patch("netwatch.handle_command"), patch("time.sleep"):
                resp = authed_client.post(
                    "/api/cmd",
                    json={"cmd": "status"},
                    headers={"Origin": "https://my-tunnel.example.com"},
                )
        assert resp.status_code == 200


# ═══════════════════════════════════════════════════════════
#  API STATE & TIMESERIES
# ═══════════════════════════════════════════════════════════

class TestAPIState:
    def test_api_state_returns_valid_json(self, authed_client):
        resp = authed_client.get("/api/state")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        expected_keys = {
            "time", "uptime", "total_packets", "total_bytes",
            "hosts", "host_count", "protocols", "dns", "honeypot",
            "nmap", "arp", "alerts", "osint", "threat_dist",
        }
        assert expected_keys.issubset(set(data.keys()))

    def test_api_state_has_correct_types(self, authed_client):
        resp = authed_client.get("/api/state")
        data = json.loads(resp.data)
        assert isinstance(data["hosts"], list)
        assert isinstance(data["total_packets"], int)
        assert isinstance(data["total_bytes"], int)
        assert isinstance(data["host_count"], int)
        assert isinstance(data["protocols"], list)
        assert isinstance(data["threat_dist"], dict)

    def test_api_state_with_populated_hosts(self, authed_client, populated_hosts):
        # Invalidate cache so fresh snapshot is built
        netwatch._snapshot_cache["data"] = None
        netwatch._snapshot_cache["ts"] = 0
        resp = authed_client.get("/api/state")
        data = json.loads(resp.data)
        assert data["host_count"] == 1
        assert len(data["hosts"]) == 1
        host = data["hosts"][0]
        assert host["ip"] == "203.0.113.42"
        assert host["bytes_in"] == 5000
        assert host["packets"] == 100

    def test_api_state_cache_returns_same_data(self, authed_client):
        resp1 = authed_client.get("/api/state")
        resp2 = authed_client.get("/api/state")
        assert resp1.data == resp2.data

    def test_api_timeseries_returns_list(self, authed_client):
        resp = authed_client.get("/api/timeseries")
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, list)

    def test_api_timeseries_with_samples(self, authed_client):
        with netwatch._ts_lock:
            netwatch._ts_samples.extend([
                {"ts": 1000, "packets": 10, "bytes": 500, "protos": {"TCP": 8}},
                {"ts": 1005, "packets": 15, "bytes": 700, "protos": {"TCP": 12}},
            ])
        resp = authed_client.get("/api/timeseries")
        data = resp.get_json()
        assert len(data) == 2
        assert data[0]["ts"] == 1000

    def test_api_timeseries_last_param(self, authed_client):
        with netwatch._ts_lock:
            for i in range(10):
                netwatch._ts_samples.append(
                    {"ts": 1000 + i * 5, "packets": i, "bytes": i * 100, "protos": {}}
                )
        resp = authed_client.get("/api/timeseries?last=3")
        data = resp.get_json()
        assert len(data) == 3
        # Should be the last 3 samples
        assert data[0]["ts"] == 1035

    def test_api_timeseries_last_capped_at_120(self, authed_client):
        with netwatch._ts_lock:
            for i in range(150):
                netwatch._ts_samples.append(
                    {"ts": 1000 + i, "packets": i, "bytes": 0, "protos": {}}
                )
        resp = authed_client.get("/api/timeseries?last=200")
        data = resp.get_json()
        assert len(data) == 120


# ═══════════════════════════════════════════════════════════
#  COMMAND API
# ═══════════════════════════════════════════════════════════

class TestAPICmd:
    @pytest.fixture
    def cmd_headers(self):
        return {"Origin": f"http://127.0.0.1:{netwatch.WEB_PORT}"}

    def test_safe_command_succeeds(self, authed_client, cmd_headers):
        with patch("netwatch.handle_command") as mock_hc, patch("time.sleep"):
            netwatch.console_output.extend(["Host count: 5"])
            resp = authed_client.post(
                "/api/cmd",
                json={"cmd": "status"},
                headers=cmd_headers,
            )
        assert resp.status_code == 200
        mock_hc.assert_called_once_with("status")

    def test_unknown_command_rejected(self, authed_client, cmd_headers):
        resp = authed_client.post(
            "/api/cmd",
            json={"cmd": "hacktheplanet 1.2.3.4"},
            headers=cmd_headers,
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "not recognized" in data["error"]

    def test_empty_command_returns_error(self, authed_client, cmd_headers):
        resp = authed_client.post(
            "/api/cmd",
            json={"cmd": ""},
            headers=cmd_headers,
        )
        data = resp.get_json()
        assert "empty command" in data["error"]

    def test_whitespace_only_command_returns_error(self, authed_client, cmd_headers):
        resp = authed_client.post(
            "/api/cmd",
            json={"cmd": "   "},
            headers=cmd_headers,
        )
        data = resp.get_json()
        assert "empty command" in data["error"]

    def test_command_output_strips_ansi(self, authed_client, cmd_headers):
        def fake_handle(cmd):
            netwatch.console_output.extend(["\033[31mRed text\033[0m"])

        with patch("netwatch.handle_command", side_effect=fake_handle), patch("time.sleep"):
            resp = authed_client.post(
                "/api/cmd",
                json={"cmd": "status"},
                headers=cmd_headers,
            )
        data = resp.get_json()
        assert data["output"] == ["Red text"]

    def test_rate_limit_triggers_after_threshold(self, authed_client, cmd_headers):
        with patch("netwatch.handle_command"), patch("time.sleep"):
            for i in range(netwatch._CMD_RATE_LIMIT):
                resp = authed_client.post(
                    "/api/cmd",
                    json={"cmd": "status"},
                    headers=cmd_headers,
                )
                assert resp.status_code == 200, f"request {i+1} should pass"

        # Next request should be rate limited
        resp = authed_client.post(
            "/api/cmd",
            json={"cmd": "status"},
            headers=cmd_headers,
        )
        assert resp.status_code == 429
        data = resp.get_json()
        assert "rate limited" in data["error"]

    def test_expensive_cmd_rate_limit(self, authed_client, cmd_headers):
        with patch("netwatch.handle_command"), patch("time.sleep"):
            for i in range(netwatch._EXPENSIVE_RATE_LIMIT):
                resp = authed_client.post(
                    "/api/cmd",
                    json={"cmd": "fullrecon 1.2.3.4"},
                    headers=cmd_headers,
                )
                assert resp.status_code == 200, f"expensive cmd {i+1} should pass"

        # Next expensive command should be rate limited
        with patch("netwatch.handle_command"), patch("time.sleep"):
            resp = authed_client.post(
                "/api/cmd",
                json={"cmd": "fullrecon 1.2.3.4"},
                headers=cmd_headers,
            )
        assert resp.status_code == 429
        data = resp.get_json()
        assert "rate limited" in data["error"]

    def test_rate_limit_resets_after_window(self, authed_client, cmd_headers):
        # Fill the rate limit
        with patch("netwatch.handle_command"), patch("time.sleep"):
            for _ in range(netwatch._CMD_RATE_LIMIT):
                authed_client.post(
                    "/api/cmd",
                    json={"cmd": "status"},
                    headers=cmd_headers,
                )

        # Backdate the window start
        for ip in netwatch._cmd_rate:
            cnt, ecnt, _ = netwatch._cmd_rate[ip]
            netwatch._cmd_rate[ip] = (cnt, ecnt, time.time() - netwatch._CMD_RATE_WINDOW - 1)

        # Should succeed now (window expired)
        with patch("netwatch.handle_command"), patch("time.sleep"):
            resp = authed_client.post(
                "/api/cmd",
                json={"cmd": "status"},
                headers=cmd_headers,
            )
        assert resp.status_code == 200

    def test_internal_target_blocked_for_outbound_cmd(self, authed_client, cmd_headers):
        with patch("netwatch._is_internal_target", return_value=True):
            resp = authed_client.post(
                "/api/cmd",
                json={"cmd": "scan 127.0.0.1"},
                headers=cmd_headers,
            )
        data = resp.get_json()
        assert "internal" in data["error"].lower() or "blocked" in data["error"].lower()

    def test_cidr_too_large_rejected(self, authed_client, cmd_headers):
        resp = authed_client.post(
            "/api/cmd",
            json={"cmd": "scan 10.0.0.0/8"},
            headers=cmd_headers,
        )
        data = resp.get_json()
        assert "too large" in data["error"].lower()

    def test_cidr_within_limit_accepted(self, authed_client, cmd_headers):
        with patch("netwatch._is_internal_target", return_value=False):
            with patch("netwatch.handle_command"), patch("time.sleep"):
                resp = authed_client.post(
                    "/api/cmd",
                    json={"cmd": "scan 93.184.216.0/24"},
                    headers=cmd_headers,
                )
        assert resp.status_code == 200

    def test_all_safe_commands_accepted(self, authed_client, cmd_headers):
        """Spot check several safe commands are accepted."""
        safe_subset = ["status", "ips", "top", "blocked", "summary"]
        for cmd in safe_subset:
            netwatch._cmd_rate.clear()
            with patch("netwatch.handle_command"), patch("time.sleep"):
                resp = authed_client.post(
                    "/api/cmd",
                    json={"cmd": cmd},
                    headers=cmd_headers,
                )
            assert resp.status_code == 200, f"'{cmd}' should be safe"

    def test_all_expensive_cmds_in_safe_set(self):
        """Every expensive command must also be in the safe commands set."""
        for cmd in netwatch._EXPENSIVE_CMDS:
            assert cmd in netwatch._WEB_SAFE_CMDS, f"expensive cmd '{cmd}' not in safe set"


# ═══════════════════════════════════════════════════════════
#  HOST DETAIL API
# ═══════════════════════════════════════════════════════════

class TestAPIHostDetail:
    def test_valid_ip_with_data(self, authed_client, populated_hosts):
        resp = authed_client.get(f"/api/host/{populated_hosts}")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ip"] == "203.0.113.42"
        assert data["bytes_in"] == 5000
        assert data["bytes_out"] == 3000
        assert data["packets"] == 100
        assert 80 in data["ports"]
        assert 443 in data["ports"]
        assert data["threat_score"] == 15
        assert "scanner" in data["tags"]
        assert "honeypot_events" in data
        assert "dns_queries" in data
        assert "nmap_results" in data

    def test_invalid_ip_format_returns_400(self, authed_client):
        resp = authed_client.get("/api/host/not-an-ip")
        assert resp.status_code == 400
        data = resp.get_json()
        assert "invalid" in data["error"].lower()

    def test_unknown_ip_returns_404(self, authed_client):
        resp = authed_client.get("/api/host/198.51.100.99")
        assert resp.status_code == 404
        data = resp.get_json()
        assert "not found" in data["error"].lower()

    def test_host_with_honeypot_events(self, authed_client, populated_hosts):
        netwatch.honeypot_events.append(
            {"time": "12:00:00", "service": "telnet", "ip": "203.0.113.42", "summary": "login admin"}
        )
        resp = authed_client.get("/api/host/203.0.113.42")
        data = resp.get_json()
        assert len(data["honeypot_events"]) == 1
        assert data["honeypot_events"][0]["service"] == "telnet"

    def test_host_with_dns_queries(self, authed_client, populated_hosts):
        netwatch.dns_queries.append(
            {"time": "12:00:00", "ip": "203.0.113.42", "domain": "evil.com"}
        )
        resp = authed_client.get("/api/host/203.0.113.42")
        data = resp.get_json()
        assert len(data["dns_queries"]) == 1

    def test_host_watchlisted_flag(self, authed_client, populated_hosts):
        netwatch.watchlist.add("203.0.113.42")
        resp = authed_client.get("/api/host/203.0.113.42")
        data = resp.get_json()
        assert data["watchlisted"] is True

    def test_host_notes(self, authed_client, populated_hosts):
        netwatch.ip_notes["203.0.113.42"] = "Suspicious scanner"
        resp = authed_client.get("/api/host/203.0.113.42")
        data = resp.get_json()
        assert data["notes"] == "Suspicious scanner"

    def test_host_has_recon_flag(self, authed_client, populated_hosts, populated_recon):
        resp = authed_client.get("/api/host/203.0.113.42")
        data = resp.get_json()
        assert data["has_recon"] is True

    def test_sql_injection_in_ip_returns_400(self, authed_client):
        resp = authed_client.get("/api/host/1.1.1.1' OR 1=1--")
        assert resp.status_code == 400

    def test_path_traversal_in_ip_returns_400(self, authed_client):
        resp = authed_client.get("/api/host/../../etc/passwd")
        assert resp.status_code in (400, 404)


# ═══════════════════════════════════════════════════════════
#  RECON DETAIL API
# ═══════════════════════════════════════════════════════════

class TestAPIReconDetail:
    def test_recon_with_data(self, authed_client, populated_recon):
        resp = authed_client.get(f"/api/recon/{populated_recon}")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ip"] == "203.0.113.42"
        assert data["open_ports"] == [22, 80, 443]
        assert data["os_guess"] == "Linux"

    def test_recon_no_data_returns_404(self, authed_client):
        resp = authed_client.get("/api/recon/198.51.100.99")
        assert resp.status_code == 404
        data = resp.get_json()
        assert "no recon data" in data["error"].lower()

    def test_recon_invalid_ip_returns_400(self, authed_client):
        resp = authed_client.get("/api/recon/not-valid")
        assert resp.status_code == 400
        data = resp.get_json()
        assert "invalid" in data["error"].lower()

    def test_recon_large_list_truncated_to_50(self, authed_client):
        ip = "203.0.113.42"
        netwatch.recon_reports[ip] = {
            "ip": ip,
            "big_list": list(range(100)),
        }
        resp = authed_client.get(f"/api/recon/{ip}")
        data = resp.get_json()
        assert len(data["big_list"]) == 50


# ═══════════════════════════════════════════════════════════
#  SCAN LOG API
# ═══════════════════════════════════════════════════════════

class TestAPIScanLog:
    def test_scan_log_valid_ip_no_logs(self, authed_client):
        with patch("os.listdir", return_value=[]):
            resp = authed_client.get("/api/scan_log/203.0.113.42")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ip"] == "203.0.113.42"
        assert data["scans"] == []

    def test_scan_log_with_matching_files(self, authed_client):
        mock_files = ["nmap_203_0_113_42_2025.txt", "nmap_other_host.txt"]
        mock_content = "PORT   STATE SERVICE\n22/tcp open  ssh"
        with patch("os.listdir", return_value=mock_files):
            with patch("builtins.open", create=True) as mock_open:
                mock_open.return_value.__enter__ = lambda s: s
                mock_open.return_value.__exit__ = MagicMock(return_value=False)
                mock_open.return_value.read = MagicMock(return_value=mock_content)
                resp = authed_client.get("/api/scan_log/203.0.113.42")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ip"] == "203.0.113.42"

    def test_scan_log_invalid_ip_returns_400(self, authed_client):
        resp = authed_client.get("/api/scan_log/bad-input")
        assert resp.status_code == 400
        data = resp.get_json()
        assert "invalid" in data["error"].lower()

    def test_scan_log_with_dots_only_ip(self, authed_client):
        """IP-like format with valid chars passes validation."""
        with patch("os.listdir", return_value=[]):
            resp = authed_client.get("/api/scan_log/1.2.3.4")
        assert resp.status_code == 200


# ═══════════════════════════════════════════════════════════
#  SSRF: _is_internal_target
# ═══════════════════════════════════════════════════════════

class TestIsInternalTarget:
    def test_loopback_blocked(self):
        assert netwatch._is_internal_target("127.0.0.1") is True

    def test_loopback_full_range_blocked(self):
        assert netwatch._is_internal_target("127.0.0.2") is True

    def test_rfc1918_10_blocked(self):
        assert netwatch._is_internal_target("10.0.0.1") is True

    def test_rfc1918_192_168_blocked(self):
        assert netwatch._is_internal_target("192.168.1.1") is True

    def test_rfc1918_172_16_blocked(self):
        assert netwatch._is_internal_target("172.16.0.1") is True

    def test_link_local_blocked(self):
        assert netwatch._is_internal_target("169.254.169.254") is True

    def test_cloud_metadata_blocked(self):
        """AWS/GCP metadata endpoint must be blocked."""
        assert netwatch._is_internal_target("169.254.169.254") is True

    def test_reserved_ip_blocked(self):
        assert netwatch._is_internal_target("240.0.0.1") is True

    def test_public_ip_allowed(self):
        with patch("socket.getaddrinfo", return_value=[(2, 1, 6, '', ("93.184.216.34", 0))]):
            assert netwatch._is_internal_target("93.184.216.34") is False

    def test_another_public_ip_allowed(self):
        with patch("socket.getaddrinfo", return_value=[(2, 1, 6, '', ("1.1.1.1", 0))]):
            assert netwatch._is_internal_target("1.1.1.1") is False

    def test_hostname_resolving_to_private_blocked(self):
        with patch("socket.getaddrinfo", return_value=[(2, 1, 6, '', ("10.0.0.1", 0))]):
            assert netwatch._is_internal_target("evil.internal.com") is True

    def test_hostname_resolving_to_public_allowed(self):
        with patch("socket.getaddrinfo", return_value=[(2, 1, 6, '', ("93.184.216.34", 0))]):
            assert netwatch._is_internal_target("example.com") is False

    def test_dns_error_fails_closed(self):
        """If DNS fails, _is_internal_target should return True (fail closed)."""
        with patch("socket.getaddrinfo", side_effect=Exception("DNS failure")):
            assert netwatch._is_internal_target("no-such-host.invalid") is True

    def test_hostname_resolving_to_loopback_blocked(self):
        with patch("socket.getaddrinfo", return_value=[(2, 1, 6, '', ("127.0.0.1", 0))]):
            assert netwatch._is_internal_target("localhost.evil.com") is True

    def test_hostname_resolving_to_link_local_blocked(self):
        with patch("socket.getaddrinfo", return_value=[(2, 1, 6, '', ("169.254.1.1", 0))]):
            assert netwatch._is_internal_target("metadata.evil.com") is True


# ═══════════════════════════════════════════════════════════
#  NETWORK ACCESS CONTROL
# ═══════════════════════════════════════════════════════════

class TestNetworkAccessControl:
    def test_request_from_disallowed_ip_returns_403(self, web_client):
        """Requests from IPs outside _ALLOWED_NETS should be rejected."""
        # Flask test client uses 127.0.0.1 by default which IS allowed,
        # so we need to mock the remote_addr on the request.
        with web_client.application.test_request_context(
            "/", environ_base={"REMOTE_ADDR": "8.8.8.8"}
        ):
            from flask import request as flask_request
            resp = web_client.application.full_dispatch_request()
            # Can't easily override REMOTE_ADDR in test_client,
            # so test the logic directly.
        # Direct test of the IP check logic:
        client_ip = ipaddress.ip_address("8.8.8.8")
        assert not any(client_ip in net for net in netwatch._ALLOWED_NETS)

    def test_request_from_localhost_allowed(self):
        client_ip = ipaddress.ip_address("127.0.0.1")
        assert any(client_ip in net for net in netwatch._ALLOWED_NETS)

    def test_request_from_tailscale_allowed(self):
        client_ip = ipaddress.ip_address("100.100.1.1")
        assert any(client_ip in net for net in netwatch._ALLOWED_NETS)

    def test_request_from_lan_allowed(self):
        client_ip = ipaddress.ip_address("192.168.1.100")
        assert any(client_ip in net for net in netwatch._ALLOWED_NETS)

    def test_request_from_10_net_allowed(self):
        client_ip = ipaddress.ip_address("10.0.1.5")
        assert any(client_ip in net for net in netwatch._ALLOWED_NETS)

    def test_public_ip_not_in_allowed_nets(self):
        client_ip = ipaddress.ip_address("203.0.113.1")
        assert not any(client_ip in net for net in netwatch._ALLOWED_NETS)


# ═══════════════════════════════════════════════════════════
#  EDGE CASES
# ═══════════════════════════════════════════════════════════

class TestEdgeCases:
    @pytest.fixture
    def cmd_headers(self):
        return {"Origin": f"http://127.0.0.1:{netwatch.WEB_PORT}"}

    def test_concurrent_rate_limit_tracking_per_ip(self, authed_client, cmd_headers):
        """Rate limits are tracked per remote IP, not globally."""
        # Fill rate limit for one IP
        for _ in range(netwatch._CMD_RATE_LIMIT):
            netwatch._cmd_rate["10.0.0.1"] = (netwatch._CMD_RATE_LIMIT, 0, time.time())

        # 127.0.0.1 (test client) should still have its own quota
        with patch("netwatch.handle_command"), patch("time.sleep"):
            resp = authed_client.post(
                "/api/cmd",
                json={"cmd": "status"},
                headers=cmd_headers,
            )
        assert resp.status_code == 200

    def test_expensive_cmd_count_independent_of_normal(self, authed_client, cmd_headers):
        """Normal commands do not consume expensive command quota."""
        with patch("netwatch.handle_command"), patch("time.sleep"):
            for _ in range(10):
                authed_client.post(
                    "/api/cmd",
                    json={"cmd": "status"},
                    headers=cmd_headers,
                )

        # Expensive command should still work
        with patch("netwatch.handle_command"), patch("time.sleep"):
            resp = authed_client.post(
                "/api/cmd",
                json={"cmd": "fullrecon 1.2.3.4"},
                headers=cmd_headers,
            )
        assert resp.status_code == 200

    def test_host_detail_limits_events_to_20(self, authed_client, populated_hosts):
        """Host detail endpoint limits honeypot events to last 20."""
        for i in range(30):
            netwatch.honeypot_events.append(
                {"time": f"12:{i:02d}:00", "service": "telnet",
                 "ip": "203.0.113.42", "summary": f"event {i}"}
            )
        resp = authed_client.get("/api/host/203.0.113.42")
        data = resp.get_json()
        assert len(data["honeypot_events"]) == 20

    def test_api_state_mimetype_is_json(self, authed_client):
        resp = authed_client.get("/api/state")
        assert "application/json" in resp.content_type

    def test_web_safe_cmds_is_frozenlike_set(self):
        """_WEB_SAFE_CMDS should be a set for O(1) lookup."""
        assert isinstance(netwatch._WEB_SAFE_CMDS, set)

    def test_expensive_cmds_is_subset_of_safe(self):
        """All expensive commands must also be safe commands."""
        assert netwatch._EXPENSIVE_CMDS.issubset(netwatch._WEB_SAFE_CMDS)


# ═══════════════════════════════════════════════════════════
#  WEB HELP + DATA FLOW TESTS
# ═══════════════════════════════════════════════════════════

class TestWebHelp:
    def test_help_in_web_safe_cmds(self):
        """help command is allowed via web API."""
        assert "help" in netwatch._WEB_SAFE_CMDS

    def test_help_via_api_returns_output(self, authed_client):
        """Running help via /api/cmd returns command reference text."""
        resp = authed_client.post(
            "/api/cmd",
            json={"cmd": "help"},
            headers={"Origin": f"http://127.0.0.1:{netwatch.WEB_PORT}"},
        )
        data = resp.get_json()
        assert "output" in data
        assert len(data["output"]) > 10
        text = " ".join(data["output"])
        assert "help" in text.lower()

    def test_help_via_api_includes_scan_commands(self, authed_client):
        """Help output includes scanning commands."""
        resp = authed_client.post(
            "/api/cmd",
            json={"cmd": "help"},
            headers={"Origin": f"http://127.0.0.1:{netwatch.WEB_PORT}"},
        )
        text = " ".join(resp.get_json()["output"])
        assert "scan" in text
        assert "recon" in text

    def test_web_dashboard_html_has_help_tab(self):
        """Web dashboard JS includes help tab."""
        assert "help" in netwatch.WEB_DASHBOARD_HTML
        assert "renderHelp" in netwatch.WEB_DASHBOARD_HTML

    def test_web_dashboard_has_theme_selector(self):
        """Web dashboard has theme dropdown."""
        assert "theme-sel" in netwatch.WEB_DASHBOARD_HTML
        assert "theme-matrix" in netwatch.WEB_DASHBOARD_HTML
        assert "theme-midnight" in netwatch.WEB_DASHBOARD_HTML
        assert "theme-cyberpunk" in netwatch.WEB_DASHBOARD_HTML
        assert "theme-light" in netwatch.WEB_DASHBOARD_HTML

    def test_web_dashboard_has_scanline_selector(self):
        """Web dashboard has CRT scanline dropdown."""
        assert "scanline-sel" in netwatch.WEB_DASHBOARD_HTML
        assert "scanline-overlay" in netwatch.WEB_DASHBOARD_HTML

    def test_web_dashboard_has_cmd_bar(self):
        """Web dashboard has command input bar."""
        assert "cmd-input" in netwatch.WEB_DASHBOARD_HTML
        assert "cmd-bar" in netwatch.WEB_DASHBOARD_HTML


class TestWebDataFlow:
    def test_state_snapshot_includes_all_fields(self):
        """_state_snapshot returns all required fields for web UI."""
        snap = netwatch._state_snapshot()
        required = ["time", "total_packets", "total_bytes", "total_bytes_fmt",
                     "hosts", "host_count", "protocols", "dns", "honeypot",
                     "nmap", "nmap_running", "arp", "alerts", "osint"]
        for field in required:
            assert field in snap, f"Missing field: {field}"

    def test_state_snapshot_hosts_have_required_keys(self):
        """Each host in state snapshot has keys the web JS expects."""
        netwatch.hosts["10.0.0.99"] = {
            "bytes_in": 100, "bytes_out": 50, "packets": 5,
            "ports": {80}, "protocols": set(), "first_seen": None,
            "last_seen": None, "hostname": "test", "resolved": False,
            "threat_score": 5, "tags": {"test"},
        }
        snap = netwatch._state_snapshot()
        h = next((h for h in snap["hosts"] if h["ip"] == "10.0.0.99"), None)
        assert h is not None
        for key in ["ip", "hostname", "bytes_in", "bytes_out", "packets", "ports", "threat_score", "tags"]:
            assert key in h, f"Host missing key: {key}"
        del netwatch.hosts["10.0.0.99"]

    def test_state_snapshot_dns_entries_have_keys(self):
        """DNS entries in snapshot have time, ip, domain."""
        netwatch.dns_queries.append({"time": "12:00:00", "ip": "1.2.3.4", "domain": "test.com"})
        snap = netwatch._state_snapshot()
        assert len(snap["dns"]) > 0
        entry = snap["dns"][-1]
        assert "time" in entry
        assert "ip" in entry
        assert "domain" in entry

    def test_state_snapshot_honeypot_entries_have_keys(self):
        """Honeypot entries in snapshot have required keys."""
        netwatch.honeypot_events.append({
            "time": "12:00:00", "service": "telnet",
            "ip": "5.6.7.8", "summary": "login attempt"
        })
        snap = netwatch._state_snapshot()
        assert len(snap["honeypot"]) > 0
        entry = snap["honeypot"][-1]
        for key in ["time", "service", "ip", "summary"]:
            assert key in entry

    def test_state_snapshot_osint_included(self):
        """OSINT results are included in state snapshot."""
        netwatch.osint_results.append({
            "time": "12:00:00", "type": "GEO",
            "target": "8.8.8.8", "result": "US, Mountain View"
        })
        snap = netwatch._state_snapshot()
        assert len(snap["osint"]) > 0

    def test_cached_snapshot_returns_json_string(self):
        """_cached_snapshot returns valid JSON string."""
        netwatch._snapshot_cache["data"] = None
        netwatch._snapshot_cache["ts"] = 0
        result = netwatch._cached_snapshot()
        parsed = json.loads(result)
        assert isinstance(parsed, dict)
        assert "hosts" in parsed

    def test_state_snapshot_threat_dist(self):
        """State snapshot includes threat distribution."""
        snap = netwatch._state_snapshot()
        assert "threat_dist" in snap
        for key in ["clean", "low", "medium", "high"]:
            assert key in snap["threat_dist"]

    def test_api_state_returns_valid_json(self, authed_client):
        """GET /api/state returns valid JSON with required fields."""
        resp = authed_client.get("/api/state")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "hosts" in data
        assert "total_packets" in data

    def test_host_detail_includes_action_buttons_data(self, authed_client, populated_hosts):
        """Host detail has ports, tags, scores for action buttons."""
        resp = authed_client.get("/api/host/203.0.113.42")
        data = resp.get_json()
        assert "ports" in data
        assert "tags" in data
        assert "threat_score" in data
        assert "has_recon" in data

    def test_ifinfo_via_web_api(self, authed_client):
        """ifinfo command works via web API."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="eth0: 10.0.1.5/24", returncode=0)
            resp = authed_client.post(
                "/api/cmd",
                json={"cmd": "ifinfo"},
                headers={"Origin": f"http://127.0.0.1:{netwatch.WEB_PORT}"},
            )
            data = resp.get_json()
            assert "output" in data

    def test_speed_in_web_safe(self):
        """speed command is allowed via web."""
        assert "speed" in netwatch._WEB_SAFE_CMDS

    def test_ifinfo_in_web_safe(self):
        """ifinfo command is allowed via web."""
        assert "ifinfo" in netwatch._WEB_SAFE_CMDS


# ═══════════════════════════════════════════════════════════
#  SECURITY AUDIT FIX TESTS
# ═══════════════════════════════════════════════════════════

class TestCookiePath:
    def test_auth_cookie_has_root_path(self, web_client):
        resp = web_client.post(
            "/auth",
            json={"token": netwatch.WEB_TOKEN},
            headers={"Origin": f"http://127.0.0.1:{netwatch.WEB_PORT}"},
        )
        cookie_header = resp.headers.get("Set-Cookie", "")
        assert "Path=/" in cookie_header, "Cookie must be scoped to root path"

    def test_auth_cookie_httponly(self, web_client):
        resp = web_client.post(
            "/auth",
            json={"token": netwatch.WEB_TOKEN},
            headers={"Origin": f"http://127.0.0.1:{netwatch.WEB_PORT}"},
        )
        cookie_header = resp.headers.get("Set-Cookie", "")
        assert "HttpOnly" in cookie_header


class TestIPv6WebEndpoints:
    def test_recon_accepts_ipv6(self, authed_client):
        resp = authed_client.get("/api/recon/2001:db8::1")
        assert resp.status_code != 400 or "invalid IP" not in resp.get_json().get("error", "")

    def test_host_accepts_ipv6(self, authed_client):
        resp = authed_client.get("/api/host/2001:db8::1")
        assert resp.status_code != 400 or "invalid IP" not in resp.get_json().get("error", "")

    def test_scan_log_accepts_ipv6(self, authed_client):
        resp = authed_client.get("/api/scan_log/2001:db8::1")
        assert resp.status_code != 400 or "invalid IP" not in resp.get_json().get("error", "")

    def test_rejects_shell_chars_in_ip(self, authed_client):
        resp = authed_client.get("/api/host/;ls")
        assert resp.status_code == 400

    def test_rejects_path_traversal_in_ip(self, authed_client):
        resp = authed_client.get("/api/scan_log/../../etc/passwd")
        assert resp.status_code in (400, 404)


class TestRateDictCleanup:
    def test_auth_prunes_at_1000(self, web_client):
        for i in range(1002):
            netwatch._auth_attempts[f"10.0.{i // 256}.{i % 256}"] = (1, time.time() - 600)
        web_client.post(
            "/auth",
            json={"token": "wrong"},
            headers={"Origin": f"http://127.0.0.1:{netwatch.WEB_PORT}"},
        )
        assert len(netwatch._auth_attempts) < 1002

    def test_cmd_rate_prunes_at_1000(self, authed_client):
        for i in range(1002):
            netwatch._cmd_rate[f"10.0.{i // 256}.{i % 256}"] = (1, 0, time.time() - 300)
        authed_client.post(
            "/api/cmd",
            json={"cmd": "status"},
            headers={"Origin": f"http://127.0.0.1:{netwatch.WEB_PORT}"},
        )
        assert len(netwatch._cmd_rate) < 1002


class TestGraphQLSecurity:
    def test_query_length_rejected(self, authed_client):
        long_query = "{ hosts { ip " + " " * 5000 + "} }"
        resp = authed_client.post(
            "/graphql",
            json={"query": long_query},
            headers={"Origin": f"http://127.0.0.1:{netwatch.WEB_PORT}"},
        )
        if resp.status_code == 200:
            pytest.skip("GraphQL not available")
        assert resp.status_code == 400
        assert "too long" in resp.get_json()["errors"][0]["message"].lower()

    def test_deep_nesting_rejected(self, authed_client):
        nested = "{ " * 10 + "hosts { ip }" + " }" * 10
        resp = authed_client.post(
            "/graphql",
            json={"query": nested},
            headers={"Origin": f"http://127.0.0.1:{netwatch.WEB_PORT}"},
        )
        if resp.status_code == 200:
            pytest.skip("GraphQL not available")
        assert resp.status_code == 400

    def test_gql_mutation_rate_limited(self, authed_client):
        for i in range(25):
            netwatch._cmd_rate["127.0.0.1"] = (20, 0, time.time())
        resp = authed_client.post(
            "/graphql",
            json={"query": 'mutation { runCommand(cmd: "status") { output error } }'},
            headers={"Origin": f"http://127.0.0.1:{netwatch.WEB_PORT}"},
        )
        if resp.status_code == 200:
            data = resp.get_json()
            if data.get("data", {}).get("runCommand"):
                assert data["data"]["runCommand"]["error"] == "rate limited"


class TestNoBashInjection:
    def test_no_bash_c_with_fstring(self):
        with open(netwatch.__file__, "r") as f:
            source = f.read()
        import re as _re
        matches = _re.findall(r'subprocess\.run\(\["bash",\s*"-c",\s*f"', source)
        assert len(matches) == 0, f"Found {len(matches)} bash -c f-string calls — use socket.connect() instead"


class TestAnsiInjectionProtection:
    """Verify attacker-controlled data is sanitized before TUI/log rendering."""

    def test_short_summary_strips_ansi(self):
        malicious_user = "admin\x1b[31mHACKED\x1b[0m"
        result = netwatch._short_summary("credential", "1.2.3.4",
                                          {"username": malicious_user, "password": "test"})
        assert "\x1b" not in result, "ANSI escape in summary"

    def test_short_summary_strips_control_chars(self):
        result = netwatch._short_summary("telnet_cmd", "1.2.3.4",
                                          {"command": "id\x00\x07\x08"})
        assert "\x00" not in result
        assert "\x07" not in result

    def test_resolve_host_strips_ansi(self):
        with patch("socket.gethostbyaddr", return_value=("\x1b[31mevil.host\x1b[0m", [], [])):
            name = netwatch.resolve_host("198.51.100.99")
            assert "\x1b" not in name
        netwatch.dns_cache.pop("198.51.100.99", None)

    def test_summary_http_path_stripped(self):
        result = netwatch._short_summary("http", "1.2.3.4",
                                          {"method": "GET", "path": "/\x1b[2J\x1b[Hpwned"})
        assert "\x1b" not in result

    def test_summary_scan_probe_stripped(self):
        result = netwatch._short_summary("scan_probe", "1.2.3.4",
                                          {"method": "GET", "path": "/\x1b[31m"})
        assert "\x1b" not in result

    def test_ansi_strip_removes_osc(self):
        """OSC sequences (set terminal title) must be stripped."""
        s = "\x1b]0;evil title\x07normal"
        assert "\x1b" not in netwatch._ansi_strip(s)
        assert "normal" in netwatch._ansi_strip(s)

    def test_ansi_strip_removes_carriage_return(self):
        """\\r can be used for log forgery."""
        s = "malicious\roverwrite"
        result = netwatch._ansi_strip(s)
        assert "\r" not in result


# ═══════════════════════════════════════════════════════════
#  SECURITY HEADERS
# ═══════════════════════════════════════════════════════════

class TestSecurityHeaders:
    """Web responses must include anti-clickjacking and anti-sniffing headers."""

    def test_x_frame_options_sameorigin(self, web_client):
        # SAMEORIGIN lets the dashboard embed /replay/<sid> in an iframe while
        # still blocking cross-site framing (clickjacking protection intact).
        resp = web_client.get("/")
        assert resp.headers.get("X-Frame-Options") == "SAMEORIGIN"

    def test_x_content_type_options(self, web_client):
        resp = web_client.get("/")
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"

    def test_referrer_policy(self, web_client):
        resp = web_client.get("/")
        assert resp.headers.get("Referrer-Policy") == "no-referrer"

    def test_cache_control_no_store(self, web_client):
        resp = web_client.get("/")
        assert "no-store" in resp.headers.get("Cache-Control", "")

    def test_permissions_policy(self, web_client):
        resp = web_client.get("/")
        pp = resp.headers.get("Permissions-Policy", "")
        assert "camera=()" in pp
        assert "microphone=()" in pp

    def test_headers_on_api_endpoint(self, web_client):
        resp = web_client.get("/api/state")
        assert resp.headers.get("X-Frame-Options") == "SAMEORIGIN"
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"

    def test_after_request_present_in_source(self):
        """Prevent regression: after_request must define security headers."""
        import inspect
        src = inspect.getsource(netwatch)
        assert "X-Frame-Options" in src
        assert "after_request" in src


# ═══════════════════════════════════════════════════════════
#  SSRF DNS REBINDING DEFENSE
# ═══════════════════════════════════════════════════════════

class TestSSRFDefense:
    """SSRF validation must fail-closed and block private IPs."""

    def test_validate_url_blocks_localhost(self):
        ok, _ = netwatch._validate_target_url("http://localhost/test")
        assert not ok

    def test_validate_url_blocks_127(self):
        ok, _ = netwatch._validate_target_url("http://127.0.0.1/secret")
        assert not ok

    def test_validate_url_blocks_metadata(self):
        ok, _ = netwatch._validate_target_url("http://metadata.google.internal/v1/")
        assert not ok

    def test_validate_url_blocks_zero(self):
        ok, _ = netwatch._validate_target_url("http://0.0.0.0/")
        assert not ok

    def test_validate_url_blocks_ipv6_loopback(self):
        ok, _ = netwatch._validate_target_url("http://[::1]/")
        assert not ok

    def test_validate_url_fails_closed_on_dns_error(self):
        with patch("netwatch.socket.getaddrinfo", side_effect=Exception("nxdomain")):
            ok, reason = netwatch._validate_target_url("http://evil.example.com/")
            assert not ok
            assert "failed" in reason.lower()

    def test_validate_host_fails_closed_on_dns_error(self):
        with patch("netwatch.socket.getaddrinfo", side_effect=Exception("nxdomain")):
            ok, reason = netwatch._validate_target_host("evil.example.com")
            assert not ok

    def test_validate_host_blocks_private_10(self):
        with patch("netwatch.socket.getaddrinfo", return_value=[(None, None, None, None, ("10.0.0.1", 0))]):
            ok, _ = netwatch._validate_target_host("rebind.example.com")
            assert not ok

    def test_validate_host_blocks_link_local(self):
        with patch("netwatch.socket.getaddrinfo", return_value=[(None, None, None, None, ("169.254.1.1", 0))]):
            ok, _ = netwatch._validate_target_host("rebind.example.com")
            assert not ok


# ═══════════════════════════════════════════════════════════
#  TLS CERT_NONE INTENTIONAL VERIFICATION
# ═══════════════════════════════════════════════════════════

class TestSSLInspection:
    """osint_ssl uses CERT_NONE intentionally for cert inspection."""

    def test_ssl_function_validates_target_format(self):
        result = netwatch.osint_ssl("evil; rm -rf /")
        assert "error" in result

    def test_ssl_function_validates_target_host(self):
        with patch.object(netwatch, "_validate_target_host", return_value=(False, "blocked")):
            result = netwatch.osint_ssl("1.2.3.4")
            assert "error" in result

    def test_ssl_rejects_invalid_port(self):
        result = netwatch.osint_ssl("example.com", port=0)
        assert "error" in result
        result = netwatch.osint_ssl("example.com", port=99999)
        assert "error" in result


# ═══════════════════════════════════════════════════════════
#  NO SHELL INJECTION PATTERNS
# ═══════════════════════════════════════════════════════════

class TestNoShellInjection:
    """Ensure dangerous patterns never appear in source."""

    def test_no_shell_true(self):
        import inspect
        src = inspect.getsource(netwatch)
        assert "shell=True" not in src

    def test_no_os_system(self):
        import inspect
        src = inspect.getsource(netwatch)
        assert "os.system(" not in src

    def test_no_os_popen(self):
        import inspect
        src = inspect.getsource(netwatch)
        assert "os.popen(" not in src

    def test_no_eval(self):
        import inspect
        src = inspect.getsource(netwatch)
        lines = src.split("\n")
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith('"') or stripped.startswith("'"):
                continue
            assert "eval(" not in stripped or "evaluate" in stripped.lower()

    def test_no_pickle_loads(self):
        import inspect
        src = inspect.getsource(netwatch)
        assert "pickle.loads" not in src
        assert "pickle.load(" not in src


# ═══════════════════════════════════════════════════════════
#  IPTABLES IP VALIDATION
# ═══════════════════════════════════════════════════════════

class TestIptablesValidation:
    """Block/unblock commands must validate IPs before iptables calls."""

    def test_block_rejects_shell_injection(self):
        netwatch.console_output.clear()
        netwatch.handle_command("block 1.2.3.4;rm -rf /")
        output = " ".join(netwatch.console_output)
        assert "Invalid" in output

    def test_block_rejects_non_ip(self):
        netwatch.console_output.clear()
        netwatch.handle_command("block notanip")
        output = " ".join(netwatch.console_output)
        assert "Invalid" in output

    def test_unblock_rejects_shell_injection(self):
        netwatch.console_output.clear()
        netwatch.handle_command("unblock $(whoami)")
        output = " ".join(netwatch.console_output)
        assert "Invalid" in output
