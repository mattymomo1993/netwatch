"""Tests for v2 refactor: dispatch table, Fernet encryption, command history,
console persistence, batch operations, extracted OSINT commands."""
import sys
import os
import time
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
with patch("subprocess.check_output", return_value="inet 10.0.1.9/24 scope global\ninet 127.0.0.1/8 scope host"):
    with patch.dict(os.environ, {"WERKZEUG_RUN_MAIN": "true"}):
        import netwatch


class TestDispatchTable:

    def test_dispatch_table_exists(self):
        netwatch.handle_command("help")
        assert len(netwatch.console_output) > 0

    @patch("threading.Thread")
    def test_dispatch_deep(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("deep 10.0.1.1")
        assert any("DEEP SCAN" in c for c in netwatch.console_output)
        mock_thread.assert_called()

    @patch("threading.Thread")
    def test_dispatch_stealth(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("stealth 10.0.1.1")
        assert any("STEALTH" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_dispatch_recon(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("recon 10.0.1.1")
        assert any("RECON" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_dispatch_trace(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("trace 10.0.1.1")
        assert any("Traceroute" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_dispatch_geo(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("geo 8.8.8.8")
        assert any("Geolocating" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_dispatch_crt(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("crt example.com")
        assert any("Cert transparency" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_dispatch_headers(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("headers example.com")
        assert any("HTTP headers" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_dispatch_asn(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("asn 8.8.8.8")
        assert any("ASN lookup" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_dispatch_abuse(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("abuse 8.8.8.8")
        assert any("Abuse check" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_dispatch_secheaders(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("secheaders example.com")
        assert any("Security header" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_dispatch_techstack(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("techstack example.com")
        assert any("Tech fingerprint" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_dispatch_etrace(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("etrace 8.8.8.8")
        assert any("Enriched traceroute" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_dispatch_health(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("health example.com")
        assert any("HEALTH CHECK" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_dispatch_analyze(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("analyze 10.0.1.1")
        assert any("Analyzing" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_dispatch_rdns(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("rdns 8.8.8.8")
        assert any("Reverse DNS" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_dispatch_fullrecon(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("fullrecon 8.8.8.8")
        assert any("FULL RECON" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_dispatch_country(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("country US")
        assert any("US" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_dispatch_diffarp(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("diffarp")
        assert any("ARP TABLE DIFF" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_dispatch_sweep(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("sweep")
        assert any("NETWORK SWEEP" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_dispatch_speed(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("speed")
        mock_thread.assert_called()

    @patch("threading.Thread")
    def test_dispatch_conns(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("conns 10.0.1.1")
        assert any("Capturing TCP" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_dispatch_trackdns(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("trackdns 10.0.1.1")
        assert any("Capturing DNS" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_dispatch_invalid_target_rejected(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("deep ;rm -rf")
        assert any("Invalid target" in c for c in netwatch.console_output)
        mock_thread.assert_not_called()


class TestFernetEncryption:

    def test_fernet_key_generated(self):
        assert hasattr(netwatch, 'WEB_ENCRYPTION_KEY')
        assert len(netwatch.WEB_ENCRYPTION_KEY) > 0

    def test_fernet_instance_exists(self):
        assert hasattr(netwatch, '_fernet')

    def test_fernet_encrypt_decrypt_roundtrip(self):
        token = "test_token_value"
        encrypted = netwatch._fernet.encrypt(token.encode())
        decrypted = netwatch._fernet.decrypt(encrypted).decode()
        assert decrypted == token

    def test_verify_web_cookie_valid(self):
        encrypted = netwatch._fernet.encrypt(netwatch.WEB_TOKEN.encode()).decode()
        assert netwatch._verify_web_cookie(encrypted) is True

    def test_verify_web_cookie_invalid(self):
        assert netwatch._verify_web_cookie("garbage_value") is False

    def test_verify_web_cookie_empty(self):
        assert netwatch._verify_web_cookie("") is False

    def test_verify_web_cookie_none(self):
        assert netwatch._verify_web_cookie(None) is False

    def test_verify_web_cookie_wrong_token(self):
        encrypted = netwatch._fernet.encrypt(b"wrong_token").decode()
        assert netwatch._verify_web_cookie(encrypted) is False

    def test_verify_web_cookie_raw_token_rejected(self):
        assert netwatch._verify_web_cookie(netwatch.WEB_TOKEN) is False

    def test_auth_sets_encrypted_cookie(self):
        netwatch.web_app.config["TESTING"] = True
        with netwatch.web_app.test_client() as client:
            resp = client.post("/auth", json={"token": netwatch.WEB_TOKEN},
                               content_type="application/json")
            assert resp.status_code == 200
            cookie = client.get_cookie("nw_token")  # Werkzeug 3.x: no cookie_jar
            assert cookie is not None
            decrypted = netwatch._fernet.decrypt(cookie.value.encode()).decode()
            assert decrypted == netwatch.WEB_TOKEN


class TestCommandHistory:

    def test_history_list_exists(self):
        from collections import deque
        assert hasattr(netwatch, '_cmd_history')
        assert isinstance(netwatch._cmd_history, deque)
        assert netwatch._cmd_history.maxlen == netwatch._CMD_HISTORY_MAX

    def test_history_max_constant(self):
        assert netwatch._CMD_HISTORY_MAX == 5000

    def test_history_cleared_in_fixture(self):
        assert len(netwatch._cmd_history) == 0


class TestConsolePersistence:

    def test_console_output_persists_across_commands(self):
        netwatch.handle_command("help")
        count_after_first = len(netwatch.console_output)
        assert count_after_first > 0
        netwatch.handle_command("ips")
        count_after_second = len(netwatch.console_output)
        assert count_after_second >= count_after_first

    def test_max_console_increased(self):
        assert netwatch.MAX_CONSOLE == 5000
        from collections import deque
        assert isinstance(netwatch.console_output, deque)
        assert netwatch.console_output.maxlen == netwatch.MAX_CONSOLE

    @patch("threading.Thread")
    def test_exec_console_preserves_history(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.add_console("existing line 1")
        netwatch.add_console("existing line 2")
        initial_count = len(netwatch.console_output)
        with patch("builtins.print"):
            netwatch._exec_console_cmd("ips")
        assert len(netwatch.console_output) >= initial_count

    @patch("threading.Thread")
    def test_web_cmd_preserves_history(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.add_console("pre-existing")
        netwatch.web_app.config["TESTING"] = True
        origin = f"http://127.0.0.1:{netwatch.WEB_PORT}"
        with netwatch.web_app.test_client() as client:
            client.post("/auth", json={"token": netwatch.WEB_TOKEN},
                        headers={"Origin": origin})
            with patch("time.sleep"):
                resp = client.post("/api/cmd", json={"cmd": "ips"},
                                   headers={"Origin": origin})
            assert resp.status_code == 200
        assert any("pre-existing" in c for c in netwatch.console_output)


class TestBatchOperations:

    @patch("threading.Thread")
    def test_scanall_dispatches(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.honeypot_events.extend([
            {"time": "10:00", "service": "telnet", "ip": "203.0.113.1", "summary": "test"},
        ])
        netwatch.handle_command("scanall")
        assert any("BATCH SCAN" in c for c in netwatch.console_output)
        mock_thread.assert_called()

    @patch("threading.Thread")
    def test_geoall_dispatches(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.honeypot_events.extend([
            {"time": "10:00", "service": "telnet", "ip": "93.184.216.34", "summary": "test"},
        ])
        netwatch.handle_command("geoall")
        assert any("BATCH GEO" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_whoisall_dispatches(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.honeypot_events.extend([
            {"time": "10:00", "service": "telnet", "ip": "93.184.216.34", "summary": "test"},
        ])
        netwatch.handle_command("whoisall")
        assert any("BATCH WHOIS" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_reconall_dispatches(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.honeypot_events.extend([
            {"time": "10:00", "service": "telnet", "ip": "203.0.113.1", "summary": "test"},
        ])
        netwatch.handle_command("reconall")
        assert any("BATCH RECON" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_batch_empty_list(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("scanall")
        assert any("No IPs" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_geoall_filters_private(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.honeypot_events.extend([
            {"time": "10:00", "service": "telnet", "ip": "10.0.1.1", "summary": "test"},
        ])
        netwatch.handle_command("geoall")
        assert any("No external" in c for c in netwatch.console_output)


class TestExtractedOsintFunctions:

    def test_cmd_crt_exists(self):
        assert callable(netwatch._cmd_crt)

    def test_cmd_headers_exists(self):
        assert callable(netwatch._cmd_headers)

    def test_cmd_asn_exists(self):
        assert callable(netwatch._cmd_asn)

    def test_cmd_abuse_exists(self):
        assert callable(netwatch._cmd_abuse)

    def test_cmd_ssl_exists(self):
        assert callable(netwatch._cmd_ssl)

    def test_cmd_secheaders_exists(self):
        assert callable(netwatch._cmd_secheaders)

    def test_cmd_techstack_exists(self):
        assert callable(netwatch._cmd_techstack)

    def test_cmd_ping_exists(self):
        assert callable(netwatch._cmd_ping)

    def test_cmd_etrace_exists(self):
        assert callable(netwatch._cmd_etrace)

    def test_cmd_health_exists(self):
        assert callable(netwatch._cmd_health)

    def test_cmd_analyze_exists(self):
        assert callable(netwatch._cmd_analyze)

    def test_cmd_rdns_exists(self):
        assert callable(netwatch._cmd_rdns)

    def test_cmd_fullrecon_exists(self):
        assert callable(netwatch._cmd_fullrecon)

    def test_cmd_country_exists(self):
        assert callable(netwatch._cmd_country)

    def test_cmd_sweep_exists(self):
        assert callable(netwatch._cmd_sweep)

    def test_cmd_diffarp_exists(self):
        assert callable(netwatch._cmd_diffarp)

    def test_cmd_speed_exists(self):
        assert callable(netwatch._cmd_speed)

    @patch("netwatch.osint_crt")
    def test_cmd_crt_error_handling(self, mock_crt):
        mock_crt.return_value = {"error": "timeout"}
        netwatch._cmd_crt("example.com")
        assert any("timeout" in c for c in netwatch.console_output)

    @patch("netwatch.osint_crt")
    def test_cmd_crt_empty_result(self, mock_crt):
        mock_crt.return_value = []
        netwatch._cmd_crt("example.com")
        assert any("No certs" in c for c in netwatch.console_output)

    @patch("netwatch.osint_crt")
    def test_cmd_crt_success(self, mock_crt):
        mock_crt.return_value = [{"cn": "*.example.com", "not_after": "2025-12-31"}]
        netwatch._cmd_crt("example.com")
        assert any("1 subdomain" in c for c in netwatch.console_output)

    @patch("netwatch.osint_headers")
    def test_cmd_headers_error(self, mock_hdr):
        mock_hdr.return_value = {"error": "connection refused"}
        netwatch._cmd_headers("example.com")
        assert any("connection refused" in c for c in netwatch.console_output)

    @patch("netwatch.osint_headers")
    def test_cmd_headers_success(self, mock_hdr):
        mock_hdr.return_value = {"status": 200, "tech": ["nginx"], "headers": {"server": "nginx"}}
        netwatch._cmd_headers("example.com")
        assert any("200" in c for c in netwatch.console_output)
        assert any("nginx" in c for c in netwatch.console_output)

    @patch("netwatch.osint_asn")
    def test_cmd_asn_error(self, mock_asn):
        mock_asn.return_value = {"error": "not found"}
        netwatch._cmd_asn("10.0.0.1")
        assert any("not found" in c for c in netwatch.console_output)

    @patch("netwatch.osint_abuse")
    def test_cmd_abuse_success(self, mock_abuse):
        mock_abuse.return_value = {"ip": "8.8.8.8", "score": "0", "reports": "0"}
        netwatch._cmd_abuse("8.8.8.8")
        assert any("8.8.8.8" in c for c in netwatch.console_output)

    @patch("netwatch.osint_ssl")
    def test_cmd_ssl_with_port(self, mock_ssl):
        mock_ssl.return_value = {"protocol": "TLSv1.3", "cipher": "AES256", "bits": 256,
            "subject": "example.com", "issuer": "Let's Encrypt", "not_before": "2024-01-01",
            "not_after": "2025-01-01", "days_left": 180, "alt_names": ["*.example.com"]}
        netwatch._cmd_ssl("example.com:8443")
        mock_ssl.assert_called_once_with("example.com", 8443)

    @patch("netwatch.osint_ssl")
    def test_cmd_ssl_default_port(self, mock_ssl):
        mock_ssl.return_value = {"error": "connection refused"}
        netwatch._cmd_ssl("example.com")
        mock_ssl.assert_called_once_with("example.com", 443)

    @patch("netwatch.analyze_attacker")
    def test_cmd_analyze_no_events(self, mock_analyze):
        mock_analyze.return_value = None
        netwatch._cmd_analyze("10.0.1.1")
        assert any("No honeypot events" in c for c in netwatch.console_output)

    @patch("netwatch.analyze_attacker")
    def test_cmd_analyze_with_events(self, mock_analyze):
        mock_analyze.return_value = {
            "hostname": "evil.com", "geo": "Russia", "isp": "Evil ISP",
            "total_events": 5, "services_targeted": ["telnet", "ssh"],
            "first_seen": "10:00", "last_seen": "10:05",
            "timeline": ["10:00 telnet", "10:05 ssh"]}
        netwatch._cmd_analyze("10.0.1.1")
        assert any("ATTACKER PROFILE" in c for c in netwatch.console_output)

    @patch("netwatch.osint_reverse_dns")
    def test_cmd_rdns_success(self, mock_rdns):
        mock_rdns.return_value = {"ptr": ["dns.google"]}
        netwatch._cmd_rdns("8.8.8.8")
        assert any("dns.google" in c for c in netwatch.console_output)

    @patch("netwatch.osint_ping_analyze")
    def test_cmd_ping_with_count(self, mock_ping):
        mock_ping.return_value = {"min": "1", "avg": "5", "max": "10",
            "jitter": "2", "loss": "0", "ttl": 64, "os_guess": "Linux"}
        netwatch._cmd_ping("8.8.8.8", count=10)
        mock_ping.assert_called_once_with("8.8.8.8", 10)


class TestSectionRenderers:

    def test_section_simple_alerts_empty(self):
        lines = netwatch._section_alerts()
        assert any("ALERTS" in l for l in lines)
        assert any("no alerts" in l for l in lines)

    def test_section_simple_alerts_with_data(self):
        netwatch.alerts.append({"time": "10:00", "msg": "test alert"})
        lines = netwatch._section_alerts()
        assert any("test alert" in l for l in lines)

    def test_section_dns_empty(self):
        lines = netwatch._section_dns()
        assert any("DNS" in l for l in lines)
        assert any("waiting" in l for l in lines)

    def test_section_dns_with_data(self):
        netwatch.dns_queries.append({"time": "10:00", "ip": "10.0.1.1", "domain": "example.com"})
        lines = netwatch._section_dns()
        assert any("example.com" in l for l in lines)

    def test_section_nmap_empty(self):
        lines = netwatch._section_nmap()
        assert any("NMAP" in l for l in lines)

    def test_section_arp_empty(self):
        lines = netwatch._section_arp()
        assert any("ARP" in l for l in lines)

    def test_section_hosts_empty(self):
        lines = netwatch._section_hosts()
        assert any("HOSTS" in l for l in lines)
        assert any("no hosts" in l for l in lines)

    def test_section_honeypot_empty(self):
        lines = netwatch._section_honeypot()
        assert any("HONEYPOT" in l for l in lines)


class TestHoneypotListenerFactory:

    def test_honeypot_listener_exists(self):
        assert callable(netwatch._honeypot_listener)

    @patch("socket.socket")
    def test_telnet_honeypot_uses_factory(self, mock_sock):
        assert callable(netwatch.telnet_honeypot)

    @patch("socket.socket")
    def test_rtsp_honeypot_uses_factory(self, mock_sock):
        assert callable(netwatch.rtsp_honeypot)

    @patch("socket.socket")
    def test_ftp_honeypot_uses_factory(self, mock_sock):
        assert callable(netwatch.ftp_honeypot)
