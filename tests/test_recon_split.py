"""
Tests for the FREE vs PRO split of attacker auto-recon (_ftp_auto_recon).

FREE (PRO_ENABLED off): basic passive OSINT intel + an upgrade CTA, and the
deep nmap port-scan / fingerprint must NOT run.
PRO  (PRO_ENABLED on): basic intel PLUS the deep nmap recon path is reached.

All network/subprocess is mocked — no real calls.
"""
from unittest.mock import patch, MagicMock

import netwatch


# Sample OSINT helper returns so the free-tier path needs no network.
_GEO = {"status": "success", "country": "Russia", "countryCode": "RU",
        "city": "Moscow", "isp": "Evil ISP", "org": "Evil Org", "as": "AS12345"}
_ASN = {"as": "AS12345 Evil Net", "org": "Evil Org", "isp": "Evil ISP",
        "country": "Russia", "query": "203.0.113.99"}
_RDNS = {"PTR": ["evil.example.com."]}
_ABUSE = {"ip": "203.0.113.99", "blocklist_de": "42",
          "is_proxy": True, "is_hosting": False, "is_mobile": False}

_ATTACKER_IP = "203.0.113.99"


def _patch_osint():
    """Patch every osint_* helper the free path uses so no network is touched."""
    return (
        patch("netwatch.osint_geolocate", return_value=dict(_GEO)),
        patch("netwatch.osint_asn", return_value=dict(_ASN)),
        patch("netwatch.osint_reverse_dns", return_value=dict(_RDNS)),
        patch("netwatch.osint_abuse", return_value=dict(_ABUSE)),
    )


def _reset_cooldown():
    netwatch._recon_cooldown.clear()
    netwatch._recon_active = 0


class TestFreeTier:
    def test_free_shows_basic_intel_no_deep_scan(self, tmp_path):
        _reset_cooldown()
        p_geo, p_asn, p_rdns, p_abuse = _patch_osint()
        with patch.object(netwatch, "PRO_ENABLED", False), \
             patch.object(netwatch, "LOG_DIR", str(tmp_path)), \
             patch("netwatch.subprocess.run") as mock_run, \
             patch("netwatch.banner_grab") as mock_banner, \
             p_geo, p_asn as m_asn, p_rdns, p_abuse:
            netwatch._ftp_auto_recon(_ATTACKER_IP)

            # Basic OSINT intel was gathered.
            m_asn.assert_called_once_with(_ATTACKER_IP)

            # Deep recon (nmap subprocess + banner grab) must NOT run on free.
            assert not mock_run.called, "nmap subprocess must not run on free tier"
            assert not mock_banner.called, "banner grab must not run on free tier"

        joined = " ".join(a["msg"] for a in netwatch.alerts)
        console = " ".join(netwatch.console_output)

        # Basic intel surfaced (country + org).
        assert "Russia" in joined or "Russia" in console
        # Upgrade CTA present.
        assert any("Upgrade to Pro" in a["msg"] for a in netwatch.alerts)
        assert any("Upgrade to Pro" in c for c in netwatch.console_output)
        # No deep-recon "RECON DONE" message on free.
        assert not any("RECON DONE" in a["msg"] for a in netwatch.alerts)

    def test_free_writes_basic_intel_report(self, tmp_path):
        _reset_cooldown()
        p_geo, p_asn, p_rdns, p_abuse = _patch_osint()
        with patch.object(netwatch, "PRO_ENABLED", False), \
             patch.object(netwatch, "LOG_DIR", str(tmp_path)), \
             patch("netwatch.subprocess.run"), \
             patch("netwatch.banner_grab"), \
             p_geo, p_asn, p_rdns, p_abuse:
            netwatch._ftp_auto_recon(_ATTACKER_IP)

        report = tmp_path / f"attacker_{_ATTACKER_IP.replace('.', '_')}.txt"
        assert report.exists()
        text = report.read_text()
        assert "Basic intel" in text
        assert "Russia" in text
        # Deep-recon header must be absent on free tier.
        assert "Auto-recon at" not in text


class TestProTier:
    def test_pro_reaches_deep_recon(self, tmp_path):
        _reset_cooldown()
        p_geo, p_asn, p_rdns, p_abuse = _patch_osint()
        mock_run = MagicMock(return_value=MagicMock(
            stdout="21/tcp open ftp\n80/tcp open http\n", returncode=0))
        with patch.object(netwatch, "PRO_ENABLED", True), \
             patch.object(netwatch, "LOG_DIR", str(tmp_path)), \
             patch("netwatch.subprocess.run", mock_run), \
             patch("netwatch.banner_grab", return_value="vsftpd 2.3.4"), \
             p_geo, p_asn, p_rdns, p_abuse:
            netwatch._ftp_auto_recon(_ATTACKER_IP)

            # Deep recon path IS reached: nmap invoked.
            assert mock_run.called, "nmap subprocess must run on Pro tier"
            nmap_argv = mock_run.call_args[0][0]
            assert nmap_argv[0] == "nmap"

        joined = " ".join(a["msg"] for a in netwatch.alerts)
        # Deep recon completed.
        assert any("RECON DONE" in a["msg"] for a in netwatch.alerts)
        # No upsell CTA when Pro is enabled.
        assert not any("Upgrade to Pro" in a["msg"] for a in netwatch.alerts)
        # Basic intel still ran too.
        assert "Russia" in joined or any("Russia" in c for c in netwatch.console_output)

    def test_pro_grabs_ftp_banner_when_port_open(self, tmp_path):
        _reset_cooldown()
        p_geo, p_asn, p_rdns, p_abuse = _patch_osint()
        mock_run = MagicMock(return_value=MagicMock(
            stdout="21/tcp open ftp\n", returncode=0))
        with patch.object(netwatch, "PRO_ENABLED", True), \
             patch.object(netwatch, "LOG_DIR", str(tmp_path)), \
             patch("netwatch.subprocess.run", mock_run), \
             patch("netwatch.banner_grab", return_value="vsftpd 2.3.4") as mock_banner, \
             p_geo, p_asn, p_rdns, p_abuse:
            netwatch._ftp_auto_recon(_ATTACKER_IP)
            mock_banner.assert_called_once_with(_ATTACKER_IP, 21)


class TestGateDefaults:
    def test_pro_disabled_by_default(self):
        # Module imported without NETWATCH_PRO=1 → free tier.
        assert netwatch.PRO_ENABLED is False

    def test_whitelisted_skips_entirely(self):
        _reset_cooldown()
        with patch("netwatch.osint_geolocate") as m_geo, \
             patch("netwatch.subprocess.run") as m_run:
            netwatch._ftp_auto_recon("127.0.0.1")
            assert not m_geo.called
            assert not m_run.called
