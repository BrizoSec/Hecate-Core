from unittest.mock import MagicMock, patch

from hecate_agent.orchestrator.enrichment import (
    _get_apex_domain,
    extract_indicators,
    generate_enrichment_summary,
    query_vt_hash,
)


def test_extract_indicators():
    text = "Hash 35dd164a7f5d8b42b9870c7009f7425b1c8cb771280c9e6c525e09f3dd13c2cc. A domain is evil.shop. Also benign github.com."
    inds = extract_indicators(text)
    assert "35dd164a7f5d8b42b9870c7009f7425b1c8cb771280c9e6c525e09f3dd13c2cc" in inds["hashes"]
    assert "evil.shop" in inds["domains"]
    assert "github.com" not in inds["domains"]


def test_extract_indicators_defanged_and_cctlds():
    text = (
        "Adversary staged payload at 96.9.125[.]52 and chinadigitaltimes[.]top.\n"
        "C2 resolved at hub.zoom.com.kg and sync-telemetry.top.\n"
        "Older infra: hxxps://malicious[.]co[.]uk/gate."
    )
    inds = extract_indicators(text)
    assert "96.9.125.52" in inds["ips"]
    assert "chinadigitaltimes.top" in inds["domains"]
    assert "hub.zoom.com.kg" in inds["domains"]
    # Ensure it did NOT truncate to hub.zoom.com
    assert "hub.zoom.com" not in inds["domains"]
    assert "sync-telemetry.top" in inds["domains"]
    assert "malicious.co.uk" in inds["domains"]


def test_get_apex_domain():
    assert _get_apex_domain("hub.zoom.com.kg") == "zoom.com.kg"
    assert _get_apex_domain("c2.evil.co.uk") == "evil.co.uk"
    assert _get_apex_domain("sync-telemetry.top") == "sync-telemetry.top"
    assert _get_apex_domain("sub.corp.example.com") == "example.com"


def test_extract_indicators_filters_publisher_and_reference_domains():
    text = (
        "Adversary C2 was n.alox.one with fallback to evil.shop.\n"
        "References: https://blackpointcyber.com/blog/variola-from-clickfix-to-modular-implant/\n"
        "Read more at https://unit42.paloaltonetworks.com/research/threat-brief/\n"
        "Also see https://www.mandiant.com/resources/blog/apt41-report"
    )
    inds = extract_indicators(text)
    assert "n.alox.one" in inds["domains"]
    assert "evil.shop" in inds["domains"]
    assert "blackpointcyber.com" not in inds["domains"]
    assert "unit42.paloaltonetworks.com" not in inds["domains"]
    assert "mandiant.com" not in inds["domains"]
    assert "paloaltonetworks.com" not in inds["domains"]

@patch("hecate_agent.orchestrator.enrichment.httpx.get")
@patch("hecate_agent.orchestrator.enrichment.httpx.post")
def test_generate_enrichment_summary(mock_post, mock_get):
    mock_vt = MagicMock()
    mock_vt.status_code = 200
    mock_vt.json.return_value = {"data": {"attributes": {"last_analysis_stats": {"malicious": 5, "suspicious": 1, "harmless": 50}}}}
    
    mock_shodan = MagicMock()
    mock_shodan.status_code = 200
    mock_shodan.json.return_value = {"ports": [80, 443], "vulns": ["CVE-2023-1234"]}
    
    mock_tf = MagicMock()
    mock_tf.status_code = 200
    mock_tf.json.return_value = {"query_status": "ok", "data": [{"threat_type": "botnet", "malware_printable": "Mirai", "tags": ["IoT"]}]}
    
    mock_mb = MagicMock()
    mock_mb.status_code = 200
    mock_mb.json.return_value = {
        "query_status": "ok",
        "data": [{
            "signature": "Mirai",
            "file_type": "elf",
            "delivery_method": "exploit",
            "yara_rules": [{"rule_name": "Mirai_Botnet"}],
        }]
    }

    mock_abuseipdb = MagicMock()
    mock_abuseipdb.status_code = 200
    mock_abuseipdb.json.return_value = {
        "data": {
            "abuseConfidenceScore": 95,
            "totalReports": 34,
            "isp": "DigitalOcean, LLC",
            "usageType": "Data Center/Web Hosting/Transit",
            "countryCode": "US"
        }
    }

    mock_rdap = MagicMock()
    mock_rdap.status_code = 200
    mock_rdap.json.return_value = {
        "events": [{"eventAction": "registration", "eventDate": "2024-01-15T00:00:00Z"}],
        "entities": [{
            "roles": ["registrar"],
            "vcardArray": ["vcard", [["fn", {}, "text", "Namecheap Inc."]]]
        }]
    }

    mock_misp = MagicMock()
    mock_misp.status_code = 200
    mock_misp.json.return_value = {"response": [{"Event": {"info": "Test Event"}}]}
    
    def get_side_effect(*args, **kwargs):
        url = args[0]
        if "virustotal" in url:
            return mock_vt
        if "shodan" in url:
            return mock_shodan
        if "greynoise" in url:
            mock_gn = MagicMock(status_code=200)
            mock_gn.json.return_value = {
                "noise": False,
                "riot": True,
                "classification": "benign",
                "name": "Google Public DNS"
            }
            return mock_gn
        if "abuseipdb" in url:
            return mock_abuseipdb
        if "rdap.org" in url:
            return mock_rdap
        if "censys" in url:
            mock_censys = MagicMock()
            mock_censys.status_code = 404
            return mock_censys
        return MagicMock(status_code=404)
        
    def post_side_effect(*args, **kwargs):
        url = args[0]
        if "threatfox" in url:
            return mock_tf
        if "mb-api.abuse.ch" in url:
            return mock_mb
        if "misp" in url:
            return mock_misp
        return MagicMock(status_code=404)
        
    mock_get.side_effect = get_side_effect
    mock_post.side_effect = post_side_effect
    
    with patch("hecate_agent.orchestrator.enrichment._setting") as mock_set:
        mock_set.side_effect = lambda k, d="": "test-key" if "KEY" in k or "TOKEN" in k else d
        text = "Hash 35dd164a7f5d8b42b9870c7009f7425b1c8cb771280c9e6c525e09f3dd13c2cc and IP 8.8.8.8 and domain c2.evil.xyz"
        summary = generate_enrichment_summary(text)
    
    assert "🛡️ Automated Threat Enrichment" in summary
    assert "Hash 35dd164a7f5d8b42b9870c7009f7425b1c8cb771280c9e6c525e09f3dd13c2cc" in summary
    assert "IP 8.8.8.8" in summary
    assert "Domain c2.evil.xyz" in summary
    assert "Malicious hits: 5" in summary
    assert "Mirai" in summary
    assert "MalwareBazaar" in summary
    assert "AbuseIPDB" in summary
    assert "RDAP" in summary
    assert "Namecheap Inc." in summary


def test_query_vt_hash_no_api_key(monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    assert query_vt_hash("hash") == "Not found or error."


def test_query_vt_domain(monkeypatch):
    from hecate_agent.orchestrator.enrichment import query_vt_domain
    with patch("hecate_agent.orchestrator.enrichment.httpx.get") as mock_get:
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 8},
                    "registrar": "NameCheap",
                    "categories": {"Forcepoint": "malicious"}
                }
            }
        }
        mock_get.return_value = mock_resp
        monkeypatch.setenv("VT_API_KEY", "test-key")
        res = query_vt_domain("bad-domain.top")
        assert "Malicious hits: 8" in res
        assert "NameCheap" in res


def test_query_greynoise_ip(monkeypatch):
    from hecate_agent.orchestrator.enrichment import query_greynoise_ip
    monkeypatch.delenv("GREYNOISE_API_KEY", raising=False)
    assert query_greynoise_ip("8.8.8.8") == "GREYNOISE_API_KEY not configured."

    with patch("hecate_agent.orchestrator.enrichment.httpx.get") as mock_get:
        # Test Community format
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {
            "noise": True,
            "riot": False,
            "classification": "malicious",
            "actor": "Mirai",
            "tags": ["Mirai", "Telnet Bruteforce"]
        }
        mock_get.return_value = mock_resp
        monkeypatch.setenv("GREYNOISE_API_KEY", "gn-test-key")
        res = query_greynoise_ip("1.2.3.4")
        assert "Mass Internet Scanner (malicious)" in res
        assert "Mirai" in res

        # Test v3 Enterprise format
        mock_resp_v3 = MagicMock(status_code=200)
        mock_resp_v3.json.return_value = {
            "ip": "198.235.24.237",
            "business_service_intelligence": {"found": None, "trust_level": ""},
            "internet_scanner_intelligence": {
                "found": True,
                "classification": "benign",
                "actor": "Cortex Xpanse",
                "tags": [{"name": "F5 BIG-IP Crawler"}, {"name": "Well-Known Scanner"}]
            }
        }
        mock_get.return_value = mock_resp_v3
        res_v3 = query_greynoise_ip("198.235.24.237")
        assert "Mass Internet Scanner (benign)" in res_v3
        assert "Cortex Xpanse" in res_v3
        assert "F5 BIG-IP Crawler" in res_v3

        # Test 404 unseen IP
        mock_resp_404 = MagicMock(status_code=404)
        mock_get.return_value = mock_resp_404
        res_404 = query_greynoise_ip("8.8.8.8")
        assert "No mass-internet scanning observed" in res_404


def test_query_malwarebazaar(monkeypatch):
    from hecate_agent.orchestrator.enrichment import query_malwarebazaar
    monkeypatch.delenv("ABUSECH_API_KEY", raising=False)
    assert query_malwarebazaar("hash123") == "ABUSECH_API_KEY not configured."

    monkeypatch.setenv("ABUSECH_API_KEY", "test-key")
    with patch("hecate_agent.orchestrator.enrichment.httpx.post") as mock_post:
        # Success with YARA
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {
            "query_status": "ok",
            "data": [{
                "signature": "CobaltStrike",
                "file_type": "exe",
                "delivery_method": "phishing",
                "yara_rules": [{"rule_name": "Cobalt_Strike_Beacon"}]
            }]
        }
        mock_post.return_value = mock_resp
        res = query_malwarebazaar("hash123")
        assert "Family: CobaltStrike" in res
        assert "Type: exe" in res
        assert "Delivery: phishing" in res
        assert "YARA: Cobalt_Strike_Beacon" in res

        # Not found
        mock_resp_404 = MagicMock(status_code=200)
        mock_resp_404.json.return_value = {"query_status": "hash_not_found"}
        mock_post.return_value = mock_resp_404
        res_404 = query_malwarebazaar("hash999")
        assert "No sample found on MalwareBazaar." in res_404


def test_query_abuseipdb_ip(monkeypatch):
    from hecate_agent.orchestrator.enrichment import query_abuseipdb_ip
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    assert query_abuseipdb_ip("1.2.3.4") == "ABUSEIPDB_API_KEY not configured."

    monkeypatch.setenv("ABUSEIPDB_API_KEY", "abuseipdb-key")
    with patch("hecate_agent.orchestrator.enrichment.httpx.get") as mock_get:
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {
            "data": {
                "abuseConfidenceScore": 100,
                "totalReports": 52,
                "isp": "OVH SAS",
                "usageType": "Data Center/Web Hosting/Transit",
                "countryCode": "FR"
            }
        }
        mock_get.return_value = mock_resp
        res = query_abuseipdb_ip("51.254.10.1")
        assert "Score: 100% (Reports: 52)" in res
        assert "ISP: OVH SAS" in res
        assert "Country: FR" in res

        # Rate limit
        mock_resp_429 = MagicMock(status_code=429)
        mock_get.return_value = mock_resp_429
        assert "rate limit exceeded" in query_abuseipdb_ip("51.254.10.1")


def test_query_rdap_domain():
    from hecate_agent.orchestrator.enrichment import query_rdap_domain
    with patch("hecate_agent.orchestrator.enrichment.httpx.get") as mock_get:
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {
            "events": [
                {"eventAction": "registration", "eventDate": "2020-05-10T12:00:00Z"},
                {"eventAction": "expiration", "eventDate": "2028-05-10T12:00:00Z"}
            ],
            "entities": [{
                "roles": ["registrar"],
                "vcardArray": ["vcard", [["fn", {}, "text", "GoDaddy.com, LLC"]]]
            }]
        }
        mock_get.return_value = mock_resp
        res = query_rdap_domain("subdomain.evil-target.com")
        assert "Registered: 2020-05-10" in res
        assert "GoDaddy.com, LLC" in res

        # Not found
        mock_resp_404 = MagicMock(status_code=404)
        mock_get.return_value = mock_resp_404
        assert "Domain not found on RDAP." in query_rdap_domain("unknown-domain.xyz")




