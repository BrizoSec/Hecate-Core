from unittest.mock import MagicMock, patch

from hecate_agent.orchestrator.enrichment import (
    _get_apex_domain,
    extract_indicators,
    generate_enrichment_summary,
    query_vt_hash,
)


def test_extract_indicators():
    text = "Hash 35dd164a7f5d8b42b9870c7009f7425b1c8cb771280c9e6c525e09f3dd13c2cc. A domain is evil.shop. Also benign github.com. Exploit CVE-2024-3272 and cve-2021-44228."
    inds = extract_indicators(text)
    assert "35dd164a7f5d8b42b9870c7009f7425b1c8cb771280c9e6c525e09f3dd13c2cc" in inds["hashes"]
    assert "evil.shop" in inds["domains"]
    assert "github.com" not in inds["domains"]
    assert "CVE-2024-3272" in inds["cves"]
    assert "CVE-2021-44228" in inds["cves"]


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
        if "api.first.org" in url:
            mock_epss = MagicMock(status_code=200)
            mock_epss.json.return_value = {
                "status": "OK",
                "data": [{
                    "cve": "CVE-2023-1234",
                    "epss": "0.92500",
                    "percentile": "0.98500",
                    "date": "2026-10-16"
                }]
            }
            return mock_epss
        if "alienvault.com" in url or "otx" in url:
            mock_otx = MagicMock(status_code=200)
            mock_otx.json.return_value = {
                "pulse_info": {
                    "count": 2,
                    "pulses": [
                        {"name": "Mirai C2 Infrastructure", "adversary": "ThreatGroup-1", "tags": ["botnet", "iot"]}
                    ]
                }
            }
            return mock_otx
        if "hybrid-analysis" in url:
            mock_ha = MagicMock(status_code=200)
            mock_ha.json.return_value = {
                "threat_score": 100,
                "verdict": "malicious",
                "vx_family": "Mirai",
                "type_short": "elf",
                "reports": []
            }
            return mock_ha
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
        text = "Hash 35dd164a7f5d8b42b9870c7009f7425b1c8cb771280c9e6c525e09f3dd13c2cc and IP 8.8.8.8 and domain c2.evil.xyz and vuln CVE-2023-1234"
        summary = generate_enrichment_summary(text)
    
    assert "🛡️ Automated Threat Enrichment" in summary
    assert "Hash 35dd164a7f5d8b42b9870c7009f7425b1c8cb771280c9e6c525e09f3dd13c2cc" in summary
    assert "IP 8.8.8.8" in summary
    assert "Domain c2.evil.xyz" in summary
    assert "Vulnerability CVE-2023-1234" in summary
    assert "FIRST EPSS (Exploit Prediction)" in summary
    assert "AlienVault OTX" in summary
    assert "Hybrid Analysis (Falcon Sandbox)" in summary
    assert "Mirai C2 Infrastructure" in summary
    assert "92.50%" in summary
    assert "CRITICAL EXPLOIT PROBABILITY" in summary
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


def test_query_epss():
    from hecate_agent.orchestrator.enrichment import query_epss
    with patch("hecate_agent.orchestrator.enrichment.httpx.get") as mock_get:
        # Happy path - critical probability
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {
            "status": "OK",
            "data": [{
                "cve": "CVE-2024-3272",
                "epss": "0.98038",
                "percentile": "0.99911",
                "date": "2026-10-16"
            }]
        }
        mock_get.return_value = mock_resp
        res = query_epss("CVE-2024-3272")
        assert "98.04%" in res
        assert "CRITICAL EXPLOIT PROBABILITY" in res
        assert "99.9th percentile" in res
        assert "2026-10-16" in res

        # Not found / no score
        mock_resp_empty = MagicMock(status_code=200)
        mock_resp_empty.json.return_value = {"status": "OK", "data": []}
        mock_get.return_value = mock_resp_empty
        assert "No EPSS score published for CVE-2099-0001." in query_epss("CVE-2099-0001")

        # Invalid format
        assert "Invalid CVE identifier" in query_epss("not-a-cve")


def test_query_epss_batch():
    from hecate_agent.orchestrator.enrichment import query_epss_batch
    with patch("hecate_agent.orchestrator.enrichment.httpx.get") as mock_get:
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {
            "status": "OK",
            "data": [
                {"cve": "CVE-2024-3272", "epss": "0.98038", "percentile": "0.99911", "date": "2026-10-16"},
                {"cve": "CVE-2021-44228", "epss": "0.15000", "percentile": "0.85000", "date": "2026-10-16"},
            ]
        }
        mock_get.return_value = mock_resp
        results = query_epss_batch(["CVE-2024-3272", "CVE-2021-44228", "CVE-2099-1111"])
        assert "CVE-2024-3272" in results
        assert "CRITICAL EXPLOIT PROBABILITY" in results["CVE-2024-3272"]
        assert "CVE-2021-44228" in results
        assert "ELEVATED EXPLOIT PROBABILITY" in results["CVE-2021-44228"]
        assert "No EPSS score published for CVE-2099-1111." in results["CVE-2099-1111"]


def test_query_otx_ip_with_pulses_and_pdns():
    from hecate_agent.orchestrator.enrichment import query_otx_ip
    with patch("hecate_agent.orchestrator.enrichment._setting", return_value="otx-key"):
        with patch("hecate_agent.orchestrator.enrichment.httpx.get") as mock_get:
            def side_effect(url, **kwargs):
                if "passive_dns" in url:
                    mock_pdns = MagicMock(status_code=200)
                    mock_pdns.json.return_value = {
                        "passive_dns": [
                            {"hostname": "c2-node.malicious.net", "record_type": "A"},
                            {"hostname": "backup-relay.xyz", "record_type": "A"}
                        ]
                    }
                    return mock_pdns
                mock_gen = MagicMock(status_code=200)
                mock_gen.json.return_value = {
                    "pulse_info": {
                        "count": 5,
                        "pulses": [
                            {"name": "Cobalt Strike Infrastructure", "adversary": "APT29", "tags": ["c2", "cobalt strike"]},
                            {"name": "Red Team Operations", "adversary": "APT29", "tags": ["beacon"]}
                        ]
                    }
                }
                return mock_gen

            mock_get.side_effect = side_effect
            res = query_otx_ip("198.51.100.1")
            assert "5 Pulse(s)" in res
            assert "Cobalt Strike Infrastructure" in res
            assert "Adversary: APT29" in res
            assert "Tags: c2, cobalt strike, beacon" in res
            assert "Passive DNS: c2-node.malicious.net, backup-relay.xyz" in res


def test_query_otx_domain():
    from hecate_agent.orchestrator.enrichment import query_otx_domain
    with patch("hecate_agent.orchestrator.enrichment._setting", return_value="otx-key"):
        with patch("hecate_agent.orchestrator.enrichment.httpx.get") as mock_get:
            mock_resp = MagicMock(status_code=200)
            mock_resp.json.return_value = {
                "pulse_info": {
                    "count": 1,
                    "pulses": [
                        {"name": "Lazarus FakeJob Campaign", "adversary": "Lazarus Group", "tags": ["phishing"]}
                    ]
                }
            }
            mock_get.return_value = mock_resp
            res = query_otx_domain("evil-domain.com")
            assert "1 Pulse(s)" in res
            assert "Lazarus FakeJob Campaign" in res
            assert "Adversary: Lazarus Group" in res


def test_query_otx_hash():
    from hecate_agent.orchestrator.enrichment import query_otx_hash
    with patch("hecate_agent.orchestrator.enrichment._setting", return_value="otx-key"):
        with patch("hecate_agent.orchestrator.enrichment.httpx.get") as mock_get:
            mock_resp = MagicMock(status_code=200)
            mock_resp.json.return_value = {
                "pulse_info": {
                    "count": 12,
                    "pulses": [
                        {"name": "AsyncRAT Payload Distribution", "adversary": "UAC-0050", "tags": ["rat", "asyncrat"]}
                    ]
                }
            }
            mock_get.return_value = mock_resp
            res = query_otx_hash("44d88612fea8a8f36de82e1278abb02f")
            assert "12 Pulse(s)" in res
            assert "AsyncRAT Payload Distribution" in res
            assert "Adversary: UAC-0050" in res


def test_query_otx_cve():
    from hecate_agent.orchestrator.enrichment import query_otx_cve
    with patch("hecate_agent.orchestrator.enrichment._setting", return_value="otx-key"):
        with patch("hecate_agent.orchestrator.enrichment.httpx.get") as mock_get:
            mock_resp = MagicMock(status_code=200)
            mock_resp.json.return_value = {
                "pulse_info": {
                    "count": 4,
                    "pulses": [
                        {"name": "skynox7: Proxyjacking Edge Devices", "adversary": "skynox7", "tags": ["proxyjacking"]}
                    ]
                }
            }
            mock_get.return_value = mock_resp
            res = query_otx_cve("CVE-2024-3272")
            assert "4 Pulse(s)" in res
            assert "skynox7: Proxyjacking Edge Devices" in res
            assert "Adversary: skynox7" in res


def test_query_otx_no_api_key():
    from hecate_agent.orchestrator.enrichment import query_otx_indicator
    with patch("hecate_agent.orchestrator.enrichment._setting", return_value=""):
        res = query_otx_indicator("IPv4", "198.51.100.1")
        assert res == "OTX_API_KEY not configured."


def test_query_otx_not_found():
    from hecate_agent.orchestrator.enrichment import query_otx_indicator
    with patch("hecate_agent.orchestrator.enrichment._setting", return_value="otx-key"):
        with patch("hecate_agent.orchestrator.enrichment.httpx.get") as mock_get:
            mock_resp = MagicMock(status_code=404)
            mock_get.return_value = mock_resp
            res = query_otx_indicator("domain", "clean-domain.test")
            assert res == "No record on OTX."


def test_query_feodotracker_ip_found():
    import time
    from hecate_agent.orchestrator.enrichment import _FEODO_CACHE, query_feodotracker_ip
    mock_data = {
        "198.51.100.1": {
            "ip_address": "198.51.100.1",
            "malware": "QakBot",
            "status": "online",
            "port": 443,
            "first_seen": "2026-10-15 12:00:00",
            "as_name": "EXAMPLE-ASN",
        }
    }
    _FEODO_CACHE["data"] = mock_data
    _FEODO_CACHE["ts"] = time.time()
    res = query_feodotracker_ip("198.51.100.1")
    assert "Botnet C2: QakBot" in res
    assert "Port: 443" in res
    assert "Status: online" in res
    assert "First Seen: 2026-10-15" in res
    assert "ASN: EXAMPLE-ASN" in res


def test_query_feodotracker_ip_clean():
    import time
    from hecate_agent.orchestrator.enrichment import _FEODO_CACHE, query_feodotracker_ip
    _FEODO_CACHE["data"] = {"198.51.100.1": {"malware": "Emotet"}}
    _FEODO_CACHE["ts"] = time.time()
    res = query_feodotracker_ip("8.8.8.8")
    assert res == "Not listed on Feodo Tracker (clean)."


def test_query_sslbl_fingerprint_found():
    import time
    from hecate_agent.orchestrator.enrichment import _SSLBL_CACHE, query_sslbl_fingerprint
    _SSLBL_CACHE["data"] = {
        "d83515431690184ba48f4be8be3e9594b2ee718d": ("Vidar C&C SSL Cert", "2026-10-10"),
        "65230654877f2fedd6a066928e08d6d8": ("JA3 AsyncRAT C2", "2026-10-12"),
    }
    _SSLBL_CACHE["ts"] = time.time()
    res_sha1 = query_sslbl_fingerprint("D83515431690184BA48F4BE8BE3E9594B2EE718D")
    assert "Vidar C&C SSL Cert" in res_sha1
    assert "Listed: 2026-10-10" in res_sha1

    res_ja3 = query_sslbl_fingerprint("65230654877f2fedd6a066928e08d6d8")
    assert "JA3 AsyncRAT C2" in res_ja3
    assert "Listed: 2026-10-12" in res_ja3


def test_query_sslbl_fingerprint_clean():
    import time
    from hecate_agent.orchestrator.enrichment import _SSLBL_CACHE, query_sslbl_fingerprint
    _SSLBL_CACHE["data"] = {"d83515431690184ba48f4be8be3e9594b2ee718d": ("Vidar", "2026-10-10")}
    _SSLBL_CACHE["ts"] = time.time()
    res = query_sslbl_fingerprint("e3b0c44298fc1c149afbf4c8996fb92427ae41e4")
    assert res == "Not listed on SSLBL (clean)."


def test_query_urlhaus_url(monkeypatch):
    from hecate_agent.orchestrator.enrichment import query_urlhaus_url
    monkeypatch.delenv("ABUSECH_API_KEY", raising=False)
    assert query_urlhaus_url("http://bad.com/exe") == "ABUSECH_API_KEY not configured."

    monkeypatch.setenv("ABUSECH_API_KEY", "test-key")
    with patch("hecate_agent.orchestrator.enrichment.httpx.post") as mock_post:
        # Test found URL
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {
            "query_status": "ok",
            "url_status": "online",
            "threat": "malware_download",
            "tags": ["Mozi", "elf"],
            "payloads": [{"signature": "Mozi", "file_type": "elf"}],
        }
        mock_post.return_value = mock_resp
        res = query_urlhaus_url("http://example-c2.com/malware.bin")
        assert "Status: online" in res
        assert "Threat: malware_download" in res
        assert "Payload: Mozi" in res
        assert "Tags: Mozi, elf" in res

        # Test no results
        mock_resp_clean = MagicMock(status_code=200)
        mock_resp_clean.json.return_value = {"query_status": "no_results"}
        mock_post.return_value = mock_resp_clean
        res_clean = query_urlhaus_url("http://clean-site.org/file.pdf")
        assert res_clean == "Not listed on URLhaus."

        # Test auth error
        mock_resp_401 = MagicMock(status_code=401)
        mock_post.return_value = mock_resp_401
        res_401 = query_urlhaus_url("http://bad.com/exe")
        assert "URLhaus Auth Error" in res_401


def test_query_urlhaus_host(monkeypatch):
    from hecate_agent.orchestrator.enrichment import query_urlhaus_host
    monkeypatch.setenv("ABUSECH_API_KEY", "test-key")
    with patch("hecate_agent.orchestrator.enrichment.httpx.post") as mock_post:
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {
            "query_status": "ok",
            "url_count": 8,
            "firstseen": "2026-10-14 10:00:00",
        }
        mock_post.return_value = mock_resp
        res = query_urlhaus_host("malicious-c2-host.com")
        assert "Malware host (8 URL(s))" in res
        assert "First seen: 2026-10-14" in res

        mock_resp_none = MagicMock(status_code=200)
        mock_resp_none.json.return_value = {"query_status": "no_results"}
        mock_post.return_value = mock_resp_none
        assert query_urlhaus_host("clean.org") == "Not listed on URLhaus."


def test_query_urlhaus_payload(monkeypatch):
    from hecate_agent.orchestrator.enrichment import query_urlhaus_payload
    monkeypatch.setenv("ABUSECH_API_KEY", "test-key")
    with patch("hecate_agent.orchestrator.enrichment.httpx.post") as mock_post:
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {
            "query_status": "ok",
            "signature": "RedLineStealer",
            "file_type": "exe",
            "url_count": 4,
        }
        mock_post.return_value = mock_resp
        res = query_urlhaus_payload("d41d8cd98f00b204e9800998ecf8427e")
        assert "Payload: RedLineStealer (exe)" in res
        assert "Seen on 4 URL(s)" in res

        mock_resp_clean = MagicMock(status_code=200)
        mock_resp_clean.json.return_value = {"query_status": "no_results"}
        mock_post.return_value = mock_resp_clean
        assert query_urlhaus_payload("d41d8cd98f00b204e9800998ecf8427e") == "No payload on URLhaus."


def test_extract_indicators_extracts_urls_and_filters_publishers():
    from hecate_agent.orchestrator.enrichment import extract_indicators
    text = (
        "Adversary downloaded malware from hxxp://evil-download.com/payload.exe and http://198.51.100.5/stage2.bin. "
        "Reference: https://www.mandiant.com/resources/blog/apt41-malware. "
        "See also report at https://unit42.paloaltonetworks.com/threat-report."
    )
    inds = extract_indicators(text)
    assert "urls" in inds
    # evil-download.com and 198.51.100.5 should be included
    assert any("evil-download.com/payload.exe" in u for u in inds["urls"])
    assert any("198.51.100.5/stage2.bin" in u for u in inds["urls"])
    # Mandiant and Palo Alto publisher URLs must be filtered out
    assert not any("mandiant.com" in u for u in inds["urls"])
    assert not any("paloaltonetworks.com" in u for u in inds["urls"])


def test_query_hybrid_analysis_no_key(monkeypatch):
    from hecate_agent.orchestrator.enrichment import query_hybrid_analysis
    monkeypatch.delenv("HYBRID_ANALYSIS_API_KEY", raising=False)
    monkeypatch.delenv("HA_API_KEY", raising=False)
    monkeypatch.delenv("FALCON_SANDBOX_API_KEY", raising=False)
    assert query_hybrid_analysis("35dd164a7f5d8b42b9870c7009f7425b1c8cb771280c9e6c525e09f3dd13c2cc") == "HYBRID_ANALYSIS_API_KEY not configured."


def test_query_hybrid_analysis_invalid_hash(monkeypatch):
    from hecate_agent.orchestrator.enrichment import query_hybrid_analysis
    monkeypatch.setenv("HYBRID_ANALYSIS_API_KEY", "ha-test-key")
    res = query_hybrid_analysis("invalid-hash!")
    assert "Invalid hash format" in res


def test_query_hybrid_analysis_success(monkeypatch):
    from hecate_agent.orchestrator.enrichment import query_hybrid_analysis
    monkeypatch.setenv("HYBRID_ANALYSIS_API_KEY", "ha-test-key")
    with patch("hecate_agent.orchestrator.enrichment.httpx.get") as mock_get:
        def get_side_effect(url, *args, **kwargs):
            if "overview" in url and "report" not in url:
                mock_ov = MagicMock(status_code=200)
                mock_ov.json.return_value = {
                    "threat_score": 100,
                    "threat_level": 3,
                    "verdict": "malicious",
                    "vx_family": "AsyncRAT",
                    "type_short": "peexe",
                    "multiscan_result": 92,
                    "reports": ["rep-12345"]
                }
                return mock_ov
            elif "report/rep-12345/summary" in url:
                mock_rep = MagicMock(status_code=200)
                mock_rep.json.return_value = {
                    "environment_description": "Windows 10 64-bit",
                    "mitre_attcks": [
                        {"attck_id": "T1547", "technique": "Boot or Logon Autostart Execution"},
                        {"attck_id": "T1059.001", "technique": "PowerShell"}
                    ]
                }
                return mock_rep
            return MagicMock(status_code=404)

        mock_get.side_effect = get_side_effect
        res = query_hybrid_analysis("35dd164a7f5d8b42b9870c7009f7425b1c8cb771280c9e6c525e09f3dd13c2cc")
        assert "Verdict: MALICIOUS (Score: 100/100)" in res
        assert "Family: AsyncRAT" in res
        assert "Type: peexe" in res
        assert "Multi-Scan: 92%" in res
        assert "Env: Windows 10 64-bit" in res
        assert "MITRE: T1547, T1059.001" in res


def test_query_hybrid_analysis_not_found(monkeypatch):
    from hecate_agent.orchestrator.enrichment import query_hybrid_analysis
    monkeypatch.setenv("HYBRID_ANALYSIS_API_KEY", "ha-test-key")
    with patch("hecate_agent.orchestrator.enrichment.httpx.get") as mock_get:
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {}
        mock_get.return_value = mock_resp
        res = query_hybrid_analysis("35dd164a7f5d8b42b9870c7009f7425b1c8cb771280c9e6c525e09f3dd13c2cc")
        assert res == "No records on Hybrid Analysis."

        mock_resp_404 = MagicMock(status_code=404)
        mock_get.return_value = mock_resp_404
        assert query_hybrid_analysis("35dd164a7f5d8b42b9870c7009f7425b1c8cb771280c9e6c525e09f3dd13c2cc") == "No records on Hybrid Analysis."


def test_query_hybrid_analysis_auth_and_rate_limits(monkeypatch):
    from hecate_agent.orchestrator.enrichment import query_hybrid_analysis
    monkeypatch.setenv("HYBRID_ANALYSIS_API_KEY", "ha-test-key")
    with patch("hecate_agent.orchestrator.enrichment.httpx.get") as mock_get:
        mock_resp_401 = MagicMock(status_code=401)
        mock_get.return_value = mock_resp_401
        res_401 = query_hybrid_analysis("35dd164a7f5d8b42b9870c7009f7425b1c8cb771280c9e6c525e09f3dd13c2cc")
        assert "Hybrid Analysis Auth Error" in res_401

        mock_resp_429 = MagicMock(status_code=429)
        mock_get.return_value = mock_resp_429
        res_429 = query_hybrid_analysis("35dd164a7f5d8b42b9870c7009f7425b1c8cb771280c9e6c525e09f3dd13c2cc")
        assert "Hybrid Analysis rate limit exceeded." in res_429









