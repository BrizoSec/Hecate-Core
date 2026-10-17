from unittest.mock import MagicMock, patch

from hecate_agent.orchestrator.enrichment import extract_indicators, generate_enrichment_summary, query_vt_hash


def test_extract_indicators():
    text = "Hash 35dd164a7f5d8b42b9870c7009f7425b1c8cb771280c9e6c525e09f3dd13c2cc. A domain is evil.shop. Also benign github.com."
    inds = extract_indicators(text)
    assert "35dd164a7f5d8b42b9870c7009f7425b1c8cb771280c9e6c525e09f3dd13c2cc" in inds["hashes"]
    assert "evil.shop" in inds["domains"]
    assert "github.com" not in inds["domains"]

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
        if "censys" in url:
            mock_censys = MagicMock()
            mock_censys.status_code = 404
            return mock_censys
        return MagicMock(status_code=404)
        
    def post_side_effect(*args, **kwargs):
        url = args[0]
        if "threatfox" in url:
            return mock_tf
        if "misp" in url:
            return mock_misp
        return MagicMock(status_code=404)
        
    mock_get.side_effect = get_side_effect
    mock_post.side_effect = post_side_effect
    
    text = "Hash 35dd164a7f5d8b42b9870c7009f7425b1c8cb771280c9e6c525e09f3dd13c2cc and IP 8.8.8.8 and domain c2.evil.xyz"
    summary = generate_enrichment_summary(text)
    
    assert "🛡️ Automated Threat Enrichment" in summary
    assert "Hash 35dd164a7f5d8b42b9870c7009f7425b1c8cb771280c9e6c525e09f3dd13c2cc" in summary
    assert "IP 8.8.8.8" in summary
    assert "Domain c2.evil.xyz" in summary
    assert "Malicious hits: 5" in summary
    assert "Mirai" in summary

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



