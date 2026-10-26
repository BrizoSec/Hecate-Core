"""Unit tests for multi-target Sigma transpiler (MDE KQL, CrowdStrike CQL, Rapid7 LEQL)."""

import pytest

from hecate_agent.core.sigma_transpiler import (
    PYSIGMA_AVAILABLE,
    SigmaTranspiler,
)


@pytest.fixture
def sample_process_creation_rule() -> str:
    return """
title: Detection of Daemon Tools Lite Service Execution via DTHelper.exe
id: 1ad689ca-013c-4b3b-98ee-1a8f34a7e809
status: experimental
description: Detects DTHelper.exe service execution
references:
  - https://vulncheck.com/cve/CVE-2026-8398
author: hecate
date: '2026-10-26'
tags:
  - attack.t1190
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\DTHelper.exe'
    CommandLine|contains: '--service'
  condition: selection
falsepositives:
  - Legitimate administrative maintenance
level: high
"""


@pytest.fixture
def sample_network_rule() -> str:
    return """
title: Outbound Connection to Malicious IP
id: 2bd689ca-013c-4b3b-98ee-1a8f34a7e810
status: experimental
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    DestinationIp: '168.138.40.244'
    DestinationPort: 443
  condition: selection
level: high
"""


@pytest.mark.skipif(not PYSIGMA_AVAILABLE, reason="pySigma not installed in environment")
class TestSigmaTranspiler:
    def test_transpile_process_creation_all_targets(self, sample_process_creation_rule):
        transpiler = SigmaTranspiler()
        results = transpiler.transpile(sample_process_creation_rule)

        assert SigmaTranspiler.TARGET_MDE in results
        assert SigmaTranspiler.TARGET_CROWDSTRIKE in results
        assert SigmaTranspiler.TARGET_RAPID7 in results

        # 1. Microsoft Defender / Sentinel KQL
        mde = results[SigmaTranspiler.TARGET_MDE]
        assert mde.success is True
        assert mde.dialect == "kql"
        assert mde.file_extension == ".kql"
        assert "DeviceProcessEvents" in mde.query
        assert "DTHelper.exe" in mde.query

        # 2. CrowdStrike Falcon CQL
        cs = results[SigmaTranspiler.TARGET_CROWDSTRIKE]
        assert cs.success is True
        assert cs.dialect == "cql"
        assert cs.file_extension == ".cql"
        assert "ProcessRollup2" in cs.query or "DTHelper" in cs.query

        # 3. Rapid7 InsightIDR LEQL
        r7 = results[SigmaTranspiler.TARGET_RAPID7]
        assert r7.success is True
        assert r7.dialect == "leql"
        assert r7.file_extension == ".leql"
        assert r7.query.startswith("where(")
        assert "DTHelper.exe" in r7.query

    def test_transpile_network_connection(self, sample_network_rule):
        transpiler = SigmaTranspiler()
        results = transpiler.transpile(sample_network_rule)

        # MDE KQL should target DeviceNetworkEvents
        mde = results[SigmaTranspiler.TARGET_MDE]
        assert mde.success is True
        assert "DeviceNetworkEvents" in mde.query
        assert "168.138.40.244" in mde.query

        # Rapid7 should query destination_ip / port
        r7 = results[SigmaTranspiler.TARGET_RAPID7]
        assert r7.success is True
        assert "where(" in r7.query
        assert "168.138.40.244" in r7.query

    def test_normalize_rule_adds_windows_product_if_missing(self):
        rule_without_product = """
title: Test Process Rule
id: 3ad689ca-013c-4b3b-98ee-1a8f34a7e811
status: experimental
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith: '\\malware.exe'
  condition: selection
"""
        normalized = SigmaTranspiler.normalize_rule_for_backends(rule_without_product)
        assert "product: windows" in normalized

        transpiler = SigmaTranspiler()
        results = transpiler.transpile(rule_without_product)
        # Should succeed for MDE, CrowdStrike, and Rapid7 despite original missing product: windows
        assert results[SigmaTranspiler.TARGET_MDE].success is True
        assert results[SigmaTranspiler.TARGET_CROWDSTRIKE].success is True
        assert results[SigmaTranspiler.TARGET_RAPID7].success is True

    def test_format_markdown_queries(self, sample_process_creation_rule):
        transpiler = SigmaTranspiler()
        results = transpiler.transpile(sample_process_creation_rule)
        markdown = transpiler.format_markdown_queries(results)

        assert "##### Native EDR & SIEM Queries" in markdown
        assert "Microsoft Defender / Microsoft Sentinel (KQL)" in markdown
        assert "CrowdStrike Falcon" in markdown
        assert "Rapid7 InsightIDR" in markdown
        assert "```kql" in markdown
        assert "```cql" in markdown
        assert "```text" in markdown
        assert "where(" in markdown

    def test_transpile_invalid_rule_graceful_error(self):
        transpiler = SigmaTranspiler()
        results = transpiler.transpile("this is not valid sigma yaml: [unclosed")
        for target, res in results.items():
            assert res.success is False
            assert res.query is None
            assert res.error_message is not None

    def test_transpile_webserver_category_kql_fallback(self):
        web_rule = """
title: Webserver Access Rule
id: 4ad689ca-013c-4b3b-98ee-1a8f34a7e812
status: experimental
logsource:
  category: webserver
detection:
  selection:
    cs-uri-stem|contains: '/api/v1/admin'
    sc-status: 200
  condition: selection
level: medium
"""
        transpiler = SigmaTranspiler()
        results = transpiler.transpile(web_rule)
        mde = results[SigmaTranspiler.TARGET_MDE]
        assert mde.success is True
        assert "W3CIISLog" in mde.query
        assert "/api/v1/admin" in mde.query
        r7 = results[SigmaTranspiler.TARGET_RAPID7]
        assert r7.success is True
        assert "/api/v1/admin" in r7.query
        cs = results[SigmaTranspiler.TARGET_CROWDSTRIKE]
        assert cs.success is True
        assert "api" in cs.query and "admin" in cs.query
