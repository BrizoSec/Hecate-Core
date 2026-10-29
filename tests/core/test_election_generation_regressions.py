"""Regression cases from the Cotton Sandstorm election hunt review.

The source fragments reproduce PDF wrapping and historical infrastructure;
no model or live SIEM is required to exercise the production gates.
"""

import json
from types import SimpleNamespace

import pytest
import yaml

from hecate_agent.agents.llm.sigma_generator import (
    SigmaGenerationInput,
    SigmaGeneratorAgent,
    _invented_hash_problem,
)
from hecate_agent.core import source_evidence as se
from hecate_agent.core.provenance import IndicatorRecord, placements, routable_indicators
from hecate_agent.core.sigma_evaluator import SigmaEvaluator
from hecate_agent.core.sigma_semantics import description_mismatch

HASH = "6f765dda126e830c6cd2c7938dbb970d03be728e82c00388903a4ef3f9ecc853"
WRAPPED = HASH[:34] + "\n" + HASH[34:]
SOURCE = "https://www.ic3.gov/CSA/2024/241030.pdf"


@pytest.mark.parametrize("value", [HASH, WRAPPED, WRAPPED.replace("\n", " ")])
def test_pdf_wrapped_hash_survives_source_verification(value):
    passage = f"Google Chrome Installer.msi SHA256: {WRAPPED}"
    page = se.normalise(passage)
    artifact, reason = se._checked({"value": value, "kind": "sha256", "role": "executable", "evidence": passage}, page, page)
    assert not reason
    assert artifact.value == HASH
    assert artifact.role == "installer"
    assert placements(se._to_record(artifact, SOURCE)) == []


@pytest.mark.parametrize("source", [HASH[:-1], "a" + HASH, HASH + "a", HASH[:20] + " omitted " + HASH[20:]])
def test_hash_recovery_never_repairs_missing_or_unbounded_source_values(source):
    artifact, reason = se._checked({"value": HASH, "kind": "sha256"}, source, source)
    assert artifact is None
    assert "not found" in reason


def test_adjacent_complete_hashes_are_not_joined_into_one():
    page = HASH + " " + "a" * 64
    artifact, reason = se._checked({"value": HASH, "kind": "sha256"}, page, page)
    assert artifact is not None, reason


def test_truncated_extraction_retains_only_complete_artifacts():
    complete = {"value": "c2.example", "kind": "domain"}
    response = '{"artifacts": [' + json.dumps(complete) + ', {"value": "unfinished'
    assert se._parse(response) == [complete]
    assert se._parse('{"metadata": {"artifacts": [' + json.dumps(complete)) == []
    assert se._parse('{"artifacts": [{"value": "unfinished') == []


def test_unclassified_primary_mentions_are_not_curated_iocs():
    typed = IndicatorRecord("vps-agent.net", "domain", source=SOURCE)
    curated = IndicatorRecord("curated.example", "domain")
    c2 = IndicatorRecord("confirmed.example", "domain", "c2", source=SOURCE)
    assert routable_indicators([typed, curated, c2]) == {"domain": ["curated.example", "confirmed.example"]}
    artifact = se.SourceArtifact(value="vps-agent.net", kind="domain")
    assert se._to_record(artifact, SOURCE).source == SOURCE


def _rules(records):
    agent = SigmaGeneratorAgent.__new__(SigmaGeneratorAgent)
    data = SigmaGenerationInput(
        hypothesis="Election infrastructure compromise",
        platforms=["Windows"],
        indicator_records=[r.to_dict() for r in records],
    )
    results = agent._ioc_rules(data)
    assert all(not problem for _, problem in results)
    return [yaml.safe_load(rule.rule_yaml) for rule, _ in results if rule]


def test_historical_parent_exclusions_apply_to_model_inputs_and_generated_sigma():
    records = [
        IndicatorRecord("il-cert.net", "domain", "historical", "historical"),
        IndicatorRecord("connect.il-cert.net", "hostname", "c2", "active"),
        IndicatorRecord("http://il-cert.net/wez/api.php", "url", "c2", "active"),
        IndicatorRecord("sibling.example", "hostname", "c2", "active"),
        IndicatorRecord("old.sibling.example", "hostname", "historical", "historical"),
        IndicatorRecord("notil-cert.net", "domain", "c2", "active"),
    ]
    assert routable_indicators(records) == {"hostname": ["sibling.example"], "domain": ["notil-cert.net"]}
    rules = _rules(records)
    assert rules
    assert "il-cert.net/wez" not in json.dumps(rules)
    assert "connect.il-cert.net" not in json.dumps(rules)
    assert "sibling.example" in json.dumps(rules)


def test_proxy_detection_pairs_hosts_with_their_paths():
    rules = _rules(
        [
            IndicatorRecord("https://one.example/first.php", "url", "c2", "active"),
            IndicatorRecord("https://two.example/second.php", "url", "c2", "active"),
        ]
    )
    proxy = next(r for r in rules if r["logsource"]["category"] == "proxy")
    evaluator = SigmaEvaluator(proxy)
    assert evaluator.matches({"cs-host": "one.example", "c-uri": "/first.php"})
    assert evaluator.matches({"cs-host": "two.example", "c-uri": "/second.php"})
    assert not evaluator.matches({"cs-host": "unrelated.example", "c-uri": "/first.php"})
    assert not evaluator.matches({"cs-host": "one.example", "c-uri": "/second.php"})


def test_process_relationship_cannot_be_claimed_from_current_process_arguments():
    detection = {
        "selection_installer": {"CommandLine|contains": "Google Chrome Installer.msi"},
        "selection_rat": {"Image|endswith": "\\bd.exe", "CommandLine|contains": "8765"},
        "condition": "selection_installer and selection_rat",
    }
    assert "parent process field" in description_mismatch(detection, "Detects bd.exe spawned by the installer")
    detection["selection_installer"] = {"ParentCommandLine|contains": "Google Chrome Installer.msi"}
    assert description_mismatch(detection, "Detects bd.exe spawned by the installer") is None


def test_excluded_hash_diagnostic_does_not_accuse_source_of_invention():
    reason = _invented_hash_problem({"selection": {"Hashes": HASH}}, {})
    assert "provenance" in reason and "file role" in reason
    assert "invented" not in reason


def test_installer_filename_does_not_establish_tampering():
    from hecate_agent.core.sigma_semantics import installer_tampering_without_evidence

    detection = {"selection": {"TargetFilename|endswith": "Google Chrome Installer.msi"}, "condition": "selection"}
    assert installer_tampering_without_evidence(detection, "file_event", "Detects a trojanized installer")
    assert installer_tampering_without_evidence(detection, "file_event", "Filename lead for analyst inspection") is None


def test_model_drafts_cannot_reintroduce_excluded_network_indicators():
    from hecate_agent.agents.llm.sigma_generator import _network_role_problem

    records = [
        IndicatorRecord("il-cert.net", "domain", "historical", "historical"),
        IndicatorRecord("vps-agent.net", "domain", source=SOURCE),
        IndicatorRecord("current.example", "domain", "c2", "active"),
    ]
    typed = [r.to_dict() for r in records]
    for host in ["il-cert.net", "connect.il-cert.net", "vps-agent.net"]:
        detection = {"selection": {"QueryName": host}, "condition": "selection"}
        assert "excluded" in _network_role_problem(detection, typed)
    detection = {
        "selection": {"QueryName": "current.example"},
        "filter": {"QueryName": "il-cert.net"},
        "condition": "selection and not filter",
    }
    assert _network_role_problem(detection, typed) is None


def test_truncated_source_call_recovers_later_artifacts_from_smaller_sections():
    text = "Initial context. " * 100 + "\nThe executable bd.exe runs as bd.exe 8765.\n" + "Later context. " * 100
    calls = []

    def complete(messages):
        section = messages[-1]["content"]
        calls.append(section)
        if len(calls) == 1:
            return '{"artifacts": [{"value": "bd.exe", "kind": "process", "evidence": "The executable bd.exe runs as bd.exe 8765."}, {"value": "cut'
        artifact = {"value": "bd.exe 8765", "kind": "command_line", "evidence": "The executable bd.exe runs as bd.exe 8765."}
        return json.dumps({"artifacts": [artifact] if "8765" in section else []})

    evidence = se.extract_source_evidence(SOURCE, page_text=text, complete=complete)
    assert {a.value for a in evidence.artifacts} == {"bd.exe", "bd.exe 8765"}
    assert len(calls) == 3
    assert evidence.dropped and "retrying smaller" in evidence.dropped[0]


def test_extraction_recovery_is_bounded_and_reports_incomplete_sections():
    calls = []

    def incomplete(messages):
        calls.append(messages)
        return '{"artifacts": [{"value": "cut'

    evidence = se.extract_source_evidence(SOURCE, page_text="Source words. " * 1000, complete=incomplete)
    assert len(calls) <= evidence.chunks * 7
    assert evidence.artifacts == []
    assert any("remains incomplete" in message for message in evidence.dropped)


def test_filtered_network_sigma_transpiles_to_all_six_native_backends():
    from hecate_agent.core.sigma_transpiler import SigmaTranspiler

    rules = _rules(
        [
            IndicatorRecord("91.218.114.15", "ipv4", "c2", "active", ports=[8765]),
            IndicatorRecord("historical.example", "domain", "historical", "historical"),
        ]
    )
    rule = next(r for r in rules if r["logsource"]["category"] == "network_connection")
    converted = SigmaTranspiler().transpile(yaml.safe_dump(rule))
    assert len(converted) == 6
    for target, result in converted.items():
        assert result.success, (target, result.error_message)
        assert "91.218.114.15" in result.query.replace("\\.", ".") and "8765" in result.query
        assert "historical.example" not in result.query


def test_proxy_host_binding_survives_conversion_and_unmapped_http_reports_why():
    from hecate_agent.core.sigma_transpiler import SigmaTranspiler

    rules = _rules([IndicatorRecord("https://one.example/first.php", "url", "c2", "active")])
    proxy = next(r for r in rules if r["logsource"]["category"] == "proxy")
    transpiler = SigmaTranspiler()
    converted = transpiler.transpile(yaml.safe_dump(proxy), [transpiler.TARGET_SPLUNK, transpiler.TARGET_MDE])
    splunk = converted[transpiler.TARGET_SPLUNK]
    assert splunk.success, splunk.error_message
    assert "one.example" in splunk.query and "/first.php" in splunk.query
    kql = converted[transpiler.TARGET_MDE]
    assert not kql.success
    assert "explicit deployed table and field mapping" in kql.error_message


def test_deferred_indicators_have_reasons_in_generation_output(monkeypatch):
    agent = SigmaGeneratorAgent(llm_enabled=True)
    monkeypatch.setattr(agent, "_call_llm_with_retry", lambda *args, **kwargs: '{"rules": []}')
    monkeypatch.setattr(agent, "_get_provider", lambda: SimpleNamespace(provider_name="test", model="offline"))
    result = agent.execute(
        SigmaGenerationInput(
            hypothesis="Election infrastructure compromise",
            logsources=["process_creation"],
            platforms=["Windows"],
            indicator_records=[
                IndicatorRecord("vps-agent.net", "domain", source=SOURCE).to_dict(),
                IndicatorRecord("current.example", "domain", "c2", "active").to_dict(),
                IndicatorRecord(HASH, "sha256", "installer", "active", source=SOURCE).to_dict(),
            ],
        )
    )
    assert result.success
    assert any("vps-agent.net" in w and "does not establish" in w for w in result.warnings)
    assert any(HASH in w and "role=installer" in w for w in result.warnings)
    assert not any("indicator deferred: current.example" in w for w in result.warnings)
