"""Grounding fixes for hunt_researcher: data-source availability and CVE claims.

Both defects shared a shape -- a field whose name promised one thing while its
value measured another -- and both propagated into hunts as if they were
evidence.
"""

from athf.agents.llm.hunt_researcher import HuntResearcherAgent, ResearchSkillOutput

# Abridged from the workspace's own knowledge/environment.md.
ENVIRONMENT_PROFILE = """
## Security & Monitoring Tools
### SIEM / Log Aggregation
- Coverage:
  - Endpoint telemetry (process execution, network connections, file events)
  - Network flow data (NetFlow, firewall logs)
### EDR / Endpoint Security
- Telemetry: Process execution, network connections, file events, registry modifications
"""

# The real shape of R-0611's telemetry mapping: it describes file-path
# telemetry using underscore field names, which the OCSF-dotted keyword list
# did not match.
TELEMETRY = ResearchSkillOutput(
    skill_name="telemetry_mapping",
    summary="T1005 gathers data from local system sources before exfiltration.",
    key_findings=[
        "process_name: identifies the command-line interpreter",
        "file_paths: tracks file paths accessed during collection",
    ],
    sources=[],
    confidence=0.8,
)


def _agent() -> HuntResearcherAgent:
    return HuntResearcherAgent.__new__(HuntResearcherAgent)


# --- data_source_availability ---------------------------------------------


def test_availability_comes_from_the_environment_not_the_models_prose():
    """The field names a property of the estate. Deriving it from whichever
    words the model reached for scored three of four sources unavailable on a
    hunt whose CTI carried nine C2 URLs, and the hypothesis was then scoped to
    process telemetry alone."""
    availability = _agent()._extract_data_sources(TELEMETRY, ENVIRONMENT_PROFILE)
    assert availability == {
        "process_execution": True,
        "file_operations": True,
        "network_connections": True,
        "registry_events": True,
    }


def test_environment_that_omits_a_source_reports_it_unavailable():
    profile = "### SIEM\n- Coverage:\n  - Endpoint telemetry (process execution)\n"
    availability = _agent()._extract_data_sources(TELEMETRY, profile)
    assert availability["process_execution"] is True
    assert availability["registry_events"] is False


def test_without_an_environment_profile_it_falls_back_to_the_telemetry_mapping():
    availability = _agent()._extract_data_sources(TELEMETRY, "")
    assert availability["process_execution"] is True
    # "file_paths" must now match; the old OCSF-only keyword list missed it.
    assert availability["file_operations"] is True


def test_missing_environment_file_marker_is_not_treated_as_a_profile():
    """_load_environment returns this sentinel string rather than raising."""
    availability = _agent()._extract_data_sources(TELEMETRY, "Environment file not found")
    assert availability["file_operations"] is True  # fell back, did not match the sentinel


def test_a_failed_telemetry_call_with_no_environment_claims_nothing():
    failed = ResearchSkillOutput(
        skill_name="telemetry_mapping",
        summary="",
        key_findings=["LLM call failed: connection refused"],
        sources=[],
        confidence=0.0,
    )
    assert set(_agent()._extract_data_sources(failed, "").values()) == {False}


# --- CVE grounding ---------------------------------------------------------


def _skill_with(findings, snippet=""):
    return ResearchSkillOutput(
        skill_name="adversary_tradecraft",
        summary="s",
        key_findings=list(findings),
        sources=[{"title": "t", "url": "https://example.test", "snippet": snippet}],
        confidence=0.8,
    )


def test_drops_a_finding_citing_a_cve_no_source_mentions():
    """R-0611 stated "CVE-2024-1234 is associated with the initial access
    vector" as fact; no CVE appears anywhere in the source event."""
    skill = _skill_with(
        [
            "CVE-2024-1234 is associated with the initial access vector.",
            "The backdoor supports remote command execution.",
        ]
    )
    _agent()._drop_unsupported_cve_findings(skill, topic="Chrysalis backdoor")
    assert skill.key_findings == ["The backdoor supports remote command execution."]


def test_keeps_a_cve_a_retrieved_source_actually_reports():
    skill = _skill_with(
        ["CVE-2021-44228 was exploited in the wild."],
        snippet="Log4Shell (CVE-2021-44228) advisory",
    )
    _agent()._drop_unsupported_cve_findings(skill, topic="Log4j")
    assert len(skill.key_findings) == 1


def test_keeps_a_cve_named_in_the_research_topic():
    skill = _skill_with(["CVE-2026-9999 enables remote code execution."])
    _agent()._drop_unsupported_cve_findings(skill, topic="Analysis of CVE-2026-9999")
    assert len(skill.key_findings) == 1


def test_cve_matching_is_case_insensitive():
    skill = _skill_with(["cve-2021-44228 exploited."], snippet="CVE-2021-44228")
    _agent()._drop_unsupported_cve_findings(skill, topic="")
    assert len(skill.key_findings) == 1


def test_findings_without_any_cve_are_untouched():
    skill = _skill_with(["DLL side-loading from a hidden directory.", "Registers a service."])
    _agent()._drop_unsupported_cve_findings(skill, topic="")
    assert len(skill.key_findings) == 2
