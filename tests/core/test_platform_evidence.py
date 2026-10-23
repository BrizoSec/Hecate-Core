"""Evidence-based platform scoping (deep-dive item #6)."""

from pathlib import Path

import pytest
import yaml

from hecate_agent.core.platform_evidence import platform_evidence

VSHELL = (
    "ANY.RUN showed the executable launching cmd.exe, opening a DOCX in Word. "
    "It saves it as: C:\\Windows\\Temp\\resume.docx. "
    "The stager resolves kernel32 exports and loads activeds.dll. "
    "It exits if %TEMP%\\log_de.log already exists."
)
#: The report's attribution table: other actors' Linux chains, not this specimen.
ACTOR_TABLE = (
    "UNC5174 Historical SNOWLIGHT/VShell use; published chains were mainly Linux, using ELF droppers in /dev/shm. "
    "UNC6586 used a Linux React2Shell chain; no Windows."
)


def test_the_specimens_windows_chain_is_evidence() -> None:
    evidence = platform_evidence([VSHELL])
    assert evidence.supported == ["Windows"]
    markers = [m["marker"] for m in evidence.markers["Windows"]]
    assert {"cmd.exe", "kernel32", "activeds.dll", "%temp%", "docx"} <= set(markers)


def test_another_actors_linux_chain_is_not_this_specimen() -> None:
    assert "Linux" not in platform_evidence([VSHELL, ACTOR_TABLE]).markers


@pytest.mark.parametrize(
    "capability",
    [
        "VShell supports Linux, macOS and Windows implants.",
        "The framework offers ELF and Mach-O payloads for /proc/ injection.",
        "Not observed: any Linux component.",
    ],
)
def test_capability_and_negation_are_not_evidence(capability: str) -> None:
    evidence = platform_evidence([VSHELL, capability])
    assert evidence.supported == ["Windows"]
    assert "Linux" not in evidence.markers and "macOS" not in evidence.markers


def test_one_marker_does_not_outrank_the_hypothesis() -> None:
    """Kapibala's feed said only "PowerShell-based collection" about Linux web servers."""
    evidence = platform_evidence(["systematic data exfiltration using PowerShell-based collection and staging"])
    assert [m["marker"] for m in evidence.markers["Windows"]] == ["powershell"]
    assert evidence.supported == []


def test_a_linux_specimen_is_scoped_to_linux() -> None:
    text = "The dropper writes an ELF binary to /dev/shm and installs a systemd unit for it."
    assert platform_evidence([text]).supported == ["Linux"]


def test_the_vshell_feed_blurb_alone_is_too_thin_to_scope() -> None:
    gold = Path(__file__).resolve().parents[2] / "evals" / "gold" / "vshell-fake-resume.yaml"
    cti = yaml.safe_load(gold.read_text(encoding="utf-8"))["source"]["cti"]
    # The feed blurb alone names no platform-only artifact: scoping falls back to the intel.
    assert platform_evidence([cti]).supported == []


def test_container_and_cloud_evidence_detected() -> None:
    text = (
        "Adversary compromised a privileged Kubernetes pod and executed nsenter to escape. "
        "They then used an illicit OAuth application in Entra ID to assume an IAM role in AWS."
    )
    evidence = platform_evidence([text])
    assert "Containers" in evidence.supported
    assert "Identity Provider" in evidence.supported
    assert "IaaS" in evidence.supported


def test_an_appliance_report_is_network_devices_evidence() -> None:
    """H-0830: the report named NetScaler ADC and Gateway throughout and matched
    no marker, so one aside about SAML on another CVE scoped it to Identity Provider."""
    text = (
        "Attackers exploited NetScaler ADC and NetScaler Gateway to run commands. "
        "ThreatLabz observed web shells written on compromised NetScaler appliances. "
        "The second flaw affects appliances configured as SAML service provider or identity provider."
    )
    evidence = platform_evidence([text])
    assert "Network Devices" in evidence.supported
    assert len(evidence.markers["Network Devices"]) >= len(evidence.markers.get("Identity Provider", []))


@pytest.mark.parametrize(
    "text",
    [
        "The actor exploited FortiGate firewalls and planted a backdoor in FortiOS.",
        "Ivanti Connect Secure gateways were breached; the implant persisted on the VPN appliance.",
        "A Cisco ASA flaw let them modify ROMMON on edge devices.",
    ],
)
def test_edge_appliance_products_are_network_devices(text: str) -> None:
    assert platform_evidence([text]).supported == ["Network Devices"]
