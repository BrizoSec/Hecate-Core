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
