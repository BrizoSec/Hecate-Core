"""Two-pass query generation (deep-dive appendix A1)."""

from typing import Any, Dict, List

import pytest

from hecate_agent.agents.llm.sigma_generator import SigmaGenerationInput, SigmaGeneratorAgent
from hecate_agent.core.query_literals import literals_from_artifacts, ungrounded_value

DECOY = r"C:\Windows\Temp\Beijing Institute of Technology_..._personal resume (2).docx"
#: H-0618's verified artifacts, as the primary-source step extracted them.
ARTIFACTS: List[Dict[str, Any]] = [
    {
        "value": DECOY,
        "kind": "file_path",
        "role": "decoy document path",
        "status": "active",
        "evidence": f"It saves it as: {DECOY}",
    },
    {"value": "cmd.exe", "kind": "process", "role": "malware execution", "status": "active"},
    {"value": "Word", "kind": "process", "role": "decoy document launch", "status": "active"},
    {"value": "Beep", "kind": "api", "role": "sleep timer", "status": "active"},
    {"value": r"%TEMP%\log_de.log", "kind": "file_path", "role": "kill-switch marker", "status": "active"},
    # The author's closing joke, not this intrusion.
    {"value": "personal_resume.exe", "kind": "file_path", "role": "decoy", "status": "unknown"},
]


def _literals() -> List[Dict[str, Any]]:
    return [lit.to_dict() for lit in literals_from_artifacts(ARTIFACTS)]


def test_pass_one_writes_each_value_as_sigma_must() -> None:
    by_value = {lit["value"]: lit for lit in _literals()}
    assert by_value[DECOY]["sigma"] == r"C:\Windows\Temp\Beijing Institute of Technology_*_personal resume (2).docx"
    assert by_value[DECOY]["match"] == "wildcard"
    assert by_value[r"%TEMP%\log_de.log"]["sigma"] == r"\log_de.log"
    assert by_value["Word"]["sigma"] == r"\winword.exe"
    assert "file_event.TargetFilename" in by_value[DECOY]["fields"]
    # API names are EDR telemetry; unconfirmed artifacts are not this intrusion.
    assert "Beep" not in by_value and "personal_resume.exe" not in by_value


@pytest.mark.parametrize(
    "selection",
    [
        {"TargetFilename": r"C:\Windows\Temp\Beijing Institute of Technology_*_personal resume (2).docx"},
        {"TargetFilename|startswith": "C:\\Windows\\Temp\\", "TargetFilename|endswith": ".docx"},
        {"ParentImage|endswith": "\\cmd.exe", "Image|endswith": "\\winword.exe"},
        {"TargetFilename|endswith": "\\log_de.log"},
        {"Image|endswith": "\\powershell.exe"},  # a standard system binary
        {"Image": "C:\\Windows\\System32\\cmd.exe"},  # ...under a standard directory (rejected in the A1 replay)
    ],
)
def test_values_from_the_source_or_the_system_are_grounded(selection: Dict[str, Any]) -> None:
    assert ungrounded_value({"selection": selection, "condition": "selection"}, _literals()) == ""


@pytest.mark.parametrize(
    ("selection", "value"),
    [
        ({"ImageLoaded|contains": "vshell"}, "vshell"),
        ({"ImageLoaded|endswith": "\\Beep.dll"}, "\\Beep.dll"),
        (
            {"TargetFilename|startswith": "C:\\Windows\\Temp\\Beijing Institute of Technology_2023_"},
            "C:\\Windows\\Temp\\Beijing Institute of Technology_2023_",
        ),
    ],
)
def test_a_value_the_source_never_gives_is_ungrounded(selection: Dict[str, Any], value: str) -> None:
    """Each was drafted in an H-0618 replay: a family name, an API as a DLL, an invented year."""
    assert ungrounded_value({"selection": selection, "condition": "selection"}, _literals()) == value


def test_without_source_values_nothing_is_held_to_a_list() -> None:
    assert ungrounded_value({"selection": {"ImageLoaded|contains": "vshell"}, "condition": "selection"}, []) == ""


def test_bare_source_filename_accepts_a_path_boundary_suffix_only() -> None:
    literals = [lit.to_dict() for lit in literals_from_artifacts([
        {"value": "pypa.py", "kind": "file_path", "status": "active"},
    ])]
    assert ungrounded_value({"selection": {"TargetFilename|endswith": r"\pypa.py"}}, literals) == ""
    for key, value in [
        ("TargetFilename|endswith", r"\evilpypa.py"),
        ("TargetFilename|endswith", r"C:\Invented\pypa.py"),
        ("TargetFilename", r"\pypa.py"),
    ]:
        assert ungrounded_value({"selection": {key: value}}, literals) == value


def test_task_creation_switch_requires_source_behavior_and_same_selection_binary() -> None:
    literals = [lit.to_dict() for lit in literals_from_artifacts([
        {"value": "pypa.py", "kind": "file_path", "status": "active",
         "evidence": "A scheduled task is created for persistence of pypa.py."},
    ])]
    selection = {"Image|endswith": r"\schtasks.exe", "CommandLine|contains": "/create"}
    assert ungrounded_value({"selection": selection}, literals) == ""
    assert ungrounded_value({"selection": {**selection, "CommandLine|contains": "/delete"}}, literals) == "/delete"
    assert ungrounded_value({"selection": {**selection, "CommandLine|contains": "UpdateCheck"}}, literals) == "UpdateCheck"
    assert ungrounded_value({"selection": {"Image|endswith": r"\schtasks.exe",
                                          "TargetFilename|contains": "/create"}}, literals) == "/create"
    assert ungrounded_value({"selection": {**selection, "Image|endswith": r"\cmd.exe"}}, literals) == "/create"
    assert ungrounded_value({"binary": {"Image|endswith": r"\schtasks.exe"},
                             "action": {"CommandLine|contains": "/create"},
                             "condition": "binary or action"}, literals) == "/create"
    literals[0]["evidence"] = "The report mentions an ordinary Python file."
    assert ungrounded_value({"selection": selection}, literals) == "/create"
    literals[0]["evidence"] = "No evidence of scheduled task creation was found."
    assert ungrounded_value({"selection": selection}, literals) == "/create"


def _input(**kwargs: Any) -> SigmaGenerationInput:
    return SigmaGenerationInput(hypothesis="x", platforms=["Windows"], hunt_id="H-0001", **kwargs)


def test_pass_two_rejects_a_model_rule_with_an_invented_value() -> None:
    agent = SigmaGeneratorAgent.__new__(SigmaGeneratorAgent)
    raw = {
        "logsource_category": "image_load",
        "title": "VShell module loaded by cmd.exe",
        "description": "x",
        "detection": {
            "selection": {"ImageLoaded|contains": "vshell", "Image|endswith": "\\cmd.exe"},
            "condition": "selection",
        },
    }
    rule, problem = agent._build_rule(raw, _input(source_artifacts=ARTIFACTS))
    assert rule is None and "'vshell' is not a value the source gives" in str(problem)


def test_pass_two_accepts_the_decoy_written_with_its_elision_as_a_wildcard() -> None:
    agent = SigmaGeneratorAgent.__new__(SigmaGeneratorAgent)
    raw = {
        "logsource_category": "file_event",
        "title": "Decoy resume written to the Windows temp directory",
        "description": "The loader saves the decoy DOCX before opening it in Word",
        "detection": {
            "selection": {"TargetFilename": r"C:\Windows\Temp\Beijing Institute of Technology_*_personal resume (2).docx"},
            "condition": "selection",
        },
    }
    rule, problem = agent._build_rule(raw, _input(source_artifacts=ARTIFACTS))
    assert problem is None and rule is not None


def test_the_prompt_offers_the_literals_instead_of_model_observables() -> None:
    agent = SigmaGeneratorAgent.__new__(SigmaGeneratorAgent)
    prompt = agent._build_prompt(_input(source_artifacts=ARTIFACTS, observables=["vshell module"]), "file_event")
    assert "EXACT VALUES FROM THE SOURCE" in prompt
    assert "Beijing Institute of Technology_*_personal resume (2).docx (the report elided part of it: keep the *)" in prompt
    assert "vshell module" not in prompt
    fallback = agent._build_prompt(_input(observables=["vshell module"]), "file_event")
    assert "OBSERVABLES THE HUNT DRAFT NAMED" in fallback and "vshell module" in fallback


def test_a_file_the_source_says_is_written_becomes_a_rule_without_the_model() -> None:
    """The A1 replay's model dropped the decoy's directory and filtered out C:\\Windows\\Temp\\."""
    import yaml

    agent = SigmaGeneratorAgent.__new__(SigmaGeneratorAgent)
    built = agent._written_file_rules(_input(source_artifacts=ARTIFACTS))
    assert [p for _, p in built] == [None]
    ((rule, _),) = built
    assert yaml.safe_load(rule.rule_yaml)["detection"] == {  # type: ignore
        "selection": {"TargetFilename": r"C:\Windows\Temp\Beijing Institute of Technology_*_personal resume (2).docx"},
        "condition": "selection",
    }
    # The kill-switch marker is checked for, not written: no rule.
    assert "log_de" not in rule.rule_yaml  # type: ignore


MAC = [
    {
        "value": "/Users/<redacted>/Library/Caches/com.apple.softwareupdate/SoftwareUpdate",
        "kind": "file_path",
        "status": "active",
        "evidence": "persistence via deploying a payload at /Users/<redacted>/Library/Caches/com.apple.softwareupdate/SoftwareUpdate",
    },
    {
        "value": "$HOME/Library/Caches/com.apple.trustd/com.apple.verified",
        "kind": "file_path",
        "status": "active",
        "evidence": "cp [random filename] $HOME/Library/Caches/com.apple.trustd/com.apple.verified",
    },
]


def test_unix_variables_and_redactions_become_endswith_and_wildcards() -> None:
    by_value = {lit.value: lit for lit in literals_from_artifacts(MAC)}
    redacted = by_value[MAC[0]["value"]]
    assert redacted.sigma == "/Users/*/Library/Caches/com.apple.softwareupdate/SoftwareUpdate" and redacted.written
    assert "process_creation.Image" in redacted.fields  # a macOS executable has no extension
    home = by_value[MAC[1]["value"]]
    assert (home.sigma, home.match, home.written) == ("/Library/Caches/com.apple.trustd/com.apple.verified", "endswith", True)


@pytest.mark.parametrize(
    "selection", [{"Image": "/bin/bash"}, {"Image|endswith": "/usr/bin/xattr"}, {"Image|endswith": "/launchctl"}]
)
def test_unix_system_binaries_are_grounded(selection: Dict[str, Any]) -> None:
    """The ClickFix replay rejected a rule for /bin/bash."""
    lits = [lit.to_dict() for lit in literals_from_artifacts(MAC)]
    assert ungrounded_value({"selection": selection, "condition": "selection"}, lits) == ""


LAUNCHCTL = (
    "incorporated into the Background Task Management (BTM) subsystem via "
    "launchctl bootstrap gui/501 /Users/m1/Library/LaunchAgents/com.apple.softwareupdated.plist."
)


def test_a_bare_file_name_takes_its_full_path_from_the_evidence() -> None:
    """The Huntress replay extracted "com.apple.softwareupdated.plist" with the full path in its evidence."""
    (lit,) = literals_from_artifacts(
        [{"value": "com.apple.softwareupdated.plist", "kind": "file_path", "status": "active", "evidence": LAUNCHCTL}]
    )
    assert lit.sigma == "/Users/*/Library/LaunchAgents/com.apple.softwareupdated.plist"  # the victim's account generalized
    assert lit.written  # a LaunchAgent plist is written to persist


@pytest.mark.parametrize(
    ("artifact", "written"),
    [
        (
            {
                "value": "$HOME/Library/Caches/homeenergyd/com.apple.homeenergyd",
                "role": "executable",
                "evidence": "Filesystem path used by this malware",
            },
            True,
        ),
        (
            {"value": "%TEMP%\\log_de.log", "role": "kill-switch marker", "evidence": "Kill-switch marker %TEMP%\\log_de.log"},
            False,
        ),
        (
            {
                "value": "C:\\Windows\\Temp\\notes.txt",
                "role": "unknown",
                "evidence": "The stager exits if the file already exists",
            },
            False,
        ),
    ],
)
def test_the_malwares_own_file_is_written_but_a_file_it_checks_for_is_not(artifact: Dict[str, Any], written: bool) -> None:
    (lit,) = literals_from_artifacts([{**artifact, "kind": "file_path", "status": "active"}])
    assert lit.written is written
