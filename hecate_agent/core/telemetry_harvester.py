"""Telemetry Harvester and Sensor Stream Interceptor.

Parses raw execution traces (strace output, container logs, kernel audit records)
and translates low-level syscalls into standardized, normalized Sigma telemetry
events (process_creation, network_connection, file_event).

Enriches events with:
- Initiating process context (Image, CommandLine, ParentImage, ProcessId)
- Process tree hierarchy and parent-child tracking
- Target filenames and network destination IPs/ports
- Noise filtering of OS dynamic linker and shared library artifacts
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger(__name__)

#: Paths ignored during file event collection to prevent low-level OS noise
IGNORED_FILE_PREFIXES = (
    "/etc/ld.so",
    "/usr/lib",
    "/lib",
    "/usr/share/locale",
    "/snap/code",
    "/proc/",
    "/sys/",
    "/dev/",
    "/newroot",
    "uid_map",
    "gid_map",
    "setgroups",
)

#: Regex matchers for strace output lines
_EXECVE_RE = re.compile(r'^(?:\[pid\s+(\d+)\]\s+)?execve\("([^"]+)",\s*\[(.*?)\](?:\s*,\s*[^)]+)?\)\s*=\s*0')
_CONNECT_IPV4_RE = re.compile(
    r'^(?:\[pid\s+(\d+)\]\s+)?connect\(\d+,\s*\{sa_family=AF_INET,\s*sin_port=htons\((\d+)\),\s*sin_addr=inet_addr\("([^"]+)"\)\}'
)
_CONNECT_IPV6_RE = re.compile(
    r'^(?:\[pid\s+(\d+)\]\s+)?connect\(\d+,\s*\{sa_family=AF_INET6,\s*sin6_port=htons\((\d+)\),\s*inet_pton\(AF_INET6,\s*"([^"]+)"'
)
_OPENAT_RE = re.compile(r'^(?:\[pid\s+(\d+)\]\s+)?openat\([^,]+,\s*"([^"]+)",\s*([^,]+)(?:,\s*[^)]+)?\)\s*=\s*\d+')
_CREAT_RE = re.compile(r'^(?:\[pid\s+(\d+)\]\s+)?creat\("([^"]+)"[^)]*\)\s*=\s*\d+')
_UNLINK_RE = re.compile(r'^(?:\[pid\s+(\d+)\]\s+)?(?:unlink|unlinkat)\([^,]*"([^"]+)"[^)]*\)\s*=\s*0')
_RENAME_RE = re.compile(
    r'^(?:\[pid\s+(\d+)\]\s+)?(?:rename|renameat|renameat2)\([^,]*"([^"]+)",\s*[^,]*"([^"]+)"[^)]*\)\s*=\s*0'
)


def _extract_quoted_args(raw_args: str) -> List[str]:
    """Extract individual string arguments from an strace argv string list."""
    return [
        m.group(1).encode("utf-8").decode("unicode_escape", errors="replace")
        for m in re.finditer(r'"([^"\\]*(?:\\.[^"\\]*)*)"', raw_args)
    ]


class TelemetryHarvester:
    """Extracts structured Sigma telemetry from sandbox execution traces."""

    def __init__(self, filter_os_noise: bool = True):
        self.filter_os_noise = filter_os_noise

    def parse_strace(
        self,
        trace_text: str,
        is_intrusion: bool = True,
        initial_parent_image: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Parse raw strace output lines into normalized Sigma telemetry events."""
        events: List[Dict[str, Any]] = []
        process_table: Dict[int, Dict[str, Any]] = {}
        # Keep track of the most recently executed process as default parent for child forks
        active_pids: List[int] = []

        for line in trace_text.splitlines():
            line = line.strip()
            if not line:
                continue

            # 1. Process Creation (execve)
            m_exec = _EXECVE_RE.search(line)
            if m_exec:
                pid_str, image, raw_args = m_exec.groups()
                pid = int(pid_str) if pid_str else (active_pids[-1] if active_pids else 1)
                args = _extract_quoted_args(raw_args)
                command_line = " ".join(args) if args else image

                # Determine parent process
                parent_pid = active_pids[-1] if (active_pids and active_pids[-1] != pid) else None
                parent_info = process_table.get(parent_pid) if parent_pid else None
                parent_image = parent_info.get("Image") if parent_info else initial_parent_image

                proc_entry = {
                    "Image": image,
                    "CommandLine": command_line,
                    "ProcessId": pid,
                    "ParentProcessId": parent_pid,
                    "ParentImage": parent_image,
                }
                process_table[pid] = proc_entry
                if pid not in active_pids:
                    active_pids.append(pid)

                # Ignore harness container launcher binary from threat telemetry
                if self.filter_os_noise and (image.endswith("/bwrap") or image == "bwrap"):
                    continue

                event = {
                    "category": "process_creation",
                    "Image": image,
                    "CommandLine": command_line,
                    "ProcessId": pid,
                    "ParentProcessId": parent_pid,
                    "ParentImage": parent_image,
                    "is_intrusion": is_intrusion,
                }
                events.append(event)
                continue

            # 2. Network Connection (connect IPv4 / IPv6)
            m_conn4 = _CONNECT_IPV4_RE.search(line)
            m_conn6 = _CONNECT_IPV6_RE.search(line)
            if m_conn4 or m_conn6:
                m_conn = m_conn4 or m_conn6
                assert m_conn is not None
                pid_str, port_str, dest_ip = m_conn.groups()
                pid = int(pid_str) if pid_str else (active_pids[-1] if active_pids else 1)
                port = int(port_str)

                # Ignore internal localhost connections if noise filtering is on
                if self.filter_os_noise and dest_ip in ("127.0.0.1", "::1"):
                    continue

                proc_info = process_table.get(pid, {})
                event = {
                    "category": "network_connection",
                    "DestinationIp": dest_ip,
                    "DestinationPort": port,
                    "Initiated": True,
                    "Image": proc_info.get("Image", ""),
                    "CommandLine": proc_info.get("CommandLine", ""),
                    "ProcessId": pid,
                    "is_intrusion": is_intrusion,
                }
                events.append(event)
                continue

            # 3. File Events (openat write/create, creat, unlink, rename)
            m_open = _OPENAT_RE.search(line)
            if m_open:
                pid_str, target_file, flags = m_open.groups()
                pid = int(pid_str) if pid_str else (active_pids[-1] if active_pids else 1)

                # Check if file was opened with modifying flags
                is_write = any(f in flags for f in ("O_CREAT", "O_WRONLY", "O_RDWR", "O_APPEND", "O_TRUNC"))
                if is_write:
                    if self.filter_os_noise and any(target_file.startswith(ign) for ign in IGNORED_FILE_PREFIXES):
                        continue

                    proc_info = process_table.get(pid, {})
                    events.append(
                        {
                            "category": "file_event",
                            "TargetFilename": target_file,
                            "Action": "write",
                            "Image": proc_info.get("Image", ""),
                            "ProcessId": pid,
                            "is_intrusion": is_intrusion,
                        }
                    )
                continue

            m_creat = _CREAT_RE.search(line)
            if m_creat:
                pid_str, target_file = m_creat.groups()
                pid = int(pid_str) if pid_str else (active_pids[-1] if active_pids else 1)
                if self.filter_os_noise and any(target_file.startswith(ign) for ign in IGNORED_FILE_PREFIXES):
                    continue

                proc_info = process_table.get(pid, {})
                events.append(
                    {
                        "category": "file_event",
                        "TargetFilename": target_file,
                        "Action": "create",
                        "Image": proc_info.get("Image", ""),
                        "ProcessId": pid,
                        "is_intrusion": is_intrusion,
                    }
                )
                continue

            m_unlink = _UNLINK_RE.search(line)
            if m_unlink:
                pid_str, target_file = m_unlink.groups()
                pid = int(pid_str) if pid_str else (active_pids[-1] if active_pids else 1)
                if self.filter_os_noise and any(target_file.startswith(ign) for ign in IGNORED_FILE_PREFIXES):
                    continue

                proc_info = process_table.get(pid, {})
                events.append(
                    {
                        "category": "file_event",
                        "TargetFilename": target_file,
                        "Action": "delete",
                        "Image": proc_info.get("Image", ""),
                        "ProcessId": pid,
                        "is_intrusion": is_intrusion,
                    }
                )
                continue

            m_rename = _RENAME_RE.search(line)
            if m_rename:
                pid_str, old_file, new_file = m_rename.groups()
                pid = int(pid_str) if pid_str else (active_pids[-1] if active_pids else 1)
                if self.filter_os_noise and any(new_file.startswith(ign) for ign in IGNORED_FILE_PREFIXES):
                    continue

                proc_info = process_table.get(pid, {})
                events.append(
                    {
                        "category": "file_event",
                        "TargetFilename": new_file,
                        "OriginalFilename": old_file,
                        "Action": "rename",
                        "Image": proc_info.get("Image", ""),
                        "ProcessId": pid,
                        "is_intrusion": is_intrusion,
                    }
                )
                continue

        return events

    def parse_json(
        self,
        raw_json: Union[str, List[Dict[str, Any]]],
        is_intrusion: bool = True,
    ) -> List[Dict[str, Any]]:
        """Parse structured EDR/JSON telemetry events and normalize taxonomy."""
        if isinstance(raw_json, str):
            try:
                data = json.loads(raw_json)
            except Exception as exc:
                logger.error("Failed to parse JSON telemetry: %s", exc)
                return []
        else:
            data = raw_json

        items = data if isinstance(data, list) else [data]
        normalized: List[Dict[str, Any]] = []

        for item in items:
            if not isinstance(item, dict):
                continue
            ev = dict(item)
            if "is_intrusion" not in ev:
                ev["is_intrusion"] = is_intrusion
            normalized.append(ev)

        return normalized
