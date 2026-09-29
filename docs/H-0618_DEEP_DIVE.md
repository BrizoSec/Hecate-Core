# Deep Dive: H-0618 and R-0616

Review of hunt H-0618 ("VShell via fake-resume lure"), its four Sigma rules, and
the research document R-0616 that grounded it. Written 2026-09-27.

- **Hunt:** `hunts/2026/Q3/H-0618.md`, rules in `queries/H-0618/`
- **Research:** `research/R-0616.md`
- **Source CTI:** OTX pulse "A fake resume invoked China's defence-tech elite, then installed VShell"
- **Primary source:** [blog.himanshuanand.com](https://blog.himanshuanand.com/2026/08/a-fake-resume-invoked-chinas-defence-tech-elite-then-installed-vshell)
- **Run:** Hecate-Runner cycle `7a7b1c`, a single run from a blank workspace,
  491 s end to end, on `qwen3:30b-a3b-instruct-2507-q4_K_M` with a 16K context

Every claim in the draft was checked against the primary source.

## Summary

H-0618 is **partly source-grounded, but materially incomplete and not ready to
run**. The pipeline only saw the 2,194-character OTX blurb, while the primary
source carries the process tree, file paths, API chain, two distinct network
ports, hash roles, and detection guidance. The draft copied indicator values,
but lost their roles and treated historical passive-DNS domains as campaign
indicators. It also overstates what was observed: the source confirms VShell
registration and health traffic, not operator activity, persistence, theft, or
lateral movement. The primary source's confidence and negative-evidence
distinctions need to survive into the research and hunt.

| Area | Result | Notes |
|---|---|---|
| Hypothesis | Mixed | Specific, but overstates the victim context and follow-on impact |
| Indicators | Mixed | Values copied exactly; artifact roles and domain relevance lost |
| Technique mapping | Poor | Incomplete; T1113 is a capability here, not observed behavior |
| Platform | Wrong | Linux and Windows; the chain is Windows-only |
| Behavioural rules | Not ready | The file rule is semantically inconsistent with the sample |
| IOC rules | Not ready | Hash roles are mixed; DNS names are not tied to this sample |
| Research (R-0616) | Weak | Zero web searches; rewords the blurb and adds errors |
| Grounding audit | Misleading | Reports 0 unsupported while the platform and several observables are wrong |

## Fact check against the primary source

| Draft says | Primary source says | Verdict |
|---|---|---|
| Custom Go loader with sandbox, CPU and sleep-timer evasion | Also specific: at least 4 logical CPUs; "BeepSleep" timing check via `kernel32!Beep` at 30 kHz for 10 s; exits if the path contains `C:\Users\Administrator\Desktop` | Correct, shallow |
| Fileless SNOWLIGHT stager, 4.65 MB, XOR key `0x99`, VShell RAT | Also the API chain: `AllocADsMem` (activeds.dll), `VirtualProtect`, `RtlMoveMemory`, `CreateThread` | Correct, shallow |
| Platform: Linux, Windows | Windows only: `cmd.exe`, Word, `kernel32`, `activeds.dll`, `w32` architecture tag | Wrong |
| R-0616: "the initial payload is a fileless Go loader" | The Go loader is an on-disk EXE inside a ZIP; only the stager and VShell run in memory | Wrong, introduced by research |
| `MySQL_LOG.txt` treated as a log ("legitimate log monitoring…") | It is the DOCX decoy download URL; `EasyConnectUpdata_Log.txt` stages the shellcode | Wrong role |
| C2 on port 50813 | 50813 is HTTP staging; 50812 carries the SNOWLIGHT check-in and VShell transfer | Incomplete; 50812 missing and services conflated |
| All hashes treated as executables | Roles include ZIP archive, Go loader, encrypted HTTP response, shellcode, encoded VShell stream, decoded VShell, and DOCX | Misleading; most are not process-image hashes |
| Techniques T1036, T1113 | T1036 fits; T1113 is a RAT capability, not observed intrusion behaviour | Partly |
| Not mentioned | Process tree: resume EXE → `cmd.exe` → Word opening a DOCX from `C:\Windows\Temp\` | Missing; the best behavioural signal |
| Not mentioned | Kill switch: `%TEMP%\log_de.log` | Missing |
| Not mentioned | Author's detection guidance: four concrete hunts | Missing |
| Five hostnames treated as active IOCs | The source classifies the old DNS observations as historical tenants; none appears in the sample configuration or PCAP | Not campaign indicators without corroboration |
| Persistence, collection, and lateral movement stated as facts | VShell offers these capabilities, but the sandbox run showed registration and health traffic only | Capability is not observed use |

## What worked well

1. **Hypothesis.** Specific, testable and entirely sourced; the strongest the
   pipeline has produced.
2. **Indicators.** All 16 copied exactly, and the grounding table traces each
   one to the CTI.
3. **Deterministic IOC generation.** The hash, DNS and network rules avoid
   model-generated indicator values and have source references. Their current
   content still needs correction: hash roles are mixed, the DNS names are not
   linked to this sample, and the network rule needs port scoping.
4. **Some Sigma validation.** Three bad candidates were rejected: two
   `example.com` placeholders and one invalid `|in` modifier. That checks part
   of the rule form; it did not catch the surviving file rule's event semantics
   or establish that the fields map to the target SIEM.
5. **Attribution.** Honestly "Unknown", carrying the source's reasoning
   (commodity, cracked VShell) instead of inventing an actor.
6. **Pipeline behaviour.** Triage parked a commentary roundup first, and the
   cycle completed cleanly in about 8 minutes with nothing fabricated.

## What worked poorly

### Write-up

- **Technique mapping.** T1036 is supported by the disguised resume. T1113 is
  only a VShell feature in this sample. Candidate observed-behavior mappings
  include T1204.002 (user execution), T1059.003 (`cmd.exe`), T1497.001 and
  T1497.003 (system and time checks), T1105 (downloads), T1140 (decoding),
  T1620 (in-process reflective loading), T1071.001 (HTTP), T1095 (raw TCP),
  and T1573 (encrypted VShell traffic). Treat these as evidence-linked
  candidates, not a measured recall denominator; a gold set must first define
  which behaviors count as observed in the report.
- **Platform.** The model's ABLE Location said "Linux and Windows workstations"
  and platform scoping trusted it over the evidence.
- **Unobservable observables.** "Command line contains sleep timer or CPU check
  logic" cannot be seen in a command line; the checks run inside the binary.
  `process_name: <unknown executable…>` is a placeholder. The baseline refers to
  files with "similar SHA256 hashes", which is not a meaningful comparison.
- **ABLE Evidence** is generic ("unknown binaries with Chinese-language file
  names") where the source gives the exact lure name.

### Hunt queries

- **The one attempted behavioural rule (`file_event`) is semantically
  inconsistent with the sample.** Its map requires the hash, `Image` containing
  `MySQL_LOG.txt`, and `TargetFilename` containing `MySQL_LOG.txt` on one event;
  the source describes that string as a URL path and the downloaded decoy is
  saved under a resume-style `.docx` name. It then excludes images containing
  `Windows`. This makes a match to the reported behavior unlikely and field
  availability still needs backend validation; avoid claiming it is logically
  impossible in every possible schema.
- **The hash rule dilutes its coverage.** Only the Go loader hash can match
  process execution. The ZIP never runs, and the shellcode and decoded VShell
  exist only in memory. The rule is harmless but overstates coverage.
- **The network rule is too broad and incomplete.** It matches the IP on any
  destination port and includes hostnames not seen in this specimen. Split
  HTTP staging on `50813` from raw TCP/VShell traffic on `50812`. Search exact
  URL paths only in proxy/web logs that retain them.
- **The DNS query is not a campaign detection.** The five names are historical
  passive-DNS tenants according to the primary source, not names in the
  sample's configuration or PCAP. The query should not present them as active
  C2 without additional evidence.
- **DNS rule description mismatch.** It says "or a subdomain of a published
  domain", but the detection only matches exact names.
- **No behavioural rules**, although the author lists four detections that
  translate directly into Sigma.

### Research (R-0616)

- **Zero web searches.** No `TAVILY_API_KEY` is configured in either `.env`,
  so research runs ungrounded, while the cycle trail reports "web search on".
  R-0616 rewords the OTX blurb four ways (1.6 minutes, 4 LLM calls) and adds one
  error (the "fileless Go loader"). Its `$0.00` cost for four calls also needs
  reconciliation against provider usage and pricing; treat zero as unknown
  until verified, not as proof that the calls were free.
- **Telemetry mapping failed.** All six proposed fields are flagged
  "NOT AN OCSF FIELD" by the pipeline's own validator.
- **Data-source availability is a template.** `registry_events: true`
  appears regardless of the environment.
- **Gaps and Focus are generic**; they would fit any fileless malware report.
  R-0616 also promotes the historical domains as current network indicators and
  describes persistence and lateral movement without preserving the source's
  caveat that those actions were not observed.

### Grounding audit

It reports "every checkable claim traces back to a source" because it checks
literals only: indicators, technique IDs and named entities. The wrong platform,
the wrong URL role, the unobservable observables and the dead rule all pass. It
also lists "DOCX", a file type, as a named entity.

## What H-0618 should have contained

Derived from the primary source's detail and the author's detection guidance:

| Category | Rule |
|---|---|
| process/correlation | Resume-named loader execution followed by the reported `cmd.exe`/Word decoy process chain; require same-host and short time window, with field names mapped to the actual EDR |
| file_event | `.docx` created under `C:\Windows\Temp\` by the loader, correlated with process and network events |
| file/API telemetry | Access or existence check for `%TEMP%\log_de.log`; the stager checks whether it exists, so a file-creation rule alone is not supported |
| EDR memory/API telemetry | In-process memory allocation, executable protection, copy, and thread-start sequence; `activeds.dll`/`AllocADsMem` is supporting detail, not sufficient alone |
| network_connection | Outbound connection to `38.207.178.192:50813` (HTTP staging) or `:50812` (raw TCP/SNOWLIGHT and VShell); separate rules and retain time bounds |
| proxy/web | Exact requests for `/EasyConnectUpdata_Log.txt` and `/MySQL_LOG.txt`, only where URL path is captured |

Candidate techniques to add, each linked to supporting source evidence:
T1204.002, T1059.003, T1497.001, T1497.003, T1105, T1140, T1620, T1071.001,
T1095, and T1573. Keep T1113 as a capability/follow-on lead unless screen
capture is observed. Do not count candidates as observed behavior without
confirming the source's evidence for each one.

## Root causes

1. **The pipeline never reads the primary source.** Every stage worked from
   the OTX blurb, so the model filled gaps from priors: the platform, the URL
   role, and the dead rule.
2. **Research adds no evidence.** No search key is configured and nothing
   says so.
3. **Technique matching is phrase-literal.** It needs ATT&CK's own names;
   reports describe behaviour ("sandbox detection", "XOR-decodes", "disguised as
   a resume").
4. **Validators check form, not meaning.** Sigma validation checks syntax and
   placeholders, not whether a field belongs to its log source or whether
   multiple fields describe the same observed event. The grounding audit checks
   literals, not the platform, indicator roles, whether an observable can be
   observed, or whether a claimed IOC is current and related to this sample.

## Enhancements, ranked by impact

| # | Enhancement | Fixes | Effort |
|---|---|---|---|
| 1 | **Primary-source extraction in the Runner.** The artifact extractor (fetch, extract, verbatim check) exists in Core but only the LangGraph path uses it. Pass extracted claims and artifacts to hypothesis, observables, and query generation while retaining provenance and confidence. | Missing process tree, paths, ports, APIs and guidance; wrong URL role; weak victim/platform scope | Medium; the parts exist |
| 2 | **Typed IOC provenance.** Store object role, algorithm, stage, source, observation date, confidence, and current-versus-historical status. Route hashes/domains to event types that can actually observe them; preserve ports and paths. | Wrong event mappings; stale domains; unscoped network rules | Medium |
| 3 | **Research grounding.** Configure search, report actual search count, and distinguish source-only synthesis from independent research. Warn and limit unsupported enrichment when searches are unavailable; do not automatically park solely for that reason. | R-0616 adding no independent evidence; misleading "web search on" | Small |
| 4 | **Evidence-gated behavior-to-technique mapping.** Map behavior descriptions to candidate techniques, attach the supporting passage, and distinguish observed technique use from tool capability. Do not use a phrase-only match or a raw "fileless" label as proof of T1620. | Incomplete and overclaimed ATT&CK mapping | Small to medium |
| 5 | **Sigma semantic validation.** Enforce `_LOGSOURCE_FIELDS` and the actual backend schema; check artifact/event compatibility, same-event AND logic, selection OR logic, URL-versus-local-path use, and rule-description consistency. | The inconsistent file rule and backend field uncertainty | Small to medium |
| 6 | **Evidence-based platform scoping.** Treat sample architecture and platform evidence (`.exe`, `cmd.exe`, `kernel32`, `w32`) as stronger than a model's broad Location; keep unsupported platforms out of this specimen's hunt. | The wrong platform | Small |
| 7 | **Observable and claim audit.** Reject `<…>` placeholders and impossible field claims; flag command-line descriptions for internal API behavior, “similar hash” baselines, and assertions of persistence/exfiltration when only capability is reported. | Unobservable observables and capability/behavior conflation | Small |
| 8 | **Detection-guidance ingestion.** Turn the source author's endpoint and network guidance into candidate analytics with a source citation. Generate Sigma only where supported; route memory/API and multi-event sequence detections to EDR or backend-specific correlation when required. | Missing behavioral detections without promising unavailable telemetry | Small once #1 exists |
| 9 | **Fix telemetry mapping.** Validate proposed OCSF fields against the schema, then map them to the actual organization's event fields; keep registry availability unknown unless the environment documents it. | Invalid fields and unsupported availability claims | Small |
| 10 | **A gold set from this review.** Encode positive and negative expected claims, IOC roles, platform, and query semantics; score pipeline changes against that set. Define the denominator before reporting technique recall. | Measuring accuracy consistently instead of relying on impressions | Small |
| 11 | **Cost and provenance quality gates.** Treat zero estimated cost as unknown when pricing/usage is missing, and retain the source/sample context for every generated indicator. | Misleading research metrics and untraceable IOC claims | Small |

**Suggested order:** Build #10 first so later changes are measurable. Then
do #1 and #2 together: retrieve source evidence and preserve artifact roles and
confidence. Add #3 so the workflow accurately reports whether it independently
researched the source. #4 through #9 then improve mappings, query semantics,
scope, and observability. Apply #11 alongside research-metric handling.

## Uplift tracker

Status of each enhancement above, and of the additional ones suggested in the
appendix. Update this table as work lands; measure each change with
`hecate-agent eval-gold` against the baseline below.

**Baseline** (H-0618 as reviewed, `evals/gold/vshell-fake-resume.yaml`):
23/71 checks (32.4%); technique recall 1/11.

| # | Enhancement | Status | Completed | Notes |
|---|---|---|---|---|
| 1 | Primary-source extraction in the Runner | Done | 2026-09-27 | `core/source_evidence.py`: whole-page chunked extraction, verbatim value and evidence checks, report-label confidence; Runner `source` step feeds research, hypothesis, Sigma, draft and grounding. Measured with #2 (see below) |
| 2 | Typed IOC provenance | Done | 2026-09-27 | `core/provenance.py`: role, status, confidence, evidence, ports; role-routed IOC rules. Live replay: indicators 24/24 (was 6/24) |
| 3 | Research grounding | Done | 2026-09-27 | `TAVILY_API_KEY` configured. Research records the actual search count and why it is zero; frontmatter `grounding: independent\|source-only`; source-only documents carry a banner; the trail and the draft's research line state the grounding; source-only research is not counted as evidence for technique filtering or the grounding audit; items are warned about, not parked. The gold replay's research ran independent (2 web searches) |
| 4 | Evidence-gated behaviour-to-technique mapping | Done | 2026-09-27 | `core/technique_evidence.py`: curated behaviour catalog; each passage judged observed, capability, negated, or another actor's context; only observed use proposes a technique. Runner drops capability-only techniques (T1113), generalises unsupported sub-techniques to a supported parent, keeps CTI-named IDs, and renders a Technique Evidence table. Live replay: recall 11/11 (was 1/11) |
| 5 | Sigma semantic validation | Done | 2026-09-27 | `core/sigma_semantics.py`, shared with `eval-gold`, gates every model-drafted and deterministic IOC rule; a rejection is returned to the model as retry feedback. Rejects: fields outside the log source's taxonomy; documents or archives as process images or loaded modules; API names in file or module fields, or in a non-script-host command line; bare numbers in path fields; URL/path/host confusion (honouring Sigma escapes); report elisions ("…") as literals; AND-ed constraints no single event meets; a description promising suffix matching or a parent→child chain the selection reverses; an OR-ed branch broad on its own; a published hash in an event its role never produces; filters excluding, or rebuilt from, the threat's own named artifacts. Backend-specific field mapping is out of scope: no backend is configured. Benchmark: 12 of 806 SigmaHQ core rules rejected (1.5%), 10 of them fields outside the strict taxonomy list. Live replay: rule semantics 3/3; 69/71 overall |
| 6 | Evidence-based platform scoping | Done | 2026-09-28 | `core/platform_evidence.py` counts distinct platform-only markers (`cmd.exe`, `kernel32`, `%TEMP%`, ELF, `/dev/shm`, LaunchAgents, …) in the feed item and primary source, only in sentences reporting observed activity, so capability lists and other actors' tradecraft do not count. With two or more markers the evidence outranks the model: platforms the hypothesis or Location names without evidence are dropped with a trail line, techniques cannot widen onto unevidenced platforms, and the prose claim is flagged in the Claim Audit. Thinner evidence (one marker, or the feed blurb alone) leaves the existing scoping in place. On the VShell report: Windows only; its Linux mentions are the attribution table's other actors. Live replay: platform 7/7, 70/71 overall (the model named Windows only this run; the override path is covered by a Runner test reproducing the original H-0618 Location) |
| 7 | Observable and claim audit | Done | 2026-09-27 | `core/claim_audit.py`, run by the Runner on the final technique list. Removes placeholder, "similar hash", command-line-shows-internal-logic and API-name-as-file observables; softens persistence, exfiltration, lateral movement and credential theft stated as fact without a technique of that kind ("could enable", "potentially enabling", "to potentially achieve", plus "(capability; not observed in the source)"); rewrites "fileless" to "in-memory" beside a loader the source publishes as an executable. Every action is listed under Grounding as a Claim Audit and in the trail. Sector and motive claims are not rewritten. Live replay: claims 13/13 (was 10/13) |
| 8 | Detection-guidance ingestion | Done | 2026-09-28 | `core/detection_guidance.py` finds the primary source's detection section, rebuilds each item from the scraped page, and routes it: Sigma (files, process launches, registry), EDR (API sequences, memory, code signing), IDS/NDR (bytes in traffic), IOC sweep, or review. File and process-chain items become deterministic Sigma rules quoting and citing the guidance, one per event in the source's direction (joining a chain needs backend correlation), through the #5 gate. Sigma-routed guidance also goes into the model prompt with an instruction not to contradict it. The draft gains a "Detection Guidance from the Source" table: each item, where it runs, and the rule drafted. Live replay: detections 5/6; 70/71 overall |
| 9 | Fix telemetry mapping | Done | 2026-09-28 | `core/telemetry_mapping.py`. Fields are normalized before validation (event-class prefixes such as `process_activity.` stripped, `parent_process` placed under `process`), so R-0616's six "NOT AN OCSF FIELD" flags were five-of-six false alarms; a field still invalid is removed from the mapping and listed apart with its closest documented field, not flagged inline. Each valid field is mapped to the event field `knowledge/environment.md` documents for it (`process.cmd_line` → `command_line`), or marked unmapped. Availability counts only configured telemetry sections of the profile, so registry reads "Unknown" while the EDR product is "[To be configured]"; without a profile the labels say the values come from the mapping. Not scored by the gold set; the live replay's R-0616 mapped all fields validly (four to documented fields, three unmapped; `network_endpoint.*` then mapped to both endpoint sides), and the score stayed 70/71 |
| 10 | Gold set from this review | Done | 2026-09-27 | `evals/gold/vshell-fake-resume.yaml` (11-technique denominator, negative cases, IOC roles, detections); `hecate-agent eval-gold`; baseline locked in `tests/core/test_gold_eval.py`; workflow in `evals/README.md` |
| 11 | Cost and provenance quality gates | Done | 2026-09-28 | Cost: `cost_tracker.summarize_cost` reports a cost only when it is known; a local model with no per-token price, missing token usage, or a mix with local calls is `null` with a `cost_basis` saying why, and fallback pricing is labelled. R-0616 now records `total_cost_usd: null` ("not priced: local model … compute is not metered") with 14,776/2,045 tokens instead of `$0.0000`; `research list` shows n/a, `research stats` counts unpriced documents apart, and the Runner's stage metrics carry null instead of 0.0. Provenance: every Sigma rule that matches a published indicator carries `hecate_provenance` (value, type, role, status, confidence, source, typing passage; feed-only values marked "cti feed"; historical ones have no rule), and the Runner checks every address and hash in every rule after drafting, naming any untraced one with a warning. Live replay: 5 indicators across 7 rules, all traced; 70/71 unchanged |
| A1 | Two-pass query generation (appendix) | Done | 2026-09-28 | Pass one (`core/query_literals.py`) turns the primary source's verified, active artifacts into Sigma-ready literals with their fields: the report's elided decoy path becomes `C:\Windows\Temp\Beijing Institute of Technology_*_personal resume (2).docx`, `%TEMP%\log_de.log` an `endswith` on `\log_de.log`, "Word" `\winword.exe`; API names and unconfirmed artifacts are left out. Pass two: the model gets these instead of its own observables and may use only them (whole or in part) plus standard system binaries and directories in file, process, command-line and registry fields; a file the source says the malware writes becomes a deterministic `file_event` rule. Rejected on replays: `vshell` as a module, `SNOWLIGHT`, an invented year. The replays also fixed three earlier checks: a filter is rejected when it would match an artifact the source names (a `\Windows\Temp\` filter on the decoy rule), system binaries under system directories are grounded, and a `*` inside a value counts as wildcard matching; a model rule reversing the guidance chain (Word → `cmd.exe`) is now rejected. Live replay: detections 6/6; 70/71, the one failure being "defense-tech sector" prose variance |
| A2 | Rule-reviewer sub-agent (appendix) | Done | 2026-09-28 | `agents/llm/rule_reviewer.py`, run by the Sigma generator when `review_rules` is set (Runner: `HECATE_RUNNER_SIGMA_REVIEW_ENABLED`, on). Each model-drafted rule is reviewed against the hypothesis and the verified source passages; deterministic rules are not. The reviewer is the same local model, so a rule is dropped only for a contradiction quoted verbatim from a passage; any other verdict is kept on the rule as `hecate_review`. A coverage call lists behaviours no rule detects; a gap is reported only if its quote is verbatim, the behaviour is loggable (not memory, packet content or EDR), and no rule already matches the file or address it names. Live replay: 71/71, but the reviewer added little: it kept a weak rule (`cmd.exe` connecting to the C2, which the source does not say), and all five of its gaps were grounded but not real gaps, which the added filters now drop. Treat it as advisory |
| A3 | OS-specific telemetry examples in prompts (appendix) | Done | 2026-09-28 | `core/telemetry_examples.py`: 18 entries across Windows, Linux and macOS, each saying where an internal really appears (event, field, example value) and where it never does (`memfd_create` as `/memfd:<name> (deleted)` in `Image`, never a file name; Win32 APIs in EDR only; reflective loading never in `image_load`; `%TEMP%` as the expanded path). Entries fire on specific terms, only in sentences reporting observed activity, on the hunt's platforms; VShell gets exactly three (APIs, in-memory loading, `%TEMP%`). Added to the hypothesis, research telemetry-mapping and Sigma prompts. Live replay: 71/71, with no API-name or ungrounded-value rejections (3 to 6 logged lines in each of the four previous comparable runs; one run, so a signal, not proof). The same replay's observables listed a bare `Beep`, a memory-only hash, a network-content hash and `personal_resume.exe`; the claim audit now removes bare API names and values the pipeline knows no log can show, and `file_activity.path` normalizes to `file.path` |

**Measurements** (one live Runner cycle on the same OTX pulse and CTI text, scored with
`hecate-agent eval-gold`; single runs carry model variance):

| Run | Checks | Techniques | Platform | Claims | Indicators | Detections | Rule semantics | Recall |
|---|---|---|---|---|---|---|---|---|
| Baseline (H-0618 as reviewed) | 23/71 (32.4%) | 7/18 | 6/7 | 3/13 | 6/24 | 1/6 | 0/3 | 1/11 |
| After #1 + #2 (2026-09-27) | 58/71 (81.7%) | 7/18 | 7/7 | 13/13 | 24/24 | 4/6 | 3/3 | 1/11 |
| After #1–#4 (2026-09-27) | 66/71 (93.0%) | 18/18 | 7/7 | 10/13 | 24/24 | 4/6 | 3/3 | 11/11 |
| After #1–#4 + #7 (2026-09-27) | 68/71 (95.8%) | 18/18 | 7/7 | 13/13 | 24/24 | 4/6 | 2/3 | 11/11 |
| After #1–#5 + #7 (2026-09-27) | 69/71 (97.2%) | 18/18 | 7/7 | 13/13 | 24/24 | 4/6 | 3/3 | 11/11 |
| After #1–#5, #7, #8 (2026-09-28) | 70/71 (98.6%) | 18/18 | 7/7 | 13/13 | 24/24 | 5/6 | 3/3 | 11/11 |
| After #1–#8 (2026-09-28) | 70/71 (98.6%) | 18/18 | 7/7 | 13/13 | 24/24 | 5/6 | 3/3 | 11/11 |
| After #1–#9 (2026-09-28) | 70/71 (98.6%) | 18/18 | 7/7 | 13/13 | 24/24 | 5/6 | 3/3 | 11/11 |
| After #1–#11 (2026-09-28) | 70/71 (98.6%) | 18/18 | 7/7 | 13/13 | 24/24 | 5/6 | 3/3 | 11/11 |
| After #1–#11 + A1 (2026-09-28) | 70/71 (98.6%) | 18/18 | 7/7 | 12/13 | 24/24 | 6/6 | 3/3 | 11/11 |
| After #1–#11 + A1, A2 (2026-09-28) | 71/71 (100%) | 18/18 | 7/7 | 13/13 | 24/24 | 6/6 | 3/3 | 11/11 |
| After #1–#11 + A1–A3 (2026-09-28) | 71/71 (100%) | 18/18 | 7/7 | 13/13 | 24/24 | 6/6 | 3/3 | 11/11 |

After #1 and #2 the remaining failures were technique mapping (#4: 10 observed
techniques missing, T1113 still mapped from wording) and two behavioural
detections. After #4 every observed technique is mapped and T1113 is dropped as
capability-only. The three claim checks that failed in the #1–#4 run (a
"fileless" Go loader, "enables persistent" access, "defense-tech sector") sit in
model-written prose (hypothesis, justification, ABLE behaviour) that #4 does not
touch; the previous run happened to avoid them. That run-to-run prose variance
is what item #7 targets. The two model-drafted behavioural rules in that run were also
semantically wrong in ways the gold set does not yet check (a reversed
`winword.exe` → `cmd.exe` chain, and the `Beep` API matched in `CommandLine`);
item #5 and a stricter gold set should catch both. The gold predicate for the decoy
process chain was tightened on 2026-09-27 after it accepted any `.exe` parent;
the baseline score is unchanged by that fix.

With #7 the audit softened "to achieve persistent" and "enabling … lateral
movement" in that run; "defense-tech sector" did not recur, which is model
variance, not the audit. A first #7 run scored 67/71 and exposed two bugs, both
fixed before the recorded run: independent research's feature list ("a VShell RAT
… enabling command execution, file access, screen capture") mapped T1113 as
observed, and the softening broke participles and infinitives ("…, could enable",
"to could achieve"). The `persistence-as-fact` gold pattern now accepts hedged
wording; the baseline and the #1–#4 draft score the same under it. The remaining
failures are the two behavioural detections (#5, #8) and one rule-semantics check:
a model-drafted rule put `ParentImage`/`IpAddress` in `image_load` and
`DestinationIp`/`DestinationPort` in `process_creation` (#5). That run also mapped
T1678, which is not in the gold set and needs review.

Item #5 took three live runs. Each run's surviving model rules showed a defect
the checks did not yet cover, and each was added with a test: an API name as a
loaded module (`ImageLoaded|contains: Beep`), a file name as a DNS name, the
report's "…" elision matched literally, a filter excluding the decoy the source
names, a port as a module path, the loader's executable hash in `image_load`,
and a filter rebuilt from the decoy's own name with an invented year. The final
run scored 69/71 before one last check (a `.docx` as `ImageLoaded`) landed; that
check rejects a rule no gold check credits, so the score is unchanged.
The benchmark also exposed three false positives, fixed before the final run:
Sigma's `\?` wildcard escape read as a Windows path, API names rejected on
PowerShell command lines (inline P/Invoke carries them legitimately), and
`not 1 of filter_*` misparsed. The same gate caught a deterministic DNS IOC
rule promising subdomain matching for exact hostnames; its description is fixed.

The two remaining failures are the behavioural detections (#8). In the final run
the model did write a correct decoy rule (`TargetFilename|startswith:
C:\Windows\Temp\Beijing Institute of Technology_` with `|endswith: _personal
resume (2).docx`), but the gold `decoy-docx-written` predicate tests a single
value against `\windows\temp\.*\.docx` and does not combine a block's
`startswith`/`endswith` pair, so it is not credited. Its `process_creation`
rule still has Word spawning cmd.exe, the reverse of the source's chain; only
source-grounded detection guidance (#8) can catch that. That run also mapped
T1678 and T1684, which are not in the gold set and need review.

With #8 the VShell report's "detection and hunting" section yields 11 items: 2
IOC sweeps, 3 IDS/NDR byte patterns, 4 EDR analytics (the `AllocADsMem` →
`VirtualProtect` → `CreateThread` sequence, executable-memory allocation after a
TCP receive, and two certificate items; the last is the author's remark about
the Kingsoft certificate rather than an instruction), and 2 Sigma items drafted
as 3 rules: `%TEMP%\log_de.log` written (noted as creation only, since the
stager checks for the file) and the chain as two events, resume-themed
executable → `cmd.exe` and `cmd.exe` → `winword.exe`. The first satisfies
`decoy-process-chain`. The one remaining failure, `decoy-docx-written`, comes
from the report's narrative, not its guidance: the model's file rule was
rejected for matching the report's "…" elision literally, and no rule for the
decoy written under `C:\Windows\Temp\` survived. The run's one surviving model
rule, `dns_query` with `Image: cmd.exe` and `QueryResults: 38.207.178.192`, is
valid Sigma but weak: the report says no domain name appears in the malware's
configuration or traffic, and nothing shows `cmd.exe` resolving names. No
check catches that without reasoning over the source; it needs review, as does
T1678, again mapped and not in the gold set.

Item #6 does not move the score: the platform checks already passed because
recent runs' hypotheses happened to name Windows alone. It removes that
dependence. The #6 replay logged "the specimen's evidence shows Windows:
cmd.exe, c:\windows, c:\users, activeds.dll, kernel32.dll, %temp%". Its
surviving model rules were weak again: a `dns_query` rule excluding every
`.com` name, a `file_event` rule with `cmd.exe` writing the kill-switch marker
(the source says the stager only checks for it), and an `image_load` rule whose
filter repeated its selection, so it could never fire. The last is a general
logic defect and is now rejected by the #5 gate (a filter whose conditions the
selection already requires); SigmaHQ's rejection count is unchanged at 12, and
the run's score is the same without that rule.

A1 took two replays. The first scored 70/71 with the model drafting the decoy
rule from pass one's wildcard but dropping its directory and filtering out
`\Windows\Temp\`, where the decoy is written; the fixes above followed. The
second passed every detection for the first time (6/6), the decoy covered by the
deterministic written-file rule. Its one failure is the "defense-tech sector"
claim, which the claim audit leaves to review by design (#7) and which has now
recurred in two of the last eight runs; the model's prose varies run to run,
so single-run totals move by one either way. The run's one surviving model rule
had Word starting `cmd.exe`, reversing the source's guidance; such rules are now
rejected, and the score is the same without it.

The A2 replay is the first to pass every check, 71/71. Part of that is
variance: its prose did not repeat the "defense-tech sector" claim, which the
claim audit leaves to review. Across the last runs the claims dimension moved
between 12/13 and 13/13 with no code change behind it, so the dependable
result is 70 to 71 of 71; the other five dimensions have held at full marks
since A1. The reviewer itself did not contribute to the score: A2's value is
the per-rule note and a coverage list that, after filtering, only names gaps a
Sigma rule could close.

**End-to-end review fixes (2026-09-28).** Reprocessing the example after A3
scored 70/71 and exposed defects the gold set does not score, now fixed:
the Grounding section reported technique IDs as unknown malware names, listed
the dropped T1113 as a claim, and counted values a rule's filter excludes as
indicators (now 0 unsupported on both passes); an `image_load` rule
constraining only the loading process (every DLL `cmd.exe` loads) is rejected;
softening consumes a preceding adverb ("could enable", not "directly could
enable"); the claim audit removes APIs named anywhere in the suspicious or
normal lists and known-unobservable values inside an entry ("SHA-256: …"),
and flags artifacts the source does not tie to the intrusion where the prose
names them; a target sector the source never states ("in China's
defense-tech sector", "targeting Chinese defense-tech researchers") is
replaced with "(target sector unconfirmed by the source)", and an asserted
motive the source never states is marked. The confirmation replay scored
71/71 with a clean Grounding section.

**Second gold case (2026-09-28).** `evals/gold/macos-clickfix-stealer.yaml`
(Huntress, ClickFix fake CAPTCHA delivering a Go macOS stealer) was written
from the report before any run, to test generalization. The pipeline first
scored 39/55: platform, claims and rule semantics held, and the C2 and hosting
IPs that appear only in the report reached the rules, but technique recall was
2/12 and four of six detections were missing. The causes were Windows- and
VShell-specific tuning: a behaviour catalog without macOS or Unix tradecraft,
source extraction primed to label artifacts "decoy document path" with no
`script` hash role and "Library" in a path read as a DLL, the page's
"You Might Also Like" teasers read as report text, and path handling that
knew only `%TEMP%`, backslashes and Windows binaries. After the fixes the
case scores 53/55 (recall 12/12) and VShell 71/71. The two remaining macOS
misses (`xattr` quarantine removal, shell-history wiping) need rules built from
the command lines in observed-behaviour passages, which the pipeline does not
yet do; they appear only when extraction happens to capture those commands.
`core/command_rules.py` now builds those rules: each command of a known
external program quoted in an observed sentence becomes a deterministic
`process_creation` rule (the program's image and its first distinctive
argument), nine on the Huntress report and none on VShell. The case scores
54/55. The one remaining check, `history-wiped`, expects `history -d` in a
process command line; `history` and `fc` are shell builtins that start no
process, so no process event can record them. That detection was replaced by
`loader-fetched`, the `curl` fetch of the loader in the same pasted command.

## Independent review and recommendation audit

This review compared the draft and R-0616 with the [primary technical report](https://blog.himanshuanand.com/2026/08/a-fake-resume-invoked-chinas-defence-tech-elite-then-installed-vshell/)
and the current Sigma and MITRE guidance. It did not execute the detection
queries. The Hecate hunt validator accepts the Markdown structure; that result
does not verify query semantics, field availability, or whether an indicator
belongs to this sample.

### Additional findings

- **The IOC values and their relevance are different questions.** The five
  hostnames were copied from the OTX blurb, but the primary report places them
  in older passive-DNS history and says none appeared in this sample's
  configuration or PCAP. Keep them as historical context unless new evidence
  links them to the infection. Do not use them in the current campaign DNS or
  network rule by default.
- **The process hash rule mixes artifact roles.** Of the seven SHA-256 values,
  only `81c511…` is the Go loader's file hash. `c25d44…` is the ZIP, `f6d4da…`
  is an encrypted HTTP response, `052461…` is shellcode, `ed2eaa…` is the
  encoded VShell stream, `c666ac…` is the decoded in-memory VShell, and
  `de3f56…` is the DOCX decoy. The MD5 `a7cc7e…` is also the loader. Route these
  by object and telemetry type rather than treating them all as process image
  hashes.
- **The file rule is unlikely to match the sample, but “can never match” is
  too absolute.** Sigma map fields are conjunctive; this rule requires all of
  `Hashes`, `Image`, and `TargetFilename` conditions on a single event, then
  negates a Windows image filter. The source's URL basename is not the local
  DOCX filename. Correct the event semantics and backend mapping before
  characterizing it as impossible in every possible schema. ([Sigma rule
  conditions](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html))
- **The DNS rule's description exceeds its selection.** It lists exact
  `QueryName` values and no wildcard or suffix modifier, so it does not match
  subdomains as claimed. Independently, those names are not evidenced as this
  specimen's C2. ([Sigma modifiers](https://sigmahq.io/sigma-specification/specification/sigma-appendix-modifiers.html))
- **The kill-switch marker is checked, not created.** The stager exits if
  `%TEMP%\log_de.log` already exists. Prefer telemetry for file existence or
  access by the process if available; a creation-only rule is not supported by
  the report.
- **An `activeds.dll` image load alone is weak.** The source describes use of
  its `AllocADsMem`/`ReallocADsMem` exports followed by memory copy, executable
  protection, and thread creation. Alerting on the correlated in-process API
  sequence is more specific; treat the DLL load as supporting context.
- **The primary report distinguishes platform capabilities from this run.**
  VShell supports screen capture and other operator functions, but this run
  only showed registration and health traffic. Keep `T1113`, persistence,
  exfiltration, and lateral movement as capability or follow-up hypotheses
  until there is evidence of use. The directly described checks and memory
  behavior support candidate mappings to T1497.001, T1497.003, and T1620.
  ([MITRE T1497.001](https://attack.mitre.org/techniques/T1497/001/),
  [T1497.003](https://attack.mitre.org/techniques/T1497/003/),
  [T1620](https://attack.mitre.org/techniques/T1620/))
- **The campaign objective should stay confidence-graded.** The source assesses
  an academic recipient as likely, but says the operator and ultimate motive
  remain unknown. Avoid presenting “China's defense-tech sector,” national
  infrastructure impact, persistence, or theft as established facts.

### Review of existing recommendations

The existing recommendations are directionally sound, with these refinements:

1. **Primary-source extraction (#1): keep and prioritize.** Preserve exact
   source passages, sample context, evidence type, and confidence; do not pass
   extracted text to a model as though every source claim were independently
   confirmed.
2. **Research grounding (#3): keep, but don't auto-park on missing search.**
   Clearly mark source-only synthesis, report actual search counts, and block
   independent-verification claims when no search occurred. A missing search
   key alone should not silently discard otherwise actionable CTI.
3. **Technique mapping (#4): keep as evidence-gated candidates.** `T1204.002`,
   `T1059.003`, `T1497.001`, `T1497.003`, `T1105`, `T1140`, `T1620`,
   `T1071.001`, `T1095`, and `T1573` are useful candidates from the report;
   distinguish observed execution from inferred mapping and VShell capability.
   Do not call the current result “18% recall” until the expected set is
   reviewed and T1113 is excluded from observed behavior.
4. **Sigma validation (#5): strengthen beyond field lists.** Check the
   configured backend's fields, which fields belong to each event type, AND/OR
   semantics, artifact role, and whether the detection description is actually
   expressed by the selections. The current environment profile is generic, so
   backend-specific readiness remains unknown.
5. **Platform scoping (#6): keep.** Narrow this hunt to the Windows x86
   specimen; do not infer Linux coverage from ATT&CK's technique platform
   lists.
6. **Indicator roles (#2): expand and prioritize.** Add confidence and
   active/historical status alongside role, algorithm, stage, and source.
   Separate HTTP `50813` from raw TCP `50812`; keep the historical domains out
   of active rules pending corroboration.
7. **Behavioral analytics (#8): keep as candidates, not guaranteed Sigma.**
   Process/file/network correlations are promising where those events exist;
   memory/API sequence detection requires EDR support. Query paths belong in
   proxy telemetry, not generic network flow.
8. **Gold set (#10): keep and broaden.** Include negative cases: historical
   domains, non-loader hashes, mere VShell capability, unsupported platforms,
   and a query whose description claims subdomain matching but has no suffix
   logic. Score semantic correctness as well as coverage.

**Recommended immediate disposition:** retain H-0618 in `planning`; remove or
quarantine the DNS rule until the hostnames are corroborated; rebuild the file
rule; split the network detection by port and event source; and restrict the
process hash rule to the loader's hashes. Then validate against the actual SIEM
mapping and representative positive/benign events before promotion.

## Appendix: Automated Analysis on H-0618 Overwrite (Linux Fileless Execution)

*Note: The H-0618 and R-0616 files were recently overwritten by the runner with a new run based on "Linux Fileless Execution". Below is the deep dive analysis on that subsequent run, mapping to the recommendations established above.*

### 1. What Worked Well
- **Threat Intel Synthesis (R-0616):** The agent successfully ingested the Elastic.co threat intelligence and accurately synthesized the core behaviors: `memfd_create` staging, interpreter one-liners, execution of deleted binaries, and in-memory kernel module loads.
- **Gap Identification (R-0616):** The research accurately pinpointed legitimate detection gaps, such as the lack of visibility into process memory mappings and file descriptor inheritance patterns.
- **Hunt Scoping & Hypothesis (H-0618):** The transition from research to hunt planning successfully preserved the core intent. The hypothesis statement was clear, actionable, and aligned perfectly with the underlying intelligence.

### 2. What Worked Poorly
- **OCSF Field Hallucinations (R-0616):** In Section 3 (Telemetry Mapping), the agent hallucinated field names and even injected self-corrections into the final markdown (e.g., `process_activity.process.cmd_line [NOT AN OCSF FIELD; did you mean process.cmd_line?]`). This is a clear manifestation of the lack of Schema Validation.
- **Misunderstanding of System Calls vs. File Names (H-0618):** In the "What Suspicious Looks Like" section, the agent listed `process.file.name: 'memfd_create'`. It fundamentally confused a system call (`memfd_create`) with a binary name.
- **Catastrophic Sigma Rule Generation (H-0618):** The resulting Sigma query was completely disconnected from the research. It searched for `CommandLine|contains: 'zsh -c '` and filtered out `ParentImage|endswith: ruby`. It missed all the primary indicators (`/proc/self/fd/`, `/dev/shm`, `bash`, `python`, etc.).

### 3. Review of Established Recommendations against the New Run

The new run directly reinforces the necessity of the recommendations already established in this document:

- **Reinforces Recommendation #5 (Sigma semantic validation):** The catastrophic `zsh`/`ruby` rule demonstrates that without semantic validation, the pipeline will generate logically unsound rules that ignore the core hypothesis.
- **Reinforces Recommendation #9 (Fix telemetry mapping):** The OCSF field hallucinations and self-corrections in the markdown explicitly prove that the pipeline is guessing schema structures instead of validating against a hard-coded dictionary.
- **Reinforces Recommendation #7 (Observable and claim audit):** Treating `memfd_create` as a `process.file.name` is an impossible field claim that should have been caught by an observable audit.

### 4. Additional Enhancements Suggested
- **Two-Pass Query Generation:** The Sigma generation should be a two-step process: 1) Extract the exact string values and paths to query. 2) Map those values into Sigma syntax.
- **"Rule Reviewer" Sub-Agent:** Add a node after query generation that asks: *"Does this rule accurately and comprehensively hunt for the behaviors described in the hypothesis?"*
- **OS-Specific Telemetry Examples:** Provide explicit examples in the prompt of how OS-specific internals (like `memfd_create` or `/proc/self/fd/`) actually manifest in EDR logs to prevent the confusion between syscalls and binary names.
