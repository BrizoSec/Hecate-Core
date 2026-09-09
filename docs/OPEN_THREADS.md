# Open Threads

Running tracker for work that is known, deliberately unfinished, and easy to
lose. Covers both repositories — `Hecate-Core` (the Hecate framework and the
dogfooded hunting workspace) and `Hecate-Runner` (the autonomous orchestrator)
— because most threads cross the boundary.

**Last reviewed:** 2026-09-09 (C2, C3, C4, C5, E1, E3, G4, Q3 closed; G7 opened; G5, G6, G8, G9 closed; H1, H2, H3 closed; V1 closed (per-log-source Sigma generation); V2 accepted as-is)

Each item records *why it matters*, not just what it is, so a future reader can
judge whether it still does. Evidence is cited by file and line where it exists,
so a claim here can be checked rather than believed.

**Owner** is one of:

- **You** — needs a decision, access, or knowledge about the estate that the
  codebase cannot supply.
- **Me** — implementable from what is already here.
- **Decision** — either path is defensible; someone has to choose.

**Identifiers are stable.** A closed thread's number is retired, never reused —
renumbering once already made "is G2 resolved?" ambiguous between the item that
was closed and the item that inherited its number. Gaps in the sequence are
intentional.

---

## Grounding

The pipeline enforces grounding at three points: intake filters, evidence
carried into generation, and a post-draft audit
(`Hecate-Runner/src/hecate_runner/grounding.py`). These are the gaps that
remain in that chain.

### G1. `knowledge/environment.md` is still the template — **You**

67 placeholder markers remain (`[To be configured]`, `[Specify your platform
version]`); the EDR product is unset.

This is not cosmetic. `data_source_availability` in every research document now
derives from this file rather than from the model's prose — a deliberate change,
because the field names a property of the estate. But the file currently
describes an *example* estate, so the four data sources reporting "available"
are the template's examples, and hunts are being scoped against them.

**Observed cost, 2026-09-09.** H-0001 was drafted from an OTX pulse about a
**Redis cryptomining botnet on Linux servers** — cron injection, XMRig, Monero,
an exposed toolkit at 188.245.99.156. The draft came out scoped to Windows:

```yaml
platform: ["Windows"]
data_sources: ["Windows Security Event Logs", ...]
logsource: {category: file_event, product: windows}
detection: {selection: {TargetFilename|endswith: .exe}, filter: {Image|contains: redis-cli.exe}}
```

The template is Windows-centric throughout — Windows Event Logs, `windows_logs`,
Windows field names, Domain Controllers — so the estate it describes is the
estate every hunt is scoped to, whatever the threat. Nothing else in the
pipeline can correct this: platform narrowing only removes platforms the
hypothesis contradicts, and the hypothesis had no reason to say Linux.

The hunt is mechanically perfect — valid Sigma, 0 unsupported claims, a clean
grounding table — and would find nothing, because it is hunting the wrong
operating system. That is the failure mode worth taking seriously: the quality
signals all read green.

**Next step:** populate it, or tell me to make the derivation report `unknown`
when the profile is still a template rather than reporting its examples as fact.
The second is a real option and I can do it in an hour; the first is better.
Given the above, a third option is now worth considering: refuse to scope a
hunt's platform from a profile that still contains placeholder markers, and
leave the field empty for the operator instead of asserting Windows.

---

### G7. Web-grounded research is silently ungrounded — Tavily quota exhausted — **You**

Found 2026-09-08 while confirming a clean full run. The Tavily key in
`Hecate-Core/.env` is over its plan limit:

```text
ForbiddenError: This request exceeds your plan's set usage limit.
Please upgrade your plan or contact support@tavily.com
```

The effect is invisible from the outside. `_get_search_client()` and the
search call in `hunt_researcher.py` both catch bare `Exception` and continue,
so research still runs, still emits a document, still reports success — with
`web_searches: 0`. The Skill 2 "Adversary Tradecraft (web search)" section is
written from model recall alone.

It is measurable in the corpus. Every research doc through R-0622 (14:26 UTC)
recorded `web_searches: 2`; every one from R-0623 (14:51 UTC) onward records
`0`. Nothing else changed at that boundary — it predates the H3 rename by five
hours.

Why this matters more than a missing feature: `research_enabled` exists
*because* ungrounded generation measured ~30% accuracy on known-answer
fixtures, and its own docstring says a research failure must abort the cycle
rather than fall through to an ungrounded hypothesis. Quota exhaustion never
reaches that guardrail, because research does not fail — it degrades. Drafts
since 14:51 carry the same "research-grounded" framing as the ones before.

**Next step:** two parts, and the second matters even after the key is fixed.
(1) Restore Tavily capacity — the key is a `tvly-dev-` tier. (2) Stop the
degradation being silent: have the researcher record that a search was
attempted and failed, and let the orchestrator treat "web search enabled but
0 searches performed" as a research failure, which the documented policy
already says should refund the quota and leave the CTI queued.

## CTI intake and backfill

### C1. 765 curated MISP events sit behind the cursor — **You**

Measured 2026-09-07: under the current org allowlist and galaxy filter, the
whole archive holds **781** routable events. Only **16** are ahead of the
cursor; **765** (spanning 2016-10 → 2025-12) are behind it, skipped when the
cursor was seeded to 2026-01-01.

That seed was chosen before the org allowlist existed, when the alternative was
drafting 856 Rectifyq events. With the allowlist in place, reseeding to the
start of the archive is now safe — dumps and the high-volume feed are walked
past automatically.

**Next step:** decide whether to reseed. Backups of the cursor from the last
seed are in the session scratchpad. Left alone, MISP produces ~16 more curated
hunts and then goes quiet until new events publish.

## Query generation and execution

### Q1. `QUERY_PROVIDER=mock` — the Splunk backend is unproven — **You**

`SplunkQueryProvider` shells out to `hecate-agent splunk search` and is unit-tested
against a fake binary, but has never touched a real SIEM. Ready-to-wire, not
proven.

**Next step:** needs real Splunk access. Switching is meant to be config only
(`HECATE_RUNNER_QUERY_PROVIDER=splunk` plus `SPLUNK_HOST`/`SPLUNK_TOKEN` in the
workspace `.env`); `hecate-runner doctor` checks for both.

### Q2. Sigma rules cannot be executed by the approve path — **Decision**

Deliberate. Sigma is platform-neutral, which is why it was chosen while no query
platform is committed; the propose/approve path executes a concrete query
language. So generated rules are review material, not runnable.

**Next step:** if execution is wanted, the bridge is pySigma conversion at
approve time (`sigma convert -t <backend>`), which means adding the dependency
and choosing a backend — i.e. committing to a platform.

---

## Environment and deployment

### E2. Slack webhook unset — **You**

`hecate-runner doctor` reports it. Without it, drafts land silently in `hunts/`
with no alert — fine while the workspace is watched by hand, less fine later.

---

## Recently closed

Kept briefly so a returning reader can tell what was fixed from what was
dropped.

| Thread | Resolution |
|--------|------------|
| One-off guidance essays still draft invented hunts (C5) | **Accepted as-is 2026-09-09.** No code change. The rate is 2 in 11 (down from 3 in 15 before C4), both drafts carry `requires-human-review`, and an operator identifies them from the title alone — one review slot out of six a day. The alternative, widening the title patterns to guidance shapes, was judged not worth the brittleness at this volume. A model gate is separately ruled out: two formulations were measured, "is this actionable" (27 parked of 36) and the narrower "does it name a specific actor, malware family, campaign or CVE" (18 of 24), and both parked unambiguous intelligence including *ClearFake ... delivers Amatera stealer* and *Critical N-able N-central Vulnerability and Active Exploitation*, and both split one monthly series across contradictory verdicts. That is a property of the 14B local model, not the prompt. **Revisit if:** the daily draft quota rises (the same rate costs more in absolute terms), the rate climbs above roughly 2 in 11, a stronger model becomes available for intake, or the parked queue starts being reviewed routinely — which would make a broader gate cheap, since a wrong park would then cost a glance rather than a lost hunt |
| `MISP_BACKFILL=true` left on after catching up (C2) | **Switched to normal operating mode 2026-09-09.** `HECATE_RUNNER_MISP_BACKFILL=false`; MISP now considers only the last 30 days. Verified the mechanism rather than assuming it: the effective query timestamp is `max(cursor, now-30d)`, so turning backfill off moved the window from the cursor (2026-07-21) straight to the freshness floor (2026-08-10) — no stranded cursor, no churn. Measured cost of that jump before making it: 96 events in the gap, of which exactly **1** was routable under the org allowlist and galaxy filter (ESET, *MoustachedBouncer: Espionage against foreign diplomats*). Backfill had run 2026-09-07 → 09-09, walking the cursor from its 2026-01-01 seed to 2026-07-21. The ~765 curated events still behind the cursor remain out of reach — that is **C1**, and reaching them needs a cursor reset, not just re-enabling this flag |
| Non-actionable CTI drafted into hunts (C4) | Two halves. The empty case — no narrative field, no indicator inventory and no free-form prose — is now walked past (option 2). The commentary case is **parked, not skipped**: `cti_triage.py` holds back items whose publisher category names a commentary series (`the good, the bad and the ugly`, `threat source newsletter`, `company`, `product updates`) or whose title has a recurring recap shape, writing them whole to `<cti_queue>/parked/` with the reason. `hecate-runner parked list`, `parked show` and `parked restore` inspect and replay them. Parking is what makes gating on a heuristic acceptable at all: a dropped item is invisible and permanent because the cursor has already advanced, a parked one is a file with its reason attached. Measured on 36 live entries: 10 parked, all correctly. A model gate was measured first and rejected — 8/8 on hand-picked cases, then on the same 36 it parked 27 including three unambiguous DFIR Report writeups (Lynx ransomware, Bumblebee/AdaptixC2, BengalSEO → H-0616) and gave three different verdicts to three entries of one monthly series. `HECATE_RUNNER_CTI_TRIAGE=off` restores the old behaviour. **Scope correction:** this catches *recurring-series* commentary only. One-off guidance essays still route — see **C5** |
| Ollama timed out during Sigma drafting (E3) | Resolved by the per-log-source split (V1), which is what this thread's own next step offered as the alternative to raising the deadline: it shortens each response instead. One call per log source now (`llm_calls: len(logsources)`), so the risk stopped scaling with how many log sources a hunt touches. Measured over the orchestrator log — before: 10 runs, median 87s, one timeout at the 180s ceiling (H-0617, ~1 hunt in 3 affected). After: **13 runs, zero timeouts**, median 35s, worst 143s — and that worst case covered two log sources, so ~70s per call against a per-call ceiling of 180s. Cross-category field leakage, the other reason for the split, is also gone: 15 detection fields across the current 8 rules, 0 out of category. `HECATE_OLLAMA_TIMEOUT_SEC` remains unset at its 180s default — residual risk on a bigger model or a contended GPU, mitigable any time with one line in `Hecate-Core/.env` |
| MCP surface and config contracts still named `athf` (H3) | Renamed to **hecate**: MCP server `name="hecate"` and all 21 tools `hecate_*`, resource scheme `hecate://`, env vars `ATHF_*` → `HECATE_*`, `.athfconfig.yaml` → `.hecateconfig.yaml`, `.athf/stix-data/` → `.hecate/stix-data/`, Runner's `AthfClient`/`athf_client.py` → `HecateClient`/`hecate_client.py`. Live `.env` files, both STIX caches and the systemd unit migrated in the same pass. Verified end to end on a live MISP cycle |
| Generated rules were never validated as Sigma | pySigma now parses every rendered rule in `_build_rule`; anything it rejects is dropped with the parser's own reason. This immediately found a systematic bug in our renderer: the hunt link was written into Sigma's `related:` field, whose `id` must be a UUID, so **all 17 rules in the corpus were unparseable** (`SigmaRelatedError`). The link is now a custom `hunt_id:` key, which pySigma accepts. With that fixed, 3 of 17 remained genuinely invalid and had passed every structural check: a query-DSL `$or:` key, a nonexistent `\|in` modifier, and a detection that was empty. Verified live — the model emitted an empty-detection `dns_query` rule and it was rejected, while the rules kept parse clean. `pysigma`is an optional extra (`.[sigma]`); when absent the validator warns loudly once and falls back to structural checks, because a validator that silently passes everything is worse than none |
| Sigma drafts matched on literal placeholders (G6) | Two fixes. The prompt was seeding them: its JSON example used `"known-good"`, which came back as `known-good-script.exe` across four different hunts — it now states the shape's values are placeholders and are rejected. And `_placeholder_problem()` enforces that at validation, alongside empty values and impossible IPv4 (`123.456.789`). A value the source CTI actually supplied is never rejected, so genuine intelligence naming `malicious-update.example.com` still passes. Measured: **8 of 25** drafted rules would be rejected, not the 2 first recorded here — the original count grepped only four literal tokens. A live run then produced `signed_binary_path`, a placeholder no denylist anticipated, so a generic rule rejects bare snake_case identifiers: real detection content carries a separator (`\\`, `/`, `.`, `-`, `=`), a description does not |
| Entity extraction named generic nouns, missed the real family (G9) | Root cause was a defeated anchor: `_MALWARE_COLLOCATION_RE` documented "a capitalised token" but carried a global `re.IGNORECASE`, so `[A-Z]` matched lowercase and the OTX tag "chrome rat" became a family named `chrome`. Flag now scoped to the category noun only. Stopwords extended with platform and language nouns (`Browser`, `JavaScript`, `IoT`, `Rust-based`) found by running the extractor over 50 live pulses. Added a bounded all-caps rule — only inside a sentence naming a malware category, minimum four characters — which recovers `PEEP`, `SNOWLIGHT`, `FDMTP`, `GLUTTON`, `ENDLESSDOORS`. Distinct entities across the live corpus fell 34 → 26, all eight removed being generic. Re-auditing real hunts then caught two false positives the corpus could not show, both from our own scaffolding: the template's `DRAFT` marker (reported UNSUPPORTED on every draft) and the `MISP` provider label; denying both recovered `Crysis` and `KadNap` from those same lines |
| Publisher's domain graded as an asserted indicator (G5) | Indicator claims are now scoped to each Sigma rule's `detection:` section, not the whole rule. The audit had been reading `references:` — the citation of the article the hunt came from — and grading the publisher's host (`unit42.paloaltonetworks.com`, `socradar.io`) as an indicator *asserted by CTI*. A block with no `detection:` key is still audited whole, so the fabrication check keeps its fail-safe. Note the earlier framing here was wrong: nothing ever *hunted* for those domains — they never appeared in a `detection:` block, only in citations and the grounding table |
| OTX indicator values never reached the model (G8) | `_indicator_detail_lines()` added to the OTX provider, rendering the same `Key indicators:` shape the MISP one emits so `hunt_audit` and the grounding audit parse it unchanged. Verified against the live PEEP pulse: the CVE (`CVE-2026-20316`) and 13 SHA256 hashes now appear where only `CVE (1), FileHash-SHA256 (13)` did. Capped at 10 values per type with the elision reported, and bulk pulses past 40 indicators stay counts-only. CVEs are kept here though `_indicator_map` still excludes them from Sigma drafting — naming the CVE the source cited is what lets the audit tell it from an invented one |
| CTI indicator values never reached the model | **MISP only** — `_attribute_detail_lines()` inlines concrete values for curated events; dumps still summarised as counts. The OTX half was built later, see the G8 row above |
| `data_source_availability` measured the model's prose | Now derived from `environment.md` — see **G1**, which is the remaining half |
| Hunts scoped to one data source | Derived deterministically from techniques + indicator types |
| 15 techniques → 2, sub-technique precision lost | `merge_techniques` keeps the CTI's list and collapses a bare parent into its sub-technique |
| Fabricated `CVE-2024-1234` in R-0611 | Guard added at generation; R-0611 redacted by hand with an explicit note |
| Platform list contradicted the hypothesis | Platforms narrowed by what the hypothesis claims — narrowing only, never adding |
| Research documents had no back-link | `hecate-agent research link` added and called after every draft |
| `hyp.data_sources or ["CrowdStrike"]` | Removed; empty is an honest gap |
| `hecate-agent attack lookup` returned `not_found` for revoked IDs | Now follows `revoked-by` and reports `superseded_from` |
| `require_galaxy` weaker than its name | `require_attack_technique` added — see **C3** for the default |
| Grounding was circular (research treated as proof) | Evidence ranked: CTI is `asserted`, research-only is `corroborated` |
| `misp-poll` ignored galaxy/backfill/org settings | Wired to settings. OTX and RSS pollers were checked and match their factory |
| Grounding audit never run live | First live run 2026-09-07 on H-0616: section present, 0 unsupported |
| Prose claims unaudited (G2) | Audit now checks named entities — actor designators, `<Name> backdoor`-style collocations and CamelCase families. Precision-first: generic phrasing and rule bodies are excluded |
| Indicator sweeps wanted too (C3) | Decided: `REQUIRE_ATTACK_TECHNIQUE` stays off, so sweep-shaped CTI keeps flowing alongside behavioural hunts |
| RSS items carry no structured indicators (V2) | **Decided: accept.** Feed summaries measurably contain none (0 IPs/hashes/domains across 30 live entries); the indicators are in the linked article, and fetching arbitrary third-party URLs is an unacceptable network-posture risk. Documented at `cti/rss.py` and in the Runner README so the asymmetry reads as a property of the source, not a defect. Revisit only if outbound fetching ever becomes acceptable — defanged-indicator extraction is the precise method, measured at 5–35 per article with no publisher false positives |
| Sigma generation under a small context window (V1) | Split into one LLM call per applicable log source. Each prompt names a single category and offers only that category's field names; a failure now costs one rule instead of all six. Runner `SIGMA_TIMEOUT_SEC` raised 900 → 1800 to bound the sequential calls |
| Package named `agentic-threat-hunting-framework` (H2) | Renamed to **hecate-agent**: `hecate/` → `hecate_agent/` (318 imports), console scripts `hecate-agent` / `hecate-agent-mcp`, CI and pre-commit rescoped, docs and anchors updated, Hecate-Runner repointed. Verified end to end on a live cycle (H-0624). `HECATE_*` env vars, `.hecateconfig.yaml`, `.hecate/stix-data/` and the MCP surface (`hecate_*` tool names, server `name="hecate"`) were deliberately left — see **H3** |
| mypy hook unsatisfiable (H1) | Scoped to `files: ^hecate/`, matching the command CLAUDE.md documents. Verified non-vacuous: 55 files checked, and a planted type error still fails the hook. **All 15 pre-commit hooks now pass, exit 0** |
| Bandit gating pre-commit (H1) | Hook now runs `--severity-level high`, with the reasoning recorded at the hook and in CLAUDE.md. The 29 low / 4 medium findings are visible on demand; none are High |
| Complexity debt (H1) | All 23 C901s resolved: 5 MCP `register_*` exempted in place (mccabe folds nested tool bodies), 18 genuinely refactored. Coverage was raised first where it was too low to refactor safely |
| Repo lint debt (H1) | black, isort and mypy clean across `hecate/` and `tests/`; unused imports, redefinitions, an f-string and required-E402 imports all resolved. Nine C901s remain — see H1 |
| No retrospective audit command (G4) | `hecate-runner audit` re-grades hunts on disk; `--update` refreshes their Grounding section, `--strict` exits non-zero on a fabrication, `--check-attack` validates technique IDs. CTI recovery is a tested function, not an inline regex |
| No log rotation (E1) | Copy-and-truncate rotation at startup, keeping the inode because systemd is a second writer to the same file. 5 MB / 5 archives, configurable |
| `queries/` untracked (Q3) | Now tracked, with a README recording why generated rules are review artifacts rather than build output |
| CVE guard only warned on summaries (G3) | Summaries are now redacted at sentence granularity, keeping surrounding analysis and leaving a visible marker |
