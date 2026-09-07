# Open Threads

Running tracker for work that is known, deliberately unfinished, and easy to
lose. Covers both repositories — `Hecate-Core` (the ATHF framework and the
dogfooded hunting workspace) and `Hecate-Runner` (the autonomous orchestrator)
— because most threads cross the boundary.

**Last reviewed:** 2026-09-07 (G2, G3 closed)

Each item records *why it matters*, not just what it is, so a future reader can
judge whether it still does. Evidence is cited by file and line where it exists,
so a claim here can be checked rather than believed.

**Owner** is one of:

- **You** — needs a decision, access, or knowledge about the estate that the
  codebase cannot supply.
- **Me** — implementable from what is already here.
- **Decision** — either path is defensible; someone has to choose.

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

**Next step:** populate it, or tell me to make the derivation report `unknown`
when the profile is still a template rather than reporting its examples as fact.
The second is a real option and I can do it in an hour; the first is better.

### G2. No retrospective audit command — **Me**

The audit runs during drafting. There is no way to re-audit hunts already on
disk, which matters whenever the audit itself improves — every existing hunt was
graded by an older version, or by none.

Doing it ad hoc is error-prone: a throwaway script written during this session
silently failed to extract the CTI block and reported `asserted=0` for a hunt
that was in fact fully grounded.

**Next step:** `hecate-runner audit [HUNT_ID...]`, reusing `audit_draft`, with
CTI extraction from the Threat Context block as a tested function rather than an
inline regex.

---

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

### C2. `MISP_BACKFILL=true` should eventually be turned off — **You**

Backfill drops the freshness floor so the archive can be walked oldest-first.
Once the cursor reaches the present it converges into normal behaviour on its
own, so leaving it on is harmless *until* the cursor is lost — at which point a
fresh cursor restarts from the beginning of the archive rather than from the
30-day window.

**Next step:** turn it off once the cursor passes the present, or accept the
restart risk knowingly.

### C3. `REQUIRE_ATTACK_TECHNIQUE` is off by default — **Decision**

`HECATE_RUNNER_MISP_REQUIRE_ATTACK_TECHNIQUE` exists and defaults to `false`.
`require_galaxy` asks "is this curated"; this asks "can this produce a
behavioural hunt". They differ: an event tagged only with a threat-actor or
malware galaxy carries a cluster but no attack-pattern, yields no technique IDs,
and can only ever become an indicator sweep. Observed live on the 17:46 poll of
2026-09-07.

**Next step:** if the goal is evaluating hunt quality, turning this on routes
only events a behavioural hunt can be built from. If indicator sweeps are wanted
too, leave it off.

---

## Query generation and execution

### Q1. `QUERY_PROVIDER=mock` — the Splunk backend is unproven — **You**

`SplunkQueryProvider` shells out to `athf splunk search` and is unit-tested
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

### Q3. `queries/` is untracked — **Decision**

Generated Sigma rules are written to `$ATHF_WORKSPACE/queries/H-XXXX/`. The
directory has never been committed or gitignored, so it currently drifts.

**Next step:** track them (rules become reviewable artifacts with history) or
ignore them (they regenerate from the hunt). Tracking is probably right, since
an analyst editing a rule during review is editing that file.

---

## Environment and deployment

### E1. No log rotation — **Me**

`Hecate-Core/logs/orchestrator.log` is the only file in `logs/` and grows
unbounded (170 KB today, one file, no rotation). Slow-burning, but the
orchestrator runs hourly forever.

### E2. Slack webhook unset — **You**

`hecate-runner doctor` reports it. Without it, drafts land silently in `hunts/`
with no alert — fine while the workspace is watched by hand, less fine later.

---

## Repository hygiene

### H1. Neither repo is lint-clean at the repo level — **Decision**

Verified 2026-09-07 on `Hecate-Core`:

- **black:** 22 files under `athf/` would be reformatted.
- **isort:** 4 files under `tests/mcp/` fail.
- **flake8 C901:** 23 functions exceed the complexity limit, the worst being
  `_hunt_create.new` (27) and `register_investigate_tools` (26).

All pre-existing. Everything changed during this session's work was brought to
black/isort/flake8/mypy clean individually, and a repo-wide `black athf` was
deliberately reverted because it produced a 24-file diff unrelated to the work
in flight.

**Next step:** if the repo should be format-clean, that is its own commit, made
on purpose, not smuggled into a feature change.

### H2. Package still named `agentic-threat-hunting-framework` — **Decision**

`pyproject.toml` declares the old name while the project is called Hecate. The
CLI entry point is `athf`. Renaming touches the published package name, the
entry point, every import, and any existing install.

---

## Verification gaps

### V1. Sigma generation under a small context window — **Me**

Ollama runs with `-c 4096`. One call writes a rule for every applicable log
source; on the reference event that is six rules in one response. The first live
run produced six rules that all failed validation (every one omitted
`detection.condition`); after the prompt was sharpened it produced 6/6 valid.

It works, but it is close to the ceiling. If rule counts grow or the model
changes, splitting into one call per log source is the fix — each response then
fits comfortably and a failure costs one rule instead of all of them.

### V2. RSS items carry no structured indicators — **Me**

MISP and OTX both populate `metadata["indicators"]`; RSS does not, because feed
entries have no structured indicator field. RSS-sourced hunts therefore derive
their data sources from techniques alone.

Probably correct as-is — extracting indicators from article prose is its own
fabrication risk — but it means RSS hunts are systematically less grounded than
MISP ones, and the grounding audit will show fewer `asserted` claims for them.

---

## Recently closed

Kept briefly so a returning reader can tell what was fixed from what was
dropped.

| Thread | Resolution |
|--------|------------|
| CTI indicator values never reached the model | MISP/OTX now inline concrete values for curated events; dumps still summarised as counts |
| `data_source_availability` measured the model's prose | Now derived from `environment.md` — see **G1**, which is the remaining half |
| Hunts scoped to one data source | Derived deterministically from techniques + indicator types |
| 15 techniques → 2, sub-technique precision lost | `merge_techniques` keeps the CTI's list and collapses a bare parent into its sub-technique |
| Fabricated `CVE-2024-1234` in R-0611 | Guard added at generation; R-0611 redacted by hand with an explicit note |
| Platform list contradicted the hypothesis | Platforms narrowed by what the hypothesis claims — narrowing only, never adding |
| Research documents had no back-link | `athf research link` added and called after every draft |
| `hyp.data_sources or ["CrowdStrike"]` | Removed; empty is an honest gap |
| `athf attack lookup` returned `not_found` for revoked IDs | Now follows `revoked-by` and reports `superseded_from` |
| `require_galaxy` weaker than its name | `require_attack_technique` added — see **C3** for the default |
| Grounding was circular (research treated as proof) | Evidence ranked: CTI is `asserted`, research-only is `corroborated` |
| `misp-poll` ignored galaxy/backfill/org settings | Wired to settings. OTX and RSS pollers were checked and match their factory |
| Grounding audit never run live | First live run 2026-09-07 on H-0616: section present, 0 unsupported |
| Prose claims unaudited (G2) | Audit now checks named entities — actor designators, `<Name> backdoor`-style collocations and CamelCase families. Precision-first: generic phrasing and rule bodies are excluded |
| CVE guard only warned on summaries (G3) | Summaries are now redacted at sentence granularity, keeping surrounding analysis and leaving a visible marker |
