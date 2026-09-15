# Future Enhancements

Forward-looking capability work: things worth building that nothing is
currently blocked on.

This is deliberately **not** `OPEN_THREADS.md`. That file tracks known
defects and decisions that are already costing something — an unpopulated
estate profile, an exhausted API key. This one holds work that would make
the system better than it was designed to be. An item here is a proposal; an
item there is a debt.

Where a claim below is measured, the measurement is quoted, because the
useful part of a roadmap is knowing which entries rest on evidence and which
rest on judgement.

---

## 1. Knowledge the model is not being given

Ranked by effect, and all of it upstream of hunt quality. Two of these are
cheap and neither is exotic — the pipeline already looks for the files.

### 1.1 `knowledge/OCSF_SCHEMA_REFERENCE.md` — **done**

The file exists (4,417 bytes, inside the loader's 5,000-char budget so nothing
is cut) and loads both from inside the workspace and via `HECATE_WORKSPACE`.
Generated from the official schema at <https://schema.ocsf.io>: eight event
classes with their UIDs, ten objects with their hunting-relevant fields, and a
table of the inventions actually observed in generated research
(`process_name`, `process.command_line`, `event_id`).

Deliberately a **field dictionary, not worked examples** — it is injected
beside "now produce your answer", and hunt-shaped prose there becomes the next
thing the model copies. Tests assert no `powershell`, `download cradle`,
`clickhouse` or `domain-joined` appears in it, and an opt-in drift test
(`pytest -m network`) re-checks the documented fields against the live schema
so it cannot go stale unnoticed.

**The reference alone did not fix field naming**, which is the part worth
remembering. With it loaded, research still produced
`process.execution.command_line`, `file.file_name` and
`network.tcp.connection.remote_address`; a later run produced a different set
again — `process_activity.cmd_line`, `file_activity.path` — prefixing object
paths with *class* names. The model reproduces the shape of an OCSF path
without consulting the dictionary in front of it.

So validation was added alongside it (`core/ocsf_fields.py`): the canonical
set is parsed from the reference itself, so the document the model reads and
the rule its output is checked against cannot drift apart. Invented fields are
**flagged in place**, not dropped:

```text
process_activity.cmd_line [NOT AN OCSF FIELD; did you mean process.cmd_line?]: ...
```

Flagged rather than dropped for the same reason the grounding audit reports a
fabricated claim instead of deleting it: silently removing all six would leave
a telemetry section that merely looked empty. Verified live — 6 of 6
inventions caught on a real research run.

**Remaining, if you want it:** the suggestions are hints and two of six were
wrong (`process_activity.name` → `file.name`, where `process.name` was meant).
Ambiguity deliberately returns no suggestion rather than a confident wrong
one, since a wrong correction would be copied. Sharpening that is optional
polish, not a defect.

### 1.2 `knowledge/environment.md` — **done**

The file is 8,161 bytes. `_load_environment()` truncates at 2,000, so **about
a quarter of it reaches the model.** Whatever matters most — platforms,
which OS families actually exist, the real SIEM and EDR — has to be in the
first quarter or it is not in the prompt at all.

Populating it is **G1**; the truncation is what makes *where* you populate it
matter, and is worth raising if the profile grows.

### 1.3 `knowledge/hunting-knowledge.md` — wired, gated off, needs tuning

Not a documentation question: the file is meant to educate the model, and the
document states its own routing in *Using This Knowledge Base* — Sections 1, 2
and 5 before generating a hypothesis, Section 3 for pivots, Section 4 for
rigour. Nothing was reading it.

It is now wired (`core/hunting_knowledge.py`, per-section selection with a
budget, truncated on a heading boundary and declared when partial) but
**disabled by default** behind `HECATE_HUNTING_KNOWLEDGE`, because switching
it on made output worse. Given Linux Redis cryptomining CTI, the hypothesis
came back as:

```text
Hypothesis: Adversaries use PowerShell to download and execute malicious scripts
Behavior:   PowerShell download cradle
Techniques: T1059.004   <- Unix Shell, under a PowerShell hypothesis
```

No mention of Redis, cron, XMRig or Monero. The 12 KB slice sent contained
`powershell` 8 times and `download cradle` twice.

The cause is **proximity, not size**. The agent is asked to emit a hypothesis
in a fixed schema and handed a block of well-formed example hypotheses —
`Good: "PowerShell downloads from temp directories indicate malware staging"`
— so it copies the nearest one. This is the same failure as the Sigma
placeholders and the prompt's own `ClickHouse` and `Windows domain-joined
endpoints` examples, relocated into the knowledge file.

Trimming the budget lowers the odds without changing the shape of the
mistake, and the examples cannot simply be stripped — Section 2 *is* a
TTP-to-observable catalogue, and Section 1 teaches through Good/Bad pairs.
Measured example density per section:

| Section | Density |
|---------|---------|
| 4 — Analytical Rigor | 3.9/KB |
| 1 — Hypothesis Generation | 3.0/KB |
| 2 — Behavioral Models | 1.8/KB |
| 5 — Framework Mental Models | 1.6/KB |
| 3 — Pivot Logic | 0.9/KB |

**Next step:** revisit once **G1** and **G7** are fixed, because until
research is grounded and the estate profile is real, no change in output can
be attributed to this flag. Then measure the same CTI with it on and off. The
least-bad first attempt is Section 5 alone, at a small budget, injected at the
*researcher* rather than the hypothesis step — frameworks shape reasoning
there, and the researcher emits prose rather than a schema waiting to be
filled with the nearest example.

### 1.4 `.hecateconfig.yaml` — still the shipped defaults

```yaml
siem: Other
query_language: Custom
edr: Other
```

These seed default data sources for new hunts. Naming the real stack costs
one edit and makes every subsequent hunt's data sources concrete.

### 1.5 Things genuinely worth writing that do not exist yet

- **Crown jewels / asset criticality.** The pipeline has no notion of what
  matters most, so every hunt is scoped as though all telemetry is equal.
- **Known-good baselines.** What normally runs, what normally beacons, which
  admin tools are sanctioned. This is what turns a generic rule into one with
  a usable false-positive rate, and Sigma `falsepositives:` entries are being
  guessed today.
- **Prior hunt outcomes.** Which hypotheses have already been tested and
  found nothing. Nothing currently stops the system re-proposing them.
- **Log source coverage and retention.** Which categories genuinely exist and
  how far back. `applicable_logsources()` currently derives from techniques
  and indicator types alone, so it can target telemetry nobody collects.

---

## 2. CTI source onboarding

Provider surface is small — `next_item()` and `acknowledge()`, plus a branch
in `cti/get_provider()` and a cursor file. Cost is mostly the blurb builder.

| Option | Value | Effort | Notes |
|--------|-------|--------|-------|
| **TAXII 2.1 client** | Highest | ~1 day | One provider unlocks ISACs, CISA AIS, commercial feeds, other MISP instances. STIX in, so techniques and indicators arrive structured rather than scraped |
| **More vendor RSS** | High | **done** | Config only — add URLs to `HECATE_RUNNER_RSS_FEED_URLS`. RSS already produces the narrative-rich hunts; Google TAG, Mandiant, Sekoia, Volexity, ESET are not yet subscribed |
| **CISA KEV** | Medium | ~half day | Free, no auth, authoritative. Vulnerability-shaped rather than behaviour-shaped, so hunts become "is this CVE exploited here" |
| **abuse.ch** (ThreatFox / URLhaus / MalwareBazaar) | Low | ~half day | Free and high volume, but pure indicators — feeds the sweep path only |
| **NVD / GitHub advisories** | Low | ~half day | Same shape as KEV, noisier and less curated |

Note the sequencing argument: while **G1** and **G7** stand, a new source's
hunts inherit the same Windows-shaped scope and ungrounded research as the
current ones. More sources multiply volume, not quality.

---

## 3. Source configuration UX

Enabling and disabling sources already works — `HECATE_RUNNER_CTI_MULTI_PROVIDERS`
is a comma-separated list, `doctor` validates it, and an unknown name raises
`ValueError: Unknown CTI provider`. What is missing is discoverability: you
have to know the variable exists.

Proposed: `hecate-runner sources list | enable <name> | disable <name>`,
showing each source's configured state, whether its credentials are present,
and where its cursor sits. Small, and it makes the existing mechanism
visible.

---

## 4. Grounding precision

### 4.1 A path is not a domain — **done**

H-0003's `MacSync.app` was graded **UNSUPPORTED — domain in no source**. It
is a macOS bundle, and the detection reads
`TargetFilename|endswith: /MacSync.app`. `.app` is a real TLD, and
`_FILE_SUFFIXES` deliberately excludes real TLDs so that `.com` C2 domains
cannot be exempted from the fabrication check.

Fix without weakening that rule: **a value containing `/` or `\` is a path.**
General, and removes the class rather than the instance.

### 4.2 Unresolvable technique IDs reach the frontmatter — **done**

H-0006 carries `T1438`, which does not exist in Enterprise ATT&CK (a
deprecated Mobile ID). `hecate-agent attack lookup T1438` returns
`{"error": "not_found"}`, and `hunt validate` marks the hunt invalid.

The orchestrator already records `TechniqueFact(valid=meta.found)` for the
grounding audit but does not drop the ID. Keeping it may be deliberate —
dropping would hide the model's error — but the current outcome is a hunt the
project's own validator rejects. Decide which.

### 4.3 `hunt validate` exits 0 on invalid hunts — **done**

The CI job "Validate Hunt Examples" only failed because an unparseable file
raised an uncaught `ValueError`. A hunt that is merely *invalid* passes the
job. Either the exit code should reflect validity, or the job's name
overstates what it checks.

---

## 5. Review workflow

Intake triage parks commentary rather than discarding it (**C4**), which is
what makes gating on a heuristic acceptable. That guarantee only holds if
someone reads the parked queue — otherwise it is a slower delete.

Worth adding when the volume justifies it: parked items surfaced in
`hecate-runner status`, an age-out policy, and a note in the Slack draft
notification (**E2**) when something was held back.

---

## 6. Intake classification, revisited

Two model-based intake gates were measured and rejected (**C5**):
"is this actionable" parked 27 of 36 live entries; the narrower "does this
name a specific actor, malware family, campaign or CVE" parked 18 of 24 —
both discarding unambiguous intelligence, and both giving contradictory
verdicts across three entries of one monthly series.

That is a property of the 14B local model, not of the prompts. Worth
revisiting on a stronger model, and worth remembering that the parked-queue
design already removes most of the risk of trying.

A cheaper use of the same idea: have the model **label** a draft's likely
value for the reviewer rather than gate on it. A wrong label costs nothing.
