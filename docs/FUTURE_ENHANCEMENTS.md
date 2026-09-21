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
| **CISA KEV** | Medium | ~half day | Free, no auth, authoritative. Vulnerability-shaped rather than behaviour-shaped, so hunts become "is this CVE exploited here" |
| ~~**abuse.ch**~~ (ThreatFox / URLhaus / MalwareBazaar) | Low | ~half day | Free and high volume, but pure indicators — feeds the sweep path only |
| **NVD / GitHub advisories** | Low | ~half day | Same shape as KEV, noisier and less curated |

Note the sequencing argument: while **G1** and **G7** stand, a new source's
hunts inherit the same Windows-shaped scope and ungrounded research as the
current ones. More sources multiply volume, not quality.

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

---

## 7. Autonomous Execution & Full Agency

To transition Hecate from an automated draft generator to a **fully agentic** threat hunting platform, the system needs to close the loop between generation, execution, and iteration. 

### 7.1 Autonomous Query Execution & Tuning
Currently, the pipeline stops at drafting a query and leaves it in `planning` status for human review. A fully agentic platform should execute the query against the SIEM/EDR automatically. 
- **Validation loops:** If a query errors out (syntax), the agent should read the error and rewrite it. If it returns 10 million events, the agent should recognize it's too broad and autonomously tune out false positives. 
- **Result:** The human operator reviews a *proven* query that is guaranteed to execute and yield a manageable volume of hits.

### 7.2 Automated Pivoting & Sub-Hunting
When a hunt actually yields anomalous results, the agent shouldn't just stop. It should autonomously pivot.
- **Dynamic exploration:** If a query finds a suspicious `powershell.exe` execution, the agent should automatically spawn sub-queries to fetch the parent process (`cmd.exe`), any child network connections, and file modifications within a 5-minute window, assembling a complete attack graph for the analyst.

### 7.3 Human-in-the-Loop Feedback Integration
Right now, if an analyst fixes a broken Sigma rule or adjusts a drafted hypothesis, that knowledge stays in the SIEM or the specific Markdown file.
- **Continuous learning:** The platform should monitor git commits or review actions. When an operator edits a drafted hunt before execution, the agent should extract the diff and automatically append the correction to `knowledge/hunting-knowledge.md` or a vector database to ensure it never makes the same mistake twice.

### 7.4 Dynamic Intelligence Gathering
Current CTI sources (MISP, OTX, RSS) are largely static and rely on pre-existing feeds. 
- **Active scraping:** Deploy a specialized sub-agent that autonomously crawls threat intel blogs, social media, and dark web forums. When it identifies a new TTP, it should parse the unstructured text, summarize the observables, and push it directly into the triage queue without waiting for a vendor to publish a structured feed.

### 7.5 Self-Healing & Continuous Validation
Log schemas change, and old hunts break.
- **Automated regression:** The agent should periodically re-run historical, successful hunts against recent telemetry. If a previously working query suddenly throws a schema error (e.g., a field name changed from `process.name` to `process.executable`), the agent should autonomously rewrite the query, validate the fix, and submit the update for review.
