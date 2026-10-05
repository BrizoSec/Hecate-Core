# Gold sets

A gold set is the reviewed answer for one piece of CTI. Scoring a drafted hunt
against it measures a pipeline change instead of judging it by eye, and
nothing in the scoring calls a model, so two scores are comparable.

| Case | Gold set | Built from | Baseline |
|---|---|---|---|
| VShell via fake-resume lure | `gold/vshell-fake-resume.yaml` | `docs/H-0618_DEEP_DIVE.md` | 23/71 checks (32.4%), technique recall 1/11 |
| ClickFix macOS stealer (Huntress) | `gold/macos-clickfix-stealer.yaml` | the Huntress report | 39/55 checks (70.9%), technique recall 2/12, on the pipeline as of 2026-09-28 before the macOS/Unix fixes (no pre-change baseline); 53/55 after them; 54/55 with rules from quoted commands. The `history-wiped` detection expected a shell builtin in a process command line, which no process event records; it was replaced on 2026-09-29 by `loader-fetched` (the `curl` fetch of the loader) |
| Redis cryptomining botnet (hunt.io) | `gold/redis-cryptomining-botnet.yaml` | the hunt.io report, written before any run | 40/53 checks (75.5%), technique recall 2/9, on the pipeline as of 2026-09-29; 53/53 on 2026-10-03, after server-side tradecraft joined the technique catalog, ports and cron paths were read from the report's tables, token and fingerprint "hashes" were typed as non-files, the page's second copy of the article was dropped, and sentences about the operator's own machine stopped counting as victim evidence. One of those 53 comes from a scorer change made the same day: see "What is scored" |

The baseline is the H-0618 draft reviewed in the deep dive, frozen in
`tests/fixtures/gold/vshell-fake-resume/` and locked by
`tests/core/test_gold_eval.py`.

## Scoring a draft

```bash
hecate-agent eval-gold evals/gold/vshell-fake-resume.yaml hunts/2026/Q3/H-0618.md
hecate-agent eval-gold GOLD DRAFT --output json > after.json   # for diffing runs
hecate-agent eval-gold GOLD DRAFT --fail-under 0.6             # exit 1 below 60%
```

Rules are read from `<workspace>/queries/<hunt_id>/`, or from the YAML blocks
embedded in the draft when that directory is absent. `--queries DIR` overrides
both.

## Scoring a pipeline change

Replay the gold set's exact CTI through one real cycle in a scratch workspace,
then score the draft it produces. Run it once before the change and once after.

`replay.py` does both. Run it with the Runner's interpreter:

```bash
cd ../Hecate-Runner
.venv/bin/python ../Hecate-Core/evals/replay.py redis-cryptomining-botnet
.venv/bin/python ../Hecate-Core/evals/replay.py vshell-fake-resume --workspace /tmp/gold-vshell --json score.json
```

It builds a blank scratch workspace, runs one cycle on the case, prints the
score with every failed check, and keeps the workspace so the draft, the rules
and `logs/orchestrator.log` can be read. The item comes from the case's saved
OTX pulse in `pulses/`, so it carries the feed's indicator list as a live
cycle would; its text is the gold set's `source.cti`. A cycle fetches the
report and calls the workspace's model: 10 to 20 minutes on the local one.

The same by hand, through the file queue. This passes the text only, without
the feed's indicator list, so its scores are not comparable with `replay.py`'s:

```bash
# 1. A scratch copy of the workspace, reset to a blank state
cp -a Hecate-Core /tmp/gold-ws
HECATE_WORKSPACE=/tmp/gold-ws hecate-runner reset --yes --no-archive

# 2. The gold CTI into the file queue
python -c "import yaml,sys; print(yaml.safe_load(open(sys.argv[1]))['source']['cti'])" \
  evals/gold/vshell-fake-resume.yaml > /tmp/gold-ws/cti_queue/next.txt

# 3. One cycle, reading only the file queue
HECATE_WORKSPACE=/tmp/gold-ws HECATE_RUNNER_CTI_PROVIDER=file hecate-runner run

# 4. Score the draft it wrote
hecate-agent eval-gold evals/gold/vshell-fake-resume.yaml /tmp/gold-ws/hunts/*/*/H-*.md
```

A single run carries model variance: repeat step 3 a few times before reading
a small difference as a real change.

## Saved outputs

`outputs/<case>/` holds one replay's output per case, for review without
running the pipeline: `draft.md` (the drafted hunt), `rules/` (its Sigma
rules), `research.md`, `trail.log` (what each pipeline step decided),
`score.json` (the `eval-gold` report) and `source.txt` (the primary report's
text as the pipeline fetched it). They are from 2026-10-03, on the code
committed as Hecate-Core `907b30c` and Hecate-Runner `3c3fad2`, and each
scores full marks. The Redis and VShell runs predate one fix in that commit:
rules whose titles shortened to the same file name overwrote each other, so
the Redis `rules/` lacks the rules for `/etc/cron.d/.redis-miner`,
`/etc/cron.d/redis-miner` and `/var/spool/cron/root`. To rescore one:

```bash
hecate-agent eval-gold evals/gold/<case>.yaml evals/outputs/<case>/draft.md --queries evals/outputs/<case>/rules
```

## What is scored

Every positive and every negative item is one check; the score is checks passed
over checks run.

| Dimension | Positive checks | Negative checks |
|---|---|---|
| techniques | each reviewed observed technique is mapped | each ruled-out technique is absent |
| platform | each expected platform is listed | each unsupported platform is absent |
| claims | required facts appear in the draft's own prose | forbidden assertions do not |
| indicators | artifacts appear where their role requires | artifacts do not appear where their role forbids |
| detections | each expected detection exists, with every field in one selection block | — |
| rule semantics | — | no field outside its log source category, no non-executable process image, no description promising matching the selection lacks |

Claims are checked against the draft's own writing only: rule YAML, the quoted
source CTI, the grounding table and the Primary Source Evidence table are
excluded, so the source can neither satisfy nor violate a claim on the draft's
behalf. The evidence table was excluded on 2026-10-03: it quotes the report
verbatim, and on the Redis case its row for a file from a separate, historical
directory ("deploy_meterpreter.sh Downloads and installs meterpreter.elf") was
scored as the draft claiming Meterpreter was installed. The Technique Evidence
table, which can quote the research document, is still scored.

## Technique recall and its denominator

Technique recall is reported separately, always as hits over a stated
denominator. The denominator is the gold set's `techniques.observed` list:
behaviours the primary source shows in that sample, each with its supporting
passage. It is not the draft's own list, and it excludes tool capability that
was not observed (for VShell, screen capture, persistence and lateral
movement, which the gold set lists as `forbidden`).

A draft ID matches an expected ID when they are equal or the draft ID is a
sub-technique of it. A parent ID matches an expected sub-technique only when
the entry sets `accept_parent: true`. IDs under `acceptable` earn no credit and
no penalty. IDs in none of the lists are reported as unreviewed, for a human to
add to the gold set.

## Writing a gold set

Start from a reviewed draft and its primary source. Keep every entry traceable:
give each observed technique its `evidence` passage, each forbidden item its
`reason`, and each indicator its `role` and `status`. Paste the exact CTI the
pipeline receives under `source.cti`, so reruns start from the same input.
Negative cases matter as much as positive ones: historical indicators,
artifacts that never exist as a process, capability without observed use, and
unsupported platforms are where drafts go wrong.
