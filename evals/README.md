# Gold sets

A gold set is the reviewed answer for one piece of CTI. Scoring a drafted hunt
against it measures a pipeline change instead of judging it by eye, and
nothing in the scoring calls a model, so two scores are comparable.

| Case | Gold set | Built from | Baseline |
|---|---|---|---|
| VShell via fake-resume lure | `gold/vshell-fake-resume.yaml` | `docs/H-0618_DEEP_DIVE.md` | 23/71 checks (32.4%), technique recall 1/11 |
| ClickFix macOS stealer (Huntress) | `gold/macos-clickfix-stealer.yaml` | the Huntress report | 39/55 checks (70.9%), technique recall 2/12, on the pipeline as of 2026-09-28 (no pre-change baseline) |

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

Feed the gold set's exact CTI through one cycle in a scratch workspace, then
score the draft it produces. Run it once before the change and once after.

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
source CTI and the grounding table are excluded, so the CTI can neither satisfy
nor violate a claim on the draft's behalf.

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
