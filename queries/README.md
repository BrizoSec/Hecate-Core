# Generated detection rules

One directory per hunt (`H-XXXX/`), holding the Sigma rules `hecate-runner`
drafts for that hunt — one rule per applicable log source, written before the
hunt reaches an operator.

**These are tracked in git on purpose.** They are review artifacts, not build
output. Three reasons the alternative (regenerate on demand) is wrong here:

- An analyst who corrects a field name or a false-positive during review is
  editing *this file*. Regenerating would discard that work, and the same
  prompt does not produce the same rule twice.
- A rule's history is the audit trail for what was proposed against the
  environment and when — the same reason the hunt files themselves are tracked.
- Generation costs an LLM call per hunt. Rules that vanish get regenerated.

## What is in them

Sigma, deliberately: the hunt program has no committed query platform, and
`sigma convert -t <backend>` retargets a rule to Splunk, Elastic, CrowdStrike
or Defender later. Drafting here commits to nothing.

Each rule carries `status: experimental`, an author line naming the generator,
and a `related:` entry pointing back at its hunt. The model returns structured
JSON and the YAML is rendered by the generator, so a malformed rule cannot be
produced; rules whose `condition` names an undefined selection are rejected
rather than written.

## What they are not

Not reviewed, and not runnable from here. The hunt's own CHECK section embeds
each rule with an `Unreviewed` banner — field names and false positives are the
model's proposal and must be checked against real telemetry first. The
propose/approve path in `hecate-runner` executes a concrete query language, not
Sigma, so nothing in this directory reaches a data source on its own.

Deleting a hunt's directory is safe; it is regenerated the next time that hunt
is drafted, minus any human edits.
