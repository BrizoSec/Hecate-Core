# Example 1: LSASS Memory Credential Dumping (T1003.001)

This example demonstrates a complete hunting lifecycle investigating adversary attempts to dump credentials from the Local Security Authority Subsystem Service (LSASS) memory.

## Included Artifacts

* `research/R-0001-lsass-dumping.md`: Thorough 5-skill pre-hunt research document.
* `hunts/H-0001-lsass-dumping.md`: Full hunt documentation following the LOCK pattern (Learn, Observe, Check, Keep).
* `detections/sigma-lsass-dumping.yml`: Promoted Sigma detection rule with calibrated false-positive exclusions.
* `queries/lsass-dumping.spl`: Bounded Splunk search query.

## Quick Test

```bash
# Validate the hunt
hecate-agent hunt validate examples/01-lsass-memory-credential-dumping/hunts/H-0001-lsass-dumping.md
```
