# Example 2: Scheduled Task Persistence (T1053.005)

This example explores an adversary maintaining persistence on Windows endpoints by creating scheduled tasks that invoke payloads staged in user-writable directories.

## Included Artifacts

* `research/R-0002-scheduled-tasks.md`: Detailed research on Windows Task Scheduler architecture and abuse vectors.
* `hunts/H-0002-scheduled-tasks.md`: LOCK-pattern threat hunt document.
* `detections/sigma-scheduled-tasks.yml`: Sigma rule for anomalous task creation.
* `queries/scheduled-tasks.kql`: Microsoft Sentinel / Defender KQL search query.
