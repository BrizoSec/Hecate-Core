# Example 3: Obfuscated Encoded PowerShell Execution (T1059.001)

This example explores hunting for obfuscated or base64-encoded PowerShell executions used by adversaries to bypass command-line inspection and evade basic signature matching.

## Included Artifacts

* `research/R-0003-encoded-powershell.md`: Deep research into PowerShell execution arguments, script block logging, and evasion tactics.
* `hunts/H-0003-encoded-powershell.md`: Complete LOCK-pattern threat hunt document.
* `detections/sigma-encoded-powershell.yml`: Exported Sigma rule detecting encoded or hidden-window PowerShell commands.
* `queries/encoded-powershell.spl`: Splunk hunt query with parent process filtering.
