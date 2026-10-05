# Evaluation of Three Threat-Hunting Cases

## 1. Overall Quality

| Case | Score | Overall Judgement |
|---|---|---|
| vshell-fake-resume | 71/71 | Highly specific but contains logical errors in network rules (including historical ports and unsupported `winword.exe` exclusions) and slightly misrepresents the execution chain. |
| macos-clickfix-stealer | 55/55 | Reasonable coverage but suffers from brittle rule logic (e.g., hardcoded absolute paths, broken proxy `endswith`), and indicator hallucinations in the grounding table. |
| redis-cryptomining-botnet | 53/53 | Poor conceptual boundary between operator toolkit and victim infrastructure, leading to operator techniques and connections being drafted into victim detections. |

## 2. Findings the Scorer Did Not Catch (Output vs Source)

### vshell-fake-resume
* **Draft prose misrepresents the execution chain:** The draft claims "SNOWLIGHT stager that downloads and decodes a VShell RAT via a decoy DOCX". The source separates these actions: the loader opens the DOCX, while the SNOWLIGHT stager handles the RAT.
* **Draft rule hallucinates an unsupported filter:** Rule `154d0136-2ba8-4b0b-90de-047c7b49006d` arbitrarily adds `Image|endswith: \winword.exe` as an exclusion for C2 beaconing. The source never suggests Word communicates with the C2.

### macos-clickfix-stealer
* **Brittle Proxy Rule:** The rule `Request for a URL path named in the source intelligence` uses `c-uri|endswith: - /92392991a0cca55`. The source indicates the URL contains `?force=1` (line 38), so an `endswith` will fail on logs capturing query strings.
* **Weak Technique Mapping:** `T1684` is mapped based merely on the introductory campaign description, not on technical evidence of system behavior.

### redis-cryptomining-botnet
* **Rule that could never match real telemetry:** Rule `b1a5e223-7574-4362-a20d-3d30a0d113f8` checks `CommandLine|contains: /tmp/xmrig-*/xmrig`. Bash expands wildcards before execution, so process logs will record the expanded path, never the literal `*`.
* **Rule includes attacker-only connection:** Rule `58e841b5-1147-4a83-9b88-8054f17dcad7` includes `45.155.102.89:10128`. The source specifies this is a proxy "used by the operator's own host".
* **Technique mapped without evidence:** Maps `T1213.006` in claims but it is not a valid MITRE subtechnique and is missing from the Technique Evidence table.

## 3. Problems with the Gold Sets (Gold vs Source)

### vshell-fake-resume
* **Gold is too strict by omitting T1571:** Gold fails to list `T1571` (Non-Standard Port). The source explicitly details communication over ports 50812 and 50813.

### macos-clickfix-stealer
* **Missing AppleScript Technique (T1059.002):** Gold accepts the parent `T1059` but fails to explicitly list `T1059.002`. The source explicitly states `osascript` is used to trigger macOS UI elements.

### redis-cryptomining-botnet
* **Gold is silent on explicit QA target indicators:** Gold fails to list or forbid IPs explicitly marked as dev/QA targets in the source (e.g., `47.250.92.230`, `34.166.99.116`).
* **Gold is too strict on XMRig payload download:** Gold requires a `process_creation` rule for `curl xmrig`, ignoring the valid `proxy` layer detection for the payload URL drafted by the model.
* **Gold is silent on documented persistence paths:** Gold only covers `/etc/cron.d/redis-miner` but ignores fallback persistence paths (`/etc/apt/apt.conf.d/99sys-update`, `/etc/profile.d/sys-init.sh`) listed in the source.
