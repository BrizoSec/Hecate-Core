# Agentic Threat Hunting Framework (ATHF)

> Give your threat hunting program memory and agency.

Threat hunting frameworks like PEAK and TaHiTI taught us how to hunt, but not how to make our hunts remember.

The **Agentic Threat Hunting Framework (ATHF)** is a blueprint for building systems that can recall past investigations, learn from outcomes, and augment human decision-making. It is the memory and automation layer that makes your existing process AI-ready. ATHF is not a replacement for your methodology. It enhances what you already use by creating structure, memory, and context for both humans and AI.

## Why It Exists
Most threat hunting programs lose valuable context once a hunt ends. Notes live in Slack or tickets, queries are written once and forgotten, and lessons learned exist only in analysts' heads. When someone asks, "Have we hunted this before?", the answer depends entirely on who remembers.

Even when AI tools are introduced, they are often disconnected from the team's actual work. Someone might copy and paste a CTI report into ChatGPT and ask for ideas, but without access to your environment, your data, or your past hunts, the AI starts from zero every time.

ATHF changes that by giving your hunts structure, persistence, and context. It provides a way to make every past investigation accessible to both humans and AI assistants, turning disjointed documentation into a foundation for memory and learning.

## The Core: The LOCK Pattern

Every threat hunt follows the same basic loop: **Learn → Observe → Check → Keep**.

ATHF formalizes that loop with the **LOCK Pattern**, a lightweight structure that is readable by both humans and AI tools.

**Learn:** Gather context from threat intelligence, alerts, or anomalies.
*Example:* "We received CTI indicating increased use of Rundll32 for execution (T1218.011)."

**Observe:** Form a hypothesis about what the adversary might be doing.
*Example:* "Adversaries may be using Rundll32 to load unsigned DLLs to bypass security controls."

**Check:** Test the hypothesis using bounded queries or scripts.
*Example (Splunk):*
```spl
index=winlogs EventCode=4688 CommandLine="*rundll32*" NOT Signed="TRUE"
```

**Keep:** Record findings and lessons learned.
*Example:* "No evidence of execution found in the past 14 days. Query should be expanded to include encoded commands next run."

By capturing every hunt in this format, ATHF makes it possible for AI assistants to recall prior work, generate new hypotheses, and suggest refined queries based on past results.

## The Five Levels of Agentic Hunting

ATHF defines a simple maturity model for evolving your hunting program. Each level builds on the previous one.

| Level | Focus | What Changes | Example |
|-------|-------|--------------|---------|
| **0** | Manual | Hunts live in Slack or tickets | "Didn't we already look at this last year?" |
| **1** | Documented | Hunts are written in LOCK-structured markdown files | Markdown repo with `hunts/H-0001.md` |
| **2** | Searchable | AI reads and recalls context via context file | Claude Code summarizes past hunts in seconds |
| **3** | Generative | AI gets specialized hunting tools and capabilities | MCP server lets Claude search and analyze past hunts |
| **4** | Autonomous | Multi-agent workflows share structured memory | Multiple agents create, validate, and document hunts |

Most teams stop at Levels 1 or 2. That alone gives enormous benefit. At Level 1, your knowledge is documented and persists beyond individuals. At Level 2, your AI assistant can search your hunt history and act as an informed partner rather than a guessing machine.

### Level 1 Example: Documented Hunts

You document hunts using LOCK in markdown.

**Example:** `hunts/H-0031.md`

```markdown
# H-0031: Detecting Remote Management Abuse via PowerShell and WMI (TA0002 / T1028 / T1047)

**Learn**
Incident response from a recent ransomware case showed adversaries using PowerShell remoting and WMI to move laterally between Windows hosts.
These techniques often bypass EDR detections that look only for credential theft or file-based artifacts.
Telemetry sources available: Sysmon (Event IDs 1, 3, 10), Windows Security Logs (Event ID 4624), and EDR process trees.

**Observe**
Adversaries may execute PowerShell commands remotely or invoke WMI for lateral movement using existing admin credentials.
Suspicious behavior includes PowerShell or wmiprvse.exe processes initiated by non-admin accounts or targeting multiple remote systems in a short time window.

**Check**
index=sysmon OR index=edr
(EventCode=1 OR EventCode=10)
| search (Image="*powershell.exe" OR Image="*wmiprvse.exe")
| stats count dc(DestinationHostname) as unique_targets by User, Computer, CommandLine
| where unique_targets > 3
| sort - unique_targets

**Keep**
Detected two accounts showing lateral movement patterns:
- `svc_backup` executed PowerShell sessions on five hosts in under ten minutes
- `itadmin-temp` invoked wmiprvse.exe from a workstation instead of a jump server

Confirmed `svc_backup` activity as legitimate backup automation.
Marked `itadmin-temp` as suspicious; account disabled pending review.

Next iteration: expand to include remote registry and PSExec telemetry for broader coverage.
```

When someone new joins the team, they can quickly see what was tested, what was learned, and what should be tried next. This alone prevents redundant hunts and lost context.

### Level 2 Example: Searchable Memory

Now you add an `AGENTS.md` file to your repository. It provides context for the AI:

```markdown
# AGENTS.md

## Purpose
This repository contains threat hunting hypotheses and execution notes following the LOCK pattern (Learn → Observe → Check → Keep).
AI assistants use this context to recall past investigations, summarize lessons learned, and generate new hypotheses and queries aligned with our environment and data sources.

## Scope
The repository includes:
- `hunts/` – LOCK-structured hunt markdown files
- `queries/` – validated search queries associated with each hunt
- `templates/` – reference files for new hunts
- `memory/` – archives or indexes for search and recall

AI tools should read these files to:
- Identify existing hunts for a given MITRE ATT&CK technique or behavior
- Summarize what was learned or validated
- Recommend related hypotheses or query refinements
- Avoid duplication by referencing past outcomes

## Data Sources
| Source | Description | Platform | Notes |
|---------|-------------|-----------|-------|
| winlogs | Windows Event Logs | Splunk index=winlogs | Sysmon + Security Events |
| edr | Endpoint Detection and Response | CrowdStrike Falcon | Process and network telemetry |
| proxy | Zscaler | Network activity | Domain, URL, and user metadata |
| auth | Okta, AzureAD | Identity logs | Login success, MFA, and device context |
| dns | Internal resolvers | CoreDNS or Infoblox | Useful for C2 and tunneling patterns |

## Workflow Expectations
1. All hunts must follow the LOCK pattern and live in `hunts/` with a unique ID (H-XXXX).
2. Each hunt should include:
   - A hypothesis describing adversary behavior
   - Relevant data sources and ATT&CK mappings
   - One or more queries in `queries/`
   - A **Keep** section documenting validation results and next steps
3. When possible, include contextual tags such as `#windows`, `#credential-access`, `#persistence`.

## AI Usage Guidelines
AI assistants may:
- Summarize findings from past hunts
- Generate new hypotheses based on ATT&CK techniques or CTI context
- Propose bounded queries using existing data sources
- Draft hunt documentation in LOCK format

AI assistants must not:
- Execute queries or modify production systems
- Generate queries for data sources not listed above
- Overwrite existing hunt files without human review

## Guardrails
- AI-generated output is treated as a draft until reviewed by a human analyst.
- Every new or updated hunt must be validated for query safety, accuracy, and scope.
- Use the **environment.md** file to understand available telemetry and platform constraints before suggesting new hunts.
- Maintain version control discipline: each update should be committed with a message referencing the hunt ID.

## Example Interactions
**You can ask:**
- "What have we learned about PowerShell lateral movement?"
- "Generate a new hypothesis for credential dumping using LSASS, referencing past hunts."
- "Summarize outcomes of hunts related to T1059 (Command Execution)."
- "Suggest improvements to the query used in H-0021."

**The AI should respond with:**
- A reference to prior hunts (H-XXXX)
- A LOCK-structured hypothesis or summary
- Safe, bounded query suggestions based on listed data sources

## Version
ATHF v1.0
Maintainer: [Your Name or Team]
Last Updated: [Insert Date]
```

Once that file exists, you can open your repo in Claude Code, GitHub Copilot, or Cursor and ask:

> "What have we learned about T1028?"

The AI searches your hunts directory, summarizes the results, and suggests a new hypothesis or query. What used to take 20 minutes of grepping and copy-pasting now takes under five.

### Level 3 Example: Generative Capabilities

At this stage, you give your AI assistant **custom tools** that extend its capabilities beyond just reading files. Instead of manually drafting hunt hypotheses, your AI can generate LOCK-formatted hunts using a specialized tool that incorporates memory from past hunts.

The most effective way to do this is by creating an **MCP (Model Context Protocol) server** that exposes hunting-specific tools to Claude Code, Cursor, or other AI assistants.

**Example: Hunt Hypothesis Generator**

Below is an MCP server that gives Claude the ability to generate hunt hypotheses:

```python
"""
hunt_mcp_server.py
Level 3 example – MCP tool for generating LOCK-formatted hunt hypotheses.
"""

from mcp.server import Server
from mcp.server.stdio import stdio_server
from pathlib import Path
import json

app = Server("athf-hunt-server")
HUNTS_DIR = Path("hunts")

@app.list_tools()
async def list_tools():
    return [
        {
            "name": "generate_hunt_hypothesis",
            "description": "Generate a LOCK-formatted hunt hypothesis from CTI or threat context",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "threat_context": {
                        "type": "string",
                        "description": "CTI report, alert details, or threat description"
                    },
                    "technique_id": {
                        "type": "string",
                        "description": "MITRE ATT&CK technique ID (e.g., T1059.001)"
                    }
                },
                "required": ["threat_context", "technique_id"]
            }
        }
    ]

@app.call_tool()
async def call_tool(name: str, arguments: dict):
    if name == "generate_hunt_hypothesis":
        return await generate_hypothesis(
            arguments["threat_context"],
            arguments["technique_id"]
        )

async def generate_hypothesis(threat_context: str, technique_id: str):
    """
    Generate a LOCK-formatted hunt hypothesis using past hunt context.
    """
    # Search past hunts for this technique
    past_hunts = search_past_hunts(technique_id)

    # Read AGENTS.md for data sources
    data_sources = load_data_sources()

    # Build context for the AI
    context = {
        "threat": threat_context,
        "technique": technique_id,
        "past_hunts": past_hunts,
        "available_data_sources": data_sources,
        "lessons_learned": extract_lessons(past_hunts)
    }

    # Return structured context for Claude to generate the hypothesis
    return {
        "context": context,
        "instruction": "Generate a LOCK-formatted hunt hypothesis that avoids duplication"
    }

def search_past_hunts(technique_id: str):
    """Search for past hunts related to this technique."""
    related = []
    for hunt_file in HUNTS_DIR.glob("H-*.md"):
        content = hunt_file.read_text()
        if technique_id in content:
            related.append({
                "file": hunt_file.name,
                "summary": extract_keep_section(content)
            })
    return related

if __name__ == "__main__":
    stdio_server(app)
```

**Using It with Claude Code**

Once installed, you paste a CTI report into Claude and say:

> "Generate a hunt hypothesis for this new Qakbot campaign (T1059.003)"

Claude will:
1. **Use the `generate_hunt_hypothesis` tool** with the CTI context
2. **Receive structured data** about past hunts, data sources, and lessons learned
3. **Generate a complete LOCK-formatted hypothesis** avoiding duplication and incorporating what worked before

**Example Output:**

```markdown
# H-0157: PowerShell-Based Qakbot Loader Detection (T1059.003)

**Learn**
New Qakbot campaign observed using Windows Script Host to execute obfuscated
PowerShell commands for initial access. Based on H-0142, we know Qakbot often
uses base64 encoding and registry persistence.

**Observe**
Adversaries will likely execute PowerShell with -EncodedCommand parameter from
wscript.exe or cscript.exe parent processes. Looking for PowerShell execution
chains originating from non-standard parents.

**Check**
index=winlogs EventCode=4688
| search ParentImage="*wscript.exe" OR ParentImage="*cscript.exe"
| search Image="*powershell.exe"
| where CommandLine LIKE "%EncodedCommand%" OR CommandLine LIKE "%-enc%"
| stats count by User, Computer, CommandLine

**Keep**
[To be completed after hunt execution]
- Reference lessons from H-0142: check for registry persistence in Run keys
- Expand to include WMI execution if initial query yields high volume
```

**The difference:**
- **Level 2:** Claude reads past hunts and suggests ideas
- **Level 3:** Claude generates complete, context-aware hunt hypotheses using a specialized tool

At Level 3, success looks like this:
- Claude **generates** LOCK-formatted hunts instead of just discussing them
- New hunts **reference** lessons learned from past hunts automatically
- Hypotheses are **validated** against your actual data sources
- You spend time **refining and executing** hunts, not writing them from scratch

### Level 4 Example: Autonomous Workflows

At this stage, you move from **reactive assistance** to **proactive automation**. Instead of asking your AI for help with each task, you deploy autonomous agents that monitor, reason, and act based on objectives you define.

The key difference from Level 3: **agents operate autonomously** rather than waiting for your prompts. They detect events, make decisions within guardrails, and coordinate with each other through shared memory (your LOCK-structured hunts).

**Example: Multi-Agent Hunt Pipeline**

Below is a conceptual workflow showing how multiple autonomous agents coordinate:

```yaml
# config/agent_workflow.yaml
# Defines autonomous agents and their coordination

agents:
  - name: cti_monitor
    role: Watch CTI feeds and identify relevant threats
    triggers:
      - schedule: "every 6 hours"
      - webhook: "/api/cti/new"
    actions:
      - search_hunts(technique_id)  # Check if we've hunted this before
      - trigger_agent("hypothesis_generator") if new_technique

  - name: hypothesis_generator
    role: Create LOCK-formatted hunt hypotheses
    triggers:
      - agent_event: "cti_monitor.new_technique"
    actions:
      - search_hunts(technique_id)  # Get historical context
      - generate_lock_hypothesis()
      - validate_query()
      - create_draft_hunt_file()
      - trigger_agent("validator")

  - name: validator
    role: Review and validate draft hunts
    triggers:
      - agent_event: "hypothesis_generator.draft_ready"
    actions:
      - validate_query(query, platform)
      - check_data_source_compatibility()
      - flag_for_human_review() if issues_found
      - trigger_agent("notifier")

  - name: notifier
    role: Alert analysts when hunts need review
    triggers:
      - agent_event: "validator.review_needed"
    actions:
      - post_to_slack(channel="#threat-hunting", hunt_id)
      - create_github_issue(labels=["hunt-review"])

guardrails:
  - all_hunts_require_human_approval: true
  - no_automatic_query_execution: true
  - log_all_agent_actions: true
  - daily_summary_report: true
```

**How It Works:**

1. **CTI Monitor Agent** runs every 6 hours, checking threat feeds
2. Detects new Qakbot campaign using T1059.003
3. Searches past hunts - finds we haven't covered this sub-technique
4. **Triggers Hypothesis Generator Agent**
5. Generator searches historical hunts for context
6. Creates draft hunt `H-0156.md` with LOCK structure
7. **Triggers Validator Agent**
8. Validator checks query against data sources from `AGENTS.md`
9. Flags for human review
10. **Triggers Notifier Agent**
11. Posts to Slack: "New hunt H-0156 ready for review"

**You wake up to:**
> "3 new draft hunts created overnight based on recent CTI. Ready for your review."

**The difference:**
- **Level 2:** You ask AI questions, it responds
- **Level 3:** You direct AI to use tools
- **Level 4:** Agents work autonomously toward objectives, notify you when human judgment is needed

At Level 4, success looks like this:
- Agents **monitor** CTI feeds without your intervention
- Agents **generate** draft hunts based on new threats
- Agents **coordinate** through shared memory (LOCK hunts)
- You focus on **validating** and **approving** rather than creating from scratch

**Implementation Options:**

Level 4 can be built using various agent frameworks:
- **LangGraph** - For building stateful, multi-agent workflows
- **CrewAI** - For role-based agent collaboration
- **AutoGen** - For conversational agent patterns
- **Custom orchestration** - Purpose-built for your environment

The key is that **all agents share the same memory layer** - your LOCK-structured hunts - ensuring consistency and enabling true coordination.

## How to Get Started

1. **Clone the repository**
   ```bash
   git clone https://github.com/sydney-nebulock/agentic-threat-hunting-framework
   ```

2. Review the `templates/` and `hunts/` directories

3. Start documenting new hunts using the LOCK pattern

4. Add an `AGENTS.md` file once you have a few hunts recorded

5. Choose an AI assistant that can read your files and start using memory-aware prompts

You can be operational at **Level 1 within a day** and **Level 2 within a week**. No coding or infrastructure changes are required until Level 3.

## Why This Matters

Agentic threat hunting is not about replacing analysts. It is about building systems that can:

- Remember what has been done before
- Learn from past successes and mistakes
- Support human judgment with contextual recall

When your framework has memory, you stop losing knowledge to turnover or forgotten notes. When your AI assistant can reference that memory, it becomes a force multiplier instead of a curiosity.

## Feedback and Contributions

ATHF is open source and under active development. Feedback, forks, and pull requests are welcome.

You can find the repository here:
**[https://github.com/Nebulock-Inc/agentic-threat-hunting-framework](https://github.com/Nebulock-Inc/agentic-threat-hunting-framework)**

Try it in your own environment, adapt it to your workflow, and share what you learn. The goal is to help every threat hunting team move from ad-hoc memory to structured, agentic capability.

If you build on ATHF, I would love to hear about your implementation and how your team integrates memory into the hunt loop.

**Happy thrunting!**

---

## Closing

ATHF is a framework for the future of threat hunting. It learns, remembers, and scales with you.

**Start small. Document one hunt. Add structure. Build memory.**

Once your program can remember, everything else becomes possible.
