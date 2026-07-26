# Agentic Threat Hunting Framework (ATHF)

![ATHF Logo](https://raw.githubusercontent.com/Nebulock-Inc/agentic-threat-hunting-framework/main/assets/athf_logo.png)

*Give your threat hunting program memory and agency.*

The **Agentic Threat Hunting Framework (ATHF)** is the memory and automation layer for your threat hunting program. It gives your hunts structure, persistence, and context - making every past investigation accessible to both humans and AI.

ATHF works with any hunting methodology (PEAK, TaHiTI, or your own process). It's not a replacement; it's the layer that makes your existing process AI-ready.

## What is ATHF?

ATHF provides structure and persistence for threat hunting programs. It's a markdown-based framework, wrapped in a Python CLI, that:

- Documents hunts using the LOCK pattern (Learn → Observe → Check → Keep)
- Maintains a searchable repository of past investigations
- Enables AI assistants to reference your environment and previous work
- Works with any SIEM/EDR platform
- Includes AI-powered research and hypothesis generation agents
- Exposes an MCP server so AI coding assistants (Claude Code, Cursor, Copilot) can operate the framework directly

## How It Works

ATHF is deliberately **not** a database or a hosted platform — the source of truth is a directory of version-controlled Markdown files. Everything else (the CLI, the agents, the MCP server) is a layer that reads and writes those files. This is what makes the framework simple to fork, diff in a PR, and grep by hand when the tooling isn't available.

```
your-workspace/
├── hunts/            H-XXXX.md   — formal, hypothesis-driven hunts (tracked in metrics)
├── investigations/   I-XXXX.md   — exploratory/triage work (not tracked in metrics)
├── research/         R-XXXX.md   — pre-hunt research docs (5-skill methodology)
├── knowledge/        hunting-knowledge.md, domain files — expert context AI reads before hypothesizing
├── environment.md    Your data sources, tech stack, visibility gaps
└── .athfconfig.yaml  Workspace configuration (LLM provider, paths)
```

Each hunt/investigation/research file is Markdown with YAML frontmatter (ID, status, MITRE ATT&CK technique/tactic, platform, links to related work). The CLI parses and validates that structure; nothing about the data model requires the CLI to exist — you could hand-write these files and lose none of the framework's value.

**Core subsystems** (`athf/core/`):

| Subsystem                  | File                                        | Purpose                                                                                                                                                                     |
|----------------------------|---------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Hunt lifecycle             | `hunt_manager.py`                           | Create/list/search/validate hunts, compute ATT&CK coverage                                                                                                                  |
| Hunt/investigation parsing | `hunt_parser.py`, `investigation_parser.py` | YAML frontmatter + Markdown section parsing                                                                                                                                 |
| ATT&CK data                | `attack_matrix.py`                          | Provider abstraction: hardcoded v14 fallback, or live STIX data via `mitreattack-python` (835+ techniques)                                                                  |
| LLM provider               | `llm_provider.py`                           | Model-agnostic completion interface — Anthropic, OpenAI, AWS Bedrock, Ollama, or any LiteLLM-supported backend, selected by whichever API key/env var is present            |
| Research                   | `research_manager.py`                       | Drives the 5-skill pre-hunt research methodology (system research, adversary tradecraft via Tavily web search, OCSF telemetry mapping, related-hunt correlation, synthesis) |
| Eval harness               | `eval_harness.py`                           | Known-answer fixtures (mostly ATT&CK technique-ID recall) that spot-check an LLM provider/model before you swap it into production use                                      |
| Templates                  | `template_engine.py`                        | Jinja2 rendering for hunt/investigation/research file scaffolding                                                                                                           |

**Agents** (`athf/agents/llm/`) are thin, single-purpose wrappers around the LLM provider — `hypothesis-generator` (turns threat intel into a structured LOCK hypothesis) and `hunt-researcher` (runs the 5-skill research workflow). They're invoked one-shot via `athf agent run <name>`; there is no persistent agent process.

**The MCP server** (`athf/mcp/`) exposes hunt management, semantic search, ATT&CK coverage, research, investigations, and hypothesis generation as MCP tools, so an AI coding assistant can call them as native tool calls instead of shelling out to the CLI.

**Semantic search** (`athf similar`) uses `scikit-learn` (TF-IDF + cosine similarity) over hunt/investigation content to find conceptually related past work, not just keyword matches — this is what prevents duplicate hunts across a growing corpus.

## The Problem

Most threat hunting programs lose valuable context once a hunt ends. Notes live in Slack or tickets, queries are written once and forgotten, and lessons learned exist only in analysts' heads.

Even AI tools start from zero every time without access to your environment, your data, or your past hunts.

ATHF changes that by giving your hunts structure, persistence, and context.

**Read more:** [docs/why-athf.md](https://github.com/Nebulock-Inc/agentic-threat-hunting-framework/blob/main/docs/why-athf.md)

## The LOCK Pattern

Every threat hunt follows the same basic loop: **Learn → Observe → Check → Keep**.

![The LOCK Pattern](https://raw.githubusercontent.com/Nebulock-Inc/agentic-threat-hunting-framework/main/assets/athf_lock.png)

- **Learn:** Gather context from threat intel, alerts, or anomalies
- **Observe:** Form a hypothesis about adversary behavior
- **Check:** Test hypotheses with targeted queries
- **Keep:** Record findings and lessons learned

**Why LOCK?** It's small enough to use and strict enough for agents to interpret. By capturing every hunt in this format, ATHF makes it possible for AI assistants to recall prior work and suggest refined queries based on past results.

**Read more:** [docs/lock-pattern.md](https://github.com/Nebulock-Inc/agentic-threat-hunting-framework/blob/main/docs/lock-pattern.md)

## The Five Levels of Agentic Hunting

ATHF defines a simple maturity model. Each level builds on the previous one.

**Most teams will live at Levels 1–2. Everything beyond that is optional maturity.**

![The Five Levels](https://raw.githubusercontent.com/Nebulock-Inc/agentic-threat-hunting-framework/main/assets/athf_fivelevels.png)

| Level | Capability | What You Get                                           |
|-------|------------|--------------------------------------------------------|
| **0** | Ad-hoc     | Hunts exist in Slack, tickets, or analyst notes        |
| **1** | Documented | Persistent hunt records using LOCK                     |
| **2** | Searchable | AI reads and recalls your hunts                        |
| **3** | Generative | AI executes queries via MCP tools, conducts research   |
| **4** | Agentic    | Autonomous agents monitor and act, generate hypotheses |

**Level 1:** Operational within a day
**Level 2:** Operational within a week
**Level 3:** 2-4 weeks (optional)
**Level 4:** 1-3 months (optional)

**Read more:** [docs/maturity-model.md](https://github.com/Nebulock-Inc/agentic-threat-hunting-framework/blob/main/docs/maturity-model.md)

## Capabilities

Everything below is a real, testable CLI command — not aspirational. Run `athf <command> --help` for full flags.

**Hunt & investigation management**
- Create, list, search, and validate hunts (`athf hunt new/list/search/validate`) and investigations (`athf investigate new/list/search/promote`)
- Full-text search (`athf hunt search`) and semantic similarity search (`athf similar`) to avoid duplicate work
- MITRE ATT&CK coverage analysis by tactic/technique, with gap identification (`athf hunt coverage`)

**Research & hypothesis generation**
- 5-skill pre-hunt research: system internals, adversary tradecraft (live web search via Tavily), OCSF telemetry-gap mapping, related-hunt correlation, and synthesis (`athf research new`)
- AI-powered hypothesis generation from threat intel, following the ABLE framework (`athf agent run hypothesis-generator`)
- AI-powered deep research agent (`athf agent run hunt-researcher`)

**MITRE ATT&CK data**
- Hardcoded v14 fallback (zero dependencies) or live STIX data via `mitreattack-python` (`athf attack update/status/lookup/techniques`) — full technique metadata: platforms, data sources, sub-techniques, accurate per-tactic counts

**AI assistant integration**
- Context export optimized for LLM consumption — one command replaces ~5 file reads (`athf context --hunt/--tactic/--platform`)
- MCP server exposing hunt management, search, research, investigations, and hypothesis generation as native tool calls for Claude Code, Cursor, Copilot, or any MCP client (`athf mcp serve`)

**Multi-provider LLM support**
- Anthropic, OpenAI, AWS Bedrock, Ollama (local, no API key), or anything supported via LiteLLM — auto-detected from whichever credentials are present, or explicitly set via `.athfconfig.yaml` / env vars
- Known-answer eval harness to spot-check a model before relying on it in production (`athf eval`)

**Extensibility**
- Plugin system via Python entry points (`athf.mcp_tools`) for organizations that want to register custom MCP tools without forking the core CLI
- Splunk integration out of the box (`athf splunk`); any other data source is documented, queried, and referenced through your own `integrations/<datasource>/AGENTS.md`

## 🚀 Quick Start

### Option 1: Install from PyPI (Recommended)

```bash
# Install ATHF
pip install agentic-threat-hunting-framework

# Initialize your hunt program
athf init

# NEW: Conduct research before hunting (5-skill methodology)
athf research new --topic "LSASS dumping" --technique T1003.001

# Create your first hunt (link to research)
athf hunt new --technique T1003.001 --title "LSASS Credential Dumping" --research R-0001
```

### Option 2: Install from Source (Development)

```bash
# Clone and install from source
git clone https://github.com/Nebulock-Inc/agentic-threat-hunting-framework
cd agentic-threat-hunting-framework
pip install -e .

# Initialize and start hunting
athf init
athf hunt new --technique T1003.001
```

### Option 3: Pure Markdown (No Installation)

```bash
# Clone the repository
git clone https://github.com/Nebulock-Inc/agentic-threat-hunting-framework
cd agentic-threat-hunting-framework

# Copy a template and start documenting
mkdir -p hunts
cp athf/data/templates/HUNT_LOCK.md hunts/H-0001.md

# Customize AGENTS.md with your environment
# Add your SIEM, EDR, and data sources
```

**Choose your AI assistant:** Claude Code, GitHub Copilot, or Cursor - any tool that can read your repository files.

**Full guide:** [docs/getting-started.md](https://github.com/Nebulock-Inc/agentic-threat-hunting-framework/blob/main/docs/getting-started.md)

## Running Locally

For development, or if you want the full CLI (not just the pure-Markdown option), run it inside a virtual environment so `athf`'s dependencies stay isolated from your system Python:

```bash
git clone https://github.com/Nebulock-Inc/agentic-threat-hunting-framework
cd agentic-threat-hunting-framework

python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

pip install -e ".[dev]"            # dev extras: pytest, mypy, flake8, pre-commit
# or pip install -e ".[all]"       # every optional extra (attack, mcp, similarity, litellm, splunk)

# Verify
which athf                          # should point inside .venv
athf --version

athf init --non-interactive
```

**Configure an LLM provider** (needed for `athf research new`, `athf agent run`, and `athf eval`) by setting one of these env vars — ATHF auto-detects whichever is present:

```bash
export ANTHROPIC_API_KEY=sk-ant-...     # or
export OPENAI_API_KEY=sk-...            # or
export AWS_PROFILE=default              # Bedrock
# or run a local model with no key at all:
export OLLAMA_HOST=http://localhost:11434
```

Override the auto-detected provider/model explicitly via `.athfconfig.yaml` or `ATHF_LLM_PROVIDER` / `ATHF_LLM_MODEL`. See [docs/CONFIGURATION.md](docs/CONFIGURATION.md) for the full reference.

**Run the test suite** before committing changes:

```bash
pytest -q                                          # full suite
python -m mypy athf                                # type checking
python -m flake8 athf --select=E9,F63,F7,F82       # CI's syntax-error gate
```

**Full guide:** [docs/INSTALL.md](https://github.com/Nebulock-Inc/agentic-threat-hunting-framework/blob/main/docs/INSTALL.md)

## Running in a Container

A `Dockerfile` and `docker-compose.yml` are included so you don't need Python installed on the host at all. The container installs ATHF with every optional extra (`pip install -e ".[all]"`) and drops you into an interactive shell with a persistent named volume (`workspace`) mounted at `/workspace` — your hunts, investigations, and research survive container restarts and rebuilds.

```bash
# 1. Provide credentials (only needed for research/hypothesis-generation agents)
cp .env.example .env
# fill in ANTHROPIC_API_KEY or OPENAI_API_KEY in .env

# 2. Build and start
docker compose up -d

# 3. Attach a shell
docker compose exec athf bash

# Inside the container:
athf init --non-interactive
athf hunt new --technique T1003.001 --non-interactive
```

**No API key? Run a fully local model with Ollama:**

```bash
docker compose --profile ollama up -d
docker compose exec athf bash
# First run pulls the model (~2GB) via the one-shot ollama-pull service; wait for it to finish.
# Override the model: OLLAMA_MODEL=llama3.2:1b docker compose --profile ollama up -d
```

**AWS Bedrock:** uncomment the `~/.aws` volume mount in `docker-compose.yml` and set `AWS_PROFILE` in `.env`.

The container image runs as a non-root `hunter` user and only installs `git`/`curl` beyond the Python base image — there's no daemon, exposed port, or network listener by default (the MCP server, if you use it, is opt-in and talks over stdio to whatever AI assistant launches it, not over the network).

## Running Perpetually & Agentically

ATHF itself is a **CLI, not a service** — there's no built-in daemon, scheduler, or "watch mode." That's intentional: every command is a single, auditable, file-based operation, which keeps the framework simple to reason about and easy to fork. "Perpetual" and "agentic" operation (Level 3-4 in the [maturity model](#the-five-levels-of-agentic-hunting)) is achieved by wrapping those one-shot commands in your own scheduling layer. Two supported paths:

### 1. Always-on via an AI assistant (Level 3, interactive)

Run the MCP server and leave it registered with your AI coding assistant. It doesn't loop or poll anything itself — it just responds to tool calls on demand, so it's "perpetual" in the sense that it's always available, not that it's always running background work:

```bash
pip install 'athf[mcp]'
athf mcp serve --workspace /path/to/hunts
```

```json

{
  "athf": {
    "command": "athf-mcp",
    "env": { "ATHF_WORKSPACE": "/path/to/your/hunts" }
  }
}
```

### 2. Autonomous background agents (Level 4, scheduled)

For agents that act **without** a human prompting each step (CTI monitoring → hypothesis generation → draft hunt creation), drive the CLI from an external scheduler. ATHF provides the building blocks (`athf research new`, `athf agent run hypothesis-generator`, `athf hunt new`); the loop itself is standard infrastructure:

**cron** (simplest, single host):

```bash
# crontab -e
0 */6 * * * cd /path/to/workspace && /path/to/.venv/bin/athf agent run hypothesis-generator \
  --threat-intel "$(curl -s https://your-cti-feed/latest)" >> logs/agentic-run.log 2>&1
```

**systemd timer** (single host, with logging/restart semantics):

```ini
# /etc/systemd/system/athf-hunt-refresh.service
[Unit]
Description=ATHF scheduled hypothesis generation

[Service]
Type=oneshot
WorkingDirectory=/path/to/workspace
ExecStart=/path/to/.venv/bin/athf agent run hypothesis-generator --threat-intel "..."
```

```ini
# /etc/systemd/system/athf-hunt-refresh.timer
[Unit]
Description=Run ATHF hypothesis generation every 6 hours

[Timer]
OnCalendar=*-*-* 00,06,12,18:00:00
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
systemctl enable --now athf-hunt-refresh.timer
```

**GitHub Actions** (no host to manage, results land as a PR for human review):

```yaml
# .github/workflows/scheduled-research.yml
name: Scheduled ATHF research
on:
  schedule:
    - cron: "0 */6 * * *"
  workflow_dispatch: {}
jobs:
  research:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install -e ".[all]"
      - run: athf research new --topic "$(cat latest-cti-topic.txt)"
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
          TAVILY_API_KEY: ${{ secrets.TAVILY_API_KEY }}
      - uses: peter-evans/create-pull-request@v6
        with: { commit-message: "Scheduled ATHF research", branch: athf/scheduled-research }
```

In every case: agents **draft** (research docs, hypotheses, hunt files) and a human **validates** before anything is promoted to a tracked hunt — see the guardrails and multi-agent coordination patterns in [docs/level4-agentic-workflows.md](docs/level4-agentic-workflows.md) for how to wire CTI-monitor, hypothesis-generator, and validator roles together safely.

## 🔧 CLI Commands

ATHF includes a full-featured CLI for managing your hunts. Here's a quick reference:

### Initialize Workspace

```bash
athf init                           # Interactive setup
athf init --non-interactive         # Use defaults
```

### Research & Hypothesis Generation

```bash
# Conduct thorough pre-hunt research (15-20 min)
athf research new --topic "LSASS dumping" --technique T1003.001

# Quick research for urgent hunts (5 min)
athf research new --topic "Pass-the-Hash" --depth basic

# Generate AI-powered hypothesis from threat intel
athf agent run hypothesis-generator --threat-intel "APT29 targeting SaaS"

# List research and agents
athf research list
athf agent list
```

### Create Hunts

```bash
athf hunt new                       # Interactive mode
athf hunt new \
  --technique T1003.001 \
  --title "LSASS Dumping Detection" \
  --platform windows \
  --research R-0001                 # Link to research document
```

### List & Search

```bash
athf hunt list                      # Show all hunts
athf hunt list --status completed   # Filter by status
athf hunt list --directory test     # Filter by environment (test/production)
athf hunt list --output json        # JSON output
athf hunt search "kerberoasting"    # Full-text search
athf hunt search "credential" --directory production  # Search with directory filter
athf research search "credential"   # Search research docs
```

### Validate & Stats

```bash
athf hunt validate                  # Validate all hunts
athf hunt validate H-0001           # Validate specific hunt
athf hunt stats                     # Show statistics
athf hunt coverage                  # MITRE ATT&CK coverage
athf research stats                 # Research metrics
```

### ATT&CK Data Management

```bash
# Install STIX support (optional)
pip install 'athf[attack]'

# Download live ATT&CK data (835+ techniques with full metadata)
athf attack update

# Check provider status
athf attack status

# Look up technique metadata
athf attack lookup T1003.001

# List techniques for a tactic
athf attack techniques credential-access
```

Without `mitreattack-python`, ATHF uses a hardcoded v14 fallback (14 tactics, approximate counts). With it, you get full technique metadata: platforms, data sources, sub-techniques, and accurate counts.

### MCP Server

```bash
# Install MCP dependencies
pip install 'athf[mcp]'

# Start MCP server (for Claude Code, Copilot, Cursor, etc.)
athf mcp serve --workspace /path/to/hunts
```

Configure in `~/.claude/mcp-servers.json`:
```json
{
  "athf": {
    "command": "athf-mcp",
    "env": { "ATHF_WORKSPACE": "/path/to/your/hunts" }
  }
}
```

The standalone `athf-mcp` entry point auto-detects your workspace from cwd or `ATHF_WORKSPACE` env var. Use `athf mcp serve --workspace /path` for explicit paths.

Exposes 17 tools: hunt management, semantic search, ATT&CK coverage, research, investigations, and AI-powered hypothesis generation — all accessible directly from your AI coding assistant.

---
