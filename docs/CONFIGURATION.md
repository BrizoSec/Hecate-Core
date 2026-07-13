# ATHF Configuration Reference

This document is the single source of truth for configuring ATHF: environment variables, the `.athfconfig.yaml` workspace config, LLM provider setup, API keys, and the hunt template.

---

## Table of Contents

1. [How the Pipeline Works](#how-the-pipeline-works)
2. [Quick Setup](#quick-setup)
3. [API Keys Reference](#api-keys-reference)
4. [LLM Provider Configuration](#llm-provider-configuration)
5. [`.athfconfig.yaml` Format](#athfconfigyaml-format)
6. [All Environment Variables](#all-environment-variables)
7. [Hunt Template (`HUNT_TEMPLATE.j2`)](#hunt-template-hunt_templatej2)
8. [MCP Server Configuration](#mcp-server-configuration)
9. [STIX / ATT&CK Data](#stix--attck-data)
10. [Docker Configuration](#docker-configuration)

---

## How the Pipeline Works

```
User / AI assistant
        │
        ▼
┌───────────────────────────────────────────────────────────────────┐
│  1. RESEARCH   athf research new --topic "..." --technique T1003  │
│     • Skill 1: System internals (web search via Tavily)           │
│     • Skill 2: Adversary tradecraft (web search + ATT&CK STIX)    │
│     • Skill 3: Telemetry mapping (OCSF schema + environment.md)   │
│     • Skill 4: Related past hunts (semantic similarity search)    │
│     • Skill 5: Synthesis (LLM aggregation)                        │
│     → Creates R-XXXX.md in research/                              │
└────────────────────────────┬──────────────────────────────────────┘
                             │
                             ▼
┌───────────────────────────────────────────────────────────────────┐
│  2. HYPOTHESIS   athf agent run hypothesis-generator              │
│     • Loads research context from R-XXXX.md                       │
│     • Injects real ATT&CK technique names (STIX grounding)        │
│     • Calls LLM to generate structured JSON hypothesis            │
│     • Validates output T-codes against ATT&CK (strips hallucinations) │
│     → Prints hypothesis; optionally appends to R-XXXX.md          │
└────────────────────────────┬──────────────────────────────────────┘
                             │
                             ▼
┌───────────────────────────────────────────────────────────────────┐
│  3. HUNT CREATION   athf hunt new --research R-XXXX               │
│     • Renders HUNT_TEMPLATE.j2 with hypothesis fields             │
│     • Creates H-XXXX.md in hunts/production/YYYY/QN/             │
│     • Validates YAML frontmatter                                  │
│     → Hunt file ready for query development                       │
└────────────────────────────┬──────────────────────────────────────┘
                             │
                             ▼
┌───────────────────────────────────────────────────────────────────┐
│  4. QUERY EXECUTION   (human or data source integration)          │
│     • Analyst writes and runs queries (Splunk, KQL, SQL, etc.)    │
│     • athf splunk search (Splunk REST integration)                │
│     • Results recorded in hunt file (CHECK section)               │
└────────────────────────────┬──────────────────────────────────────┘
                             │
                             ▼
┌───────────────────────────────────────────────────────────────────┐
│  5. DOCUMENTATION   (human edits hunt file)                       │
│     • KEEP section: findings, TP/FP counts, lessons learned       │
│     • athf hunt validate H-XXXX (CI/CD check)                    │
│     • athf investigate promote I-XXXX (if started as investigation)│
└───────────────────────────────────────────────────────────────────┘
```

Each LLM call is grounded with real data where possible:
- **Technique names/descriptions** come from local ATT&CK STIX data (`athf attack update`)
- **Adversary tradecraft** comes from Tavily web search results
- **Telemetry fields** come from `knowledge/OCSF_SCHEMA_REFERENCE.md` and `environment.md`
- **Past hunt context** comes from local semantic search against `hunts/`

---

## Quick Setup

### Minimum viable (no AI, no web search)

```bash
pip install agentic-threat-hunting-framework
athf init
athf hunt new --technique T1003.001 --title "LSASS Dumping" --non-interactive
```

No API keys required. Hunt creation and management work fully offline.

### With AI hypothesis generation (pick one LLM provider)

```bash
# Option A: Anthropic (Claude)
export ANTHROPIC_API_KEY=sk-ant-...
pip install 'agentic-threat-hunting-framework[litellm]'

# Option B: OpenAI
export OPENAI_API_KEY=sk-...

# Option C: Local Ollama (no API key needed)
# Install Ollama: https://ollama.com, then:
ollama pull qwen2.5:14b
# ATHF auto-detects Ollama at localhost:11434
```

### With research agent (requires web search)

```bash
export TAVILY_API_KEY=tvly-...
athf research new --topic "LSASS dumping" --technique T1003.001
```

Get a free Tavily key at <https://tavily.com> (1,000 free searches/month).

### With live ATT&CK data (better grounding)

```bash
pip install 'agentic-threat-hunting-framework[attack]'
athf attack update   # Downloads ~50 MB STIX bundle once
```

---

## API Keys Reference

| Key | Required? | What It Enables | Where to Get It |
|-----|-----------|-----------------|-----------------|
| `ANTHROPIC_API_KEY` | Optional | Claude hypothesis/research generation | <https://console.anthropic.com> |
| `OPENAI_API_KEY` | Optional | GPT-4 hypothesis/research generation | <https://platform.openai.com> |
| `TAVILY_API_KEY` | Optional | Web search in research agent (Skills 1 & 2) | <https://tavily.com> |
| `SPLUNK_TOKEN` | Optional | `athf splunk search` — execute SPL queries | Splunk Settings → Tokens |
| `AWS_PROFILE` / `AWS_ACCESS_KEY_ID` | Optional | AWS Bedrock LLM provider | AWS IAM |

**None of these are required to use core ATHF features** (hunt creation, validation, search, statistics). They unlock progressively richer AI capabilities.

### What happens without each key

| Missing Key | Effect |
|-------------|--------|
| No LLM key and no Ollama | `athf agent run` and `athf research new` fall back to template-based output (no AI analysis) |
| No `TAVILY_API_KEY` | Research Skill 1 and Skill 2 proceed with model recall only; findings are flagged `[UNCERTAIN]` |
| No `SPLUNK_TOKEN` | `athf splunk` commands fail with a credentials error |
| No ATT&CK STIX | Technique grounding uses FallbackProvider; output T-code validation is skipped |

---

## LLM Provider Configuration

### Auto-detection order

When no provider is explicitly configured, ATHF checks in this order:

```
1. ANTHROPIC_API_KEY set?  → LiteLLM + anthropic/claude-sonnet-4-5-20250514
2. OPENAI_API_KEY set?     → OpenAI-compatible + gpt-4o
3. AWS_PROFILE or
   AWS_ACCESS_KEY_ID set?  → Bedrock + claude-sonnet-4-5-20250929-v1:0
4. Ollama reachable at
   OLLAMA_HOST (or
   localhost:11434)?        → Ollama + llama3
5. None of the above       → RuntimeError (no provider found)
```

### Config file override (`.athfconfig.yaml`)

Takes priority over auto-detection. Supports all four providers:

```yaml
# Anthropic via LiteLLM
llm:
  provider: litellm
  model: anthropic/claude-opus-4-5

# OpenAI-compatible (including Azure, Together, etc.)
llm:
  provider: openai
  model: gpt-4o-mini
  base_url: https://api.openai.com/v1   # optional override

# AWS Bedrock
llm:
  provider: bedrock
  model: us.anthropic.claude-sonnet-4-5-20250929-v1:0
  region: us-west-2

# Local Ollama
llm:
  provider: ollama
  model: qwen2.5:14b
  base_url: http://localhost:11434
  timeout_sec: 300   # seconds per request (default: 180)
```

### Environment variable overrides

Environment variables take priority over `.athfconfig.yaml`:

```bash
ATHF_LLM_PROVIDER=ollama      # Force a specific provider
ATHF_LLM_MODEL=llama3.2:3b   # Override the model
ATHF_LLM_BASE_URL=http://...  # Override the base URL (useful in Docker)
ATHF_OLLAMA_TIMEOUT_SEC=300   # Ollama request timeout
```

### Full priority order (highest → lowest)

```
explicit config dict (programmatic API)
  └── ATHF_LLM_PROVIDER / ATHF_LLM_MODEL / ATHF_LLM_BASE_URL (env vars)
        └── .athfconfig.yaml llm section (config file)
              └── auto-detection (ANTHROPIC_API_KEY → OPENAI_API_KEY → AWS → Ollama)
```

### Provider-specific notes

**LiteLLM** (`provider: litellm`)
- Requires: `pip install 'athf[litellm]'`
- Supports 100+ models via a single interface (Anthropic, OpenAI, Gemini, Cohere, etc.)
- Model names follow LiteLLM format: `anthropic/claude-opus-4-5`, `openai/gpt-4o`, `gemini/gemini-2.0-flash`
- Set the corresponding provider API key (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, etc.)

**Bedrock** (`provider: bedrock`)
- Requires: `pip install 'athf[bedrock]'`
- Uses your existing AWS credentials (`~/.aws/credentials` or IAM role)
- Set `AWS_PROFILE` or `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY`
- Region defaults to `us-east-1`; override with `AWS_REGION` or config `region:`

**Ollama** (`provider: ollama`)
- Requires: `pip install 'athf[ollama]'` + local Ollama installation
- No API key needed — runs locally
- Install Ollama: <https://ollama.com>
- Pull a model before use: `ollama pull qwen2.5:14b`
- Recommended models by hardware:
  - Apple Silicon (M1/M2/M3): `qwen2.5:14b`, `phi4:14b`, `llama3.1:8b`
  - NVIDIA GPU: `qwen2.5:32b`, `llama3.1:70b`
  - CPU only: `qwen2.5:3b`, `llama3.2:1b`

**OpenAI-compatible** (`provider: openai`)
- Works with OpenAI and any API that follows the OpenAI schema (Together.ai, Groq, LM Studio, vLLM, etc.)
- Set `base_url` in config to point at a non-OpenAI endpoint

---

## `.athfconfig.yaml` Format

ATHF searches for this file in two locations (in order):
1. `<workspace>/.athfconfig.yaml`
2. `<workspace>/config/.athfconfig.yaml`

**Full example:**

```yaml
# LLM provider configuration
llm:
  provider: ollama          # litellm | bedrock | ollama | openai
  model: qwen2.5:14b
  base_url: http://localhost:11434
  timeout_sec: 300          # Ollama only

# Workspace settings (set automatically by athf init)
workspace:
  hunt_prefix: H            # Prefix for hunt IDs (default: H)
  research_prefix: R        # Prefix for research IDs (default: R)
  investigation_prefix: I   # Prefix for investigation IDs (default: I)
```

This file is gitignored by default — it is machine-local config (your LLM key, local Ollama URL, etc.). Commit `environment.md` for team-shared context instead.

---

## All Environment Variables

### LLM / AI

| Variable | Default | Description |
|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | — | Anthropic API key; triggers auto-detection |
| `OPENAI_API_KEY` | — | OpenAI API key; triggers auto-detection |
| `ATHF_LLM_PROVIDER` | auto | Force provider: `litellm`, `bedrock`, `ollama`, `openai` |
| `ATHF_LLM_MODEL` | provider default | Override model name |
| `ATHF_LLM_BASE_URL` | provider default | Override API base URL (useful in Docker) |
| `ATHF_OLLAMA_TIMEOUT_SEC` | `180` | Per-request timeout for Ollama calls |
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama service URL |

### AWS Bedrock

| Variable | Default | Description |
|----------|---------|-------------|
| `AWS_PROFILE` | — | AWS credentials profile name |
| `AWS_ACCESS_KEY_ID` | — | AWS access key (alternative to profile) |
| `AWS_SECRET_ACCESS_KEY` | — | AWS secret key |
| `AWS_REGION` / `AWS_DEFAULT_REGION` | `us-east-1` | AWS region for Bedrock |

### Web Search (Research Agent)

| Variable | Default | Description |
|----------|---------|-------------|
| `TAVILY_API_KEY` | — | Tavily search API key. Without this, Skills 1 & 2 run without web context and flag uncertain findings with `[UNCERTAIN]` |

### Splunk Integration

| Variable | Default | Description |
|----------|---------|-------------|
| `SPLUNK_HOST` | — | Splunk hostname or IP |
| `SPLUNK_TOKEN` | — | Splunk authentication token |
| `SPLUNK_VERIFY_SSL` | `true` | Whether to verify Splunk SSL certificate |

### ATHF Workspace & Data

| Variable | Default | Description |
|----------|---------|-------------|
| `ATHF_WORKSPACE` | cwd walk-up | Explicit workspace root path (MCP server) |
| `ATHF_STIX_CACHE` | `~/.athf/stix-data/` | Directory for ATT&CK STIX JSON cache |

---

## Hunt Template (`HUNT_TEMPLATE.j2`)

Located at `templates/HUNT_TEMPLATE.j2`. Rendered by `athf hunt new` using Jinja2. You can edit this file to change the structure of every new hunt file created in your workspace.

### Available template variables

| Variable | Type | Source | Description |
|----------|------|--------|-------------|
| `hunt_id` | `str` | auto | Sequential ID, e.g. `H-0042` |
| `title` | `str` | `--title` | Hunt title |
| `status` | `str` | `--status` | Default: `in-progress` |
| `date` | `str` | auto | Today's date (`YYYY-MM-DD`) |
| `hunter` | `str` | `--hunter` | Analyst name. Default: `AI Assistant` |
| `platform` | `list[str]` | `--platform` | e.g. `["Windows", "macOS"]` |
| `tactics` | `list[str]` | `--tactic` | e.g. `["credential-access"]` |
| `techniques` | `list[str]` | `--technique` | e.g. `["T1003.001"]` |
| `data_sources` | `list[str]` | `--data-source` | e.g. `["EDR process telemetry"]` |
| `tags` | `list[str]` | `--tags` | Arbitrary tags |
| `hypothesis` | `str \| None` | `--hypothesis` | Full hypothesis statement |
| `threat_context` | `str \| None` | `--threat-context` | Threat intel motivating the hunt |
| `actor` | `str \| None` | `--actor` | Threat actor (ABLE framework) |
| `behavior` | `str \| None` | `--behavior` | Behavior description (ABLE) |
| `location` | `str \| None` | `--location` | Scope / environment (ABLE) |
| `evidence` | `str \| None` | `--evidence` | Data fields to examine (ABLE) |
| `spawned_from` | `str \| None` | `--research` | Research doc ID, e.g. `R-0001` |
| `hypothesis_duration_minutes` | `float \| None` | `--hypothesis-duration` | Time spent on hypothesis |

### Customizing the template

Edit `templates/HUNT_TEMPLATE.j2` directly. The template uses standard Jinja2 syntax:

```jinja
{# Conditional section #}
{% if actor %}
**Threat Actor:** {{ actor }}
{% endif %}

{# Default value #}
**Status:** {{ status | default('in-progress') }}

{# Join a list #}
**Techniques:** {{ ', '.join(techniques) if techniques else 'TBD' }}
```

Changes take effect immediately on the next `athf hunt new`. Existing hunt files are not affected.

### LOCK section structure

The template follows the LOCK pattern. Each section serves a specific purpose:

| Section | Purpose | Fill in when |
|---------|---------|--------------|
| **LEARN** | Hypothesis, threat context, ABLE scoping, related research | Hunt creation |
| **OBSERVE** | Normal vs. suspicious behavior, expected observables | Before query execution |
| **CHECK** | Query text, results, performance notes | During hunt execution |
| **KEEP** | Findings, TP/FP counts, lessons learned, follow-up actions | Hunt completion |

---

## MCP Server Configuration

The MCP server exposes ATHF as tools for AI assistants (Claude Code, Cursor, Copilot, etc.).

### Starting the server

```bash
# Default (stdio transport — for Claude Code / local AI tools)
athf mcp serve

# HTTP transport (for remote / networked AI tools)
athf mcp serve --transport streamable-http --port 8080

# Explicit workspace
athf mcp serve --workspace /path/to/your/workspace
```

### Workspace discovery (server)

The server finds your workspace in this order:
1. `--workspace` CLI flag
2. `ATHF_WORKSPACE` environment variable
3. Walk up from `cwd` looking for `.athfconfig.yaml`

### Claude Code integration

Add to your `.claude/settings.json` or `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "athf": {
      "command": "athf-mcp",
      "env": {
        "ATHF_WORKSPACE": "/path/to/your/workspace"
      }
    }
  }
}
```

Or use `athf-mcp` as a standalone entry point (installed alongside `athf`).

### MCP tools that create files

These tools write to your workspace without a confirmation prompt:

| Tool | Creates | Notes |
|------|---------|-------|
| `athf_hunt_new` | `hunts/production/YYYY/QN/H-XXXX.md` | Atomic exclusive create |
| `athf_research_new` | `research/R-XXXX.md` | |
| `athf_investigate_new` | `investigations/I-XXXX.md` | |
| `athf_agent_run_researcher` | `research/R-XXXX.md` | Full 5-skill research |
| `athf_agent_run_hypothesis` (with `research_id`) | Appends to existing `R-XXXX.md` | |

---

## STIX / ATT&CK Data

Live ATT&CK data improves grounding across all LLM calls:
- Technique names and descriptions are injected into prompts (not recalled from model memory)
- Output technique IDs are validated against the real matrix (hallucinated IDs are stripped)

### Setup

```bash
pip install 'agentic-threat-hunting-framework[attack]'
athf attack update        # Downloads enterprise-attack.json (~50 MB, one-time)
athf attack status        # Verify: shows provider type, technique count, version
athf attack lookup T1003.001   # Spot-check a technique
```

### Cache location

```
Default:  ~/.athf/stix-data/enterprise-attack.json
Workspace: <workspace>/.athf/stix-data/  (if .athfconfig.yaml exists in workspace)
Override:  ATHF_STIX_CACHE=/custom/path
```

### Without STIX

ATHF falls back to `FallbackProvider` which has no technique data. This means:
- Technique grounding in prompts is skipped (model uses recall)
- Output T-code validation is skipped (hallucinated IDs pass through)
- `athf attack lookup` returns nothing

---

## Docker Configuration

### Environment variables for containers

```yaml
# docker-compose.yml excerpt
environment:
  - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY:-}
  - OPENAI_API_KEY=${OPENAI_API_KEY:-}
  - TAVILY_API_KEY=${TAVILY_API_KEY:-}
  - ATHF_LLM_PROVIDER=${ATHF_LLM_PROVIDER:-}
  - ATHF_LLM_MODEL=${ATHF_LLM_MODEL:-}
  # Override config file's base_url so the container reaches host Ollama:
  - ATHF_LLM_BASE_URL=${ATHF_LLM_BASE_URL:-http://host.docker.internal:11434}
  - OLLAMA_HOST=${OLLAMA_HOST:-http://host.docker.internal:11434}
```

### Running with native macOS Ollama (recommended)

```bash
# 1. Start Ollama on your Mac (uses Metal GPU automatically)
ollama serve
ollama pull qwen2.5:14b

# 2. Start ATHF container (points at host Ollama)
docker compose up -d athf
docker compose exec athf bash

# Inside container — Ollama is reachable at host.docker.internal:11434
athf agent run hypothesis-generator --threat-intel "..."
```

### Running with containerized Ollama

```bash
# Pulls qwen2.5:14b on first run (~9 GB)
docker compose --profile ollama up -d

# Override model
OLLAMA_MODEL=llama3.1:8b docker compose --profile ollama up -d
```

### `.env` file

Copy `.env.example` to `.env` and fill in your keys:

```bash
cp .env.example .env
# Edit .env with your API keys
docker compose up -d
```

The `.env` file is gitignored. Never commit API keys to version control.
