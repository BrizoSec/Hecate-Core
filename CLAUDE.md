# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is **ATHF (Agentic Threat Hunting Framework)** — a Python CLI + MCP server that gives threat hunting programs structured documentation, AI-powered research, and hunt lifecycle management. It is published as the `agentic-threat-hunting-framework` PyPI package, with the `athf` entry point.

## Development Setup

```bash
# Install in editable mode with all dev dependencies
pip install -e ".[dev]"

# Install with all optional features
pip install -e ".[all]"

# Set up pre-commit hooks
pre-commit install
```

Copy `.env.example` to `.env` and configure API keys before running agents or research commands.

## Common Commands

```bash
# IMPORTANT: activate the venv first — two tests invoke `athf` via subprocess
# and will fail if the system Python's athf binary is found first on PATH
source /Users/chemch/Projects/Hecate/.venv/bin/activate

# Run all tests with coverage
pytest tests/ -v --cov=athf --cov-report=term-missing

# Run a single test file
pytest tests/test_hunt_manager.py -v

# Lint (syntax errors only — fast)
flake8 athf --count --select=E9,F63,F7,F82 --show-source --statistics

# Full lint pass
flake8 athf --count --exit-zero --max-complexity=10 --max-line-length=127 --statistics

# Type check
mypy athf --ignore-missing-imports

# Format code
black athf --line-length=127
isort athf --profile black --line-length 127

# Security scan
bandit -c pyproject.toml -r athf

# Run all pre-commit hooks
pre-commit run --all-files

# Validate hunt files in a workspace
athf hunt validate

# Start the MCP server
athf mcp serve
athf-mcp  # standalone entry point
```

## Architecture

### Package Structure

```
athf/
├── cli.py                  # Click CLI root; registers all command groups + plugin system
├── plugin_system.py        # Entry-point-based plugin discovery (athf.commands / athf.mcp_tools groups)
├── commands/               # Click command groups (one file per top-level command)
│   ├── hunt.py             # Hunt management (delegates to _hunt_create, _hunt_lifecycle, _hunt_query)
│   ├── investigate.py      # Investigation commands (delegates to _investigate_*)
│   ├── research.py         # Research lifecycle
│   ├── agent.py            # Agent execution (hypothesis-generator, hunt-researcher)
│   ├── context.py          # AI-optimized context export (reduces token usage)
│   ├── similar.py          # Semantic similarity search via TF-IDF (requires scikit-learn)
│   ├── attack.py           # MITRE ATT&CK STIX data management
│   ├── mcp.py              # MCP server control
│   └── splunk.py           # Optional Splunk integration (loaded conditionally)
├── core/                   # Business logic layer
│   ├── hunt_manager.py     # Hunt file discovery, lifecycle, stats, ATT&CK coverage; class-level cache keyed on fs fingerprint
│   ├── hunt_parser.py      # YAML frontmatter + LOCK section markdown parser
│   ├── investigation_parser.py
│   ├── research_manager.py # Research document lifecycle (R-XXXX.md)
│   ├── llm_provider.py     # Model-agnostic LLM abstraction (LiteLLM / OpenAI / Anthropic / Bedrock / Ollama); lazy imports
│   ├── attack_matrix.py    # MITRE ATT&CK coverage; STIX provider with JSON fallback
│   ├── cost_tracker.py     # Token cost estimation with fuzzy model-name matching
│   ├── envelope.py         # Structured data envelope / schema
│   ├── eval_harness.py     # Model quality evaluation
│   ├── template_engine.py  # Jinja2 template rendering for hunt/investigation files
│   ├── splunk_client.py    # Splunk REST API client
│   └── web_search.py       # Tavily search integration
├── agents/                 # LLM-powered agent implementations
│   ├── base.py             # BaseAgent abstract class
│   └── llm/
│       ├── hypothesis_generator.py  # Generates hunt hypotheses from threat intel
│       ├── hunt_researcher.py       # 5-skill pre-hunt research methodology
│       └── pivot_suggester.py
├── mcp/                    # MCP server (FastMCP)
│   ├── server.py           # Server factory, workspace discovery, plugin tool loading
│   └── tools/              # MCP tool implementations (mirrors CLI commands)
│       ├── hunt_tools.py
│       ├── investigate_tools.py
│       ├── research_tools.py
│       ├── agent_tools.py
│       ├── attack_tools.py
│       └── search_tools.py
└── data/                   # Bundled package data (templates, docs, example hunts, prompts)
    ├── templates/HUNT_LOCK.md       # Canonical hunt template
    ├── knowledge/hunting-knowledge.md
    └── prompts/ai-workflow.md
```

### Key Design Patterns

**Hunt file format:** Markdown files with YAML frontmatter (`---`) followed by the LOCK-pattern body (Learn / Observe / Check / Keep sections). Files are named `H-XXXX.md` and stored under `hunts/{YYYY}/{QX}/`. Investigations use `I-XXXX.md` under `investigations/`, research uses `R-XXXX.md` under `research/`.

**CLI-first invariant:** The CLI (and MCP tools) are the only sanctioned way to create/validate hunt files. Direct file writes bypass ID sequencing and YAML frontmatter generation — never create hunt/investigation/research files manually.

**LLM provider auto-detection:** `athf.core.llm_provider.create_provider()` inspects environment variables in priority order (LiteLLM → OpenAI → Anthropic → Bedrock → Ollama). All optional LLM dependencies use lazy imports so the base package installs without any AI SDK.

**HuntManager caching:** `HuntManager` uses a class-level cache keyed on a filesystem fingerprint (file count + max mtime). Fresh instances are created per CLI invocation and per MCP tool call, making the class-level cache the right scope for deduplication without stale-data risk.

**Plugin system:** Plugins register via `entry_points` groups `athf.commands` (CLI commands) and `athf.mcp_tools` (MCP tool registrations). The CLI and MCP server discover them at startup.

**MCP server:** `mcp/server.py` uses `FastMCP` (requires `mcp[cli]<2.0.0` — the 2.0.0 release removed `mcp.server.fastmcp`). Start with `athf mcp serve` or the `athf-mcp` entry point.

### Optional Dependencies

| Extra | Provides |
|-------|----------|
| `[similarity]` | `scikit-learn` — required for `athf similar` |
| `[splunk]` | `requests` — Splunk REST integration |
| `[litellm]` / `[llm]` | LiteLLM multi-provider support |
| `[anthropic]` | Direct Anthropic SDK |
| `[openai]` | Direct OpenAI SDK |
| `[bedrock]` | `boto3` for AWS Bedrock |
| `[attack]` | `mitreattack-python` for live STIX data |
| `[mcp]` | `mcp[cli]<2.0.0` for MCP server |
| `[all]` | Everything above |

### Code Style

- Line length: 127 characters (black + flake8 + isort all configured to 127)
- Python 3.8+ compatibility required (no walrus operator, no `match`, use `Optional[X]` not `X | None`)
- mypy strict mode enabled; all functions need type annotations
- Bandit security linting skips `B101` (assert statements)
