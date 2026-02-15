# Design: Agentic Capabilities for ATHF

**Date:** 2026-02-15
**Status:** Approved
**Author:** Sydney Marrone + AI Assistant

## Problem

ATHF is marketed as "agentic" but currently provides two single-shot LLM wrappers (HypothesisGeneratorAgent, HuntResearcherAgent) with no reasoning loops, tool calling, state management, multi-agent orchestration, human-in-the-loop checkpoints, or event-driven triggers. The internal implementation (Hunt-Vault) has battle-tested versions of all six capabilities, but they're hardcoded and not reusable.

## Decision

Implement six capabilities in the ATHF public framework by generalizing patterns from Hunt-Vault. Use Approach A (Layered Agent Runtime) with native Claude tool_use behind a provider abstraction.

### Design Constraints (from stakeholder input)

- **Deployment:** Hybrid CLI + optional daemon mode
- **LLM Provider:** Multi-provider (Bedrock + direct Anthropic API)
- **Tool Scope:** ATHF internal tools + read-only SIEM queries
- **Dependencies:** Accept targeted deps, no large frameworks

## Architecture Overview

```
EVENT LAYER (Cap 6)
  Event Sources → EventDispatcher → Triggers → Pipeline

ORCHESTRATION LAYER (Cap 4)
  Pipeline = [AgentStep, RouterStep, CheckpointStep, ...]
  PipelineContext carries results between steps

AGENT LAYER (Cap 1 + 2)
  ReasoningAgent.run():
    LLM invoke (with tool definitions)
    → stop_reason: "tool_use" → validate → execute tool → observe → loop
    → stop_reason: "end_turn" → finalize

STATE LAYER (Cap 3)
  Layer 3: SessionState (cross-invocation, YAML persistence)
  Layer 2: RunState (single run() call, in-memory)
  Layer 1: StepState (single iteration, ephemeral)

CHECKPOINT LAYER (Cap 5)
  CheckpointPolicy → CheckpointHandler → CheckpointRequest/Response
  Handlers: CLI (interactive), AutoApprove (autonomous), Slack (plugin)

PLUGIN SYSTEM (existing, extended)
  PluginRegistry: _agents, _commands, _tools (NEW), _pipelines (NEW), _triggers (NEW)
```

---

## Capability 1: Reasoning Loop

### Source

Hunt-Vault's `DeepBaselineInvestigator._iterative_analysis()` — iterative LLM loop with up to 5 rounds of follow-up ClickHouse queries. Currently 600+ lines of loop management, message accumulation, retry logic, and token tracking hardcoded in one agent class.

### Design

Add optional `run()` method to `Agent` base class (default calls `execute()` for backward compatibility). New `ReasoningAgent(LLMAgent)` subclass implements a step-based loop driven by the LLM provider's `stop_reason`:

- `stop_reason: "tool_use"` → validate tool call → execute → observe → loop
- `stop_reason: "end_turn"` → finalize and return result

Subclass hooks:
- `build_system_prompt(state)` — domain-specific system prompt
- `build_initial_prompt(state)` — initial user message with context
- `finalize(state, response, force)` — build typed output from LLM response
- `validate_tool_call(state, tool_call)` — safety gate (e.g., SQL validation)
- `on_step_complete(state, step)` — logging, checkpointing, session bridging

### Key Types

```python
@dataclass
class RunState(Generic[InputT]):
    input: InputT
    evidence: List[StepRecord]
    messages: List[Dict[str, Any]]
    step_count: int = 0
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_cost_usd: float = 0.0
    store: Dict[str, Any]  # Domain-specific state

@dataclass
class StepRecord:
    step: int
    tool_call: ToolCall
    result: ToolResult
    duration_ms: int
    timestamp: str
```

---

## Capability 2: Tool System

### Source

Hunt-Vault's `_safe_query()` + `_is_safe_query()` in DeepBaselineInvestigator. LLM requests SQL queries via JSON, agent validates and executes them. Pattern repeated across multiple agents but not abstracted.

### Design

Use Claude's native `tool_use` API behind an `LLMProvider` abstraction.

**Tool interface:**

```python
class ToolDefinition(ABC):
    name: str
    description: str
    input_schema: Dict[str, Any]  # JSON Schema

    @abstractmethod
    def execute(self, input_data: Dict[str, Any]) -> ToolResult

@dataclass
class ToolResult:
    success: bool
    output: Any
    error: Optional[str] = None
    metadata: Dict[str, Any]
```

**LLM Provider abstraction:**

```python
class LLMProvider(ABC):
    @abstractmethod
    def invoke(self, messages, system, tools=None, max_tokens=4096) -> LLMResponse

class BedrockAnthropicProvider(LLMProvider): ...
class DirectAnthropicProvider(LLMProvider): ...
```

Tools register via `PluginRegistry.register_tool()` and entry point group `athf.tools`.

**ATHF built-in tools:** SimilarHuntTool, HuntSearchTool, ContextLoadTool, WebSearchTool, CoverageTool, HuntValidateTool.

**Hunt-Vault plugin tools:** ClickHouseQueryTool, BaselineCheckTool, DecisionPrecedentTool, SuppressionCheckTool.

---

## Capability 3: Session State

### Source

Hunt-Vault's `SessionManager` (785 lines) — singleton with file-based persistence, three parallel log streams (queries, decisions, findings), query-to-decision context linking.

### Design

Three state layers:

1. **StepState** (ephemeral) — single think→act→observe iteration
2. **RunState** (in-memory) — single `agent.run()` call, accumulates evidence and messages
3. **SessionState** (persistent) — cross-invocation hunt session lifecycle

**Persistence abstraction:**

```python
class SessionStore(ABC):
    def save_event(self, session_id, event: SessionEvent) -> None
    def load_events(self, session_id, event_type=None) -> List[SessionEvent]
    def save_metadata(self, session_id, metadata) -> None
    def load_metadata(self, session_id) -> Dict[str, Any]

class YAMLSessionStore(SessionStore): ...  # Ships with ATHF
```

**Hunt-Vault adds:** `ClickHouseSessionStore` as plugin.

`SessionManager` revised to depend on `SessionStore` interface. Existing convenience API (`log_query`, `log_decision`, `log_finding`) unchanged.

`on_step_complete` hook in `ReasoningAgent` bridges Layer 2 → Layer 3 (logs tool calls to active session).

---

## Capability 4: Multi-Agent Orchestration

### Source

Hunt-Vault's `lambda_handler.py` (886 lines) — severity-based routing between agents. `HuntExecutorAgent` — sequential agent chaining. `SignalInvestigatorAgent` — conditional enrichment.

### Design

Lightweight `Pipeline` that composes agents with routing rules:

```python
class Pipeline:
    name: str
    steps: List[PipelineStep]
    def run(self, initial_input) -> PipelineContext

class PipelineStep(ABC):
    name: str
    def execute(self, context: PipelineContext) -> PipelineContext

class AgentStep(PipelineStep): ...     # Run any agent
class RouterStep(PipelineStep): ...    # Conditional branching
class CheckpointStep(PipelineStep): ... # Human gate
```

`PipelineContext` carries shared results between steps. `input_mapper` functions translate between agent-specific typed inputs.

Pipelines register via `PluginRegistry.register_pipeline()` and entry point group `athf.pipelines`.

**Not building:** DAG engine, parallel execution, retry/backoff, pipeline state persistence. Pipelines are linear with conditional branches.

**ATHF ships:** Pipeline runtime, step types, CLI commands (`athf pipeline list`, `athf pipeline run`).

**Hunt-Vault defines:** baseline-investigation, signal-investigation, cti-to-hunt pipeline definitions.

---

## Capability 5: Human-in-the-Loop Checkpoints

### Source

Hunt-Vault's LOCK OBSERVE stage (mandatory human gate), Lambda `DEEP_INVESTIGATION_THRESHOLD` (policy-based auto-approval), `DecisionManager` precedent lookup (accelerated approval).

### Design

Spectrum from fully autonomous to fully manual via `CheckpointPolicy`:

- `ALWAYS_PAUSE` — always wait for human
- `PAUSE_ON_LOW_CONFIDENCE` — pause if agent confidence below threshold
- `AUTO_APPROVE` — log for audit trail but don't wait
- `POLICY_BASED` — custom function decides

```python
@dataclass
class Checkpoint:
    name: str
    description: str
    policy: CheckpointPolicy
    confidence_threshold: float = 0.8
    policy_fn: Optional[Callable] = None

class CheckpointHandler(ABC):
    def request_approval(self, request: CheckpointRequest) -> CheckpointResponse

class CLICheckpointHandler(CheckpointHandler): ...     # Interactive terminal
class AutoApproveHandler(CheckpointHandler): ...        # Autonomous mode
```

Integrates at two points:
- `CheckpointStep` in pipelines (between agents)
- `on_step_complete` in `ReasoningAgent` (within reasoning loop)

**ATHF ships:** Checkpoint types, CLIHandler, AutoApproveHandler.

**Hunt-Vault adds:** SlackCheckpointHandler, DecisionPrecedentEnricher, severity-based policy functions.

---

## Capability 6: Event-Driven Triggers

### Source

Hunt-Vault's Lambda handler — EventBridge scheduled rules (5 layers), S3 state for smart deduplication, severity-based auto-investigation routing.

### Design

```python
@dataclass
class Event:
    event_type: str        # "baseline.detect", "cti.new_technique"
    payload: Dict[str, Any]
    source: str            # "cli", "schedule", "webhook", "agent"

@dataclass
class Trigger:
    name: str
    event_pattern: str     # Glob: "baseline.*"
    pipeline_name: str
    max_runs_per_hour: Optional[int]
    max_runs_per_day: Optional[int]
    condition: Optional[Callable]

class EventDispatcher:
    def register_trigger(self, trigger: Trigger)
    def dispatch(self, event: Event) -> List[PipelineContext]

class EventSource(ABC):
    def listen(self, callback: Callable[[Event], None])
```

**CLI mode:** `athf trigger emit baseline.detect --payload '{...}'` + cron scheduling.

**Daemon mode (optional):** `EventSource` implementations for schedule, webhook, Lambda.

YAML trigger configuration in `.athfconfig.yaml`.

**ATHF ships:** Event, Trigger, EventDispatcher, CLI commands, YAML config loading.

**Hunt-Vault adds:** LambdaEventSource, ScheduleEventSource, WebhookEventSource, Daemon class, CloudFormation templates, S3 state management.

---

## Ownership Split

### ATHF (Public Framework) — ~2,000 new lines

| New File | Contents |
|---|---|
| `athf/agents/reasoning.py` | ReasoningAgent, RunState, StepRecord (~250 lines) |
| `athf/agents/tools.py` | ToolDefinition, ToolResult, ToolCall (~80 lines) |
| `athf/agents/providers.py` | LLMProvider, BedrockAnthropicProvider, DirectAnthropicProvider (~300 lines) |
| `athf/core/pipeline.py` | Pipeline, PipelineStep, AgentStep, RouterStep, PipelineContext (~200 lines) |
| `athf/core/checkpoints.py` | Checkpoint, CheckpointRequest/Response, CLIHandler, AutoApproveHandler (~200 lines) |
| `athf/core/events.py` | Event, Trigger, EventDispatcher, EventSource ABC (~200 lines) |
| `athf/core/session.py` | SessionStore ABC, YAMLSessionStore, SessionEvent, SessionManager (~300 lines) |
| `athf/tools/builtin.py` | 6 built-in tools wrapping existing CLI functionality (~250 lines) |
| `athf/commands/trigger.py` | `athf trigger emit/list` CLI (~100 lines) |
| `athf/commands/pipeline.py` | `athf pipeline list/run` CLI (~100 lines) |

Modified: `base.py` (+run method), `plugin_system.py` (+3 registries), `cli.py` (+2 command groups), `__init__.py` files, `pyproject.toml`.

### Hunt-Vault (Internal) — ~900 lines changed

| Change | What |
|---|---|
| New: tool wrappers (~200 lines) | ClickHouseQueryTool, BaselineCheckTool, etc. |
| New: pipeline definitions (~150 lines) | baseline-investigation, signal-investigation, cti-to-hunt |
| New: event sources (~150 lines) | LambdaEventSource, ScheduleEventSource |
| Refactor: DeepBaselineInvestigator (~200 lines delta) | Extend ReasoningAgent, remove inline loop management |
| Refactor: lambda_handler.py (~200 lines delta) | 886 lines → ~30 line adapter |

### Backward Compatibility

All existing code unchanged: `Agent.execute()`, `AgentResult`, `LLMAgent`, `DeterministicAgent`, `PluginRegistry` existing methods, all CLI commands, hunt file format, `.athfconfig.yaml` existing sections.

---

## Implementation Order

| Phase | What | Depends On | Parallelizable |
|---|---|---|---|
| **1** | `LLMProvider` + `BedrockAnthropicProvider` + `DirectAnthropicProvider` | Nothing | Yes (with 4) |
| **2** | `ToolDefinition` + `ToolResult` + built-in tools | Phase 1 | No |
| **3** | `ReasoningAgent` + `RunState` | Phase 1 + 2 | No |
| **4** | `SessionStore` + `YAMLSessionStore` + revised `SessionManager` | Nothing | Yes (with 1) |
| **5** | `Pipeline` + step types + CLI commands | Phase 3 | No |
| **6** | `Checkpoint` system + handlers | Phase 5 | No |
| **7** | `Event` + `Trigger` + `EventDispatcher` + CLI | Phase 5 | No |
| **8** | Integration tests across all capabilities | All above | No |
| **9** | Hunt-Vault migration (agents, Lambda, tools, pipelines) | All above | No |

Phases 1 and 4 can run in parallel. After Phase 3, the framework is meaningfully more agentic.

---

## New Dependencies

```toml
[project.optional-dependencies]
reasoning = ["boto3>=1.26.0"]
anthropic = ["anthropic>=0.39.0"]
daemon = ["apscheduler>=3.10.0"]  # Optional, for ScheduleEventSource
```

No new required dependencies. All capabilities are optional installs.

---

## Success Criteria

1. `DeepBaselineInvestigator` runs on `ReasoningAgent` with native tool_use (fewer lines, same behavior)
2. Hunt-Vault's Lambda handler replaced by ~30-line adapter using EventDispatcher + Pipeline
3. A Splunk user (no ClickHouse) can define a ReasoningAgent with custom tools and run it
4. All existing ATHF tests pass without modification
5. `athf pipeline run` and `athf trigger emit` CLI commands work end-to-end
