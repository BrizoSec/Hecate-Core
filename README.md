<p align="center">
  <img src="assets/athf_logo.jpg" alt="ATHF Logo" width="400"/>
</p>

# Agentic Threat Hunting Framework (ATHF)

> Give your threat hunting program memory and agency.

The **Agentic Threat Hunting Framework (ATHF)** is the memory and automation layer for your threat hunting program. It gives your hunts structure, persistence, and context - making every past investigation accessible to both humans and AI.

ATHF works with any hunting methodology (PEAK, TaHiTI, or your own process). It's not a replacement; it's the layer that makes your existing process AI-ready.

## Why It Exists

Most threat hunting programs lose valuable context once a hunt ends. Notes live in Slack or tickets, queries are written once and forgotten, and lessons learned exist only in analysts' heads.

Even AI tools start from zero every time without access to your environment, your data, or your past hunts.

ATHF changes that by giving your hunts structure, persistence, and context.

**Read more:** [docs/why-athf.md](docs/why-athf.md)

## The LOCK Pattern

Every threat hunt follows the same basic loop: **Learn → Observe → Check → Keep**.

![The LOCK Pattern](assets/athf_lock.png)

- **Learn:** Gather context from threat intel, alerts, or anomalies
- **Observe:** Form a hypothesis about adversary behavior
- **Check:** Test hypotheses with targeted queries
- **Keep:** Record findings and lessons learned

**Why LOCK?** It's small enough to use and strict enough for agents to interpret. By capturing every hunt in this format, ATHF makes it possible for AI assistants to recall prior work and suggest refined queries based on past results.

**Read more:** [docs/lock-pattern.md](docs/lock-pattern.md)

## The Five Levels of Agentic Hunting

ATHF defines a simple maturity model. Each level builds on the previous one.

**Most teams will live at Levels 1–2. Everything beyond that is optional maturity.**

![The Five Levels](assets/athf_fivelevels.png)

| Level | Capability | What You Get |
|-------|-----------|--------------|
| **1** | Documented | Persistent hunt records using LOCK |
| **2** | Searchable | AI reads and recalls your hunts |
| **3** | Generative | AI executes queries via MCP tools |
| **4** | Agentic | Autonomous agents monitor and act |

**Level 1:** Operational within a day
**Level 2:** Operational within a week
**Level 3:** 2-4 weeks (optional)
**Level 4:** 1-3 months (optional)

**Read more:** [docs/maturity-model.md](docs/maturity-model.md)

## Quick Start

1. **Clone the repository**

   ```bash
   git clone https://github.com/Nebulock-Inc/agentic-threat-hunting-framework
   ```

2. **Start documenting hunts** using the LOCK pattern ([templates/](templates/))

3. **Add context files** once you have a few hunts recorded:
   - [AGENTS.md](AGENTS.md) - Your environment and data sources
   - [knowledge/hunting-knowledge.md](knowledge/hunting-knowledge.md) - Included expertise

4. **Choose an AI assistant** that can read your files (Claude Code, GitHub Copilot, Cursor)

**Full guide:** [docs/getting-started.md](docs/getting-started.md)

## Documentation

### Core Concepts

- [Why ATHF Exists](docs/why-athf.md) - The problem and solution
- [The LOCK Pattern](docs/lock-pattern.md) - Structure for all hunts
- [Maturity Model](docs/maturity-model.md) - The five levels explained
- [Getting Started](docs/getting-started.md) - Step-by-step onboarding

### Level-Specific Guides

- [Level 1: Documented Hunts](docs/maturity-model.md#level-1-documented-hunts)
- [Level 2: Searchable Memory](docs/maturity-model.md#level-2-searchable-memory)
- [Level 3: Generative Capabilities](docs/level3-mcp-examples.md)
- [Level 4: Agentic Workflows](docs/level4-agentic-workflows.md)

### Integration & Customization

- [MCP Catalog](integrations/MCP_CATALOG.md) - Available tool integrations
- [Quickstart Guides](integrations/quickstart/) - Setup for specific tools
- [Using ATHF](USING_ATHF.md) - Adoption and customization

## Why This Matters

Agentic threat hunting is not about replacing analysts. It's about building systems that can:

- Remember what has been done before
- Learn from past successes and mistakes
- Support human judgment with contextual recall

When your framework has memory, you stop losing knowledge to turnover or forgotten notes. When your AI assistant can reference that memory, it becomes a force multiplier.

## Feedback and Contributions

ATHF is open source and under active development. Feedback, forks, and pull requests are welcome.

**Repository:** [https://github.com/Nebulock-Inc/agentic-threat-hunting-framework](https://github.com/Nebulock-Inc/agentic-threat-hunting-framework)

Try it in your own environment, adapt it to your workflow, and share what you learn. The goal is to help every threat hunting team move from ad-hoc memory to structured, agentic capability.

---

**Start small. Document one hunt. Add structure. Build memory.**

Memory is the multiplier. Agency is the force.
Once your program can remember, everything else becomes possible.

Happy hunting!
