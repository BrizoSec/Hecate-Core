# Agentic Threat Hunting Framework (Hecate)

Hecate provides structure and persistence for threat hunting programs. It's a markdown-based framework, wrapped in a Python CLI, that enables AI-powered threat hunting.

## 🚀 Quick Start

```bash
# Install Hecate
pip install hecate-agent

# Conduct research before hunting
hecate-agent research new --topic "LSASS dumping" --technique T1003.001

# Create your first hunt
hecate-agent hunt new --technique T1003.001 --title "LSASS Credential Dumping" --research R-0001
```

There is no separate init step: `hunts/`, `research/` and `queries/` are created
on first use. To check that a workspace has the optional dependencies its
commands actually need, run `hecate-agent env check`.

For more detailed instructions, see the [Getting Started Guide](docs/getting-started.md).

## Key Features

* **Structured Hunting:** Documents hunts using the LOCK pattern (Learn → Observe → Check → Keep).
* **Searchable Repository:** Maintains a searchable repository of past investigations.
* **AI-Powered:** Includes AI-powered research and hypothesis generation agents.
* **Extensible:** Works with any SIEM/EDR platform and can be extended with custom plugins.

## The LOCK Pattern

Every threat hunt follows the same basic loop: **Learn → Observe → Check → Keep**.

![The LOCK Pattern](https://raw.githubusercontent.com/Nebulock-Inc/agentic-threat-hunting-framework/main/assets/athf_lock.png)

This structure makes it possible for AI assistants to recall prior work and suggest refined queries based on past results. For more details, see the [LOCK Pattern Guide](docs/lock-pattern.md).

## The Five Levels of Agentic Hunting

Hecate defines a simple maturity model to help you assess and improve your threat hunting capabilities.

![The Five Levels](https://raw.githubusercontent.com/Nebulock-Inc/agentic-threat-hunting-framework/main/assets/athf_fivelevels.png)

Most teams will live at Levels 1–2. Everything beyond that is optional maturity. For more details, see the [Maturity Model Guide](docs/maturity-model.md).

## Documentation

* [Getting Started](docs/getting-started.md)
* [Installation](docs/INSTALL.md)
* [CLI Reference](docs/CLI_REFERENCE.md)
* [Configuration](docs/CONFIGURATION.md)
* [LOCK Pattern](docs/lock-pattern.md)
* [Maturity Model](docs/maturity-model.md)

## Related repositories

* [Hecate-Runner](https://github.com/BrizoSec/Hecate-Runner) — autonomous orchestrator that drafts hunts into this workspace from live CTI.
* [agentic-threat-hunting-framework](https://github.com/Nebulock-Inc/agentic-threat-hunting-framework) — the upstream project Hecate grew out of.

## Contributing

Issues and pull requests are welcome on [BrizoSec/Hecate-Core](https://github.com/BrizoSec/Hecate-Core).

## License

MIT, per the `license` field in `pyproject.toml`.
