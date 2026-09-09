"""Investigation management commands."""

import click

INVESTIGATION_EPILOG = """
\b
Examples:
  # Interactive investigation creation
  hecate-agent investigate new

  # Non-interactive with all options
  hecate-agent investigate new --title "Alert Triage - PowerShell" --type finding --non-interactive

  # List investigations with filters
  hecate-agent investigate list --type finding

  # Search investigations for keywords
  hecate-agent investigate search "PowerShell"

  # Validate investigation structure
  hecate-agent investigate validate I-0042

\b
Workflow:
  1. Create investigation → hecate-agent investigate new
  2. Edit investigation file → investigations/I-XXXX.md
  3. Document findings and analysis
  4. Optionally promote to formal hunt → hecate-agent investigate promote I-XXXX

\b
Learn more: See investigations/README.md for full documentation
"""


@click.group(epilog=INVESTIGATION_EPILOG)
def investigate() -> None:
    """Manage security investigations and exploratory work.

    \b
    Investigation commands help you:
    • Triage alerts and findings
    • Baseline new data sources
    • Explore and sandbox queries
    • Document ad-hoc analysis work
    • Promote investigations to formal hunts

    \b
    Note: Investigations are NOT tracked in metrics.
    They won't contribute to hunt success rates or cost tracking.
    """


# Register subcommands from split submodules
from hecate_agent.commands._investigate_create import new  # noqa: E402
from hecate_agent.commands._investigate_lifecycle import promote  # noqa: E402
from hecate_agent.commands._investigate_query import list_investigations, search, validate  # noqa: E402

investigate.add_command(new)
investigate.add_command(list_investigations)
investigate.add_command(search)
investigate.add_command(validate)
investigate.add_command(promote)
