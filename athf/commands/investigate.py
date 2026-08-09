"""Investigation management commands."""

import click


INVESTIGATION_EPILOG = """
\b
Examples:
  # Interactive investigation creation
  athf investigate new

  # Non-interactive with all options
  athf investigate new --title "Alert Triage - PowerShell" --type finding --non-interactive

  # List investigations with filters
  athf investigate list --type finding

  # Search investigations for keywords
  athf investigate search "PowerShell"

  # Validate investigation structure
  athf investigate validate I-0042

\b
Workflow:
  1. Create investigation → athf investigate new
  2. Edit investigation file → investigations/I-XXXX.md
  3. Document findings and analysis
  4. Optionally promote to formal hunt → athf investigate promote I-XXXX

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
from athf.commands._investigate_create import new  # noqa: E402
from athf.commands._investigate_query import list_investigations, search, validate  # noqa: E402
from athf.commands._investigate_lifecycle import promote  # noqa: E402

investigate.add_command(new)
investigate.add_command(list_investigations)
investigate.add_command(search)
investigate.add_command(validate)
investigate.add_command(promote)
