"""ATHF command-line interface."""

import click
from athf.__version__ import __version__
from athf.commands import init, hunt


EPILOG = """
\b
Examples:
  # Initialize a new hunting workspace
  athf init

  # Create your first hunt
  athf hunt new

  # Search for credential dumping hunts
  athf hunt search "credential dumping"

  # List all completed hunts
  athf hunt list --status completed

  # Show program statistics
  athf hunt stats

\b
Getting Started:
  1. Run 'athf init' to set up your workspace
  2. Run 'athf hunt new' to create your first hunt
  3. Document using the LOCK pattern (Learn → Observe → Check → Keep)
  4. Track findings and iterate

\b
Documentation:
  • Full docs: https://github.com/Nebulock-Inc/agentic-threat-hunting-framework
  • CLI reference: docs/CLI_REFERENCE.md
  • AI workflows: prompts/ai-workflow.md

\b
Need help? Run 'athf COMMAND --help' for command-specific help.

\b
Created by Sydney Marrone © 2025
"""


@click.group(epilog=EPILOG)
@click.version_option(
    version=__version__,
    prog_name="athf",
    message="%(prog)s version %(version)s\nAgentic Threat Hunting Framework\nCreated by Sydney Marrone © 2025"
)
def cli():
    """Agentic Threat Hunting Framework (ATHF) - Hunt management CLI

    \b
    ATHF gives your threat hunting program memory and agency by:
    • Structured documentation with the LOCK pattern
    • Hunt tracking and metrics across your program
    • AI-assisted hypothesis generation and workflows
    • MITRE ATT&CK coverage analysis

    \b
    Quick Start:
      athf init           Set up a new hunting workspace
      athf hunt new       Create a hunt from template
      athf hunt list      View all hunts
      athf hunt search    Find hunts by keyword
      athf hunt stats     Show program metrics
    """
    pass


# Register command groups
cli.add_command(init.init)
cli.add_command(hunt.hunt)


def main():
    """Main entry point for the CLI."""
    cli()


if __name__ == "__main__":
    main()
