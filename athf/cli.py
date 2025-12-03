"""ATHF command-line interface."""

import click
from athf.__version__ import __version__
from athf.commands import init, hunt


@click.group()
@click.version_option(version=__version__, prog_name="athf")
def cli():
    """Agentic Threat Hunting Framework (ATHF)

    Give your threat hunting program memory and agency.
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
