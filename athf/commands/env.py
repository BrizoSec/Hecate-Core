"""Environment management commands."""

import subprocess  # nosec B404
import sys
from pathlib import Path
from typing import Union

import click
from rich.console import Console
from rich.panel import Panel

console = Console()

ENV_EPILOG = """
\b
Examples:
  # Setup virtual environment with default Python
  athf env setup

  # Setup with specific Python version
  athf env setup --python python3.13

  # Include dev dependencies
  athf env setup --dev

  # Clean up existing venv and recreate
  athf env setup --clean

\b
After setup:
  # Activate venv (bash/zsh)
  source .venv/bin/activate

  # Deactivate
  deactivate
"""


@click.group(epilog=ENV_EPILOG)
def env() -> None:
    """Manage Python virtual environment.

    Commands for setting up, cleaning, and managing the Python
    virtual environment for ATHF development.
    """
    pass


@env.command(name="setup")
@click.option(
    "--python",
    default="python3",
    help="Python executable to use (default: python3)",
)
@click.option("--dev", is_flag=True, help="Install development dependencies")
@click.option("--clean", is_flag=True, help="Remove existing venv before creating")
def setup(python: str, dev: bool, clean: bool) -> None:  # noqa: C901
    """Setup Python virtual environment with dependencies.

    Creates .venv directory and installs athf package with
    all dependencies from pyproject.toml.

    \b
    Steps:
    1. Create .venv directory (or clean existing)
    2. Install athf package in editable mode
    3. Install scikit-learn for semantic search
    4. Show activation instructions

    \b
    Examples:
      athf env setup
      athf env setup --python python3.13
      athf env setup --dev
      athf env setup --clean
    """
    venv_path = Path(".venv")

    # This command creates a development venv from source (pip install -e .).
    # It only makes sense when run from the ATHF source repository root.
    # Users who installed ATHF via pip already have a working environment
    # and do not need to run this command.
    if not Path("pyproject.toml").exists():
        console.print("[red]Error: pyproject.toml not found in the current directory.[/red]")
        console.print()
        console.print("[bold]athf env setup[/bold] is for ATHF source-repo developers only.")
        console.print("It creates a local .venv by running [cyan]pip install -e .[/cyan] from the repo root.")
        console.print()
        console.print("If you installed ATHF via pip, your environment is already set up —")
        console.print("you can run [cyan]athf[/cyan] commands directly without a separate venv.")
        raise click.Abort()

    # Clean existing venv if requested
    if clean and venv_path.exists():
        console.print("[yellow]🧹 Removing existing .venv directory...[/yellow]")
        try:
            import shutil

            shutil.rmtree(venv_path)
            console.print("[green]✅ Removed existing .venv[/green]\n")
        except Exception as e:
            console.print(f"[red]Error removing .venv: {e}[/red]")
            raise click.Abort()

    # Check if venv already exists
    if venv_path.exists():
        console.print("[yellow]⚠️  .venv already exists[/yellow]")
        console.print("[dim]Use --clean to remove and recreate[/dim]\n")

        # Show helpful usage instructions
        if sys.platform == "win32":
            activate_cmd = ".venv\\Scripts\\activate"
        else:
            activate_cmd = "source .venv/bin/activate"

        usage_panel = Panel(
            f"[bold cyan]To use the existing virtual environment:[/bold cyan]\n\n"
            f"[green]1. Activate the venv:[/green]\n"
            f"   {activate_cmd}\n\n"
            f"[green]2. Run athf commands:[/green]\n"
            f"   athf --version\n"
            f"   athf hunt --help\n\n"
            f"[green]3. Or use without activating:[/green]\n"
            f"   .venv/bin/athf [command]\n\n"
            f"[dim]💡 Your prompt will show (.venv) when activated[/dim]",
            title="✨ Virtual Environment Ready",
            border_style="cyan",
        )
        console.print(usage_panel)
        raise click.Abort()

    # Create virtual environment
    console.print(f"[cyan]📦 Creating virtual environment with {python}...[/cyan]")
    try:
        subprocess.run(
            [python, "-m", "venv", ".venv"],
            check=True,
            capture_output=True,
            text=True,
        )
        console.print("[green]✅ Virtual environment created[/green]\n")
    except subprocess.CalledProcessError as e:
        console.print(f"[red]Error creating venv: {e.stderr}[/red]")
        raise click.Abort()
    except FileNotFoundError:
        console.print(f"[red]Error: {python} not found[/red]")
        console.print("[dim]Try: athf env setup --python python3.13[/dim]")
        raise click.Abort()

    # Determine pip path
    if sys.platform == "win32":
        pip_path = venv_path / "Scripts" / "pip"
    else:
        pip_path = venv_path / "bin" / "pip"

    # Upgrade pip
    console.print("[cyan]📦 Upgrading pip...[/cyan]")
    try:
        subprocess.run(
            [str(pip_path), "install", "--upgrade", "pip"],
            check=True,
            capture_output=True,
            text=True,
        )
        console.print("[green]✅ pip upgraded[/green]\n")
    except subprocess.CalledProcessError as e:
        console.print(f"[yellow]Warning: Failed to upgrade pip: {e.stderr}[/yellow]\n")

    # Install athf package
    console.print("[cyan]📦 Installing ATHF package...[/cyan]")
    install_cmd = [str(pip_path), "install", "-e", "."]
    if dev:
        install_cmd.append("[dev]")

    try:
        subprocess.run(
            install_cmd,
            check=True,
            capture_output=True,
            text=True,
        )
        console.print("[green]✅ ATHF installed[/green]\n")
    except subprocess.CalledProcessError as e:
        console.print(f"[red]Error installing package: {e.stderr}[/red]")
        raise click.Abort()

    # Install scikit-learn for athf similar command
    console.print("[cyan]📦 Installing scikit-learn for semantic search...[/cyan]")
    try:
        subprocess.run(
            [str(pip_path), "install", "scikit-learn"],
            check=True,
            capture_output=True,
            text=True,
        )
        console.print("[green]✅ scikit-learn installed[/green]\n")
    except subprocess.CalledProcessError as e:
        console.print(f"[yellow]Warning: Failed to install scikit-learn: {e.stderr}[/yellow]")
        console.print("[dim]athf similar command will not work without scikit-learn[/dim]\n")

    # Success message
    console.print("[bold green]🎉 Virtual environment setup complete![/bold green]\n")

    # Show activation instructions
    if sys.platform == "win32":
        activate_cmd = ".venv\\Scripts\\activate"
    else:
        activate_cmd = "source .venv/bin/activate"

    activation_panel = Panel(
        f"[cyan]{activate_cmd}[/cyan]\n\n"
        f"[dim]Then verify installation:[/dim]\n"
        f"[white]athf --version[/white]\n"
        f"[white]athf hunt --help[/white]",
        title="🚀 Next Steps",
        border_style="green",
    )
    console.print(activation_panel)


@env.command(name="clean")
def clean() -> None:
    """Remove virtual environment.

    Deletes the .venv directory to start fresh.

    \b
    Example:
      athf env clean
      athf env setup
    """
    venv_path = Path(".venv")

    if not venv_path.exists():
        console.print("[yellow]No .venv directory found[/yellow]")
        return

    console.print("[yellow]🧹 Removing .venv directory...[/yellow]")
    try:
        import shutil

        shutil.rmtree(venv_path)
        console.print("[green]✅ Virtual environment removed[/green]")
        console.print("[dim]Run 'athf env setup' to recreate[/dim]")
    except Exception as e:
        console.print(f"[red]Error removing .venv: {e}[/red]")
        raise click.Abort()


@env.command(name="info")
def info() -> None:  # noqa: C901
    """Show virtual environment information.

    Display Python version, installed packages, and venv location.

    \b
    Example:
      athf env info
    """
    venv_path = Path(".venv")

    if not venv_path.exists():
        console.print("[yellow]No .venv directory found[/yellow]")
        console.print("[dim]Run 'athf env setup' to create[/dim]")
        return

    # Determine python path
    if sys.platform == "win32":
        python_path = venv_path / "Scripts" / "python"
    else:
        python_path = venv_path / "bin" / "python"

    if not python_path.exists():
        console.print("[red]Error: Virtual environment appears corrupted[/red]")
        console.print("[dim]Run 'athf env setup --clean' to recreate[/dim]")
        return

    # Get Python version
    try:
        result = subprocess.run(
            [str(python_path), "--version"],
            check=True,
            capture_output=True,
            text=True,
        )
        python_version = result.stdout.strip()
    except subprocess.CalledProcessError:
        python_version = "Unknown"

    # Get installed packages count
    pip_path = python_path.parent / "pip"
    package_count: Union[int, str]
    try:
        result = subprocess.run(
            [str(pip_path), "list", "--format", "freeze"],
            check=True,
            capture_output=True,
            text=True,
        )
        package_count = len(result.stdout.strip().split("\n"))
    except subprocess.CalledProcessError:
        package_count = "Unknown"

    # Check for athf installation
    try:
        result = subprocess.run(
            [str(pip_path), "show", "agentic-threat-hunting-framework"],
            check=True,
            capture_output=True,
            text=True,
        )
        athf_installed = "✅ Installed" if result.returncode == 0 else "❌ Not installed"
    except subprocess.CalledProcessError:
        athf_installed = "❌ Not installed"

    # Check for scikit-learn
    try:
        result = subprocess.run(
            [str(pip_path), "show", "scikit-learn"],
            check=True,
            capture_output=True,
            text=True,
        )
        sklearn_installed = "✅ Installed" if result.returncode == 0 else "❌ Not installed"
    except subprocess.CalledProcessError:
        sklearn_installed = "❌ Not installed"

    # Display info
    console.print("\n[bold]Virtual Environment Info:[/bold]\n")
    console.print(f"  [cyan]Location:[/cyan] {venv_path.absolute()}")
    console.print(f"  [cyan]Python:[/cyan] {python_version}")
    console.print(f"  [cyan]Packages:[/cyan] {package_count} installed")
    console.print(f"  [cyan]athf:[/cyan] {athf_installed}")
    console.print(f"  [cyan]scikit-learn:[/cyan] {sklearn_installed} [dim](required for athf similar)[/dim]")
    console.print()


@env.command(name="activate")
def activate() -> None:
    """Show command to activate virtual environment.

    Note: Cannot activate directly (subprocesses can't modify parent shell).
    Copy and run the printed command to activate.

    \b
    Example:
      athf env activate
      # Then copy and run the printed command
    """
    venv_path = Path(".venv")

    if not venv_path.exists():
        console.print("[yellow]No .venv directory found[/yellow]")
        console.print("[dim]Run 'athf env setup' to create[/dim]")
        raise click.Abort()

    # Determine activation command based on platform
    if sys.platform == "win32":
        activate_cmd = ".venv\\Scripts\\activate"
    else:
        activate_cmd = "source .venv/bin/activate"

    console.print("\n[bold cyan]To activate the virtual environment, run:[/bold cyan]\n")
    console.print(f"  [green]{activate_cmd}[/green]\n")
    console.print("[dim]💡 Tip: Copy the command above and run it in your shell[/dim]\n")


@env.command(name="check")
def check() -> None:  # noqa: C901
    """Run a dependency health checklist for your ATHF workspace.

    Verifies that all optional and required components are installed
    and configured correctly. Useful after a fresh install or upgrade.

    \b
    Checks:
      • Python version
      • athf package
      • scikit-learn (for athf similar)
      • litellm (for AI agents)
      • mitreattack-python (for ATT&CK STIX)
      • STIX data file (for technique lookup)
      • tavily-python (for web search)
      • Workspace config (.athfconfig.yaml)
      • Environment context (knowledge/environment.md)

    \b
    Example:
      athf env check
    """
    import importlib.util

    console.print("\n[bold cyan]🩺 ATHF Dependency Check[/bold cyan]\n")

    ok = "[bold green]✅[/bold green]"
    warn = "[bold yellow]⚠️ [/bold yellow]"
    fail = "[bold red]❌[/bold red]"

    def _check(label: str, status: bool, detail: str = "", optional: bool = False) -> None:
        icon = ok if status else (warn if optional else fail)
        line = f"  {icon} {label}"
        if detail:
            line += f"  [dim]{detail}[/dim]"
        console.print(line)

    # Python version
    ver = sys.version_info
    py_ok = ver >= (3, 9)
    _check(f"Python {ver.major}.{ver.minor}.{ver.micro}", py_ok,
           "" if py_ok else "requires Python 3.9+")

    # athf package
    try:
        import athf  # type: ignore
        athf_version = getattr(athf, "__version__", "unknown")
        _check(f"athf {athf_version}", True)
    except ImportError:
        _check("athf", False, "not importable — installation may be broken")

    # scikit-learn
    sklearn_ok = importlib.util.find_spec("sklearn") is not None
    _check("scikit-learn", sklearn_ok,
           "required for `athf similar`" if not sklearn_ok else "",
           optional=True)

    # litellm
    litellm_ok = importlib.util.find_spec("litellm") is not None
    _check("litellm", litellm_ok,
           "required for AI agents (`athf agent run`)" if not litellm_ok else "",
           optional=True)

    # mitreattack-python
    mitreattack_ok = importlib.util.find_spec("mitreattack") is not None
    _check("mitreattack-python", mitreattack_ok,
           "required for STIX technique data (`athf attack update`)" if not mitreattack_ok else "",
           optional=True)

    # STIX data file
    if mitreattack_ok:
        try:
            from athf.core.attack_matrix import _get_stix_file_path, is_using_stix
            stix_path = _get_stix_file_path()
            stix_ok = stix_path.exists() and is_using_stix()
            _check("ATT&CK STIX data", stix_ok,
                   str(stix_path) if stix_ok else f"not found at {stix_path} — run `athf attack update`",
                   optional=True)
        except Exception:
            _check("ATT&CK STIX data", False, "could not determine status", optional=True)
    else:
        _check("ATT&CK STIX data", False, "mitreattack-python not installed", optional=True)

    # tavily-python
    tavily_ok = importlib.util.find_spec("tavily") is not None
    _check("tavily-python", tavily_ok,
           "required for web search in agents" if not tavily_ok else "",
           optional=True)

    # Workspace config
    from athf.commands._hunt_create import get_config_path
    config_path = get_config_path()
    config_ok = config_path.exists()
    _check(".athfconfig.yaml", config_ok,
           str(config_path) if config_ok else f"not found — run `athf init`")

    # Environment context
    env_md = Path("knowledge") / "environment.md"
    env_ok = env_md.exists()
    _check("knowledge/environment.md", env_ok,
           "" if env_ok else "create this file to give AI agents context about your environment",
           optional=True)

    console.print()


@env.command(name="deactivate")
def deactivate_cmd() -> None:
    """Show command to deactivate virtual environment.

    Note: Cannot deactivate directly (subprocesses can't modify parent shell).
    Copy and run the printed command to deactivate.

    \b
    Example:
      athf env deactivate
      # Then copy and run the printed command
    """
    console.print("\n[bold cyan]To deactivate the virtual environment, run:[/bold cyan]\n")
    console.print("  [green]deactivate[/green]\n")
    console.print("[dim]💡 This will return you to your system Python[/dim]\n")
