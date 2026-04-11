"""AgentGuard CLI entry point."""

from __future__ import annotations

import typer

app = typer.Typer(name="agentguard", help="AgentGuard — agent governance and security runtime.")


@app.command()
def version() -> None:
    """Print the AgentGuard version."""
    from agentguard import __version__

    typer.echo(f"agentguard {__version__}")


if __name__ == "__main__":
    app()
