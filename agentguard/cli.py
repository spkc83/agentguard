"""AgentGuard CLI -- command-line interface for audit, policy, and verification.

Entry point: `agentguard` (configured in pyproject.toml).
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from agentguard._logging import configure_logging

app = typer.Typer(
    name="agentguard",
    help="Agent governance and security runtime for AI agents.",
    no_args_is_help=True,
)
audit_app = typer.Typer(help="Audit log operations.")
policy_app = typer.Typer(help="Policy management. (Coming in v0.3.0)")
verify_app = typer.Typer(help="Formal verification. (Coming in v0.3.0)")

app.add_typer(audit_app, name="audit")
app.add_typer(policy_app, name="policy")
app.add_typer(verify_app, name="verify")

console = Console()


@app.callback()
def main(
    json_output: bool = typer.Option(False, "--json", help="Output in JSON format."),
) -> None:
    """AgentGuard -- governance runtime for AI agents."""
    configure_logging(json_output=json_output)


@audit_app.command("show")
def audit_show(
    log_dir: Path = typer.Option("./audit-logs", help="Audit log directory."),
    agent_id: str | None = typer.Option(None, help="Filter by agent ID."),
) -> None:
    """Show audit log events."""
    from agentguard.core.audit import FileAuditBackend

    async def _show() -> None:
        backend = FileAuditBackend(directory=log_dir)
        events = await backend.read_all()

        if agent_id:
            events = [e for e in events if e.agent_id == agent_id]

        if not events:
            console.print("[yellow]No audit events found.[/yellow]")
            return

        table = Table(title=f"Audit Events ({len(events)} total)")
        table.add_column("Event ID", style="dim")
        table.add_column("Timestamp")
        table.add_column("Agent")
        table.add_column("Action")
        table.add_column("Resource")
        table.add_column("Result", style="bold")

        for event in events:
            result_style = {
                "allowed": "green",
                "denied": "red",
                "escalated": "yellow",
                "error": "red bold",
            }.get(event.result, "white")
            table.add_row(
                event.event_id[:12] + "...",
                event.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                event.agent_id[:12] + "...",
                event.action,
                event.resource,
                f"[{result_style}]{event.result}[/{result_style}]",
            )

        console.print(table)

    asyncio.run(_show())


@audit_app.command("verify")
def audit_verify(
    log_dir: Path = typer.Option("./audit-logs", help="Audit log directory."),
) -> None:
    """Verify audit log HMAC chain integrity."""
    from agentguard.core.audit import AppendOnlyAuditLog, FileAuditBackend
    from agentguard.exceptions import AuditTamperDetectedError

    async def _verify() -> None:
        try:
            log = AppendOnlyAuditLog(backend=FileAuditBackend(directory=log_dir))
            result = await log.verify_chain()
            if result.valid:
                console.print(
                    f"[green]Audit chain verified.[/green]"
                    f" {result.event_count} events, no tampering detected."
                )
        except AuditTamperDetectedError as e:
            console.print(
                f"[red bold]TAMPER DETECTED[/red bold] at event index {e.event_index} "
                f"(event_id={e.event_id})"
            )
            raise typer.Exit(code=1) from None

    asyncio.run(_verify())


@audit_app.command("replay")
def audit_replay(
    log_dir: Path = typer.Option("./audit-logs", help="Audit log directory."),
) -> None:
    """Replay audit log events sequentially."""
    from agentguard.core.audit import FileAuditBackend

    async def _replay() -> None:
        backend = FileAuditBackend(directory=log_dir)
        events = await backend.read_all()

        if not events:
            console.print("[yellow]No audit events found.[/yellow]")
            return

        for i, event in enumerate(events):
            result_style = {
                "allowed": "green",
                "denied": "red",
                "escalated": "yellow",
                "error": "red bold",
            }.get(event.result, "white")

            console.print(f"\n[bold]--- Event {i + 1}/{len(events)} ---[/bold]")
            console.print(f"  Event ID:  [dim]{event.event_id}[/dim]")
            console.print(f"  Time:      {event.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
            console.print(f"  Agent:     {event.agent_id}")
            console.print(f"  Action:    {event.action}")
            console.print(f"  Resource:  {event.resource}")
            console.print(f"  Result:    [{result_style}]{event.result}[/{result_style}]")
            console.print(f"  Duration:  {event.duration_ms:.1f}ms")
            if event.permission_context.reason:
                console.print(f"  Reason:    {event.permission_context.reason}")

    asyncio.run(_replay())


@policy_app.command("validate")
def policy_validate() -> None:
    """Validate a policy YAML file. (Coming in v0.3.0)"""
    console.print("[yellow]Policy validation will be available in v0.3.0.[/yellow]")


@verify_app.command("rbac")
def verify_rbac() -> None:
    """Formally verify RBAC configuration. (Coming in v0.3.0)"""
    console.print("[yellow]Formal RBAC verification will be available in v0.3.0.[/yellow]")
