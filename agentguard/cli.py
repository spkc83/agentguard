"""AgentGuard CLI -- command-line interface for audit, policy, and verification.

Entry point: `agentguard` (configured in pyproject.toml).
"""

from __future__ import annotations

import asyncio
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path

import typer
import yaml
from rich.console import Console
from rich.table import Table

from agentguard._logging import configure_logging


def _parse_iso_utc(value: str | None) -> datetime | None:
    """Parse an ISO 8601 string, coercing naive datetimes to UTC.

    Audit event timestamps are tz-aware (UTC). Without coercion, a user
    passing ``2026-04-10T12:00:00`` (no offset) would trigger a
    ``TypeError`` when compared to a tz-aware event timestamp.
    """
    if value is None:
        return None
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


app = typer.Typer(
    name="agentguard",
    help="Agent governance and security runtime for AI agents.",
    no_args_is_help=True,
)
audit_app = typer.Typer(help="Audit log operations.")
policy_app = typer.Typer(help="Policy management and compliance reporting.")
verify_app = typer.Typer(help="Formal verification of RBAC and policy properties.")
observe_app = typer.Typer(help="Observability — replay, dashboard, metrics.")

app.add_typer(audit_app, name="audit")
app.add_typer(policy_app, name="policy")
app.add_typer(verify_app, name="verify")
app.add_typer(observe_app, name="observe")

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


def _write_witness(destination: Path, payload: str) -> None:
    """Atomically write an owner-only checkpoint witness file."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_path = tempfile.mkstemp(
        prefix=f".{destination.name}-", dir=destination.parent
    )
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, destination)
        temporary_path = ""
        directory_fd = os.open(destination.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary_path and os.path.exists(temporary_path):
            os.unlink(temporary_path)


@audit_app.command("export-checkpoint")
def audit_export_checkpoint(
    audit_dir: Path = typer.Option(
        "./audit-logs", "--audit-dir", "--log-dir", help="Audit log directory."
    ),
    output: Path = typer.Option(
        None, help="Write the checkpoint here instead of stdout; never rolled backwards."
    ),
) -> None:
    """Export the signed audit head for off-host rollback detection.

    Replicate the exported file to a host that does not share the audit
    directory's failure domain, then pass it back with
    ``agentguard audit verify --trusted-checkpoint``.
    """
    from agentguard.core.audit import AppendOnlyAuditLog, AuditCheckpoint, FileAuditBackend
    from agentguard.exceptions import AuditError

    async def _export() -> None:
        try:
            log = AppendOnlyAuditLog(backend=FileAuditBackend(directory=audit_dir))
            await log.verify_chain()
            checkpoint = await log.export_checkpoint()
        except (AuditError, OSError) as e:
            console.print(f"[red]Checkpoint export refused:[/red] {e}")
            raise typer.Exit(code=1) from None
        if checkpoint is None:
            console.print(
                "[red]No signed audit head to export:[/red] the log is empty or predates "
                "checkpointed schema v3."
            )
            raise typer.Exit(code=1)

        payload = checkpoint.model_dump_json()
        if output is None:
            typer.echo(payload)
            return
        if output.exists():
            try:
                existing = AuditCheckpoint.model_validate_json(output.read_text(encoding="utf-8"))
                # Authenticate the existing witness before letting it be replaced:
                # an unsigned file must not be able to block or redirect exports.
                log.verify_checkpoint_signature(existing)
            except (AuditError, OSError, ValueError) as e:
                console.print(f"[red]Existing checkpoint file is not authentic:[/red] {e}")
                raise typer.Exit(code=1) from None
            if existing.chain_id != checkpoint.chain_id:
                console.print(
                    "[red bold]WITNESS CHAIN MISMATCH[/red bold] — "
                    f"{output} commits to chain {existing.chain_id}; this log is "
                    f"chain {checkpoint.chain_id}. Refusing to rebind the witness."
                )
                raise typer.Exit(code=1)
            if existing != checkpoint and existing.head_sequence >= checkpoint.head_sequence:
                console.print(
                    "[red bold]WITNESS ROLLBACK REFUSED[/red bold] — "
                    f"{output} already commits to head sequence {existing.head_sequence}; "
                    f"this log's head is {checkpoint.head_sequence}."
                )
                raise typer.Exit(code=1)
        _write_witness(output, payload)
        console.print(
            f"[green]Checkpoint exported.[/green] head_sequence={checkpoint.head_sequence} "
            f"-> {output}"
        )

    asyncio.run(_export())


@audit_app.command("verify")
def audit_verify(
    log_dir: Path = typer.Option("./audit-logs", help="Audit log directory."),
    trusted_checkpoint: Path = typer.Option(
        None,
        help="Off-host checkpoint the log must still extend; detects a rolled-back log.",
    ),
) -> None:
    """Verify audit log HMAC chain integrity."""
    from agentguard.core.audit import AppendOnlyAuditLog, AuditCheckpoint, FileAuditBackend
    from agentguard.exceptions import AuditRollbackDetectedError, AuditTamperDetectedError

    async def _verify() -> None:
        try:
            anchor = (
                AuditCheckpoint.model_validate_json(trusted_checkpoint.read_text(encoding="utf-8"))
                if trusted_checkpoint is not None
                else None
            )
        except (OSError, ValueError) as e:
            console.print(f"[red]Trusted checkpoint unreadable:[/red] {e}")
            raise typer.Exit(code=1) from None
        try:
            log = AppendOnlyAuditLog(
                backend=FileAuditBackend(directory=log_dir),
                trusted_checkpoint=anchor,
            )
            result = await log.verify_chain()
            if result.valid:
                console.print(
                    f"[green]Audit chain verified.[/green]"
                    f" {result.event_count} events, no tampering detected."
                )
        except AuditRollbackDetectedError as e:
            console.print(
                f"[red bold]ROLLBACK DETECTED[/red bold] — local head sequence "
                f"{e.local_head_sequence} is behind trusted checkpoint head "
                f"{e.trusted_head_sequence}."
            )
            raise typer.Exit(code=1) from None
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
def policy_validate(
    policy_dir: Path = typer.Option(None, help="Policy YAML directory."),
) -> None:
    """Validate and list all loaded policy rules."""
    from agentguard.compliance.engine import PolicyEngine
    from agentguard.exceptions import PolicyLoadError

    dirs = [policy_dir] if policy_dir else None
    try:
        engine = PolicyEngine(policy_dirs=dirs)
    except PolicyLoadError as e:
        console.print(f"[red]Policy load failed:[/red] {e}")
        raise typer.Exit(code=1) from None

    table = Table(title="Loaded Policy Rules")
    table.add_column("Rule ID", style="bold")
    table.add_column("Name")
    table.add_column("Severity")
    table.add_column("Check Type")
    table.add_column("Enabled")

    for rule in engine.all_rules:
        sev_style = {
            "critical": "red bold",
            "high": "red",
            "medium": "yellow",
            "low": "green",
        }.get(rule.severity, "white")
        table.add_row(
            rule.id,
            rule.name,
            f"[{sev_style}]{rule.severity}[/{sev_style}]",
            rule.check.get("type", "unknown"),
            "yes" if rule.enabled else "no",
        )

    console.print(table)
    console.print(
        f"\n[green]{len(engine.policy_sets)} policy set(s), "
        f"{len(engine.all_rules)} rule(s) loaded.[/green]"
    )


@policy_app.command("report")
def policy_report(
    log_dir: Path = typer.Option("./audit-logs", help="Audit log directory."),
    policy_dir: Path = typer.Option(None, help="Policy YAML directory."),
    output_format: str = typer.Option("markdown", help="Output format: json or markdown."),
    trusted_checkpoint: Path = typer.Option(
        None,
        help="Out-of-band trusted audit checkpoint required for clean attestation.",
    ),
) -> None:
    """Generate a compliance report from audit events."""
    from agentguard.compliance.engine import PolicyEngine
    from agentguard.compliance.reporter import ComplianceReporter
    from agentguard.core.audit import AppendOnlyAuditLog, AuditCheckpoint, FileAuditBackend
    from agentguard.exceptions import AuditError, PolicyLoadError

    async def _report() -> None:
        backend = FileAuditBackend(directory=log_dir)
        events = await backend.read_all()

        if not events:
            console.print("[yellow]No audit events found.[/yellow]")
            return

        dirs = [policy_dir] if policy_dir else None
        try:
            engine = PolicyEngine(policy_dirs=dirs)
        except PolicyLoadError as e:
            console.print(f"[red]Policy load failed:[/red] {e}")
            raise typer.Exit(code=1) from None
        reporter = ComplianceReporter(engine)
        try:
            anchor = (
                AuditCheckpoint.model_validate_json(trusted_checkpoint.read_text(encoding="utf-8"))
                if trusted_checkpoint is not None
                else None
            )
            report = await reporter.generate_report(
                AppendOnlyAuditLog(backend=backend, trusted_checkpoint=anchor)
            )
        except (AuditError, OSError, ValueError) as e:
            console.print(f"[red]Attestation refused:[/red] {e}")
            raise typer.Exit(code=1) from None

        if output_format == "json":
            console.print(reporter.to_json(report))
        else:
            console.print(reporter.to_markdown(report))

    asyncio.run(_report())


@verify_app.command("rbac")
def verify_rbac(
    config: Path = typer.Option(None, help="RBAC YAML config file."),
) -> None:
    """Formally verify RBAC configuration for privilege escalation.

    Config file schema:

        roles:
          - name: analyst
            permissions:
              - {action: "tool:*", resource: "bureau/*", effect: allow}
              - {action: "tool:admin", resource: "*", effect: deny}
          - name: admin
            permissions:
              - {action: "*", resource: "*", effect: allow}
        target_permission:
          action: tool:admin
          resource: admin/users
        forbidden_roles: [analyst]
    """
    from agentguard.core.rbac import Permission, Role

    if config is None:
        console.print(
            "[yellow]No RBAC config specified. Use --config to provide a YAML file.[/yellow]"
        )
        console.print("Example: agentguard verify rbac --config rbac_config.yaml")
        return

    if not config.exists():
        console.print(f"[red]Config file not found: {config}[/red]")
        raise typer.Exit(code=1)

    data = yaml.safe_load(config.read_text())
    raw_roles = data.get("roles", [])
    if not raw_roles:
        console.print("[yellow]No roles defined in config.[/yellow]")
        return

    # Build Pydantic Role objects for the verifier
    roles: list[Role] = []
    for r in raw_roles:
        perms = [
            Permission(action=p["action"], resource=p["resource"], effect=p["effect"])
            for p in r.get("permissions", [])
        ]
        roles.append(
            Role(
                name=r["name"],
                permissions=perms,
                inherited_roles=r.get("inherited_roles", []),
            )
        )

    # Compute the target permission index (matching the verifier's sort order)
    all_perms: set[tuple[str, str]] = set()
    for role in roles:
        for p in role.permissions:
            all_perms.add((p.action, p.resource))
    perm_list = sorted(all_perms)

    target_action = data.get("target_permission", {}).get("action", "")
    target_resource = data.get("target_permission", {}).get("resource", "")
    try:
        target_index = perm_list.index((target_action, target_resource))
    except ValueError:
        console.print(
            f"[red]Target permission ({target_action}, {target_resource}) "
            f"not referenced by any role.[/red]"
        )
        raise typer.Exit(code=1) from None

    forbidden_roles = data.get("forbidden_roles", [])

    try:
        from agentguard.compliance.formal_verifier import FormalVerifier

        verifier = FormalVerifier()
        result = verifier.verify_rbac_escalation(
            roles=roles,
            target_permission_index=target_index,
            forbidden_roles=forbidden_roles,
        )
    except ImportError:
        console.print(
            "[red]z3-solver is required for formal verification.[/red]\n"
            "Install with: pip install 'agentguard\\[verify]'"
        )
        raise typer.Exit(code=1) from None

    if result.status == "unsat":
        console.print(
            f"[green]RBAC verified.[/green] No privilege escalation path to "
            f"({target_action}, {target_resource}) from forbidden roles "
            f"{forbidden_roles}."
        )
    elif result.status == "sat":
        console.print(
            f"[red bold]PRIVILEGE ESCALATION DETECTED[/red bold] — "
            f"forbidden roles can reach ({target_action}, {target_resource})."
        )
        if result.counterexample:
            console.print(f"[red]Counterexample:[/red] {result.counterexample}")
        raise typer.Exit(code=1)
    else:
        console.print(f"[yellow]Verification result: {result.status}[/yellow]")
        raise typer.Exit(code=2)


@verify_app.command("policy")
def verify_policy(
    policy_dir: Path = typer.Option(None, help="Policy YAML directory."),
) -> None:
    """Check policy set for contradictions and dead rules."""
    from agentguard.compliance.engine import PolicyEngine
    from agentguard.exceptions import PolicyLoadError

    dirs = [policy_dir] if policy_dir else None
    try:
        engine = PolicyEngine(policy_dirs=dirs)
    except PolicyLoadError as e:
        console.print(f"[red]Policy load failed:[/red] {e}")
        raise typer.Exit(code=1) from None

    rules = tuple(engine.all_rules)
    if not rules:
        console.print("[yellow]No policy rules found to verify.[/yellow]")
        return
    console.print(
        "[yellow]Policy verification is unsupported for declarative checks: "
        "no authorization effect is inferred from severity.[/yellow]"
    )
    raise typer.Exit(code=2)


@observe_app.command("dashboard")
def observe_dashboard(
    log_dir: Path = typer.Option("./audit-logs", help="Audit log directory."),
    output_format: str = typer.Option("markdown", help="Output format: json or markdown."),
) -> None:
    """Compute aggregate governance metrics from audit events."""
    from agentguard.core.audit import FileAuditBackend
    from agentguard.observability.dashboard import MetricsDashboard

    async def _dashboard() -> None:
        backend = FileAuditBackend(directory=log_dir)
        events = await backend.read_all()
        dashboard = MetricsDashboard()
        metrics = dashboard.compute(events)

        if output_format == "json":
            console.print(dashboard.to_json(metrics))
        else:
            console.print(dashboard.to_markdown(metrics))

    asyncio.run(_dashboard())


@observe_app.command("replay")
def observe_replay(
    log_dir: Path = typer.Option("./audit-logs", help="Audit log directory."),
    agent_id: str | None = typer.Option(None, help="Filter by agent ID."),
    action: str | None = typer.Option(None, help="Filter by action substring."),
    result: str | None = typer.Option(
        None, help="Filter by result: allowed, denied, escalated, error."
    ),
    start_time: str | None = typer.Option(
        None, help="Filter start time (ISO 8601, e.g. 2026-04-10T12:00:00+00:00)."
    ),
    end_time: str | None = typer.Option(None, help="Filter end time (ISO 8601)."),
) -> None:
    """Filtered replay of audit events with governance decision summaries."""
    from agentguard.observability.replay import ReplayDebugger

    async def _replay() -> None:
        debugger = ReplayDebugger()
        events = await debugger.load(log_dir)

        start_dt = _parse_iso_utc(start_time)
        end_dt = _parse_iso_utc(end_time)

        filtered = debugger.filter(
            events,
            agent_id=agent_id,
            action=action,
            result=result,
            start_time=start_dt,
            end_time=end_dt,
        )

        if not filtered:
            console.print("[yellow]No events match the given filters.[/yellow]")
            return

        timeline = debugger.timeline(filtered)
        for entry in timeline:
            flag_str = f" [dim]({', '.join(entry.flags)})[/dim]" if entry.flags else ""
            console.print(f"[bold]{entry.index + 1}.[/bold] {entry.decision_summary}{flag_str}")

        console.print(f"\n[green]{len(filtered)} events shown.[/green]")

    asyncio.run(_replay())


@observe_app.command("summary")
def observe_summary(
    log_dir: Path = typer.Option("./audit-logs", help="Audit log directory."),
) -> None:
    """Quick counts by result/agent/action."""
    from agentguard.core.audit import FileAuditBackend
    from agentguard.observability.replay import ReplayDebugger

    async def _summary() -> None:
        backend = FileAuditBackend(directory=log_dir)
        events = await backend.read_all()
        debugger = ReplayDebugger()
        summary = debugger.summarize(events)

        console.print(f"[bold]Total events:[/bold] {summary['total_events']}")
        console.print("\n[bold]By result:[/bold]")
        for k, v in summary["by_result"].items():
            console.print(f"  {k}: {v}")
        console.print("\n[bold]By agent:[/bold]")
        for k, v in sorted(summary["by_agent"].items(), key=lambda x: -x[1])[:10]:
            console.print(f"  {k}: {v}")
        console.print("\n[bold]Top actions:[/bold]")
        for k, v in sorted(summary["by_action"].items(), key=lambda x: -x[1])[:10]:
            console.print(f"  {k}: {v}")

    asyncio.run(_summary())


if __name__ == "__main__":  # pragma: no cover
    app()
