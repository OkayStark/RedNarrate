"""RedNarrate CLI (Typer)."""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from ..config import get_settings
from ..parsers import collect_inputs

app = typer.Typer(add_completion=False, help="AI-powered pentest report generation.")
console = Console()

_SEV_STYLE = {
    "Critical": "bold white on red",
    "High": "bold red",
    "Medium": "yellow",
    "Low": "blue",
    "Informational": "dim",
}


@app.command()
def run(
    evidence: Path = typer.Argument(..., help="Folder (or file) of tool outputs"),
    client: str = typer.Option("Client", "--client", "-c", help="Client name"),
    scope: str = typer.Option("", "--scope", "-s", help="Tested scope description"),
    dates: str = typer.Option("", "--dates", "-d", help="Engagement dates"),
    provider: Optional[str] = typer.Option(
        None, "--provider", "-p", help="LLM provider override: anthropic|ollama|none"
    ),
    model: Optional[str] = typer.Option(
        None, "--model", "-m", help="Ollama model override (e.g. qwen2.5:14b)"
    ),
    no_checkpoint: bool = typer.Option(False, "--no-checkpoint", help="Disable checkpointing"),
):
    """Run the full pipeline on a folder of evidence."""
    import os
    from ..graph import run_pipeline
    from ..config import _reset_settings
    from ..llm import reset_llm_cache

    if provider:
        os.environ["REDNARRATE_LLM_PROVIDER"] = provider
        _reset_settings()
        reset_llm_cache()
    if model:
        os.environ["REDNARRATE_OLLAMA_MODEL"] = model
        _reset_settings()
        reset_llm_cache()

    settings = get_settings()

    inputs, notes = collect_inputs(evidence)
    for n in notes:
        console.print(f"[dim]· {n}[/dim]")
    if not inputs:
        console.print("[red]No recognized tool outputs found.[/red]")
        raise typer.Exit(1)

    console.print(f"[bold]Detected inputs:[/bold] {', '.join(inputs)}")
    meta = {
        "scan_id": uuid.uuid4().hex,
        "client_name": client,
        "scope": scope,
        "engagement_dates": dates,
        "llm_provider": provider or settings.llm_provider,
        "raw_inputs": inputs,
    }

    steps = {"ingest": "Ingesting", "correlate": "Correlating",
             "score": "Scoring", "write": "Writing report"}
    with console.status("[bold green]Running pipeline...") as status:
        def progress(step):
            status.update(f"[bold green]{steps.get(step, step)}...")

        final = run_pipeline(meta, db_path=settings.db_path,
                             checkpoint=not no_checkpoint, progress=progress)

    if final.get("errors"):
        console.print("[red]Pipeline failed:[/red]")
        for e in final["errors"]:
            console.print(f"  [red]· {e}[/red]")
        raise typer.Exit(1)

    _print_findings(final.get("scored_findings", []))
    chains = final.get("attack_chains", [])
    if chains:
        console.print(f"\n[bold]Attack chains:[/bold] {len(chains)}")
        for c in chains:
            console.print(f"  · {c.get('name')} ({' → '.join(c.get('finding_ids', []))})")

    for w in final.get("warnings", []):
        console.print(f"[dim yellow]! {w}[/dim yellow]")

    console.print("\n[bold green]Report written:[/bold green]")
    for fmt, path in final.get("report_paths", {}).items():
        console.print(f"  {fmt.upper()}: {path}")


def _print_findings(findings: list[dict]) -> None:
    table = Table(title="Findings", show_lines=False)
    table.add_column("ID"); table.add_column("Finding")
    table.add_column("Severity"); table.add_column("CVSS", justify="right")
    table.add_column("Asset")
    for f in findings:
        sev = f.get("severity") or "Informational"
        asset = f"{f.get('host')}{':' + str(f['port']) if f.get('port') else ''}"
        table.add_row(
            f.get("id", ""), f.get("name", ""),
            f"[{_SEV_STYLE.get(sev, '')}]{sev}[/]",
            f"{f.get('cvss_score'):.1f}" if f.get("cvss_score") is not None else "—",
            asset,
        )
    console.print(table)


@app.command("ingest-kb")
def ingest_kb(
    knowledge: Optional[Path] = typer.Option(None, "--knowledge", help="Knowledge dir"),
):
    """Build the RAG knowledge base from the knowledge/ corpus."""
    from ..rag.ingest import build_knowledge_base

    settings = get_settings()
    kdir = str(knowledge) if knowledge else settings.knowledge_dir
    with console.status("[bold green]Chunking + embedding knowledge base..."):
        try:
            n = build_knowledge_base(knowledge_dir=kdir)
        except Exception as exc:
            console.print(f"[red]Knowledge base build failed: {exc}[/red]")
            raise typer.Exit(1)
    console.print(f"[green]Indexed {n} chunks into '{settings.chroma_dir}'.[/green]")


@app.command("list-scans")
def list_scans(limit: int = typer.Option(20, help="Max rows")):
    """List past scans."""
    from ..db import repository as repo

    settings = get_settings()
    repo.init_db(settings.db_path)
    scans = repo.list_scans(limit, db_path=settings.db_path)
    if not scans:
        console.print("[dim]No scans yet.[/dim]")
        return
    table = Table(title="Scans")
    table.add_column("ID"); table.add_column("Client"); table.add_column("Status")
    table.add_column("Created")
    for s in scans:
        table.add_row(s["id"][:8], s.get("client_name", ""),
                      s.get("status", ""), str(s.get("created_at", "")))
    console.print(table)


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", help="Bind host"),
    port: int = typer.Option(8000, help="Bind port"),
):
    """Launch the web UI (upload → status → download)."""
    import uvicorn

    uvicorn.run("rednarrate.api.app:app", host=host, port=port, factory=False)


if __name__ == "__main__":
    app()
