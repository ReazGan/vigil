"""Command line interface.

Three verbs: ``replay`` a pcap, sniff ``live``, or list the ``rules`` the
engine ships with. Output is human-readable by default and ``--json`` for
piping into something else. The CLI is a thin shell over Pipeline; all the
logic lives in the library.
"""

from __future__ import annotations

import json
import time

import click

from . import __version__
from .models import Alert, Severity
from .pipeline import Pipeline

_SEV_STYLE = {
    Severity.LOW: "green",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "red",
    Severity.CRITICAL: "bold white on red",
}


def _console():
    from rich.console import Console

    return Console()


def _print_alert(console, alert: Alert) -> None:
    style = _SEV_STYLE[alert.severity]
    stamp = time.strftime("%H:%M:%S", time.localtime(alert.ts))
    console.print(
        f"[dim]{stamp}[/] [{style}] {alert.severity.label:8} [/] "
        f"[bold]{alert.category}[/]  {alert.summary}"
    )


def _print_summary(console, pipeline: Pipeline, packets: int, elapsed: float) -> None:
    from rich.table import Table

    stats = pipeline.stats()
    traffic = stats["traffic"]
    alerts = stats["alerts"]
    pps = packets / elapsed if elapsed > 0 else 0.0

    console.print()
    console.rule("[bold]Summary")
    console.print(
        f"Packets: [bold]{packets:,}[/]   "
        f"Bytes: [bold]{traffic['total_bytes']:,}[/]   "
        f"Flows: [bold]{traffic['flows']:,}[/]   "
        f"Throughput: [bold]{pps:,.0f}[/] pkt/s"
    )
    console.print(
        f"Events: [bold]{alerts['total_events']}[/]   "
        f"(from {alerts['total_raw_alerts']:,} raw detections)"
    )

    if alerts["by_category"]:
        table = Table(show_header=True, header_style="bold")
        table.add_column("Category")
        table.add_column("Events", justify="right")
        for category, count in sorted(
            alerts["by_category"].items(), key=lambda kv: kv[1], reverse=True
        ):
            table.add_row(category, str(count))
        console.print(table)
    else:
        console.print("[green]No alerts raised.[/]")


@click.group(help="vigil: network intrusion detection engine.")
@click.version_option(__version__, prog_name="vigil")
def cli() -> None:
    pass


@cli.command(help="Run the engine over a pcap/pcapng file.")
@click.argument("pcap", type=click.Path(exists=True, dir_okay=False))
@click.option("--json", "as_json", is_flag=True, help="Emit one JSON object per alert.")
@click.option("--limit", type=int, default=0, help="Stop after N packets (0 = all).")
def replay(pcap: str, as_json: bool, limit: int) -> None:
    from .capture.pcap import PcapSource

    pipeline = Pipeline()
    console = None if as_json else _console()
    if console:
        console.print(f"[dim]Replaying[/] {pcap}")

    packets = 0
    start = time.perf_counter()
    for pkt in PcapSource(pcap):
        packets += 1
        for alert in pipeline.process(pkt):
            if as_json:
                click.echo(json.dumps(alert.as_dict()))
            else:
                _print_alert(console, alert)
        if limit and packets >= limit:
            break
    elapsed = time.perf_counter() - start

    if console:
        _print_summary(console, pipeline, packets, elapsed)


@cli.command(help="Sniff a live interface (needs privileges; Npcap on Windows).")
@click.option("--iface", default=None, help="Interface name. Default: scapy's choice.")
@click.option("--bpf", default=None, help="BPF capture filter, e.g. 'tcp or udp port 53'.")
@click.option("--json", "as_json", is_flag=True, help="Emit one JSON object per alert.")
def live(iface, bpf, as_json) -> None:
    from .capture.live import LiveSource

    pipeline = Pipeline()
    console = None if as_json else _console()
    if console:
        console.print(f"[dim]Sniffing[/] {iface or 'default interface'}  (Ctrl+C to stop)")

    packets = 0
    start = time.perf_counter()
    try:
        for pkt in LiveSource(iface=iface, bpf=bpf):
            packets += 1
            for alert in pipeline.process(pkt):
                if as_json:
                    click.echo(json.dumps(alert.as_dict()))
                else:
                    _print_alert(console, alert)
    except KeyboardInterrupt:
        pass
    elapsed = time.perf_counter() - start

    if console:
        _print_summary(console, pipeline, packets, elapsed)


@cli.command(help="List the detectors and signature rules the engine ships with.")
def rules() -> None:
    from rich.table import Table

    from .detect import build_all
    from .detect.signature import RULES

    console = _console()

    det_table = Table(title="Detectors", show_header=True, header_style="bold")
    det_table.add_column("Name")
    det_table.add_column("Category")
    det_table.add_column("Type")
    for det in build_all():
        kind = "signature" if det.name == "signature" else "behavioral"
        det_table.add_row(det.name, det.category, kind)
    console.print(det_table)

    sig_table = Table(title="Signature rules", show_header=True, header_style="bold")
    sig_table.add_column("ID")
    sig_table.add_column("Category")
    sig_table.add_column("Severity")
    for rule in RULES:
        sig_table.add_row(rule.id, rule.category, rule.severity.label)
    console.print(sig_table)


@cli.command(help="Serve the live dashboard and HTTP API.")
@click.option("--pcap", type=click.Path(exists=True, dir_okay=False), default=None,
              help="Replay this capture file as the traffic source.")
@click.option("--iface", default=None, help="Capture live from this interface instead.")
@click.option("--bpf", default=None, help="BPF filter for live capture.")
@click.option("--host", default="127.0.0.1", help="Bind address.")
@click.option("--port", default=8089, type=int, help="Bind port.")
@click.option("--loop/--no-loop", default=True, help="Loop the pcap replay (for demos).")
@click.option("--speed", default=8.0, type=float, help="Replay speed multiplier for --pcap.")
@click.option("--db", default=None, help="Persist events to this SQLite file (default: in-memory).")
def serve(pcap, iface, bpf, host, port, loop, speed, db) -> None:
    try:
        from .api.server import run_server
    except ImportError as exc:
        raise SystemExit(
            f"serve needs the api extra ({exc.name}). Install it: pip install -e \".[api]\""
        )
    run_server(pcap=pcap, iface=iface, bpf=bpf, host=host, port=port, loop=loop, speed=speed, db=db)


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
