"""Command-line interface (Typer + Rich)."""

from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from typing import Annotated, Any

import typer
from rich.console import Console, Group
from rich.live import Live
from rich.table import Table
from rich.text import Text
from scapy.all import AsyncSniffer

from airwarden import __version__
from airwarden.advisor import has_active_suggestion, recommend_active_step
from airwarden.auth_gate import AuthorizationError, AuthorizationGate
from airwarden.bettercap_client import BettercapClient
from airwarden.config import load_settings, redact_mac
from airwarden.exposure import classify_exposures, is_leak
from airwarden.live_analyzer import LiveAnalyzer
from airwarden.models import TargetAssessment
from airwarden.pcap_analyzer import analyze_pcap
from airwarden.report import to_html, to_json, top_finding
from airwarden.risk_scorer import score_target
from airwarden.state import is_potential

EXIT_CAPTURE = 1
EXIT_NOT_AUTHORIZED = 2
EXIT_STUB = 3

# How often the live view refreshes its snapshot (seconds). Patched low in tests.
_LIVE_POLL_SECONDS = 1.0
# 2.4 GHz channels swept when --hop is set.
_HOP_CHANNELS = tuple(range(1, 14))

app = typer.Typer(
    help="AirWarden — defensive WiFi audit tool for AUTHORIZED engagements only.",
    no_args_is_help=True,
    add_completion=False,
)


def _console() -> Console:
    return Console(highlight=False)


def _dash(v: Any) -> str:
    return "—" if v is None or v == "" else str(v)


def _yn(flag: bool) -> str:
    return "yes" if flag else "no"


def _stub_exit(console: Console, module: str) -> typer.Exit:
    console.print(
        f"[bold yellow]{module} is not available yet[/]: this build ships a stub that is "
        "replaced at integration time. Nothing was analyzed or sent."
    )
    return typer.Exit(EXIT_STUB)


def _version_callback(value: bool) -> None:
    if value:
        _console().print(f"AirWarden {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            help="Show the AirWarden version and exit.",
            callback=_version_callback,
            is_eager=True,
        ),
    ] = False,
) -> None:
    """AirWarden — defensive WiFi audit tool for AUTHORIZED engagements only."""


def _assessment_table(assessments: list[TargetAssessment], redact: bool) -> Table:
    table = Table(title="Access points (sorted by risk)")
    for col in ("BSSID", "SSID", "CH", "ENC", "WPS", "PMF", "Risk", "HS", "PMKID", "Top finding"):
        table.add_column(col, justify="right" if col in ("CH", "Risk") else "left")
    for t in assessments:
        ap = t.ap
        top = top_finding(t)
        table.add_row(
            _dash(redact_mac(ap.bssid) if redact else ap.bssid),
            _dash(ap.ssid),
            _dash(ap.channel),
            _dash(getattr(ap.encryption, "value", ap.encryption)),
            _yn(ap.wps_enabled),
            _yn(ap.pmf_enabled),
            f"{t.risk_score:.1f}",
            _yn(t.handshake_captured),
            _yn(t.pmkid_captured),
            _dash(top.code if top else None),
        )
    return table


def _active_followup_table(assessments: list[TargetAssessment], redact: bool) -> Table | None:
    """Render described active follow-up steps; ``None`` if nothing is suggested."""
    table = Table(title="Active follow-up (authorized engagements only)")
    for col in ("BSSID", "CH", "Action", "Pri", "Why / what it reveals"):
        table.add_column(col, justify="right" if col == "CH" else "left")
    any_row = False
    for t in assessments:
        rec = recommend_active_step(t)
        if not has_active_suggestion(rec):
            continue
        any_row = True
        ap = t.ap
        table.add_row(
            _dash(redact_mac(ap.bssid) if redact else ap.bssid),
            _dash(rec.channel),
            rec.action,
            rec.priority,
            f"{rec.rationale} {rec.yields}",
        )
    return table if any_row else None


def _set_channel(interface: str, channel: int) -> bool:
    """Best-effort channel set via ``iw`` (Linux). Returns False if it did not work."""
    try:
        subprocess.run(
            ["iw", "dev", interface, "set", "channel", str(channel)],
            check=True,
            capture_output=True,
            timeout=5,
        )
        return True
    except Exception:
        return False


class _ChannelHopper(threading.Thread):
    """Daemon thread that sweeps channels so a single radio can see the whole band."""

    def __init__(self, interface: str, channels: tuple[int, ...]) -> None:
        super().__init__(daemon=True)
        self._interface = interface
        self._channels = channels
        self._stop = threading.Event()

    def run(self) -> None:
        i = 0
        while not self._stop.is_set():
            _set_channel(self._interface, self._channels[i % len(self._channels)])
            i += 1
            self._stop.wait(0.4)

    def stop(self) -> None:
        self._stop.set()


def _scored_snapshot(analyzer: LiveAnalyzer) -> tuple[list[TargetAssessment], dict]:
    assessments, meta = analyzer.snapshot()
    for t in assessments:
        t.risk_score = score_target(t)
    assessments.sort(key=lambda t: t.risk_score, reverse=True)
    return assessments, meta


def _live_renderable(assessments: list[TargetAssessment], meta: dict, redact: bool) -> Group:
    scan_type = _dash(getattr(meta.get("scan_type"), "value", meta.get("scan_type")))
    header = Text(
        f"Live — scan type: {scan_type}   "
        f"APs: {meta.get('aps_total', 0)}   frames: {meta.get('frames_total', 0)}",
        style="bold",
    )
    items: list[Any] = [header, _assessment_table(assessments, redact)]
    active = _active_followup_table(assessments, redact)
    if active is not None:
        items.append(active)
    return Group(*items)


@app.command()
def analyze(
    pcap: Annotated[str, typer.Argument(help="Path to a pcap/pcapng capture.")],
    output_prefix: Annotated[
        str | None,
        typer.Option("--output-prefix", "-o", help="Prefix for <prefix>.json / <prefix>.html."),
    ] = None,
    redact_macs: Annotated[
        bool,
        typer.Option(
            "--redact-macs/--no-redact-macs",
            envvar="AIRWARDEN_REDACT_MACS",
            help="Zero the last 3 octets of every MAC in output.",
        ),
    ] = True,
) -> None:
    """Passively analyze a capture, score each AP, and write JSON + HTML reports."""
    console = _console()
    settings = load_settings(pcap_path=pcap, output_prefix=output_prefix, redact_macs=redact_macs)

    try:
        # TODO(integration): pcap_analyzer is a stub — replaced at integration time.
        assessments, meta = analyze_pcap(settings.pcap_path)
    except NotImplementedError:
        raise _stub_exit(console, "pcap_analyzer") from None
    except OSError as exc:
        console.print(f"[bold red]Cannot read capture[/] {settings.pcap_path!r}: {exc}")
        raise typer.Exit(1) from None

    try:
        for t in assessments:
            # TODO(integration): risk_scorer is a stub — replaced at integration time.
            t.risk_score = score_target(t)
    except NotImplementedError:
        raise _stub_exit(console, "risk_scorer") from None

    assessments.sort(key=lambda t: t.risk_score, reverse=True)

    json_path = f"{settings.output_prefix}.json"
    html_path = f"{settings.output_prefix}.html"
    to_json(assessments, meta, json_path, redact_macs=settings.redact_macs)
    to_html(assessments, meta, html_path, redact_macs=settings.redact_macs)

    scan_type = meta.get("scan_type")
    console.print(f"Scan type: [bold]{_dash(getattr(scan_type, 'value', scan_type))}[/]")
    console.print(_assessment_table(assessments, settings.redact_macs))

    active_table = _active_followup_table(assessments, settings.redact_macs)
    if active_table is not None:
        console.print(active_table)
    else:
        console.print("Active follow-up: none suggested.")

    evil = meta.get("evil_twin_ssids") or []
    if evil:
        console.print(f"Evil-twin bait (probed, not in range): [bold]{', '.join(evil)}[/]")

    all_findings = [f for t in assessments for f in t.findings]
    potential = sum(1 for f in all_findings if is_potential(f))
    confirmed = len(all_findings) - potential
    console.print(f"Issues — [bold]confirmed:[/] {confirmed}  [bold]potential:[/] {potential}")

    exposures = [e for t in assessments for e in classify_exposures(t.findings)]
    leaks = sorted({e.what for e in exposures if is_leak(e)})
    if exposures:
        tail = f" — data leaks: {', '.join(leaks)}" if leaks else ""
        console.print(f"Exposures classified: {len(exposures)}{tail}")

    console.print(f"Wrote {json_path} and {html_path}")


def _ap_list_table(aps: dict, redact: bool) -> Table | None:
    """Render a Bettercap-style ``{"aps": [...]}`` payload; ``None`` if shape is unknown."""
    entries = aps.get("aps")
    if not isinstance(entries, list) or not all(isinstance(e, dict) for e in entries):
        return None
    table = Table(title="Discovered access points")
    for col in ("BSSID", "SSID", "CH", "ENC", "Clients"):
        table.add_column(col)
    for e in entries:
        bssid = e.get("bssid") or e.get("mac") or ""
        clients = e.get("clients")
        table.add_row(
            _dash(redact_mac(bssid) if redact and bssid else bssid),
            _dash(e.get("ssid") or e.get("hostname")),
            _dash(e.get("channel")),
            _dash(e.get("encryption")),
            _dash(len(clients) if isinstance(clients, list) else clients),
        )
    return table


@app.command()
def active(
    interface: Annotated[
        str | None,
        typer.Option("--interface", "-i", help="Monitor-mode interface (informational)."),
    ] = None,
    pmkid: Annotated[
        str | None,
        typer.Option("--pmkid", help="Capture a PMKID from this single in-scope BSSID."),
    ] = None,
    redact_macs: Annotated[
        bool,
        typer.Option("--redact-macs/--no-redact-macs", envvar="AIRWARDEN_REDACT_MACS"),
    ] = True,
) -> None:
    """Gated recon via Bettercap. Requires AIRWARDEN_AUTHORIZED=1 and a scope file."""
    console = _console()
    if os.environ.get("AIRWARDEN_AUTHORIZED") != "1":
        console.print(
            "[bold red]Active mode refused.[/] Set AIRWARDEN_AUTHORIZED=1 only if you hold "
            "written authorization for this engagement and a valid scope file."
        )
        raise typer.Exit(EXIT_NOT_AUTHORIZED)

    settings = load_settings(interface=interface, redact_macs=redact_macs)
    console.print(f"Interface: {settings.interface}  Scope: {settings.scope_path}")

    try:
        # TODO(integration): auth_gate is a stub — replaced at integration time.
        gate = AuthorizationGate(settings.scope_path)
        # TODO(integration): bettercap_client is a stub — replaced at integration time.
        client = BettercapClient(
            settings.bettercap_url,
            settings.bettercap_user,
            settings.bettercap_pass,
            gate=gate,
        )
        # TODO(integration): bettercap_client is a stub — replaced at integration time.
        client.start_recon()
        # TODO(integration): bettercap_client is a stub — replaced at integration time.
        aps = client.list_aps()

        table = _ap_list_table(aps, settings.redact_macs)
        console.print(table if table is not None else json.dumps(aps, indent=2, default=str))

        if pmkid:
            # TODO(integration): bettercap_client is a stub — replaced at integration time.
            result = client.capture_pmkid(pmkid)
            console.print(
                f"PMKID capture for {redact_mac(pmkid) if settings.redact_macs else pmkid}:"
            )
            console.print(json.dumps(result, indent=2, default=str))
    except NotImplementedError:
        raise _stub_exit(console, "auth_gate / bettercap_client") from None
    except AuthorizationError as exc:
        console.print(f"[bold red]Not authorized:[/] {exc}")
        raise typer.Exit(EXIT_NOT_AUTHORIZED) from None


@app.command()
def live(
    interface: Annotated[
        str,
        typer.Option("--interface", "-i", help="Monitor-mode interface to sniff."),
    ],
    channel: Annotated[
        int | None,
        typer.Option("--channel", "-c", help="Lock to this channel (Linux; needs 'iw')."),
    ] = None,
    hop: Annotated[
        bool,
        typer.Option("--hop/--no-hop", help="Sweep 2.4 GHz channels 1-13 (Linux; needs 'iw')."),
    ] = False,
    duration: Annotated[
        float | None,
        typer.Option("--duration", "-t", help="Stop after N seconds (default: until Ctrl-C)."),
    ] = None,
    output_prefix: Annotated[
        str | None,
        typer.Option("--output-prefix", "-o", help="Write <prefix>.json/.html on exit."),
    ] = None,
    write_pcap: Annotated[
        str | None,
        typer.Option("--write-pcap", help="Also save the captured frames to this pcap."),
    ] = None,
    redact_macs: Annotated[
        bool,
        typer.Option("--redact-macs/--no-redact-macs", envvar="AIRWARDEN_REDACT_MACS"),
    ] = True,
) -> None:
    """Sniff a monitor-mode interface and detect in real time (passive; nothing is sent)."""
    console = _console()
    settings = load_settings(interface=interface, redact_macs=redact_macs)
    console.print(
        "[bold]airwarden live[/] — passive monitoring, authorized engagement only. "
        "Frames are received only; nothing is transmitted."
    )

    analyzer = LiveAnalyzer()
    try:
        sniffer = AsyncSniffer(
            iface=settings.interface,
            prn=analyzer.process,
            store=bool(write_pcap),
            monitor=True,
        )
        sniffer.start()
    except Exception as exc:
        console.print(
            f"[bold red]Cannot start live capture on {settings.interface!r}:[/] {exc}\n"
            "Live capture needs a monitor-mode interface and root (Linux)."
        )
        raise typer.Exit(EXIT_CAPTURE) from None

    hopper: _ChannelHopper | None = None
    if channel is not None:
        if not _set_channel(settings.interface, channel):
            console.print(f"[yellow]Could not set channel {channel} (needs Linux + 'iw').[/]")
    elif hop:
        hopper = _ChannelHopper(settings.interface, _HOP_CHANNELS)
        hopper.start()

    start = time.monotonic()
    try:
        with Live(console=console, refresh_per_second=4, screen=False) as view:
            while True:
                assessments, meta = _scored_snapshot(analyzer)
                view.update(_live_renderable(assessments, meta, settings.redact_macs))
                if duration is not None and time.monotonic() - start >= duration:
                    break
                time.sleep(_LIVE_POLL_SECONDS)
    except KeyboardInterrupt:
        pass
    finally:
        sniffer.stop()
        if hopper is not None:
            hopper.stop()

    assessments, meta = _scored_snapshot(analyzer)
    console.print(
        f"Stopped. Observed {meta['aps_total']} AP(s) in {meta['frames_total']} frame(s)."
    )

    if write_pcap:
        try:
            from scapy.all import wrpcap

            wrpcap(write_pcap, sniffer.results)
            console.print(f"Wrote capture to {write_pcap}")
        except Exception as exc:
            console.print(f"[yellow]Could not write pcap: {exc}[/]")

    if output_prefix:
        json_path = f"{output_prefix}.json"
        html_path = f"{output_prefix}.html"
        to_json(assessments, meta, json_path, redact_macs=settings.redact_macs)
        to_html(assessments, meta, html_path, redact_macs=settings.redact_macs)
        console.print(f"Wrote {json_path} and {html_path}")


if __name__ == "__main__":
    app()
