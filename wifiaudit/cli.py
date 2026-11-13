"""Command-line interface (Typer + Rich)."""

from __future__ import annotations

import json
import os
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.table import Table

from wifiaudit import __version__
from wifiaudit.advisor import has_active_suggestion, recommend_active_step
from wifiaudit.auth_gate import AuthorizationError, AuthorizationGate
from wifiaudit.bettercap_client import BettercapClient
from wifiaudit.config import load_settings, redact_mac
from wifiaudit.models import TargetAssessment
from wifiaudit.pcap_analyzer import analyze_pcap
from wifiaudit.report import to_html, to_json, top_finding
from wifiaudit.risk_scorer import score_target

EXIT_NOT_AUTHORIZED = 2
EXIT_STUB = 3

app = typer.Typer(
    help="wifiaudit — defensive WiFi audit tool for AUTHORIZED engagements only.",
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
        _console().print(f"wifiaudit {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            help="Show the wifiaudit version and exit.",
            callback=_version_callback,
            is_eager=True,
        ),
    ] = False,
) -> None:
    """wifiaudit — defensive WiFi audit tool for AUTHORIZED engagements only."""


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
            envvar="WIFIAUDIT_REDACT_MACS",
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
        typer.Option("--redact-macs/--no-redact-macs", envvar="WIFIAUDIT_REDACT_MACS"),
    ] = True,
) -> None:
    """Gated recon via Bettercap. Requires WIFIAUDIT_AUTHORIZED=1 and a scope file."""
    console = _console()
    if os.environ.get("WIFIAUDIT_AUTHORIZED") != "1":
        console.print(
            "[bold red]Active mode refused.[/] Set WIFIAUDIT_AUTHORIZED=1 only if you hold "
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


if __name__ == "__main__":
    app()
