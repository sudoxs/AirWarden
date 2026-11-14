"""Combined per-AP enumeration report: scan model + artifacts + handshake + matrix.

Produces a JSON structure (for tooling and lab documentation) and a readable CLI
rendering. This is the "report" layer for the passive enumeration pipeline
(scan_ingestor -> pcap_extractor / handshake_detector -> attack_mapper); the
existing ``report.py`` remains the report for the pcap-analysis pipeline.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import asdict
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from airwarden.attack_mapper import map_all
from airwarden.handshake_detector import HandshakeEvidence
from airwarden.pcap_extractor import Artifact
from airwarden.scan_ingestor import ScanResult

FOOTER = "Passive enumeration for authorized lab documentation. No active actions performed."


def _by_bssid(artifacts: list[Artifact]) -> dict[str, list[Artifact]]:
    out: dict[str, list[Artifact]] = defaultdict(list)
    for a in artifacts:
        out[a.bssid or "(unattributed)"].append(a)
    return out


def assemble(
    scan: ScanResult,
    artifacts: list[Artifact] | None = None,
    handshakes: list[HandshakeEvidence] | None = None,
) -> dict[str, Any]:
    """Build the JSON-able combined report."""
    artifacts = artifacts or []
    handshakes = handshakes or []
    matrix = map_all(scan.aps, artifacts, handshakes)
    arts = _by_bssid(artifacts)
    hs_by: dict[str, list[HandshakeEvidence]] = defaultdict(list)
    for h in handshakes:
        hs_by[h.bssid].append(h)

    aps: list[dict[str, Any]] = []
    for bssid, ap in scan.aps.items():
        pairs = hs_by.get(bssid, [])
        aps.append(
            {
                "bssid": bssid,
                "essid": ap.essid,
                "channel": ap.channel,
                "band": ap.band,
                "enc": ap.enc,
                "cipher": ap.cipher,
                "auth": ap.auth,
                "wps_version": ap.wps_version,
                "wps_locked": ap.wps_locked,
                "pmf_capable": ap.pmf_capable,
                "pmf_required": ap.pmf_required,
                "hidden": ap.hidden,
                "wpa3_transition": ap.wpa3_transition,
                "clients": ap.clients,
                "probe_ssids": ap.probe_ssids,
                "artifacts": [asdict(a) for a in arts.get(bssid, [])],
                "handshake": {
                    "complete": any(h.complete_handshake for h in pairs),
                    "pmkid": any(h.pmkid for h in pairs),
                    "pairs": [asdict(h) for h in pairs],
                },
                "applicability": [asdict(r) for r in matrix.get(bssid, [])],
            }
        )

    return {
        "summary": {
            "aps_total": len(scan.aps),
            "clients_total": len(scan.clients),
            "artifacts_total": len(artifacts),
        },
        "aps": aps,
        "clients": [asdict(c) for c in scan.clients],
        "unattributed_artifacts": [asdict(a) for a in arts.get("(unattributed)", [])],
        "footer": FOOTER,
    }


def to_json_file(report: dict[str, Any], path: str | Path) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")


def render(console: Console, report: dict[str, Any]) -> None:
    """Render the combined report to a Rich console."""
    s = report["summary"]
    console.print(
        f"[bold]AirWarden enumeration[/] — APs: {s['aps_total']}  "
        f"clients: {s['clients_total']}  artifacts: {s['artifacts_total']}"
    )
    for ap in report["aps"]:
        essid = ap["essid"] or "<hidden>"
        header = (
            f"\n[bold]{essid}[/]  {ap['bssid']}  ch {ap['channel']} ({ap['band']})  "
            f"{ap['enc'] or '?'}/{ap['auth'] or '?'}"
        )
        hs = ap["handshake"]
        flags = []
        if hs["complete"]:
            flags.append("handshake")
        if hs["pmkid"]:
            flags.append("PMKID")
        if ap["wpa3_transition"]:
            flags.append("WPA3-transition")
        if ap["wps_version"]:
            flags.append(f"WPS {ap['wps_version']}")
        if flags:
            header += "  [" + ", ".join(flags) + "]"
        console.print(header)
        if ap["clients"] or ap["probe_ssids"]:
            console.print(
                f"  clients: {len(ap['clients'])}  probes: {', '.join(ap['probe_ssids']) or '—'}"
            )

        if ap["applicability"]:
            t = Table(title="  applicability (advisory)", title_justify="left", show_edge=False)
            for col in ("Category", "Pri", "Reason", "Preconditions", "Missing evidence"):
                t.add_column(col)
            for r in ap["applicability"]:
                t.add_row(
                    r["category"], r["priority"], r["reason"], r["preconditions"],
                    r["missing_evidence"] or "—",
                )
            console.print(t)

        if ap["artifacts"]:
            t = Table(title="  artifacts", title_justify="left", show_edge=False)
            for col in ("Kind", "Frame", "Evidence", "Wireshark filter"):
                t.add_column(col)
            for a in ap["artifacts"]:
                t.add_row(
                    a["kind"], str(a["frame"] or "—"), a["snippet"], a["wireshark_filter"]
                )
            console.print(t)

    console.print(f"\n{report['footer']}")
