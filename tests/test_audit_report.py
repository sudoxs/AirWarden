"""Tests for the combined per-AP enumeration report."""

from __future__ import annotations

import io
import json
from pathlib import Path

from rich.console import Console

from airwarden.audit_report import assemble, render, to_json_file
from airwarden.handshake_detector import HandshakeEvidence
from airwarden.pcap_extractor import Artifact
from airwarden.scan_ingestor import ScanAP, ScanClient, ScanResult


def _scan() -> ScanResult:
    res = ScanResult()
    res.aps["aa:bb:cc:dd:ee:01"] = ScanAP(
        "aa:bb:cc:dd:ee:01", essid="corp", channel=44, band="5GHz",
        enc="WPA2", auth="PSK", clients=["11:22:33:44:55:66"],
    )
    res.clients.append(ScanClient("11:22:33:44:55:66", bssid="aa:bb:cc:dd:ee:01"))
    return res


def test_assemble_structure() -> None:
    arts = [Artifact("HTTP_COOKIE", 7, bssid="aa:bb:cc:dd:ee:01", snippet="cookie",
                     wireshark_filter="http.cookie && frame.number == 7")]
    hs = [HandshakeEvidence(bssid="aa:bb:cc:dd:ee:01", client="11:22:33:44:55:66",
                            complete_handshake=True, frames=[3, 4])]
    report = assemble(_scan(), arts, hs)
    assert report["summary"]["aps_total"] == 1
    ap = report["aps"][0]
    assert ap["bssid"] == "aa:bb:cc:dd:ee:01"
    assert ap["handshake"]["complete"] is True
    assert ap["artifacts"][0]["wireshark_filter"].startswith("http.cookie")
    assert any(r["category"] == "WPA2-PSK" for r in ap["applicability"])
    # the WPA2-PSK row is "high" because a handshake was captured
    psk = next(r for r in ap["applicability"] if r["category"] == "WPA2-PSK")
    assert psk["priority"] == "high"


def test_json_roundtrip(tmp_path: Path) -> None:
    report = assemble(_scan(), [], [])
    out = tmp_path / "survey.json"
    to_json_file(report, out)
    loaded = json.loads(out.read_text(encoding="utf-8"))
    assert loaded["summary"]["aps_total"] == 1


def test_render_does_not_crash() -> None:
    console = Console(file=io.StringIO(), width=120)
    render(console, assemble(_scan(), [], []))
    text = console.file.getvalue()
    assert "AirWarden enumeration" in text
    assert "corp" in text
