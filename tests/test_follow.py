"""Tests for live-follow mode: CSV tailing, incremental parsing, and dedup."""
# ruff: noqa: E501  (airodump CSV header/rows are fixed-format data lines)

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

import airwarden.cli as cli
from airwarden.follow import (
    CsvTailer,
    DedupStore,
    Finding,
    findings_report,
    format_cli_line,
    session_summary,
)
from airwarden.scan_ingestor import IncrementalScan

runner = CliRunner()
ENV = {"COLUMNS": "200", "AIRWARDEN_REDACT_MACS": None, "AIRWARDEN_AUTHORIZED": None}

_CSV = """\
BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
AA:BB:CC:DD:EE:01, t, t, 6, 54, OPN, , , -20, 10, 0, 0.0.0.0, 8, FreeWiFi,
F0:9F:C2:71:22:11, t, t, 3, 54, WEP, WEP, , -31, 401, 2100, 0.0.0.0, 8, wifi-old,

Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs
78:C1:A7:BF:72:46, t, t, -52, 27, (not associated), wifi-offices,Jason
"""

_AP_HEADER = "BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key"
_CLIENT_HEADER = "Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs"
_AP_ROW = "AA:BB:CC:DD:EE:01, t, t, 6, 54, OPN, , , -20, 10, 0, 0.0.0.0, 8, FreeWiFi,"
_CLIENT_ROW = "11:22:33:44:55:66, t, t, -30, 5, aa:bb:cc:dd:ee:01,"


# ---------------------------------------------------------------------------
# CsvTailer
# ---------------------------------------------------------------------------


def test_tailer_reads_only_new_lines(tmp_path: Path) -> None:
    p = tmp_path / "scan.csv"
    p.write_text("a\nb\n", encoding="utf-8")
    tailer = CsvTailer(p)
    rotated, lines = tailer.poll()
    assert rotated is False
    assert lines == ["a", "b"]
    # No new bytes → no lines.
    assert tailer.poll() == (False, [])
    # Append one line.
    with p.open("a", encoding="utf-8") as fh:
        fh.write("c\n")
    rotated, lines = tailer.poll()
    assert rotated is False
    assert lines == ["c"]


def test_tailer_holds_partial_last_line(tmp_path: Path) -> None:
    p = tmp_path / "scan.csv"
    p.write_text("done\npar", encoding="utf-8")
    tailer = CsvTailer(p)
    _, lines = tailer.poll()
    assert lines == ["done"]  # "par" is buffered, not emitted
    with p.open("a", encoding="utf-8") as fh:
        fh.write("tial\n")
    _, lines = tailer.poll()
    assert lines == ["partial"]


def test_tailer_detects_truncation(tmp_path: Path) -> None:
    p = tmp_path / "scan.csv"
    p.write_text("one\ntwo\n", encoding="utf-8")
    tailer = CsvTailer(p)
    tailer.poll()
    p.write_text("fresh\n", encoding="utf-8")  # smaller than the last offset
    rotated, lines = tailer.poll()
    assert rotated is True
    assert lines == ["fresh"]


def test_tailer_missing_file(tmp_path: Path) -> None:
    tailer = CsvTailer(tmp_path / "nope.csv")
    assert tailer.poll() == (False, [])


# ---------------------------------------------------------------------------
# IncrementalScan
# ---------------------------------------------------------------------------


def test_incremental_scan_only_new_rows() -> None:
    inc = IncrementalScan()
    aps, clients = inc.feed([_AP_HEADER, _AP_ROW])
    assert [a.bssid for a in aps] == ["aa:bb:cc:dd:ee:01"]
    assert clients == []
    # Empty feed touches nothing but keeps the registry.
    assert inc.feed([]) == ([], [])
    assert "aa:bb:cc:dd:ee:01" in inc.result.aps
    # A later batch adds a client and links it to the known AP.
    aps, clients = inc.feed([_CLIENT_HEADER, _CLIENT_ROW])
    assert [c.station for c in clients] == ["11:22:33:44:55:66"]
    assert "11:22:33:44:55:66" in inc.result.aps["aa:bb:cc:dd:ee:01"].clients


def test_incremental_scan_merges_repeated_ap_rows() -> None:
    inc = IncrementalScan()
    inc.feed([_AP_HEADER, _AP_ROW])
    # airodump rewrites the same row with an updated beacon count.
    updated = _AP_ROW.replace("-20, 10,", "-20, 99,")
    inc.feed([_AP_HEADER, updated])
    assert len(inc.result.aps) == 1
    assert inc.result.aps["aa:bb:cc:dd:ee:01"].beacons == 99


# ---------------------------------------------------------------------------
# DedupStore
# ---------------------------------------------------------------------------


def test_dedup_collapses_same_key() -> None:
    store = DedupStore(clock=lambda: 10.0, started_at=0.0)
    rec, is_new = store.observe(Finding("HANDSHAKE", "hs", bssid="aa", client_mac="bb"))
    assert is_new and rec.count == 1
    rec, is_new = store.observe(Finding("HANDSHAKE", "hs again", bssid="aa", client_mac="bb"))
    assert not is_new and rec.count == 2
    assert store.unique_count == 1
    assert store.total_count == 2
    assert store.duplicate_count == 1


def test_dedup_keeps_distinct_keys() -> None:
    store = DedupStore()
    store.observe(Finding("HANDSHAKE", "hs", bssid="aa", client_mac="bb"))
    store.observe(Finding("HANDSHAKE", "hs", bssid="aa", client_mac="cc"))  # different client
    store.observe(Finding("PROBE", "probe", client_mac="bb", key_payload={"ssid": "x"}))
    assert store.unique_count == 3


def test_dedup_payload_distinguishes_evidence() -> None:
    store = DedupStore()
    store.observe(Finding("WPS", "wps", bssid="aa", key_payload={"version": "1.0"}))
    store.observe(Finding("WPS", "wps", bssid="aa", key_payload={"version": "2.0"}))
    assert store.unique_count == 2  # a version change is a new finding


# ---------------------------------------------------------------------------
# Reporting + formatting
# ---------------------------------------------------------------------------


def test_findings_report_schema() -> None:
    store = DedupStore(started_at=0.0, clock=lambda: 1.0)
    store.observe(Finding("WEP", "wep net", bssid="aa", ssid="old", frame=5))
    store.observe(Finding("WEP", "wep net", bssid="aa", ssid="old", frame=5))
    report = findings_report(store, follow_mode=True, files_followed=["scan.csv"])
    session = report["session"]
    assert session["follow_mode"] is True
    assert session["files_followed"] == ["scan.csv"]
    assert session["total_findings"] == 2
    assert session["unique_findings"] == 1
    assert session["duplicate_findings"] == 1
    finding = report["findings"][0]
    for key in ("count", "first_seen", "last_seen", "duplicate", "duplicate_of", "sample_frame"):
        assert key in finding
    assert finding["count"] == 2
    assert finding["duplicate"] is True
    assert finding["sample_frame"] == 5


def test_format_cli_line_marker() -> None:
    store = DedupStore()
    rec, _ = store.observe(
        Finding("HANDSHAKE", "Handshake detected (frames 221-224)", ssid="wifi-mobile")
    )
    line = format_cli_line(rec, show_count=True)
    assert line.startswith("[×1]")  # [×1]
    assert "[wifi-mobile]" in line
    assert "Handshake detected (frames 221-224)" in line


def test_session_summary() -> None:
    store = DedupStore()
    store.observe(Finding("AP", "ap", bssid="aa"))
    out = session_summary(store, duration=754.0, json_path="report.json")
    assert "=== Session summary ===" in out
    assert "Unique findings: 1" in out
    assert "Duplicates suppressed: 0" in out
    assert "Duration: 00:12:34" in out
    assert "report.json" in out


# ---------------------------------------------------------------------------
# CLI follow mode
# ---------------------------------------------------------------------------


def _stop_after_first_poll(_seconds: float) -> None:
    raise KeyboardInterrupt


def test_survey_follow_show_duplicates_and_summary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    csv = tmp_path / "scan.csv"
    csv.write_text(_CSV, encoding="utf-8")
    out = tmp_path / "rep.json"
    monkeypatch.setattr(cli, "_FOLLOW_SLEEP", _stop_after_first_poll)

    result = runner.invoke(
        cli.app,
        ["survey", "--csv", str(csv), "--follow", "--show-duplicates", "-o", str(out)],
        env=ENV,
    )
    assert result.exit_code == 0, result.output
    assert "[×1]" in result.output  # [×1] marker on first prints
    assert "=== Session summary ===" in result.output

    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["session"]["follow_mode"] is True
    assert doc["session"]["files_followed"] == [str(csv)]
    assert any(f["finding_type"] == "AP" for f in doc["findings"])
    assert any(f["finding_type"] == "WEP" for f in doc["findings"])
    assert all("count" in f and "duplicate" in f for f in doc["findings"])


def test_survey_follow_hide_duplicates_summary_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    csv = tmp_path / "scan.csv"
    csv.write_text(_CSV, encoding="utf-8")
    monkeypatch.setattr(cli, "_FOLLOW_SLEEP", _stop_after_first_poll)

    result = runner.invoke(
        cli.app, ["survey", "--csv", str(csv), "--follow"], env=ENV
    )
    assert result.exit_code == 0, result.output
    assert "new findings" in result.output
    assert "×" not in result.output  # no [×N] markers when hiding duplicates


def test_survey_one_shot_json_has_findings(tmp_path: Path) -> None:
    csv = tmp_path / "scan.csv"
    csv.write_text(_CSV, encoding="utf-8")
    out = tmp_path / "survey.json"
    result = runner.invoke(cli.app, ["survey", "--csv", str(csv), "-o", str(out)], env=ENV)
    assert result.exit_code == 0, result.output
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["session"]["follow_mode"] is False
    assert doc["summary"]["aps_total"] == 2  # existing one-shot structure preserved
    assert any(f["finding_type"] == "OPEN_NETWORK" for f in doc["findings"])
