"""Tests for airwarden.report (dataclasses are constructed directly; no stubs called)."""

from __future__ import annotations

import csv
import json
from html.parser import HTMLParser
from pathlib import Path

import pytest

from airwarden.models import AccessPoint, Encryption, Finding, ScanType, TargetAssessment
from airwarden.report import FOOTER, to_csv, to_html, to_json

RAW_MACS = ("aa:bb:cc:dd:ee:01", "11:22:33:44:55:66", "de:ad:be:ef:00:02", "0a:0b:0c:0d:0e:03")


@pytest.fixture
def assessments() -> list[TargetAssessment]:
    wpa2 = TargetAssessment(
        ap=AccessPoint(
            bssid="aa:bb:cc:dd:ee:01",
            ssid="CorpWiFi",
            channel=6,
            encryption=Encryption.WPA2,
            pmf_enabled=False,
            clients={"11:22:33:44:55:66"},
        ),
        findings=[
            Finding("NO_PMF", "medium", 0.9, "RSN caps: MFPC=0", "Enable 802.11w (PMF)."),
            Finding("WEAK_CIPHER", "high", 0.6, "TKIP offered", "Disable TKIP."),
        ],
        risk_score=72.0,
    )
    wps_open = TargetAssessment(
        ap=AccessPoint(
            bssid="de:ad:be:ef:00:02",
            ssid="<script>alert(1)</script>",
            channel=11,
            encryption=Encryption.OPEN,
            wps_enabled=True,
        ),
        findings=[Finding("WPS_ENABLED", "high", 1.0, "WPS IE present", "Disable WPS.")],
        risk_score=45.5,
    )
    wpa3 = TargetAssessment(
        ap=AccessPoint(
            bssid="0a:0b:0c:0d:0e:03",
            ssid="",
            channel=36,
            encryption=Encryption.WPA3,
            pmf_enabled=True,
        ),
        risk_score=10.0,
        handshake_captured=True,
    )
    return [wpa2, wps_open, wpa3]


@pytest.fixture
def meta() -> dict:
    return {"scan_type": ScanType.TARGETED.value, "scan_evidence": {"probe_requests": 3}}


def _assert_redacted(text: str) -> None:
    for raw in RAW_MACS:
        assert raw not in text
    for red in ("aa:bb:cc:00:00:00", "11:22:33:00:00:00", "de:ad:be:00:00:00"):
        assert red in text


def test_to_json_valid_and_redacted(tmp_path: Path, assessments, meta) -> None:
    out = tmp_path / "r.json"
    to_json(assessments, meta, str(out))
    text = out.read_text(encoding="utf-8")
    doc = json.loads(text)
    _assert_redacted(text)
    assert doc["meta"] == meta
    assert len(doc["assessments"]) == 3
    first = doc["assessments"][0]
    assert first["ap"]["encryption"] == "wpa2"
    assert first["ap"]["clients"] == ["11:22:33:00:00:00"]
    assert first["findings"][0]["code"] == "NO_PMF"


def test_to_json_unredacted(tmp_path: Path, assessments, meta) -> None:
    out = tmp_path / "r.json"
    to_json(assessments, meta, str(out), redact_macs=False)
    text = out.read_text(encoding="utf-8")
    assert "aa:bb:cc:dd:ee:01" in text
    assert "11:22:33:44:55:66" in text


def test_to_csv_valid_and_redacted(tmp_path: Path, assessments) -> None:
    out = tmp_path / "r.csv"
    to_csv(assessments, str(out))
    text = out.read_text(encoding="utf-8")
    _assert_redacted(text)
    rows = list(csv.DictReader(text.splitlines()))
    assert len(rows) == 3
    assert rows[0]["bssid"] == "aa:bb:cc:00:00:00"
    assert rows[0]["clients"] == "11:22:33:00:00:00"
    assert rows[0]["finding_codes"] == "NO_PMF;WEAK_CIPHER"
    assert rows[1]["encryption"] == "open"


class _Checker(HTMLParser):
    """Collects text and verifies that every opened non-void tag is closed."""

    VOID = {"meta", "br", "hr", "img", "input", "link"}

    def __init__(self) -> None:
        super().__init__()
        self.stack: list[str] = []
        self.text: list[str] = []

    def handle_starttag(self, tag, attrs) -> None:
        if tag not in self.VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag) -> None:
        assert self.stack and self.stack[-1] == tag, f"unbalanced </{tag}>"
        self.stack.pop()

    def handle_data(self, data) -> None:
        self.text.append(data)


def test_to_html_contents(tmp_path: Path, assessments, meta) -> None:
    out = tmp_path / "r.html"
    to_html(assessments, meta, str(out))
    html = out.read_text(encoding="utf-8")

    checker = _Checker()
    checker.feed(html)
    checker.close()
    assert checker.stack == []
    text = " ".join(" ".join(checker.text).split())

    for raw in RAW_MACS:
        assert raw not in html
    for red in ("aa:bb:cc:00:00:00", "de:ad:be:00:00:00", "0a:0b:0c:00:00:00"):
        assert red in html
    assert "targeted" in text
    assert "Total APs 3" in text
    assert "Risk 0-30 1" in text
    assert "Risk 31-60 1" in text
    assert "Risk 61-100 1" in text
    assert "Requires targeted follow-up" in html
    assert FOOTER in html
    # SSID is escaped, not injected.
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    # Top finding's recommendation is the next step.
    assert "Disable TKIP." in html


def test_to_html_follow_up_rules(tmp_path: Path, assessments, meta) -> None:
    out = tmp_path / "r.html"
    to_html(assessments, meta, str(out))
    html = out.read_text(encoding="utf-8")
    section = html.split("Requires targeted follow-up", 1)[1]
    assert "aa:bb:cc:00:00:00" in section  # WPA2, no handshake, no PMKID
    assert "de:ad:be:00:00:00" in section  # WPS on, PMF off
    assert "0a:0b:0c:00:00:00" not in section  # WPA3 with PMF and handshake


def test_to_html_empty(tmp_path: Path) -> None:
    out = tmp_path / "nested" / "r.html"
    to_html([], {"scan_type": "unknown", "scan_evidence": {}}, str(out))
    html = out.read_text(encoding="utf-8")
    assert "No access points found." in html
    assert FOOTER in html


def test_to_json_includes_active_recommendation(tmp_path: Path, assessments, meta) -> None:
    out = tmp_path / "r.json"
    to_json(assessments, meta, str(out))
    doc = json.loads(out.read_text(encoding="utf-8"))
    # WPA2, PMF off, no handshake/PMKID -> clientless PMKID request suggested.
    wpa2 = next(a for a in doc["assessments"] if a["ap"]["bssid"] == "aa:bb:cc:00:00:00")
    rec = wpa2["active_recommendation"]
    assert rec["action"] == "pmkid_capture"
    assert rec["priority"] == "high"
    # WPA3 with a captured handshake -> no active step.
    wpa3 = next(a for a in doc["assessments"] if a["ap"]["bssid"] == "0a:0b:0c:00:00:00")
    assert wpa3["active_recommendation"]["action"] == "none"


def test_to_html_active_followup_section(tmp_path: Path, assessments, meta) -> None:
    out = tmp_path / "r.html"
    to_html(assessments, meta, str(out))
    html = out.read_text(encoding="utf-8")
    assert "Active follow-up recommendations" in html
    section = html.split("Active follow-up recommendations", 1)[1]
    assert "aa:bb:cc:00:00:00" in section  # WPA2 target is actionable
    assert "pmkid_capture" in section
    assert "0a:0b:0c:00:00:00" not in section  # material already captured, no row
