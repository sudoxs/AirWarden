"""Tests for wifiaudit.cli. Reserved stub modules are replaced with fakes."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

import wifiaudit.cli as cli
from wifiaudit.models import AccessPoint, Encryption, Finding, TargetAssessment

runner = CliRunner()
ENV = {"COLUMNS": "200", "WIFIAUDIT_REDACT_MACS": None, "WIFIAUDIT_AUTHORIZED": None}


def _fake_analyze(path: str) -> tuple[list[TargetAssessment], dict]:
    low = TargetAssessment(
        ap=AccessPoint(bssid="aa:bb:cc:dd:ee:01", ssid="LowNet", channel=1),
    )
    high = TargetAssessment(
        ap=AccessPoint(
            bssid="11:22:33:44:55:66",
            ssid="HighNet",
            channel=6,
            encryption=Encryption.WPA2,
            wps_enabled=True,
        ),
        findings=[Finding("WPS_ENABLED", "high", 1.0, "WPS IE", "Disable WPS.")],
    )
    return [low, high], {"scan_type": "general", "scan_evidence": {}}


def _fake_score(t: TargetAssessment) -> float:
    return 80.0 if t.ap.wps_enabled else 5.0


def _raise_stub(*args, **kwargs):
    raise NotImplementedError("replaced at integration time")


@pytest.fixture
def patched_analysis(monkeypatch: pytest.MonkeyPatch) -> None:
    # cli imports these names at module top, so patch them where they are looked up.
    monkeypatch.setattr(cli, "analyze_pcap", _fake_analyze)
    monkeypatch.setattr(cli, "score_target", _fake_score)


def test_help_lists_commands() -> None:
    result = runner.invoke(cli.app, ["--help"], env=ENV)
    assert result.exit_code == 0
    assert "analyze" in result.output
    assert "active" in result.output


def test_version_flag() -> None:
    from wifiaudit import __version__

    result = runner.invoke(cli.app, ["--version"], env=ENV)
    assert result.exit_code == 0
    assert __version__ in result.output


def test_analyze_renders_and_writes(tmp_path: Path, patched_analysis) -> None:
    prefix = tmp_path / "out"
    result = runner.invoke(cli.app, ["analyze", "x.pcap", "-o", str(prefix)], env=ENV)
    assert result.exit_code == 0, result.output

    out = result.output
    for col in ("BSSID", "SSID", "CH", "ENC", "WPS", "PMF", "Risk", "HS", "PMKID", "Top finding"):
        assert col in out
    assert "11:22:33:00:00:00" in out
    assert "11:22:33:44:55:66" not in out
    assert "WPS_ENABLED" in out
    assert "—" in out  # empty "Top finding" cell for LowNet
    assert out.index("HighNet") < out.index("LowNet")  # sorted by risk desc

    doc = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
    assert [a["risk_score"] for a in doc["assessments"]] == [80.0, 5.0]
    assert doc["assessments"][0]["ap"]["bssid"] == "11:22:33:00:00:00"
    html = (tmp_path / "out.html").read_text(encoding="utf-8")
    assert "Requires targeted follow-up" in html


def test_analyze_no_redact(tmp_path: Path, patched_analysis) -> None:
    prefix = tmp_path / "out"
    result = runner.invoke(
        cli.app, ["analyze", "x.pcap", "-o", str(prefix), "--no-redact-macs"], env=ENV
    )
    assert result.exit_code == 0, result.output
    assert "11:22:33:44:55:66" in result.output
    assert "11:22:33:44:55:66" in (tmp_path / "out.json").read_text(encoding="utf-8")


def test_analyze_stub_exits_3(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "analyze_pcap", _raise_stub)
    result = runner.invoke(
        cli.app, ["analyze", "nonexistent.pcap", "-o", str(tmp_path / "o")], env=ENV
    )
    assert result.exit_code == 3
    assert "stub" in result.output
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert not (tmp_path / "o.json").exists()


def test_active_requires_authorization_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    def _must_not_construct(*a, **k):
        raise AssertionError("gate must not be constructed without authorization")

    monkeypatch.setattr(cli, "AuthorizationGate", _must_not_construct)
    result = runner.invoke(cli.app, ["active", "--interface", "wlan0mon"], env=ENV)
    assert result.exit_code == 2
    assert "refused" in result.output


def test_active_stub_exits_3(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "AuthorizationGate", _raise_stub)
    result = runner.invoke(
        cli.app, ["active", "-i", "wlan0mon"], env={**ENV, "WIFIAUDIT_AUTHORIZED": "1"}
    )
    assert result.exit_code == 3
    assert "stub" in result.output


class _FakeGate:
    def __init__(self, scope_path=None) -> None:
        self.scope_path = scope_path


class _FakeClient:
    instances: list[_FakeClient] = []

    def __init__(self, base_url, username, password, gate) -> None:
        self.gate = gate
        self.calls: list[tuple] = []
        _FakeClient.instances.append(self)

    def start_recon(self) -> dict:
        self.calls.append(("start_recon",))
        return {}

    def list_aps(self) -> dict:
        self.calls.append(("list_aps",))
        return {
            "aps": [
                {
                    "mac": "aa:bb:cc:dd:ee:01",
                    "hostname": "LabAP",
                    "channel": 6,
                    "encryption": "WPA2",
                    "clients": [{}, {}],
                },
            ]
        }

    def capture_pmkid(self, bssid: str) -> dict:
        self.calls.append(("capture_pmkid", bssid))
        return {"status": "ok"}


@pytest.fixture
def fake_active(monkeypatch: pytest.MonkeyPatch) -> type[_FakeClient]:
    _FakeClient.instances = []
    monkeypatch.setattr(cli, "AuthorizationGate", _FakeGate)
    monkeypatch.setattr(cli, "BettercapClient", _FakeClient)
    return _FakeClient


def test_active_lists_aps_without_actions(fake_active) -> None:
    result = runner.invoke(
        cli.app, ["active", "-i", "wlan1mon"], env={**ENV, "WIFIAUDIT_AUTHORIZED": "1"}
    )
    assert result.exit_code == 0, result.output
    assert "LabAP" in result.output
    assert "aa:bb:cc:00:00:00" in result.output
    (client,) = fake_active.instances
    assert isinstance(client.gate, _FakeGate)
    assert client.calls == [("start_recon",), ("list_aps",)]


def test_active_pmkid_called_once(fake_active) -> None:
    result = runner.invoke(
        cli.app,
        ["active", "-i", "wlan1mon", "--pmkid", "aa:bb:cc:dd:ee:01"],
        env={**ENV, "WIFIAUDIT_AUTHORIZED": "1"},
    )
    assert result.exit_code == 0, result.output
    (client,) = fake_active.instances
    assert client.calls[-1] == ("capture_pmkid", "aa:bb:cc:dd:ee:01")
    assert sum(1 for c in client.calls if c[0] == "capture_pmkid") == 1
