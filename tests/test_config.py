"""Tests for wifiaudit.config."""

from __future__ import annotations

import os

import pytest

from wifiaudit.config import Settings, load_settings, redact_mac


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in list(os.environ):
        if key.startswith("WIFIAUDIT_"):
            monkeypatch.delenv(key)


def test_defaults() -> None:
    s = load_settings()
    assert s == Settings(pcap_path="")
    assert s.bettercap_url == "http://127.0.0.1:8081"
    assert s.redact_macs is True


def test_env_overrides_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WIFIAUDIT_BETTERCAP_URL", "http://10.0.0.5:8081")
    monkeypatch.setenv("WIFIAUDIT_REDACT_MACS", "false")
    monkeypatch.setenv("WIFIAUDIT_PCAP_PATH", "env.pcap")
    s = load_settings()
    assert s.bettercap_url == "http://10.0.0.5:8081"
    assert s.redact_macs is False
    assert s.pcap_path == "env.pcap"


def test_overrides_beat_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WIFIAUDIT_BETTERCAP_URL", "http://env:8081")
    monkeypatch.setenv("WIFIAUDIT_REDACT_MACS", "0")
    s = load_settings(bettercap_url="http://override:8081", redact_macs=True)
    assert s.bettercap_url == "http://override:8081"
    assert s.redact_macs is True


def test_none_override_is_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WIFIAUDIT_OUTPUT_PREFIX", "from_env")
    assert load_settings(output_prefix=None).output_prefix == "from_env"


def test_unknown_override_rejected() -> None:
    with pytest.raises(TypeError):
        load_settings(not_a_field="x")


def test_bad_bool_env_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WIFIAUDIT_REDACT_MACS", "maybe")
    with pytest.raises(ValueError):
        load_settings()


@pytest.mark.parametrize(
    ("mac", "expected"),
    [
        ("aa:bb:cc:dd:ee:ff", "aa:bb:cc:00:00:00"),
        ("AA:BB:CC:DD:EE:FF", "AA:BB:CC:00:00:00"),
        ("aa-bb-cc-dd-ee-ff", "aa-bb-cc-00-00-00"),
        (" 01:23:45:67:89:ab ", "01:23:45:00:00:00"),
    ],
)
def test_redact_mac_valid(mac: str, expected: str) -> None:
    assert redact_mac(mac) == expected


@pytest.mark.parametrize(
    "mac",
    [
        "",
        "not-a-mac",
        "aa:bb:cc:dd:ee",
        "aa:bb:cc:dd:ee:ff:00",
        "aa:bb-cc:dd:ee:ff",
        "gg:bb:cc:dd:ee:ff",
        "aabbccddeeff",
        "a:b:c:d:e:f",
    ],
)
def test_redact_mac_malformed(mac: str) -> None:
    assert redact_mac(mac) == "<redacted>"
