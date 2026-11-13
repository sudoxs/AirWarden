"""Tests for the leak/exposure classification layer."""

from __future__ import annotations

from wifiaudit.exposure import classify_exposure, classify_exposures, is_leak
from wifiaudit.models import Finding


def _f(code: str, severity: str = "high") -> Finding:
    return Finding(code, severity, 1.0, "evidence", "fix")


def test_known_codes_map_to_expected_kinds() -> None:
    assert classify_exposure(_f("PMKID_CAPTURED")).what == "key_material"
    assert classify_exposure(_f("EAP_IDENTITY_LEAK")).what == "identity"
    assert classify_exposure(_f("HTTP_CREDENTIAL")).what == "plaintext_credential"
    assert classify_exposure(_f("HTTP_COOKIE")).what == "session_cookie"
    assert classify_exposure(_f("NO_PMF")).what == "config_weakness"


def test_unknown_code_is_unclassified() -> None:
    assert classify_exposure(_f("SOMETHING_NEW")) is None


def test_is_leak_separates_secrets_from_weaknesses() -> None:
    assert is_leak(classify_exposure(_f("HTTP_CREDENTIAL")))
    assert is_leak(classify_exposure(_f("HANDSHAKE_CAPTURED")))
    assert not is_leak(classify_exposure(_f("NO_PMF")))
    assert not is_leak(classify_exposure(_f("DISCONNECT_FLOOD")))


def test_classify_exposures_preserves_and_drops() -> None:
    findings = [_f("OPEN_NETWORK"), _f("NOPE"), _f("WPS_ENABLED")]
    out = classify_exposures(findings)
    assert [e.code for e in out] == ["OPEN_NETWORK", "WPS_ENABLED"]
    assert out[0].severity == "high"
    assert out[0].source and out[0].exploitability
