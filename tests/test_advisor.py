"""Tests for airwarden.advisor (pure logic; no radio, no network)."""

from __future__ import annotations

from airwarden.advisor import (
    ACTION_CONFIG,
    ACTION_NONE,
    ACTION_PMKID,
    has_active_suggestion,
    recommend_active_step,
)
from airwarden.models import AccessPoint, Encryption, TargetAssessment


def _t(enc: Encryption, **kw) -> TargetAssessment:
    ap_kw = {"bssid": "aa:bb:cc:dd:ee:01", "ssid": "Net", "channel": 6, "encryption": enc}
    for key in ("pmf_enabled", "wps_enabled"):
        if key in kw:
            ap_kw[key] = kw.pop(key)
    return TargetAssessment(ap=AccessPoint(**ap_kw), **kw)


def test_wpa2_no_material_pmf_off_recommends_pmkid_and_names_deauth() -> None:
    rec = recommend_active_step(_t(Encryption.WPA2, pmf_enabled=False))
    assert rec.action == ACTION_PMKID
    assert rec.priority == "high"
    assert rec.channel == 6
    assert "channel 6" in rec.yields
    assert "deauth" in rec.yields.lower()  # escalation is named explicitly
    assert "AIRWARDEN_AUTHORIZED=1" in rec.authorization_note
    assert has_active_suggestion(rec)


def test_wpa_personal_pmf_off_also_actionable() -> None:
    rec = recommend_active_step(_t(Encryption.WPA, pmf_enabled=False))
    assert rec.action == ACTION_PMKID
    assert has_active_suggestion(rec)


def test_wpa2_pmf_on_prefers_pmkid_and_rules_out_deauth() -> None:
    rec = recommend_active_step(_t(Encryption.WPA2, pmf_enabled=True))
    assert rec.action == ACTION_PMKID
    assert rec.priority == "medium"
    assert "not useful" in rec.yields.lower()


def test_captured_material_means_no_active_step() -> None:
    hs = recommend_active_step(_t(Encryption.WPA2, pmf_enabled=False, handshake_captured=True))
    assert hs.action == ACTION_NONE
    assert not has_active_suggestion(hs)

    pmkid = recommend_active_step(_t(Encryption.WPA2, pmf_enabled=False, pmkid_captured=True))
    assert pmkid.action == ACTION_NONE


def test_open_network_has_no_key_to_recover() -> None:
    rec = recommend_active_step(_t(Encryption.OPEN))
    assert rec.action == ACTION_NONE
    assert not has_active_suggestion(rec)


def test_wep_is_config_review() -> None:
    rec = recommend_active_step(_t(Encryption.WEP))
    assert rec.action == ACTION_CONFIG
    assert not has_active_suggestion(rec)
    assert rec.authorization_note == ""


def test_wpa3_and_enterprise_are_not_crackable() -> None:
    for enc in (Encryption.WPA3, Encryption.ENTERPRISE):
        rec = recommend_active_step(_t(enc, pmf_enabled=True))
        assert rec.action == ACTION_CONFIG
        assert rec.priority == "none"
        assert not has_active_suggestion(rec)


def test_unknown_encryption_collects_more_first() -> None:
    rec = recommend_active_step(_t(Encryption.UNKNOWN))
    assert rec.action == ACTION_NONE
    assert not has_active_suggestion(rec)
