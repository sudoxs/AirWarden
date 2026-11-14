"""Tests for the advisory attack_mapper (no execution, just classification)."""

from __future__ import annotations

from airwarden.attack_mapper import ApEvidence, evidence_for, map_all, map_ap
from airwarden.handshake_detector import HandshakeEvidence
from airwarden.pcap_extractor import Artifact
from airwarden.scan_ingestor import ScanAP


def _cats(rows) -> set[str]:
    return {r.category for r in rows}


def test_open_network_category() -> None:
    ap = ScanAP("aa:bb:cc:dd:ee:01", essid="Free", enc="OPN")
    rows = map_ap(ap, ApEvidence(http_credentials=True))
    assert _cats(rows) == {"OPN"}
    assert rows[0].priority == "high"  # cleartext creds seen -> high


def test_wep_always_high() -> None:
    rows = map_ap(ScanAP("b", enc="WEP"), ApEvidence())
    assert _cats(rows) == {"WEP"} and rows[0].priority == "high"


def test_psk_priority_depends_on_material() -> None:
    ap = ScanAP("c", enc="WPA2", auth="PSK")
    assert map_ap(ap, ApEvidence())[0].priority == "medium"
    assert map_ap(ap, ApEvidence(has_pmkid=True))[0].priority == "high"


def test_transition_is_high_and_sae_only_is_low() -> None:
    trans = ScanAP("d", enc="WPA3", auth="SAE", wpa3_transition=True)
    assert map_ap(trans, ApEvidence())[0].priority == "high"
    sae = ScanAP("e", enc="WPA3", auth="SAE")
    row = next(r for r in map_ap(sae, ApEvidence()) if r.category == "WPA3-SAE")
    assert row.priority == "low"


def test_mgt_weak_eap_raises_priority() -> None:
    ap = ScanAP("f", enc="WPA2", auth="MGT")
    weak = map_ap(ap, ApEvidence(eap_types={4}))  # EAP-MD5
    row = next(r for r in weak if r.category == "MGT")
    assert row.priority == "high"


def test_owe_and_wps() -> None:
    owe = map_ap(ScanAP("g", enc="WPA3", auth="OWE"), ApEvidence())
    assert _cats(owe) == {"OWE"}
    wps_locked = map_ap(ScanAP("h", enc="WPA2", auth="PSK", wps_version="2.0", wps_locked=True),
                        ApEvidence())
    wps_row = next(r for r in wps_locked if r.category == "WPS")
    assert wps_row.priority == "low"  # locked -> low


def test_evidence_for_from_artifacts() -> None:
    bssid = "aa:bb:cc:dd:ee:01"
    arts = [
        Artifact("HTTP_POST", 1, bssid=bssid),
        Artifact("EAP_TYPE", 2, bssid=bssid, extra={"eap_type": 25}),
        Artifact("EAP_IDENTITY", 3, bssid=bssid, extra={"identity": "CORP\\a"}),
    ]
    hs = [HandshakeEvidence(bssid=bssid, client="x", complete_handshake=True)]
    ev = evidence_for(bssid, arts, hs)
    assert ev.http_credentials and ev.has_handshake
    assert ev.eap_types == {25} and ev.eap_identities == ["CORP\\a"]


def test_map_all_covers_every_ap() -> None:
    aps = {
        "a": ScanAP("a", enc="OPN", essid="x"),
        "b": ScanAP("b", enc="WEP"),
    }
    matrix = map_all(aps)
    assert set(matrix) == {"a", "b"}
