"""Tests for airodump CSV / iw scan ingestion."""
# ruff: noqa: E501  (airodump CSV header/rows are fixed-format data lines)

from __future__ import annotations

from pathlib import Path

import pytest

from airwarden.scan_ingestor import (
    band_of,
    ingest,
    parse_airodump_csv,
    parse_iw_scan,
)

_CSV = """\
BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
F0:9F:C2:71:22:17, 2026-10-08 02:13:20, 2026-10-08 02:27:40, 44, 54, WPA2, CCMP, MGT, -28, 276, 688, 0.0.0.0, 11, wifi-global,
AA:BB:CC:DD:EE:01, t, t, 6, 54, OPN, , , -20, 10, 0, 0.0.0.0, 8, FreeWiFi,

Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs
78:C1:A7:BF:72:46, t, t, -52, 27, (not associated), wifi-offices,Jason
11:22:33:44:55:66, t, t, -30, 5, F0:9F:C2:71:22:17,
"""

_IW = """\
BSS f0:9f:c2:71:af:2f(on wlan0)
\tSSID: wifi-gratis
\tDS Parameter set: channel 44
\tRSN:\t * Version: 1
\t\t * Authentication suites: OWE
\t\t * Capabilities: MFP-required MFP-capable (0x00c0)
BSS aa:bb:cc:dd:ee:02(on wlan0)
\tSSID: wifi-IT
\tDS Parameter set: channel 11
\tRSN:\t * Version: 1
\t\t * Authentication suites: PSK SAE
\tWPS:\t * Version: 1.0
"""


def test_band_of() -> None:
    assert band_of(6) == "2.4GHz"
    assert band_of(44) == "5GHz"
    assert band_of(None) == "unknown"


def test_parse_airodump_csv() -> None:
    res = parse_airodump_csv(_CSV)
    assert set(res.aps) == {"f0:9f:c2:71:22:17", "aa:bb:cc:dd:ee:01"}
    corp = res.aps["f0:9f:c2:71:22:17"]
    assert corp.essid == "wifi-global"
    assert corp.channel == 44 and corp.band == "5GHz"
    assert corp.enc == "WPA2" and corp.cipher == "CCMP" and corp.auth == "MGT"
    assert not corp.hidden
    openap = res.aps["aa:bb:cc:dd:ee:01"]
    assert openap.enc == "OPN" and openap.band == "2.4GHz"
    # client linkage + probe parsing (probed ESSIDs keep internal commas split)
    assert "11:22:33:44:55:66" in corp.clients
    unassoc = next(c for c in res.clients if c.station == "78:c1:a7:bf:72:46")
    assert unassoc.bssid is None
    assert unassoc.probes == ["wifi-offices", "Jason"]


def test_parse_airodump_rejects_garbage() -> None:
    with pytest.raises(ValueError):
        parse_airodump_csv("not,a,valid,airodump,file\n")


def test_parse_iw_scan() -> None:
    aps = parse_iw_scan(_IW)
    gratis = aps["f0:9f:c2:71:af:2f"]
    assert gratis.auth == "OWE"
    assert gratis.pmf_required and gratis.pmf_capable
    it = aps["aa:bb:cc:dd:ee:02"]
    assert it.auth == "SAE" and it.wpa3_transition
    assert it.wps_version == "present"


def test_ingest_merges_sources(tmp_path: Path) -> None:
    csv = tmp_path / "scan-01.csv"
    csv.write_text(_CSV, encoding="utf-8")
    iw = tmp_path / "iw.txt"
    iw.write_text(_IW, encoding="utf-8")
    res = ingest(csv, iw)
    # CSV APs + iw-only APs are both present.
    assert "f0:9f:c2:71:22:17" in res.aps  # from CSV
    assert "f0:9f:c2:71:af:2f" in res.aps  # from iw
    assert res.aps["aa:bb:cc:dd:ee:02"].wpa3_transition


def test_ingest_needs_a_source() -> None:
    with pytest.raises(ValueError):
        ingest()
