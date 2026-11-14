"""Ingest airodump-ng CSV and `iw dev scan` text into a normalized AP/client model.

This is passive enumeration only: it reads files produced by other tools and
builds a tidy inventory. It transmits nothing and performs no active action.

airodump-ng writes two CSV sections separated by a blank line: access points
first, then stations (clients). `iw dev <iface> scan` emits a text block per BSS
that carries the RSN details airodump's CSV omits — AKM suites (PSK/SAE/OWE),
802.11w (PMF) capability/requirement, and WPS. The two sources are merged by
BSSID, with `iw` enriching the airodump inventory.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


def band_of(channel: int | None) -> str:
    """Map a channel number to a rough band label."""
    if not channel:
        return "unknown"
    if 1 <= channel <= 14:
        return "2.4GHz"
    if 32 <= channel <= 177:
        return "5GHz"
    return "unknown"


def _clean(value: str | None) -> str | None:
    """Strip a CSV field; turn empty / placeholder values into None."""
    if value is None:
        return None
    v = value.strip()
    return v or None


@dataclass
class ScanClient:
    """One station (client) row."""

    station: str
    bssid: str | None = None  # associated AP, or None if "(not associated)"
    power: int | None = None
    packets: int = 0
    probes: list[str] = field(default_factory=list)


@dataclass
class ScanAP:
    """A normalized access point, merged from airodump CSV and `iw scan`."""

    bssid: str
    essid: str | None = None
    channel: int | None = None
    band: str = "unknown"
    enc: str | None = None  # OPN / WEP / WPA / WPA2 / WPA3
    cipher: str | None = None  # CCMP / TKIP / WEP
    auth: str | None = None  # PSK / MGT / SAE / OWE
    wps_version: str | None = None
    wps_locked: bool | None = None
    pmf_capable: bool | None = None
    pmf_required: bool | None = None
    hidden: bool = False
    wpa3_transition: bool = False
    beacons: int = 0
    data_frames: int = 0
    clients: list[str] = field(default_factory=list)
    probe_ssids: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    aps: dict[str, ScanAP] = field(default_factory=dict)
    clients: list[ScanClient] = field(default_factory=list)


# ---------------------------------------------------------------------------
# airodump-ng CSV
# ---------------------------------------------------------------------------

_AP_HEADER = "BSSID,"
_CLIENT_HEADER = "Station MAC,"


def _parse_int(value: str | None) -> int | None:
    v = _clean(value)
    if v is None:
        return None
    try:
        return int(v)
    except ValueError:
        return None


def parse_airodump_csv(text: str) -> ScanResult:
    """Parse the text of an airodump-ng ``*.csv`` file into a ScanResult."""
    lines = text.splitlines()
    if not any(line.startswith(_AP_HEADER) for line in lines):
        raise ValueError("not an airodump-ng CSV (missing BSSID header)")

    result = ScanResult()
    section = None  # "ap" | "client"
    for raw in lines:
        line = raw.rstrip()
        if not line.strip():
            continue
        if line.startswith(_AP_HEADER):
            section = "ap"
            continue
        if line.startswith(_CLIENT_HEADER):
            section = "client"
            continue
        if section == "ap":
            ap = _parse_ap_row(line)
            if ap is not None:
                result.aps[ap.bssid] = ap
        elif section == "client":
            client = _parse_client_row(line)
            if client is not None:
                result.clients.append(client)

    # Link clients to their APs.
    for client in result.clients:
        if client.bssid and client.bssid in result.aps:
            ap = result.aps[client.bssid]
            if client.station not in ap.clients:
                ap.clients.append(client.station)
    return result


def _parse_ap_row(line: str) -> ScanAP | None:
    parts = [p.strip() for p in line.split(",")]
    if len(parts) < 14:
        return None
    bssid = parts[0].lower()
    if not re.match(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", bssid):
        return None
    essid = _clean(parts[13])
    channel = _parse_int(parts[3])
    ap = ScanAP(
        bssid=bssid,
        essid=essid,
        channel=channel,
        band=band_of(channel),
        enc=_clean(parts[5]),
        cipher=_clean(parts[6]),
        auth=_clean(parts[7]),
        beacons=_parse_int(parts[9]) or 0,
        data_frames=_parse_int(parts[10]) or 0,
        hidden=essid is None,
    )
    return ap


def _parse_client_row(line: str) -> ScanClient | None:
    # Fixed fields, then "Probed ESSIDs" which may itself contain commas.
    parts = line.split(",", 6)
    if len(parts) < 6:
        return None
    station = parts[0].strip().lower()
    if not re.match(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", station):
        return None
    bssid_raw = _clean(parts[5])
    bssid = None
    if bssid_raw and "not associated" not in bssid_raw.lower():
        bssid = bssid_raw.lower()
    probes_raw = parts[6] if len(parts) > 6 else ""
    probes = [p.strip() for p in probes_raw.split(",") if p.strip()]
    return ScanClient(
        station=station,
        bssid=bssid,
        power=_parse_int(parts[3]),
        packets=_parse_int(parts[4]) or 0,
        probes=probes,
    )


# ---------------------------------------------------------------------------
# iw dev scan
# ---------------------------------------------------------------------------

_BSS_RE = re.compile(r"^BSS\s+([0-9a-fA-F:]{17})")
_PSK_AKMS = {"PSK", "PSK-SHA256", "FT/PSK"}
_SAE_AKMS = {"SAE", "FT/SAE"}


def parse_iw_scan(text: str) -> dict[str, ScanAP]:
    """Parse `iw dev <iface> scan` text into {bssid: ScanAP} with RSN/WPS/PMF."""
    aps: dict[str, ScanAP] = {}
    current: ScanAP | None = None
    in_rsn = False
    for raw in text.splitlines():
        line = raw.strip()
        m = _BSS_RE.match(line)
        if m:
            bssid = m.group(1).lower()
            current = ScanAP(bssid=bssid)
            aps[bssid] = current
            in_rsn = False
            continue
        if current is None:
            continue
        if line.startswith("SSID:"):
            essid = line[len("SSID:") :].strip()
            current.essid = essid or None
            current.hidden = not essid
        elif "primary channel:" in line or line.startswith("DS Parameter set: channel"):
            ch = re.search(r"channel:?\s*(\d+)", line)
            if ch:
                current.channel = int(ch.group(1))
                current.band = band_of(current.channel)
        elif line.startswith("RSN:"):
            in_rsn = True
        elif line.startswith("WPA:"):
            in_rsn = False
        elif line.startswith("WPS:"):
            current.wps_version = current.wps_version or "present"
        elif in_rsn and "Authentication suites:" in line:
            suites = line.split("Authentication suites:", 1)[1].split()
            has_psk = any(s in _PSK_AKMS for s in suites)
            has_sae = any(s in _SAE_AKMS for s in suites)
            if "OWE" in suites:
                current.auth = "OWE"
            elif has_sae:
                current.auth = "SAE"
            elif has_psk:
                current.auth = current.auth or "PSK"
            current.wpa3_transition = has_psk and has_sae
        elif in_rsn and "Capabilities:" in line:
            current.pmf_capable = "MFP-capable" in line
            current.pmf_required = "MFP-required" in line
    return aps


def _merge_iw(result: ScanResult, iw_aps: dict[str, ScanAP]) -> None:
    for bssid, iw_ap in iw_aps.items():
        ap = result.aps.get(bssid)
        if ap is None:
            result.aps[bssid] = iw_ap
            continue
        if ap.essid is None and iw_ap.essid:
            ap.essid = iw_ap.essid
            ap.hidden = False
        if ap.channel is None and iw_ap.channel:
            ap.channel = iw_ap.channel
            ap.band = iw_ap.band
        ap.wps_version = ap.wps_version or iw_ap.wps_version
        for attr in ("pmf_capable", "pmf_required", "auth"):
            if getattr(ap, attr) in (None,) and getattr(iw_ap, attr) is not None:
                setattr(ap, attr, getattr(iw_ap, attr))
        ap.wpa3_transition = ap.wpa3_transition or iw_ap.wpa3_transition


def ingest(csv_path: str | Path | None = None, iw_path: str | Path | None = None) -> ScanResult:
    """Ingest an airodump CSV and/or an `iw scan` dump into one ScanResult.

    At least one source must be given. Probe SSIDs from associated clients are
    attached to their AP for convenience.
    """
    if csv_path is None and iw_path is None:
        raise ValueError("ingest() needs a csv_path and/or an iw_path")

    result = ScanResult()
    if csv_path is not None:
        result = parse_airodump_csv(Path(csv_path).read_text(encoding="utf-8", errors="ignore"))
    if iw_path is not None:
        iw_aps = parse_iw_scan(Path(iw_path).read_text(encoding="utf-8", errors="ignore"))
        _merge_iw(result, iw_aps)

    # Attach probe SSIDs of associated clients to their AP.
    by_bssid: dict[str, list[str]] = {}
    for client in result.clients:
        if client.bssid:
            by_bssid.setdefault(client.bssid, []).extend(client.probes)
    for bssid, probes in by_bssid.items():
        ap = result.aps.get(bssid)
        if ap is not None:
            ap.probe_ssids = sorted(dict.fromkeys(probes))
    return result
