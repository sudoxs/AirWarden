"""Heuristic classification of a capture as general / targeted / passive."""

from __future__ import annotations

from collections import Counter
from typing import Any

from airwarden.models import ScanType


def _ssid_of(frame: Any) -> str:
    try:
        elt = frame.getlayer("Dot11Elt")
    except Exception:
        return ""
    if elt is None or not getattr(elt, "info", None):
        return ""
    try:
        return elt.info.decode(errors="ignore")
    except Exception:
        return ""


def _channel_of(frame: Any) -> int:
    try:
        d = frame.getlayer("Dot11")
        return int(getattr(d, "channel", 0) or 0)
    except Exception:
        return 0


def classify_counts(
    probe_total: int,
    wildcard: int,
    unique_targets: int,
    channel_spread: int,
    beacons: int,
) -> tuple[ScanType, dict]:
    """Decide the scan type from pre-computed counters.

    ``channel_spread`` is the number of channels carrying sustained beacon traffic
    (>= 3 beacons). Sharing this with the live analyzer keeps the batch and
    streaming classifiers identical.
    """
    if probe_total == 0:
        return ScanType.PASSIVE_ONLY, {
            "probe_requests": 0,
            "beacons": beacons,
            "reason": "no probe requests observed; traffic is likely passive",
        }

    wildcard_ratio = wildcard / probe_total
    evidence = {
        "probe_requests": probe_total,
        "wildcard_ratio": round(wildcard_ratio, 3),
        "unique_target_ssids": unique_targets,
        "channels_with_traffic": channel_spread,
    }

    if wildcard_ratio >= 0.6 and channel_spread >= 3:
        return ScanType.GENERAL, {
            **evidence,
            "reason": "wildcard probes dominate and traffic spans multiple channels",
        }
    if wildcard_ratio <= 0.2 and (unique_targets <= 2 or channel_spread <= 1):
        return ScanType.TARGETED, {
            **evidence,
            "reason": "probes concentrate on specific SSID(s) or a single channel",
        }
    return ScanType.UNKNOWN, {
        **evidence,
        "reason": "pattern does not match the general or targeted profile",
    }


def classify_scan(frames: Any) -> tuple[ScanType, dict]:
    """Return (ScanType, evidence dict) for a pcap frame iterable."""
    probe_total = 0
    wildcard = 0
    targeted: Counter[str] = Counter()
    channels: Counter[int] = Counter()

    for f in frames:
        try:
            if f.haslayer("Dot11ProbeReq"):
                probe_total += 1
                ssid = _ssid_of(f)
                if not ssid:
                    wildcard += 1
                else:
                    targeted[ssid] += 1
            if f.haslayer("Dot11Beacon"):
                ch = _channel_of(f)
                if ch:
                    channels[ch] += 1
        except Exception:
            continue

    channel_spread = len([c for c, n in channels.items() if n >= 3])
    return classify_counts(
        probe_total, wildcard, len(targeted), channel_spread, sum(channels.values())
    )
