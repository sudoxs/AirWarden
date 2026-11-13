"""Core data model for airwarden (RESERVED — integration contract).

These dataclasses and enums are the locked interface shared by every module.
Do not add, remove, or rename fields.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class ScanType(str, Enum):
    GENERAL = "general"
    TARGETED = "targeted"
    PASSIVE_ONLY = "passive_only"
    UNKNOWN = "unknown"


class Encryption(str, Enum):
    OPEN = "open"
    WEP = "wep"
    WPA = "wpa"
    WPA2 = "wpa2"
    WPA3 = "wpa3"
    ENTERPRISE = "enterprise"
    UNKNOWN = "unknown"


@dataclass
class AccessPoint:
    bssid: str
    ssid: str
    channel: int
    encryption: Encryption = Encryption.UNKNOWN
    wps_enabled: bool = False
    pmf_enabled: bool = False
    vendor: str | None = None
    beacon_count: int = 0
    clients: set[str] = field(default_factory=set)


@dataclass
class Finding:
    code: str  # e.g. "WPS_ENABLED", "NO_PMF", "HANDSHAKE_CAPTURED"
    severity: str  # one of: info | low | medium | high | critical
    confidence: float  # 0.0 .. 1.0
    evidence: str
    recommendation: str


@dataclass
class TargetAssessment:
    ap: AccessPoint
    findings: list[Finding] = field(default_factory=list)
    risk_score: float = 0.0
    handshake_captured: bool = False
    pmkid_captured: bool = False
    deauth_frames: int = 0
