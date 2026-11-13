"""Runtime configuration and MAC-redaction helpers."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, fields
from typing import Any

ENV_PREFIX = "WIFIAUDIT_"

_TRUE = frozenset({"1", "true", "yes", "on"})
_FALSE = frozenset({"0", "false", "no", "off"})
_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}([:-])(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}$")


@dataclass
class Settings:
    """All runtime settings for a wifiaudit run."""

    pcap_path: str
    output_prefix: str = "report"
    redact_macs: bool = True
    bettercap_url: str = "http://127.0.0.1:8081"
    bettercap_user: str = "user"
    bettercap_pass: str = "pass"
    interface: str = "wlan0mon"
    scope_path: str = "scope.json"


def _parse_bool(name: str, raw: str) -> bool:
    value = raw.strip().lower()
    if value in _TRUE:
        return True
    if value in _FALSE:
        return False
    raise ValueError(f"{name}: expected a boolean (1/0, true/false, yes/no, on/off), got {raw!r}")


def load_settings(**overrides: Any) -> Settings:
    """Build ``Settings`` from defaults, then ``WIFIAUDIT_*`` env vars, then overrides.

    Precedence (lowest to highest): dataclass defaults < environment < ``overrides``.
    Each field ``foo`` is read from env var ``WIFIAUDIT_FOO``. Overrides whose value is
    ``None`` are ignored so callers can pass through unset CLI options. ``pcap_path``
    defaults to ``""`` when not provided (e.g. for the ``active`` command).

    Raises:
        TypeError: if an override names a field that ``Settings`` does not have.
        ValueError: if a boolean env var cannot be parsed.
    """
    known = {f.name: f for f in fields(Settings)}
    unknown = sorted(set(overrides) - set(known))
    if unknown:
        raise TypeError(f"Unknown setting(s): {', '.join(unknown)}")

    values: dict[str, Any] = {"pcap_path": ""}
    for name, f in known.items():
        env_name = ENV_PREFIX + name.upper()
        raw = os.environ.get(env_name)
        if raw is None:
            continue
        values[name] = _parse_bool(env_name, raw) if f.type in (bool, "bool") else raw

    values.update({k: v for k, v in overrides.items() if v is not None})
    return Settings(**values)


def redact_mac(mac: str) -> str:
    """Keep the OUI (first 3 octets) of a MAC address and zero the rest.

    The input separator (``:`` or ``-``) is preserved, e.g.
    ``aa:bb:cc:dd:ee:ff`` -> ``aa:bb:cc:00:00:00``. Malformed input returns
    ``"<redacted>"``.
    """
    if not isinstance(mac, str):
        return "<redacted>"
    candidate = mac.strip()
    match = _MAC_RE.match(candidate)
    if match is None:
        return "<redacted>"
    sep = match.group(1)
    oui = candidate.split(sep)[:3]
    return sep.join([*oui, "00", "00", "00"])
