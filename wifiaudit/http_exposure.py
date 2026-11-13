"""Layer-7 cleartext data-exposure detection for OPEN (or decrypted) captures.

Only unencrypted 802.11 data frames can be parsed up to HTTP, so in practice
this fires on open networks (or a capture already decrypted with a known PSK).
It *flags* exposure for awareness and never dumps secrets: it reports the host
and the field/cookie names involved, not the credential or cookie values.

The per-frame worker :func:`frame_exposures` is shared by the file and live
paths so both classify identically.
"""

from __future__ import annotations

from typing import Any

from wifiaudit.models import Finding

_CRED_FIELDS = ("password", "passwd", "pass", "pwd", "username", "user", "email", "login")
_METHODS = ("GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ")


def _http_text(f: Any) -> str | None:
    try:
        if not f.haslayer("Raw"):
            return None
        load = bytes(f.getlayer("Raw").load or b"")
    except Exception:
        return None
    if not load:
        return None
    text = load.decode("latin-1", "ignore")
    if "HTTP/1." in text or text.upper().startswith(_METHODS):
        return text
    return None


def _bssid_of(f: Any) -> str:
    try:
        from scapy.all import Dot11

        return (f.getlayer(Dot11).addr3 or "").lower()
    except Exception:
        return ""


def _header(text: str, name: str) -> str | None:
    prefix = name.lower() + ":"
    for line in text.split("\r\n"):
        if line.lower().startswith(prefix):
            return line[len(prefix) :].strip()
    return None


def _cookie_names(value: str) -> str:
    names = []
    for pair in value.split(";"):
        pair = pair.strip()
        if "=" in pair:
            names.append(pair.split("=", 1)[0].strip())
    return ", ".join(dict.fromkeys(n for n in names if n)) or "?"


def frame_exposures(f: Any) -> list[tuple[tuple[str, str], Finding]]:
    """Return ((code, host), Finding) pairs for one cleartext HTTP frame."""
    text = _http_text(f)
    if text is None:
        return []
    host = _header(text, "Host") or "?"
    out: list[tuple[tuple[str, str], Finding]] = []

    auth = _header(text, "Authorization")
    if auth and auth.lower().startswith("basic "):
        out.append(
            (
                ("HTTP_BASIC_AUTH", host),
                Finding(
                    "HTTP_BASIC_AUTH",
                    "high",
                    0.95,
                    f"HTTP Basic auth sent in the clear to {host} (base64, directly decodable)",
                    "Serve the endpoint over HTTPS and rotate the exposed credentials.",
                ),
            )
        )

    cookie = _header(text, "Cookie") or _header(text, "Set-Cookie")
    if cookie:
        out.append(
            (
                ("HTTP_COOKIE", host),
                Finding(
                    "HTTP_COOKIE",
                    "medium",
                    0.85,
                    f"HTTP session cookie exposed in the clear at {host} ({_cookie_names(cookie)})",
                    "Enforce HTTPS with Secure/HttpOnly cookies; the session is hijackable.",
                ),
            )
        )

    if text.upper().startswith("POST "):
        body = text.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in text else ""
        low = body.lower()
        found = sorted({fld for fld in _CRED_FIELDS if (fld + "=") in low})
        if found:
            out.append(
                (
                    ("HTTP_CREDENTIAL", host),
                    Finding(
                        "HTTP_CREDENTIAL",
                        "critical",
                        0.9,
                        f"Cleartext credential POST to {host} (fields: {', '.join(found)})",
                        "Serve the login form over HTTPS; submitted credentials are exposed.",
                    ),
                )
            )
    return out


def detect_http_exposure(frames) -> dict[str, dict[tuple[str, str], Finding]]:
    """Map BSSID -> {(code, host): Finding} of cleartext HTTP exposures, de-duplicated."""
    out: dict[str, dict[tuple[str, str], Finding]] = {}
    for f in frames:
        pairs = frame_exposures(f)
        if not pairs:
            continue
        bssid = _bssid_of(f)
        if not bssid:
            continue
        per = out.setdefault(bssid, {})
        for key, finding in pairs:
            per.setdefault(key, finding)
    return out
