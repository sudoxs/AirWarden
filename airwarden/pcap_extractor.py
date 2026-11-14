"""Passively extract evidence artifacts from a pcap, with frame numbers + filters.

Each artifact carries enough to find and verify it by hand: the frame number, the
source/destination, a short (secret-safe) evidence snippet, and an exact
Wireshark display filter. Nothing is transmitted and no secret value is dumped —
credential/cookie values are shown masked or by field name only.

Two backends:
- ``scapy`` (always available): 802.11 + EAPOL/EAP + cleartext HTTP on open or
  already-decrypted captures.
- ``tshark`` (when the binary is installed): adds TLS certificate subjects,
  EAP-MD5 challenge/response, MSCHAPv2 / NetNTLMv2 fields, and IMSI identities,
  which need deep dissection.

``extract()`` with ``backend="auto"`` uses tshark when present, else scapy.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import asdict, dataclass, field
from typing import Any

from scapy.all import EAPOL, Dot11, Dot11ProbeReq, rdpcap

from airwarden.http_exposure import _CRED_FIELDS, _cookie_names, _header, _http_text
from airwarden.pcap_analyzer import _classify_eapol_msg, _eap_from_frame

_PMKID_KDE = b"\xdd\x14\x00\x0f\xac\x04"
_EAP_NAMES = {1: "Identity", 4: "MD5", 6: "GTC", 13: "TLS", 21: "TTLS", 25: "PEAP", 50: "AKA'"}


@dataclass
class Artifact:
    """One piece of passively observed evidence."""

    kind: str
    frame: int | None = None
    src: str | None = None
    dst: str | None = None
    bssid: str | None = None
    snippet: str = ""
    wireshark_filter: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


def _addrs(f: Any) -> tuple[str | None, str | None, str | None]:
    try:
        d = f.getlayer(Dot11)
        src = (d.addr2 or None) and d.addr2.lower()
        dst = (d.addr1 or None) and d.addr1.lower()
        bssid = (d.addr3 or None) and d.addr3.lower()
        return src, dst, bssid
    except Exception:
        return None, None, None


def tshark_available() -> bool:
    return shutil.which("tshark") is not None


# ---------------------------------------------------------------------------
# scapy backend
# ---------------------------------------------------------------------------


def _http_artifacts(f: Any, n: int, src, dst, bssid) -> list[Artifact]:
    text = _http_text(f)
    if text is None:
        return []
    host = _header(text, "Host") or "?"
    out: list[Artifact] = []
    auth = _header(text, "Authorization")
    if auth and auth.lower().startswith("basic "):
        out.append(
            Artifact(
                "HTTP_BASIC_AUTH", n, src, dst, bssid,
                f"Basic auth to {host} (base64, decodable — value not shown)",
                f'http.authorization && frame.number == {n}',
            )
        )
    cookie = _header(text, "Cookie")
    if cookie:
        out.append(
            Artifact(
                "HTTP_COOKIE", n, src, dst, bssid,
                f"cookie to {host}: {_cookie_names(cookie)}",
                f"http.cookie && frame.number == {n}",
            )
        )
    set_cookie = _header(text, "Set-Cookie")
    if set_cookie:
        out.append(
            Artifact(
                "SET_COOKIE", n, src, dst, bssid,
                f"set-cookie from {host}: {_cookie_names(set_cookie)}",
                f"http.set_cookie && frame.number == {n}",
            )
        )
    if text.upper().startswith("POST "):
        body = text.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in text else ""
        low = body.lower()
        fields = sorted({fld for fld in _CRED_FIELDS if (fld + "=") in low})
        if fields:
            out.append(
                Artifact(
                    "HTTP_POST", n, src, dst, bssid,
                    f"cleartext POST to {host}, fields: {', '.join(fields)} (values not shown)",
                    f'http.request.method == "POST" && frame.number == {n}',
                )
            )
    return out


def _eapol_artifacts(f: Any, n: int, src, dst, bssid) -> list[Artifact]:
    out: list[Artifact] = []
    try:
        raw = bytes(f[EAPOL].payload or b"")
        full = bytes(f[EAPOL])
    except Exception:
        return out
    if _PMKID_KDE in raw:
        out.append(
            Artifact("PMKID", n, src, dst, bssid, "RSN PMKID KDE in EAPOL M1",
                     f"eapol && frame.number == {n}")
        )
    msg = _classify_eapol_msg(raw)
    if msg is not None:
        out.append(
            Artifact("WPA_HANDSHAKE", n, src, dst, bssid, f"EAPOL 4-way message {msg}/4",
                     f"eapol && frame.number == {n}")
        )
    parsed = _eap_from_frame(f)
    if parsed is not None:
        code, etype = parsed
        name = _EAP_NAMES.get(etype, f"type {etype}")
        out.append(
            Artifact("EAP_TYPE", n, src, dst, bssid, f"EAP method: {name}",
                     f"eap.type == {etype} && frame.number == {n}", {"eap_type": etype})
        )
        if etype == 1 and code == 2:
            ident = full[9:].split(b"\x00", 1)[0].decode(errors="ignore").strip()
            if ident:
                kind = "IMSI" if "@wlan.mnc" in ident.lower() else "EAP_IDENTITY"
                out.append(
                    Artifact(kind, n, src, dst, bssid, f"identity: {ident}",
                             f"eap.identity && frame.number == {n}", {"identity": ident})
                )
    return out


def extract_scapy_frames(frames) -> list[Artifact]:
    """Extract artifacts from an in-memory frame iterable (frame numbers are 1-based)."""
    out: list[Artifact] = []
    deauth: dict[str, list[int]] = {}
    disassoc: dict[str, list[int]] = {}
    for i, f in enumerate(frames, start=1):
        src, dst, bssid = _addrs(f)
        if f.haslayer("Raw"):
            out.extend(_http_artifacts(f, i, src, dst, bssid))
        if f.haslayer(EAPOL):
            out.extend(_eapol_artifacts(f, i, src, dst, bssid))
        if f.haslayer(Dot11ProbeReq):
            elt = f.getlayer("Dot11Elt")
            ssid = ""
            if elt is not None and elt.info:
                ssid = bytes(elt.info).decode(errors="ignore")
            if ssid:
                out.append(
                    Artifact("PROBE_SSID", i, src, dst, bssid, f"probe for {ssid!r}",
                             f"wlan.fc.type_subtype == 4 && frame.number == {i}", {"ssid": ssid})
                )
        try:
            d = f.getlayer(Dot11)
            if d is not None and d.type == 0 and d.subtype in (10, 12) and bssid:
                (disassoc if d.subtype == 10 else deauth).setdefault(bssid, []).append(i)
        except Exception:
            pass
    for bssid, idx in sorted(deauth.items()):
        out.append(
            Artifact("DEAUTH", idx[0], None, None, bssid, f"{len(idx)} deauth frame(s)",
                     f'wlan.fc.type_subtype == 12 && wlan.bssid == {bssid}', {"count": len(idx)})
        )
    for bssid, idx in sorted(disassoc.items()):
        out.append(
            Artifact("DISASSOC", idx[0], None, None, bssid, f"{len(idx)} disassoc frame(s)",
                     f'wlan.fc.type_subtype == 10 && wlan.bssid == {bssid}', {"count": len(idx)})
        )
    return out


def _extract_scapy(pcap_path: str) -> list[Artifact]:
    return extract_scapy_frames(rdpcap(pcap_path))


# ---------------------------------------------------------------------------
# tshark backend (best-effort; needs the tshark binary)
# ---------------------------------------------------------------------------

# (kind, display filter, [fields], snippet template)
_TSHARK_QUERIES: list[tuple[str, str, list[str]]] = [
    ("TLS_CERT_SUBJECT", "tls.handshake.certificate", ["frame.number", "wlan.sa", "wlan.da"]),
    ("EAP_MD5", "eap.type == 4", ["frame.number", "wlan.sa", "wlan.da", "eap.md5.value"]),
    ("EAP_IDENTITY", "eap.identity", ["frame.number", "wlan.sa", "wlan.da", "eap.identity"]),
    ("HTTP_POST", 'http.request.method == "POST"',
     ["frame.number", "ip.src", "ip.dst", "http.host"]),
    ("MSCHAPV2", "radius.Framed_MTU || eap", ["frame.number", "wlan.sa", "wlan.da"]),
    ("NETNTLMV2", "ntlmssp.ntlmv2_response",
     ["frame.number", "ip.src", "ip.dst", "ntlmssp.auth.username"]),
]


def _run_tshark(pcap_path: str, display_filter: str, fields: list[str]) -> list[list[str]]:
    cmd = ["tshark", "-r", pcap_path, "-Y", display_filter, "-T", "fields", "-E", "separator=\t"]
    for fld in fields:
        cmd += ["-e", fld]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False)
    except (OSError, subprocess.SubprocessError):
        return []
    rows = []
    for line in proc.stdout.splitlines():
        if line.strip():
            rows.append(line.split("\t"))
    return rows


def _extract_tshark(pcap_path: str) -> list[Artifact]:
    out: list[Artifact] = []
    for kind, flt, fields in _TSHARK_QUERIES:
        for row in _run_tshark(pcap_path, flt, fields):
            padded = row + [""] * (len(fields) - len(row))
            frame = int(padded[0]) if padded[0].isdigit() else None
            src = padded[1] or None
            dst = padded[2] or None
            evidence = next((v for v in padded[3:] if v), "")
            snippet = f"{kind.lower()}: {evidence}" if evidence else kind.lower()
            ident = evidence if kind in ("EAP_IDENTITY",) else ""
            real_kind = "IMSI" if ident and "@wlan.mnc" in ident.lower() else kind
            out.append(
                Artifact(real_kind, frame, src, dst, None, snippet,
                         f"{flt} && frame.number == {frame}" if frame else flt)
            )
    return out


def extract(pcap_path: str, backend: str = "auto") -> list[Artifact]:
    """Extract evidence artifacts from ``pcap_path``.

    backend: "auto" (tshark if installed, else scapy), "scapy", or "tshark".
    """
    if backend == "auto":
        backend = "tshark" if tshark_available() else "scapy"
    if backend == "tshark":
        return _extract_tshark(pcap_path)
    if backend == "scapy":
        return _extract_scapy(pcap_path)
    raise ValueError(f"unknown backend: {backend!r}")


def artifacts_to_dicts(artifacts: list[Artifact]) -> list[dict[str, Any]]:
    return [asdict(a) for a in artifacts]
