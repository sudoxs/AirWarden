# Changelog

All notable changes to `airwarden` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Confirmed vs. potential states** (`airwarden/state.py`): every finding is labelled
  `confirmed` (the network is vulnerable now) or `potential` (vulnerable only if a
  condition/attack is met), with the triggering condition spelled out. New conditional
  findings make the "potential" case explicit per category: `PSK_OFFLINE_IF_CAPTURED`
  (WPA/WPA2 with no captured handshake), `SAE_ONLINE_ONLY` (WPA3), `OWE_EVIL_TWIN`
  (Enhanced Open — now detected), and `ENTERPRISE_ROGUE_AP` (802.1X). The report shows a
  "Potential (conditional) vulnerabilities" table and confirmed/potential counts; JSON
  carries `state` and `condition` on each finding.
- **Exposure / data-leak classification** (`airwarden/exposure.py`): every finding is
  tagged with what leaked (identity, key-material, credential, session cookie,
  plaintext data, or a weakness), where it came from, and how abusable it is. The
  report and CLI show an exposure summary, and JSON carries per-AP `exposures`.
- **Layer-7 cleartext exposure** (`airwarden/http_exposure.py`): on open (or
  decrypted) captures, cleartext HTTP is flagged — credential POSTs
  (`HTTP_CREDENTIAL`), session cookies (`HTTP_COOKIE`), and Basic-auth
  (`HTTP_BASIC_AUTH`) — reported by host and field/cookie name. Secret values are
  never dumped. Encrypted (WPA2/WPA3) traffic is ciphertext, so this only fires on
  open networks or a capture already decrypted with a known PSK.
- **More passive detections**, all from the same 802.11 capture:
  - WPA3/WPA2 **transition mode** (SAE + PSK advertised) → `WPA3_DOWNGRADE_POSSIBLE`,
    and the advisor now recommends a single-client downgrade deauth for it.
  - **Enterprise EAP** insight: methods offered (`ENTERPRISE_EAP`), weak methods such
    as MD5/LEAP/GTC (`WEAK_EAP`), and cleartext identity leaks (`EAP_IDENTITY_LEAK`).
  - **Disassociation** frames (subtype 10) now count toward the disconnect-flood
    finding alongside deauth (subtype 12).
  - **Probe-request / evil-twin** intel: the SSIDs clients search for, and which of
    them no AP in range beacons (evil-twin bait), in the report and the CLI.
  - Encryption labelling now picks the strongest AKM, so a transition BSSID is
    reported as WPA3 rather than being mistaken for WPA2.
- **Live capture mode** (`airwarden live`): passively sniff a monitor-mode
  interface and run the full detection pipeline in real time, with a table that
  refreshes as frames arrive. Supports fixed-channel or `--hop` channel sweeping,
  a `--duration` limit, and writing the report and/or the raw pcap on exit. A new
  streaming `LiveAnalyzer` (`airwarden/live_analyzer.py`) shares one detection
  engine with the file path, so a live session and the pcap it writes yield
  identical findings. It only receives frames and never transmits.
- **Active follow-up advisory** (`airwarden/advisor.py`): for each access point,
  `analyze` now describes the single authorized follow-up action that would reveal
  the most information — a clientless PMKID request, or a single-client targeted
  deauth on a named BSSID/channel — with the reason and the authorization it
  requires. Rendered as a terminal table, an HTML "Active follow-up
  recommendations" section, and per-AP JSON (`active_recommendation`). Advice only;
  `analyze` transmits nothing.
- `--version` flag.
- Platform-support matrix and a Quickstart in the README, plus `pipx` install
  instructions.

### Changed
- README refreshed: removed the stale "everything is a stub" build-status note and
  documented the implemented passive pipeline.

## [0.1.0]

### Added
- Initial `airwarden` package: passive pcap analysis, scan-type classification,
  per-AP inventory and risk scoring, JSON/CSV/HTML reports, an authorization gate,
  and a gated single-target Bettercap client.
