# Changelog

All notable changes to `wifiaudit` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Live capture mode** (`wifiaudit live`): passively sniff a monitor-mode
  interface and run the full detection pipeline in real time, with a table that
  refreshes as frames arrive. Supports fixed-channel or `--hop` channel sweeping,
  a `--duration` limit, and writing the report and/or the raw pcap on exit. A new
  streaming `LiveAnalyzer` (`wifiaudit/live_analyzer.py`) shares one detection
  engine with the file path, so a live session and the pcap it writes yield
  identical findings. It only receives frames and never transmits.
- **Active follow-up advisory** (`wifiaudit/advisor.py`): for each access point,
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
- Initial `wifiaudit` package: passive pcap analysis, scan-type classification,
  per-AP inventory and risk scoring, JSON/CSV/HTML reports, an authorization gate,
  and a gated single-target Bettercap client.
