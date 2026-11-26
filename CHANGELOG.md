# Changelog
All notable changes to **Net Scanner Core** are documented in this file.

---

## [1.9.8] – 2026-11-25 Latest
- Added automatic terminal window maximization in interactive mode (`maximize_console()`) across Windows, Windows Terminal, and Linux terminals
- Expanded scan output table widths (`Hostname` `20` → `34`, `Open Ports` `50` → `56`) for clearer display of hostnames and protocol-tagged ports

---

## [1.9.7] – 2026-11-25
- Modularized codebase into `src/scanner/` (`config`, `network`, `ports`, `discovery`, `http_probe`, `smb`, `inspector`, `export`, `cli`) with `src/net_scanner.py`
- Replaced legacy interactive `scan -L/-R/-S/-T/-X` commands with a unified CLI/REPL grammar (`scan --lan`, `scan --range`, `scan --smb`, `scan --http`, `scan --flow`, `export <txt|json|csv> [FILE]`) 
- Added non-interactive `argparse` flags, CIDR target support, and TXT/JSON/CSV export
- Replaced per-host nested port-scan thread pools with a shared bounded executor and socket semaphore (`256` max), aligned TCP/UDP port lists with `PORTS.md`
- Fixed Traffic Flow (`--flow`) to use the `0.2s` default interval, real detected subnet mask, bounded FIFO deduplication, and automatic non-blocking exit on timeout expiration
- Improved HTTP scanning (`--http`) with fast TCP pre-checks, `HEAD` requests with `405`/`501` streaming-`GET` fallback, true `SSLError` HTTP retry, post-ping ARP lookup, URL output
- Improved cross-platform and offline reliability: air-gapped LAN interface fallback, active-NIC MAC detection, APIPA guard consistency, Linux `ip neigh` and `smbclient` fallbacks

---

## [1.9.6] – 2026-11-15
- Reduced the connection inspection interval from 1.0 to 0.2 seconds per pulse, improving monitoring responsiveness

---

## [1.9.5] – 2026-11-13
- Incremental streaming execution for LAN scanning and custom IP range scanning
- Fixed hostname resolution (`_resolve_hostname`), preventing blocking OS reverse-DNS timeouts
- Eliminated redundant `/32` subnet scans in `scan -R` and preserved partial scan results

---

## [1.9.4] – 2026-11-13
- Fixed user-selected timeout being discarded and sleep interval in Traffic Flow (`scan -x`)
- Added UDP datagram probing to eliminate false negatives when scanning UDP ports from PORTS.md
- Optimized connection direction lookup in Connection Inspector from O(N²) to O(N)
- Corrected ARP parsing on Windows and normalized broadcast MAC address filtering on Linux
- Added subnet size guardrails and bounded concurrent ping workers to (/16, /8) networks

---

## [1.9.3] – 2026-10-21
- Corrected inbound Traffic Flow direction detection for incoming connections

---

## [1.9.2] – 2026-10-16
- Applied minor stability improvements and general bug fixes

---

## [1.9.1] – 2026-09-12
- Resolved local IPv4 subnet detection issues across network adapters

---

## [1.9.0] – 2026-07-20
- Refined console output wording and applied general console performance optimizations

---

## [1.8.0] – 2026-06-14
- Added SMB / NetBIOS service detection scan mode
- Updated CLI menu command syntax and organization

---

## [1.7.0] – 2026-05-31
- Added local-network HTTP service scanner
- Improved CLI menu layout and overall usability
- Digitally signed the Windows executable release

---

## [1.6.0] – 2026-05-23
- Replaced the numeric menu with a command-based CLI interface (`scan -L`, `scan -R`, `scan -T`, `help`, `exit`)
- Improved custom IP range scan performance by integrating ARP and ICMP pre-filtering
- Fixed a crash triggered when switching repeatedly between scan modes
- Refined log output formatting for improved readability

---

## [1.5.0] – 2026-04-25
- Added a branded application icon to the packaged Windows executable (EXE)
- Expanded the default common port scan list to 53 unique ports
- Improved real-time detection of short-lived TCP and HTTPS connections
- Introduced socket-observation pseudo-flow tracking for UDP traffic
- Reduced Traffic Flow noise using TTL-based deduplication for repeated UDP activity

---

## [1.4.0] – 2026-04-05
- Introduced basic Traffic Inspection (Beta) as menu option 3
- Added real-time monitoring of active TCP connections with selectable port filtering

---

## [1.3.0] – 2026-03-20
- Rebranded the tool to "Uspector Network Scanner"
- Expanded the default common port scan list to 43 ports
- Tuned default concurrent worker thread counts for improved scan stability

---

## [1.2.0] – 2026-02-23
- Applied core stability optimizations to LAN discovery mode
- Fixed ARP table parsing so discovered LAN devices are accurately identified

---

## [1.1.0] – 2026-02-17
- Enhanced and balanced LAN discovery performance on Windows 11
- Optimized the custom IP range scanning engine
- Added proper detection and handling of APIPA link-local addresses (`169.254.0.0/16`)
- Improved subnet detection for Wi-Fi network adapters
- Integrated `psutil` for more reliable network interface detection
- Resolved `UnboundLocalError` in `test_print()`
- Reduced peak memory usage during concurrent `_ping` sweeps
- Fixed TCP liveness checks producing false positives on Windows 11
- Corrected MAC address parsing from system ARP tables

---

## [1.0.0] – 2026-02-04
- Initial public release
