# Changelog
All notable changes to **Core Net Scanner** are documented in this file.

---

## [1.9.1] – 2026-09-12 Latest
### Fixed
- Resolved local subnet detection issues

---

## [1.9.0] – 2026-07-20
### Fixed
- Minor text corrections and console optimizations

---

## [1.8.0] – 2026-06-14
### Added
- Added a new SMB detection scan option
- Modified several scan commands in the CLI menu

---

## [1.7.0] – 2026-05-31
### Added
- Added HTTP service scanner for local network
- Improved CLI menu layout and usability
- Windows executable is now digitally signed 

---

## [1.6.0] – 2026-05-23
### Added
- Replaced numeric menu with command-based CLI interface (scan -L, scan -R, scan -T, help, exit)
- Enhanced custom range scan performance by integrating ARP and ICMP-based filtering

### Fixed
- Fixed crash occurring when switching between scan modes repeatedly
- Refined log formatting for improved readability

---

## [1.5.0] – 2026-04-25
### Added
- Added a branded icon to the executable (EXE)
- Updated and expanded common port scanning list to 53 unique ports
- Enhanced real-time detection of short-lived TCP/HTTPS connections
- Introduced pseudo-flow tracking for UDP traffic using socket observation

### Fixed
- Reduces noise by applying TTL-based deduplication for repeated UDP activity

---

## [1.4.0] – 2026-04-05
### Added
- Added a basic Traffic Inspection feature as option 3 (Beta)
- Real-time monitoring of active TCP connections for selected ports

---

## [1.3.0] – 2026-03-20
### Added
- Name changed to "Uspector Network Scanner"
- More common ports added to the scanning list (43 total)

### Fixed
- Adjusted default worker threads for better stability

---

## [1.2.0] – 2026-02-23

### Added
- Essential stability optimizations for LAN detection mode

### Fixed
- Fixed ARP table tracing issue, devices are now detected correctly

---

## [1.1.0] – 2026-02-17

### Added
- Enhanced and balanced Windows 11 LAN scanning
- Optimized custom IP range scanning engine
- Proper handling of APIPA addresses (169.254.0.0/16)
- Enhanced subnet detection for Wi-Fi adapters
- Integrated `psutil` for improved network interface detection

### Fixed
- Resolved UnboundLocalError for local variable in test_print()
- Reduced excessive memory usage during concurrent _ping scans
- Fixed TCP alive check causing false positives on Windows 11
- Corrected MAC address parsing from ARP tables

---

## [1.0.0] – 2026-02-04 

### Initial Public Release
