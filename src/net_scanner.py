#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Author: Menny Levinski

Requirements:
 - Python 3.8+
 - pip install psutil
 - pip install requests
"""

import os
import sys

# Ensure `src/` is importable whether invoked as `python src/net_scanner.py` or `python net_scanner.py`
_SRC_DIR = os.path.dirname(os.path.abspath(__file__))
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from scanner.cli import build_arg_parser, main, parse_interactive_command, show_menu
from scanner.config import (
    COMMON_PORTS_TCP,
    COMMON_PORTS_UDP,
    IS_LINUX,
    IS_MACOS,
    IS_WINDOWS,
    MAX_SUBNET_HOSTS,
    NOISE_IP_PREFIXES,
    NOISE_PORTS,
    RISKY_PORTS,
    UDP_PROBES,
    VERSION,
    _run_check_output,
    _subproc_kwargs_hide_window,
    version,
)
from scanner.discovery import _scan_ips_incremental, discover_network
from scanner.export import (
    Spinner,
    _format_device_row,
    _print_table_header,
    _trim_col,
    ensure_console,
    export_logs_txt,
    export_results,
    export_results_csv,
    export_results_json,
    log_buffer,
    print_devices,
    reset_log_buffer,
    setup_logger,
    test_print,
)
from scanner.http_probe import http_probe, http_scan_subnet
from scanner.inspector import (
    _detect_direction,
    _get_process_name,
    _is_noise_traffic,
    start_connection_inspector,
)
from scanner.network import (
    _clamp_subnet,
    _decode_dns_name,
    _encode_dns_name,
    _get_default_interface_and_ip,
    _ip_range_from_full_ips,
    _mdns_lookup,
    _nbns_lookup,
    _parse_arp_output,
    _parse_arp_table,
    _parse_target_ips,
    _ping,
    _primary_mac,
    _resolve_hostname,
    detect_local_subnet,
    guess_subnet,
    is_private_ip,
)
from scanner.ports import _highlight_risky_ports, _scan_ports
from scanner.smb import smb_probe_shares, smb_scan

__all__ = [
    "VERSION",
    "version",
    "COMMON_PORTS_TCP",
    "COMMON_PORTS_UDP",
    "UDP_PROBES",
    "RISKY_PORTS",
    "NOISE_PORTS",
    "NOISE_IP_PREFIXES",
    "MAX_SUBNET_HOSTS",
    "IS_WINDOWS",
    "IS_LINUX",
    "IS_MACOS",
    "log_buffer",
    "reset_log_buffer",
    "setup_logger",
    "ensure_console",
    "Spinner",
    "http_probe",
    "http_scan_subnet",
    "_subproc_kwargs_hide_window",
    "_run_check_output",
    "_get_default_interface_and_ip",
    "_primary_mac",
    "guess_subnet",
    "_clamp_subnet",
    "detect_local_subnet",
    "is_private_ip",
    "_ip_range_from_full_ips",
    "_parse_target_ips",
    "_ping",
    "_parse_arp_output",
    "_parse_arp_table",
    "_encode_dns_name",
    "_decode_dns_name",
    "_nbns_lookup",
    "_mdns_lookup",
    "_resolve_hostname",
    "_scan_ports",
    "_highlight_risky_ports",
    "_scan_ips_incremental",
    "discover_network",
    "_is_noise_traffic",
    "_get_process_name",
    "_detect_direction",
    "start_connection_inspector",
    "smb_probe_shares",
    "smb_scan",
    "_trim_col",
    "_print_table_header",
    "_format_device_row",
    "test_print",
    "print_devices",
    "export_logs_txt",
    "export_results_json",
    "export_results_csv",
    "export_results",
    "build_arg_parser",
    "parse_interactive_command",
    "show_menu",
    "main",
]

if __name__ == "__main__":
    raise SystemExit(main())
