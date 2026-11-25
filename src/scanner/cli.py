"""Unified interactive REPL and non-interactive argparse CLI for Net Scanner Core."""

import argparse
import logging
import os
import shlex
import sys
import threading
import time
from typing import List, Optional, Tuple

from .config import IS_WINDOWS, VERSION
from .discovery import _scan_ips_incremental
from .export import (
    Spinner,
    _format_device_row,
    _print_table_header,
    ensure_console,
    export_results,
    reset_log_buffer,
    setup_logger,
    test_print,
)
from .http_probe import http_scan_subnet
from .inspector import start_connection_inspector
from .network import (
    _get_default_interface_and_ip,
    _parse_target_ips,
    _primary_mac,
    detect_local_subnet,
    is_private_ip,
)
from .smb import smb_scan


def show_menu() -> None:
    title = "Commands (case-insensitive):"
    print("\n" + title)
    print("–" * len(title))
    print("scan --lan    [--fast] [--no-ports] [--ports P] [--output FILE]   LAN scan (devices & ports)")
    print("scan --range  <IP|START-END|CIDR> [--fast] [--ports P]            Custom IP / range / CIDR scan")
    print("scan --smb    [--output FILE]                                     SMB / NetBIOS scan (LAN only)")
    print("scan --http   [--output FILE]                                     HTTP / HTTPS service scan (LAN only)")
    print("scan --flow   [--timeout S] [--interval S] [--ports P]            Real-time traffic flow (TCP/UDP)")
    print("export        <txt|json|csv> [FILE]                               Export last scan results")
    print("help                                                              Show menu & examples")
    print("exit                                                              Exit")
    print("\nExamples:")
    print("  > scan --lan --fast")
    print("  > scan --range 192.168.1.0/24 --ports 22,80,443 --output hosts.json")
    print("  > scan --http --output web.csv")
    print("  > scan --flow --timeout 30 --ports 80,443")
    print("  > export json results.json")


def _parse_ports_arg(raw: str) -> Optional[List[int]]:
    if not raw or not raw.strip():
        return None
    ports: List[int] = []
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        p = int(token)
        if not (1 <= p <= 65535):
            raise ValueError(f"Port out of range (1-65535): {p}")
        ports.append(p)
    return ports or None


def _wait_for_inspector(stop_event: threading.Event, thread: threading.Thread) -> None:
    """
    Wait until either the user presses Enter / Ctrl+C OR `stop_event` is set
    by timeout expiration — preventing the CLI from hanging after timeout.
    """
    is_tty = hasattr(sys.stdin, "isatty") and sys.stdin.isatty()
    try:
        if not is_tty:
            while thread.is_alive() and not stop_event.is_set():
                thread.join(timeout=0.2)
            return

        if IS_WINDOWS:
            import msvcrt

            while thread.is_alive() and not stop_event.is_set():
                if msvcrt.kbhit():
                    ch = msvcrt.getwch()
                    if ch in ("\r", "\n"):
                        break
                    if ch == "\x03":
                        raise KeyboardInterrupt
                stop_event.wait(0.1)
        else:
            import select

            while thread.is_alive() and not stop_event.is_set():
                ready, _, _ = select.select([sys.stdin], [], [], 0.1)
                if ready:
                    sys.stdin.readline()
                    break
    except KeyboardInterrupt:
        print("\nStopping due to keyboard interrupt...")
    finally:
        stop_event.set()
        thread.join(timeout=2.0)


def _log_smb_results(results: List[dict]) -> None:
    if not results:
        logging.info("No SMB devices found.")
        return
    logging.info(f"Found {len(results)} SMB-capable devices:")
    for r in results:
        logging.info("")
        logging.info(f"[{r['type']}] {r['ip']} → port {r['port']}")
        if r["shares"]:
            for share in r["shares"]:
                logging.info(f"UNC Share: \\\\{r['ip']}\\{share}")
                if r["anonymous"]:
                    logging.info("Exposure : Anonymous Share")
                    logging.info("Enumeration : Successful")
                else:
                    logging.info("Exposure : Share Detected")
                    logging.info("Enumeration : Partial")
        else:
            logging.info("Exposure : SMB Reachable")
            logging.info("Enumeration : Denied")


def _run_range_scan(
    raw_target: str,
    local: Optional[str],
    do_port_scan: bool = True,
    fast: bool = False,
    ports: Optional[List[int]] = None,
) -> List[dict]:
    target_ips = _parse_target_ips(raw_target)
    print(f"\nTarget IPs: {len(target_ips)}")
    print(", ".join(target_ips[:10]) + (" ..." if len(target_ips) > 10 else ""))

    logging.info("")
    logging.info(f"Starting custom scan for {len(target_ips)} targets...")

    valid_ips: List[str] = []
    for ip in target_ips:
        if local and ip == local:
            logging.info(f"[SKIP] {ip} is local — skipping.")
            continue
        if not is_private_ip(ip):
            logging.info(f"[SKIP] {ip} is not private — skipping.")
            continue
        valid_ips.append(ip)

    found: dict = {}
    lock = threading.Lock()
    start = time.time()

    if valid_ips:
        sep_line = _print_table_header()

        def _stream_custom(d: dict):
            key = d.get("ip") or d.get("mac")
            with lock:
                if key and key not in found:
                    found[key] = d
                logging.info(_format_device_row(d))

        try:
            _scan_ips_incremental(
                ips=valid_ips,
                subnet=None,
                local_ip=local,
                do_port_scan=do_port_scan,
                fast=fast,
                ports=ports,
                on_device=_stream_custom,
                include_arp_only=False,
                check_arp_fallback=True,
            )
        except KeyboardInterrupt:
            print("\nCustom scan interrupted — partial results preserved.")
        finally:
            logging.info(sep_line)

    elapsed = time.time() - start
    if found:
        logging.info(f"Custom scan finished in {elapsed:.1f}s — found {len(found)} devices.")
    else:
        print(f"Custom scan finished in {elapsed:.1f}s - No devices found.")
    return list(found.values())


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="net_scanner",
        description=f"Net Scanner Core v{VERSION} — Cross-platform ethical network scanner",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--lan", action="store_true", help="Run LAN scan (devices & ports)")
    mode.add_argument(
        "--range",
        metavar="TARGET",
        help="Run custom scan for a single IP, start-end range, or CIDR (e.g. 192.168.1.0/24)",
    )
    mode.add_argument("--smb", action="store_true", help="Run SMB / NetBIOS scan (LAN only)")
    mode.add_argument("--http", action="store_true", help="Run HTTP / HTTPS service scan (LAN only)")
    mode.add_argument("--flow", action="store_true", help="Run real-time TCP/UDP traffic flow inspector")

    parser.add_argument("--fast", action="store_true", help="Fast mode (skip hostname lookups)")
    parser.add_argument("--no-ports", action="store_true", help="Skip port scanning in --lan/--range mode")
    parser.add_argument("--ports", metavar="PORTS", help="Comma-separated port list (e.g. 22,80,443)")
    parser.add_argument(
        "--timeout",
        type=int,
        default=0,
        help="Traffic flow timeout in seconds for --flow (0 = unlimited)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=0.2,
        help="Polling interval in seconds for --flow (default: 0.2)",
    )
    parser.add_argument("--output", metavar="PATH", help="Export scan results/logs to file")
    parser.add_argument(
        "--format",
        choices=("txt", "json", "csv"),
        default=None,
        help="Export format for --output (default: inferred from extension or txt)",
    )
    parser.add_argument(
        "--no-maximize",
        action="store_true",
        help="Do not maximize the terminal window in interactive mode",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument(
        "--log",
        nargs="?",
        const="scan.log",
        default=None,
        help="Write logs to file (default: scan.log)",
    )
    return parser


def _infer_format(args: argparse.Namespace) -> str:
    if args.format:
        return args.format
    if args.output:
        ext = os.path.splitext(args.output)[1].lstrip(".").lower()
        if ext in ("json", "csv", "txt"):
            return ext
    return "txt"


def _normalize_flag_tokens(tokens: List[str]) -> List[str]:
    """Lowercase flag names (e.g. --LAN, --Output=foo.json) while preserving value casing."""
    normalized: List[str] = []
    for tok in tokens:
        if tok.startswith("-"):
            if "=" in tok:
                flag, val = tok.split("=", 1)
                normalized.append(f"{flag.lower()}={val}")
            else:
                normalized.append(tok.lower())
        else:
            normalized.append(tok)
    return normalized


def _split_command_line(line: str) -> List[str]:
    tokens = shlex.split(line, posix=not IS_WINDOWS)
    if IS_WINDOWS:
        cleaned = []
        for t in tokens:
            if len(t) >= 2 and ((t[0] == '"' and t[-1] == '"') or (t[0] == "'" and t[-1] == "'")):
                t = t[1:-1]
            cleaned.append(t)
        return cleaned
    return tokens


def parse_interactive_command(
    line: str,
    prompt_range_target=None,
) -> Tuple[str, object]:
    """
    Parse a line entered at the interactive `>` prompt.
    Returns one of:
      ("empty", None)
      ("help", None)
      ("exit", None)
      ("export", (fmt, path_or_none))
      ("scan", argparse.Namespace)
      ("error", message_or_none)
    """
    stripped = line.strip()
    if not stripped:
        return ("empty", None)

    try:
        tokens = _split_command_line(stripped)
    except ValueError as e:
        return ("error", f"Invalid command syntax: {e}")

    verb = tokens[0].lower()
    rest = tokens[1:]

    if verb == "help":
        return ("help", None)

    if verb == "exit":
        return ("exit", None)

    if verb == "export":
        if not rest:
            return ("error", "Usage: export <txt|json|csv> [FILE]")
        fmt = rest[0].lower()
        if fmt not in ("txt", "json", "csv"):
            return ("error", f"Unsupported export format '{rest[0]}'. Use: txt, json, or csv.")
        if len(rest) > 2:
            return ("error", "Usage: export <txt|json|csv> [FILE]")
        path = rest[1] if len(rest) == 2 else None
        return ("export", (fmt, path))

    if verb != "scan":
        return ("error", f"Unknown command '{tokens[0]}'. Type 'help' to see available commands.")

    if not rest:
        return ("error", "Missing scan mode. Type 'help' to see available scan commands.")

    flag_tokens = _normalize_flag_tokens(rest)

    # Support bare `scan --range` (no target provided) by prompting interactively when callback is supplied
    if prompt_range_target is not None and "--range" in flag_tokens:
        idx = flag_tokens.index("--range")
        missing_val = idx + 1 >= len(flag_tokens) or flag_tokens[idx + 1].startswith("-")
        if missing_val:
            entered = prompt_range_target().strip()
            if not entered:
                return ("error", "Range scan cancelled (no target provided).")
            flag_tokens.insert(idx + 1, entered)

    parser = build_arg_parser()
    try:
        parsed = parser.parse_args(flag_tokens)
    except SystemExit:
        return ("error", None)

    if not any([parsed.lan, parsed.range, parsed.smb, parsed.http, parsed.flow]):
        return ("error", "Please specify a scan mode: --lan, --range, --smb, --http, or --flow.")

    return ("scan", parsed)


def _execute_scan(
    args: argparse.Namespace,
    local: Optional[str],
    subnet,
    interactive: bool = False,
) -> Tuple[int, List[dict]]:
    """Run one scan command (shared between shell CLI flags and interactive REPL)."""
    custom_ports: Optional[List[int]] = None
    if args.ports:
        try:
            custom_ports = _parse_ports_arg(args.ports)
        except ValueError as e:
            logging.error(f"Invalid --ports value: {e}")
            return 2, []

    if interactive:
        reset_log_buffer()

    records: List[dict] = []
    start = time.time()

    if args.lan:
        if not subnet:
            logging.error("No subnet detected — LAN scan disabled.")
            return 1, []
        scan_lock = threading.Lock()
        collected: dict = {}

        def _record_device(d: dict):
            key = d.get("ip") or d.get("mac")
            if key:
                with scan_lock:
                    if key not in collected:
                        collected[key] = d

        try:
            test_print(
                subnet=subnet,
                local_ip=local,
                do_port_scan=not args.no_ports,
                fast=args.fast,
                ports=custom_ports,
                on_device=_record_device,
            )
        except KeyboardInterrupt:
            print("\nLAN scan interrupted — partial results preserved.")
        finally:
            elapsed = time.time() - start
            logging.info(f"LAN scan finished in {elapsed:.1f}s")
        records = list(collected.values())

    elif args.range:
        try:
            records = _run_range_scan(
                args.range,
                local=local,
                do_port_scan=not args.no_ports,
                fast=args.fast,
                ports=custom_ports,
            )
        except Exception as e:
            logging.error(f"Invalid target: {e}")
            return 2, []

    elif args.smb:
        if not subnet:
            logging.error("No subnet detected.")
            return 1, []
        logging.info("")
        logging.info("Scanning SMB / NetBIOS services...\n")
        spinner = Spinner("Running SMB scan")
        spinner.start()
        try:
            records = smb_scan(subnet, local_ip=local)
        except KeyboardInterrupt:
            print("\nSMB scan interrupted.")
            records = []
        finally:
            spinner.stop()
        _log_smb_results(records)

    elif args.http:
        if not subnet:
            logging.error("No subnet detected.")
            return 1, []
        try:
            records = http_scan_subnet(
                subnet,
                local_ip=local,
                on_result=lambda r: logging.info(
                    f"[HTTP] {r['ip']} → {r['url']} ({r['status']} {r['server']})"
                ),
            )
        except KeyboardInterrupt:
            print("\nHTTP scan interrupted.")
            records = []
        elapsed = time.time() - start
        logging.info(f"HTTP scan finished in {elapsed:.1f}s — found {len(records)} services.")

    elif args.flow:
        timeout = args.timeout
        if timeout < 0:
            logging.warning("Invalid --timeout (< 0); using 0 (unlimited).")
            timeout = 0
        flow_records: List[dict] = []
        stop_event, thread = start_connection_inspector(
            interval=max(0.05, args.interval),
            ports=custom_ports,
            timeout=timeout,
            local_subnet=subnet,
            on_flow=flow_records.append,
        )
        print("\nTraffic flow running... Press ENTER to stop or Ctrl+C")
        _wait_for_inspector(stop_event, thread)
        records = flow_records

    if args.output:
        fmt = _infer_format(args)
        out_path = export_results(records, fmt=fmt, path=args.output, clear_buffer=False)
        print(f"Exported ({fmt.upper()}) → {out_path}")

    return 0, records


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    is_cli_mode = any([args.lan, args.range, args.smb, args.http, args.flow])
    if not is_cli_mode:
        ensure_console("Net Scanner Core", maximize=not args.no_maximize)

    log_level = logging.DEBUG if args.debug else logging.INFO
    setup_logger(level=log_level, logfile=args.log)

    print("MIT License – © 2026 Menny Levinski\n")
    interface, local = _get_default_interface_and_ip()
    mac = _primary_mac(interface)
    logging.info(f"Net Scanner Core v{VERSION}\n")
    logging.info(f"Interface: {interface or 'N/A'}")
    logging.info(f"Local MAC: {mac or 'N/A'}")
    logging.info(f"Local Adapter IP: {local or 'N/A'}")

    subnet = detect_local_subnet(interface, local)

    # ---- Non-interactive shell CLI mode ----
    if is_cli_mode:
        code, _ = _execute_scan(args, local=local, subnet=subnet, interactive=False)
        return code

    # ---- Unified interactive REPL mode ----
    last_records: List[dict] = []
    has_run_scan = False
    show_menu()

    while True:
        try:
            line = input("\n> ")
        except (EOFError, KeyboardInterrupt):
            print("\nExiting...")
            return 0

        kind, payload = parse_interactive_command(
            line,
            prompt_range_target=lambda: input(
                "Enter target (e.g. 192.168.1.1, 192.168.1.1-192.168.1.50, or 192.168.1.0/24): "
            ),
        )

        if kind == "empty":
            continue
        if kind == "help":
            show_menu()
            continue
        if kind == "exit":
            input("\nGoodbye! Press Enter to exit...")
            return 0
        if kind == "error":
            if payload:
                print(payload)
            continue
        if kind == "export":
            fmt, path = payload
            if not has_run_scan and fmt in ("json", "csv"):
                print("No scan results to export yet. Run a scan first.")
                continue
            out_path = export_results(last_records, fmt=fmt, path=path, clear_buffer=(fmt == "txt"))
            print(f"Exported ({fmt.upper()}) → {out_path}")
            continue
        if kind == "scan":
            _, last_records = _execute_scan(payload, local=local, subnet=subnet, interactive=True)
            has_run_scan = True
