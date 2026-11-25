"""Logging, console handling, table rendering, Spinner, and TXT/JSON/CSV exporters."""

import csv
import datetime
import io
import ipaddress
import itertools
import json
import logging
import os
import sys
import threading
from typing import Iterable, List, Optional, Sequence

from .discovery import discover_network
from .network import guess_subnet
from .ports import _highlight_risky_ports

log_buffer = io.StringIO()

_TABLE_HEADERS = ["IP Address", "Hostname", "MAC", "Alive", "Open Ports"]
_TABLE_COL_WIDTHS = [15, 34, 20, 10, 56]


def reset_log_buffer() -> None:
    """Clear accumulated in-memory logs to avoid unbounded growth across scans."""
    log_buffer.seek(0)
    log_buffer.truncate(0)


def setup_logger(level=logging.INFO, logfile: Optional[str] = None) -> None:
    """Configure root logger with console, in-memory buffer, and optional file handler."""
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(message)s"))
    handlers: List[logging.Handler] = [ch]

    if logfile:
        fh = logging.FileHandler(logfile, encoding="utf-8")
        fh.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
        )
        handlers.append(fh)

    sh = logging.StreamHandler(log_buffer)
    sh.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    )
    handlers.append(sh)

    logging.basicConfig(level=level, handlers=handlers, force=True)


def _is_embedded_ide_terminal() -> bool:
    """Return True when running inside an IDE integrated terminal (e.g., VS Code, JetBrains)."""
    term_prog = os.environ.get("TERM_PROGRAM", "").lower()
    term_emu = os.environ.get("TERMINAL_EMULATOR", "").lower()
    return (
        term_prog == "vscode"
        or bool(os.environ.get("VSCODE_INJECTION"))
        or term_emu.startswith("jetbrains")
    )


def maximize_console() -> bool:
    """
    Maximize the interactive terminal window while keeping title bar and taskbar.
    Skips non-TTY/piped runs and embedded IDE terminals.
    Returns True if a maximize request was issued.
    """
    if not (hasattr(sys.stdout, "isatty") and sys.stdout.isatty()):
        return False
    if _is_embedded_ide_terminal():
        return False

    try:
        if sys.platform.startswith("win"):
            import ctypes

            SW_MAXIMIZE = 3
            user32 = ctypes.windll.user32
            if os.environ.get("WT_SESSION"):
                hwnd = user32.GetForegroundWindow()
            else:
                hwnd = ctypes.windll.kernel32.GetConsoleWindow()
            if hwnd:
                user32.ShowWindow(hwnd, SW_MAXIMIZE)
                return True
            return False

        # POSIX terminals (xterm, GNOME Terminal, Kali qterminal, Konsole, etc.)
        sys.stdout.write("\x1b[9;1t")
        sys.stdout.flush()
        return True
    except Exception:
        return False


def ensure_console(title: str = "Net Scanner Core", maximize: bool = True) -> None:
    """
    Ensure a console exists on Windows without breaking piped/redirected I/O,
    set the title, and optionally maximize the terminal window in interactive mode.
    """
    if sys.platform.startswith("win"):
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            streams_missing = sys.stdout is None or sys.stderr is None or sys.stdin is None
            if streams_missing:
                ATTACH_PARENT_PROCESS = -1
                if not kernel32.AttachConsole(ATTACH_PARENT_PROCESS):
                    kernel32.AllocConsole()
                if sys.stdout is None:
                    sys.stdout = open("CONOUT$", "w", buffering=1, encoding="utf-8", errors="ignore")
                if sys.stderr is None:
                    sys.stderr = open("CONOUT$", "w", buffering=1, encoding="utf-8", errors="ignore")
                if sys.stdin is None:
                    sys.stdin = open("CONIN$", "r", encoding="utf-8", errors="ignore")

            if hasattr(sys.stdout, "isatty") and sys.stdout.isatty():
                try:
                    kernel32.SetConsoleTitleW(str(title))
                except Exception:
                    pass
        except Exception:
            pass

    if maximize:
        maximize_console()


class Spinner:
    """Responsive console dots animation in a background thread."""

    def __init__(self, message: str = "Running scan"):
        self.message = message
        self._stop_event = threading.Event()
        self.thread = threading.Thread(target=self._spin, daemon=True)

    def _spin(self):
        for dots in itertools.cycle(["", ".", "..", "...", "....", "....."]):
            if self._stop_event.is_set():
                break
            print(f"\r{dots}   ", end="", flush=True)
            if self._stop_event.wait(0.5):
                break
        print("\r" + " " * (len(self.message) + 10) + "\r", end="", flush=True)

    def start(self):
        self.thread.start()

    def stop(self):
        self._stop_event.set()
        self.thread.join()


def _trim_col(s: str, w: int) -> str:
    return (s[: w - 3] + "...") if len(s) > w else s


def _print_table_header() -> str:
    header_line = "  ".join(h.center(w) for h, w in zip(_TABLE_HEADERS, _TABLE_COL_WIDTHS))
    sep_line = "–" * len(header_line)
    logging.info(sep_line)
    logging.info(header_line)
    logging.info(sep_line)
    return sep_line


def _format_device_row(d: dict) -> str:
    ip = d["ip"]
    host = _trim_col(d.get("hostname") or "N/A", _TABLE_COL_WIDTHS[1])
    mac = _trim_col(d.get("mac") or "N/A", _TABLE_COL_WIDTHS[2])
    alive = str(d["alive"])
    ports_str = (
        ", ".join(_highlight_risky_ports(d["open_ports"]))
        if d.get("open_ports")
        else "N/A"
    )
    ports_str = _trim_col(ports_str, _TABLE_COL_WIDTHS[4])
    return (
        f"{ip.ljust(_TABLE_COL_WIDTHS[0])}  {host.center(_TABLE_COL_WIDTHS[1])}  "
        f"{mac.center(_TABLE_COL_WIDTHS[2])}  {alive.center(_TABLE_COL_WIDTHS[3])}  "
        f"{ports_str.center(_TABLE_COL_WIDTHS[4])}"
    )


def test_print(
    subnet: Optional[ipaddress.IPv4Network] = None,
    local_ip: Optional[str] = None,
    do_port_scan: bool = True,
    fast: bool = False,
    ports: Optional[Iterable[int]] = None,
    silent: bool = False,
    on_device=None,
    allow_guess: bool = False,
) -> list:
    if subnet is None and allow_guess and local_ip and not local_ip.startswith("169.254."):
        subnet = guess_subnet(local_ip, 24)

    if not subnet:
        logging.warning("No subnet detected — LAN scan disabled.")
        return []

    if silent:
        return discover_network(
            subnet=subnet,
            local_ip=local_ip,
            do_port_scan=do_port_scan,
            fast=fast,
            ports=ports,
            on_device=on_device,
            allow_guess=allow_guess,
        )

    logging.info("")
    logging.info(f"Scanning subnet: {subnet}...")
    sep_line = _print_table_header()

    seen_ips = set()
    print_lock = threading.Lock()

    def _stream_device(d: dict):
        ip = d["ip"]
        with print_lock:
            if ip in seen_ips:
                return
            seen_ips.add(ip)
            logging.info(_format_device_row(d))
        if on_device:
            on_device(d)

    devices = []
    try:
        devices = discover_network(
            subnet=subnet,
            local_ip=local_ip,
            do_port_scan=do_port_scan,
            fast=fast,
            ports=ports,
            on_device=_stream_device,
            allow_guess=allow_guess,
        )
    finally:
        logging.info(sep_line)
        logging.info(f"Found {len(seen_ips)} devices")

    return devices


def print_devices(devices: list) -> None:
    sep_line = _print_table_header()
    seen_ips = set()
    for d in devices:
        ip = d["ip"]
        if ip in seen_ips:
            continue
        seen_ips.add(ip)
        logging.info(_format_device_row(d))
    logging.info(sep_line)


def export_logs_txt(path: str, clear_buffer: bool = True) -> str:
    with open(path, "w", encoding="utf-8") as f:
        f.write(log_buffer.getvalue())
    if clear_buffer:
        reset_log_buffer()
    return path


def export_results_json(records: Sequence[dict], path: str) -> str:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(list(records), f, indent=2, ensure_ascii=False)
    return path


def export_results_csv(records: Sequence[dict], path: str) -> str:
    rows = list(records)
    if not rows:
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write("")
        return path

    fieldnames: List[str] = []
    for row in rows:
        for k in row.keys():
            if k not in fieldnames:
                fieldnames.append(k)

    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            serialized = {}
            for k in fieldnames:
                val = row.get(k, "")
                if isinstance(val, (list, tuple)):
                    serialized[k] = "; ".join(str(x) for x in val)
                else:
                    serialized[k] = "" if val is None else val
            writer.writerow(serialized)
    return path


def export_results(
    records: Sequence[dict],
    fmt: str = "txt",
    path: Optional[str] = None,
    clear_buffer: bool = True,
) -> str:
    fmt = fmt.lower().lstrip(".")
    if path is None:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        ext = fmt if fmt in ("txt", "json", "csv") else "txt"
        path = f"scan_export_{timestamp}.{ext}"

    if fmt == "json":
        return export_results_json(records, path)
    if fmt == "csv":
        return export_results_csv(records, path)
    return export_logs_txt(path, clear_buffer=clear_buffer)
