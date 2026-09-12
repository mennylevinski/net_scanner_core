#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Author: Menny Levinski

Requirements:
 - Python 3.0+
 - pip install psutil
 - pip install requests
"""

import io
import os
import re
import sys
import time
import uuid
import platform
import socket
import logging
import datetime
import ipaddress
import subprocess
import concurrent.futures
import threading
import itertools
import psutil
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from typing import List, Dict, Iterable, Optional

version = "1.9.1"

try:
    from VersionChecker import fetch_latest_version

    fetch_latest_version(version)

except ImportError:
    pass

except Exception as e:
    pass

log_buffer = io.StringIO()
now = datetime.datetime.now().replace(microsecond=0)

# ====== Icon Setup =======
ICO_ICON = "net_scanner_icon.ico"
PNG_ICON = "net_scanner_icon.png"

def resource_path(relative_path):
    if hasattr(sys, "_MEIPASS"):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

def set_window_icon(window):
    try:
        window.iconbitmap(resource_path(ICO_ICON))
    except Exception:
        try:
            from tkinter import PhotoImage
            window.iconphoto(False, PhotoImage(file=resource_path(PNG_ICON)))
        except Exception:
            pass

# ====== Logger Setup =======
def setup_logger(level=logging.INFO, logfile: Optional[str] = None):
    """Configure root logger. Call once at program start."""
    
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(message)s"))  

    handlers = [ch]

    fh = None
    if logfile:
        fh = logging.FileHandler(logfile)
        fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
        handlers.append(fh)

    sh = logging.StreamHandler(log_buffer)
    sh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
    handlers.append(sh)

    logging.basicConfig(level=level, handlers=handlers)

# ======= Console helper =======
def ensure_console(title: str = "Net Scanner Core"):
    """Ensure a console is available on Windows with black background / white text."""
    if sys.platform.startswith("win"):
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32

            ATTACH_PARENT_PROCESS = -1
            if not kernel32.AttachConsole(ATTACH_PARENT_PROCESS):
                kernel32.AllocConsole()

            sys.stdout = open("CONOUT$", "w", buffering=1, encoding="utf-8", errors="ignore")
            sys.stderr = open("CONOUT$", "w", buffering=1, encoding="utf-8", errors="ignore")
            sys.stdin = open("CONIN$", "r", encoding="utf-8", errors="ignore")

            try:
                kernel32.SetConsoleTitleW(str(title))
            except Exception:
                pass

            try:
                os.system("color 07")
            except Exception:
                pass
        except Exception:
            pass

# --- String limitation ---
def _limit_str(s: Optional[str], max_len: int = 23) -> Optional[str]:
    if not s:
        return s
    return s if len(s) <= max_len else s[:max_len - 3] + "..."

# --- Icon path ---
def resource_path(relative_path):
    """ Get absolute path to resource (works in .py and in PyInstaller EXE) """
    if hasattr(sys, '_MEIPASS'):  # PyInstaller sets this attr
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

# ======= Noise filter helper =======
NOISE_PORTS = {
    5353,   # mDNS
    1900,   # SSDP / UPnP
    123,    # NTP
    137, 138, 139, # NetBIOS / SMB noise
    0
}

NOISE_IP_PREFIXES = (
    "127.",      # loopback
    "169.254.",  # APIPA
    "fe80:",     # IPv6 link-local
    "::1",
    "::",
)

def _is_noise_traffic(conn) -> bool:
    try:
        if conn.status not in ("ESTABLISHED", "CLOSE_WAIT", "SYN_SENT", "LISTEN"):
            return True

        l_ip = conn.laddr.ip if conn.laddr else ""
        r_ip = conn.raddr.ip if conn.raddr else ""

        l_port = conn.laddr.port if conn.laddr else 0

        # DROP IPv6 LINK-LOCAL NOISE
        if isinstance(l_ip, str) and l_ip.startswith("fe80:"):
            return True
        if isinstance(r_ip, str) and r_ip.startswith("fe80:"):
            return True

        # IPv6 multicast / local service noise
        if l_ip in ("::", "::1"):
            return True

        # IPv4 noise ranges
        if l_ip.startswith(("127.", "169.254.")):
            return True

        # Service discovery ports
        if l_port in NOISE_PORTS:
            return True

        # UDP broadcast noise
        if conn.type == socket.SOCK_DGRAM and not conn.raddr:
            return True

        return False

    except Exception:
        return True

# ======= Spinner (moving dots) =======
class Spinner:
    """Simple console spinner/dots animation in a separate thread."""
    def __init__(self, message: str = "Running scan"):
        self.message = message
        self._stop_event = threading.Event()
        self.thread = threading.Thread(target=self._spin, daemon=True)

    def _spin(self):
        for dots in itertools.cycle(["", ".", "..", "...", "....", "....."]):
            if self._stop_event.is_set():
                break
            print(f"\r{dots}   ", end="", flush=True)
            time.sleep(0.5)
            
        print("\r" + " " * (len(self.message) + 10) + "\r", end="", flush=True)

    def start(self):
        self.thread.start()

    def stop(self):
        self._stop_event.set()
        self.thread.join()

# ======= HTTP request =======
def http_probe(ip, timeout=2):
    urls = [
        f"http://{ip}",
        f"http://{ip}:80",
        f"http://{ip}:8080",
        f"http://{ip}:8000",
        f"https://{ip}",
        f"https://{ip}:443",
        f"https://{ip}:8443",
        f"https://{ip}:10443",
    ]

    headers = {
        "User-Agent": "Mozilla/5.0 (NetworkScanner)"
    }

    for url in urls:
        try:
            r = requests.get(
                url,
                headers=headers,
                timeout=(2, timeout),
                allow_redirects=True,
                verify=False   # important for routers with self-signed certs
            )

            return {
                "url": url,
                "status": r.status_code,
                "server": r.headers.get("Server", "Unknown")
            }

        except requests.exceptions.SSLError:
            # try again as HTTP fallback
            continue

        except requests.exceptions.RequestException:
            continue

    return None

# ======= LAN scanning configs =======
# Default common ports to check quickly
COMMON_PORTS_TCP = [20, 21, 22, 23, 79, 80, 389, 443, 445, 636, 989, 990, 1080, 1433, 1434, 1521, 2222, 2375, 2376, 2049, 5601, 3306, 3389, 5432, 5060, 5061, 5900, 5985, 5986, 6379, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9001, 9042, 10000, 10443, 27017, 30015]

COMMON_PORTS_UDP = [53, 67, 68, 69, 111, 123, 137, 138, 161, 162, 500, 514, 520, 1900, 3478, 4500, 5353, 5683, 11211, 27015]

# OS detection
IS_WINDOWS = platform.system().lower().startswith("win")

# Windows-specific flags to hide console windows for subprocess children
if IS_WINDOWS:
    WINDOWS_CREATE_NO_WINDOW = 0x08000000
    try:
        STARTUPINFO = subprocess.STARTUPINFO()
        STARTUPINFO.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        STARTUPINFO.wShowWindow = subprocess.SW_HIDE
    except Exception:
        STARTUPINFO = None
else:
    WINDOWS_CREATE_NO_WINDOW = 0
    STARTUPINFO = None

def _subproc_kwargs_hide_window() -> dict:
    if IS_WINDOWS:
        kwargs = {"creationflags": WINDOWS_CREATE_NO_WINDOW}
        if STARTUPINFO is not None:
            kwargs["startupinfo"] = STARTUPINFO
        return kwargs
    return {}

def _run_check_output(cmd, shell=False, **kwargs) -> str:
    base_kwargs = {"text": True, "encoding": "utf-8", "errors": "ignore", "shell": shell}
    base_kwargs.update(_subproc_kwargs_hide_window())
    base_kwargs.update(kwargs)
    return subprocess.check_output(cmd, **base_kwargs)

def _run_subprocess_run(cmd, shell=False, **kwargs) -> subprocess.CompletedProcess:
    base_kwargs = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL, "shell": shell}
    base_kwargs.update(_subproc_kwargs_hide_window())
    base_kwargs.update(kwargs)
    return subprocess.run(cmd, **base_kwargs)

def _get_default_interface_and_ip() -> (Optional[str], Optional[str]):
    """
    Detect the real default network adapter and its IPv4 address.
    Uses routing table via psutil (already imported).
    """

    try:
        addrs = psutil.net_if_addrs()

        # Get default gateway using socket trick (most reliable cross-platform)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()

        # Now find which interface owns this IP
        for iface, addr_list in addrs.items():
            for addr in addr_list:
                if addr.family == socket.AF_INET and addr.address == local_ip:
                    return iface, local_ip

    except Exception:
        pass

    return None, None

def guess_subnet(ip: Optional[str], mask_bits: int = 24) -> ipaddress.IPv4Network:
    if not ip:
        return ipaddress.ip_network("0.0.0.0/0")
    return ipaddress.ip_network(f"{ip}/{mask_bits}", strict=False)

def _ping(ip: str, timeout_ms: int = 300) -> bool:
    system = platform.system().lower()

    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        # Linux / macOS
        timeout_sec = max(1, timeout_ms // 1000)
        cmd = ["ping", "-c", "1", "-W", str(timeout_sec), ip]

    result = subprocess.run(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        **_subproc_kwargs_hide_window()
    )
    return result.returncode == 0

def _parse_arp_table() -> Dict[str, str]:
    ip_to_mac = {}
    try:
        out = _run_check_output(["arp", "-a"], shell=False)
        if IS_WINDOWS:
            for line in out.splitlines():
                m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{14,17})", line)
                if m:
                    ip, mac = m.group(1), m.group(2).replace("–", ":").lower()
                    ip_to_mac[ip] = mac
        else:
            for line in out.splitlines():
                m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]{17})", line)
                if m:
                    ip, mac = m.group(1), m.group(2).lower()
                    ip_to_mac[ip] = mac
    except Exception:
        pass
    return ip_to_mac

def _resolve_hostname(ip: str, timeout: float = 0.5) -> str:
    # 1) Reverse DNS (cross-platform, safest)
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            fut = ex.submit(socket.gethostbyaddr, ip)
            return fut.result(timeout=timeout)[0]
    except Exception:
        pass

    # Linux-only methods here
    if platform.system().lower() == "windows":
        return "N/A"

    # Helper: check if a command exists
    def cmd_exists(cmd: str) -> bool:
        return subprocess.call(
            f"command -v {cmd} >/dev/null 2>&1", shell=True
        ) == 0

    # 2) NetBIOS (nmblookup)
    if cmd_exists("nmblookup"):
        try:
            result = subprocess.check_output(
                ["nmblookup", "-A", ip],
                stderr=subprocess.DEVNULL,
                timeout=timeout,
                text=True
            )
            for line in result.splitlines():
                if "<00>" in line and "GROUP" not in line:
                    return line.split()[0]
        except Exception:
            pass

    # 3) mDNS (avahi-resolve)
    if cmd_exists("avahi-resolve-address"):
        try:
            result = subprocess.check_output(
                ["avahi-resolve-address", ip],
                stderr=subprocess.DEVNULL,
                timeout=timeout,
                text=True
            ).strip()

            if result and " " in result:
                return result.split()[-1]
        except Exception:
            pass

    return "N/A"

def _scan_ports(ip: str, ports: Iterable[int], timeout: float = 0.5, max_workers: int = 100) -> List[int]:
    open_ports = []
    ports_list = list(ports)
    if not ports_list:
        return []

    def _try_port(port: int) -> Optional[int]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    return port
        except Exception:
            pass
        return None

    worker_count = min(max_workers, len(ports_list))

    with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as ex:
        futures = {ex.submit(_try_port, p): p for p in ports_list}
        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            if res is not None:
                open_ports.append(res)

    return sorted(open_ports)

def discover_hosts(subnet: ipaddress.IPv4Network, max_workers: int = 100, tcp_ports=None, timeout: float = 0.1) -> List[str]:
    """
    Detect alive hosts in the subnet using TCP ports first, then optional ping fallback.
    Returns list of IPs that respond and (on Windows) have a MAC in ARP table.
    """
    if tcp_ports is None:
        tcp_ports = [22, 53, 80, 139, 443, 445, 3389]

    ips = [str(ip) for ip in subnet.hosts()]
    if not ips:
        return []

    ip_mac = _parse_arp_table()  # prefetch ARP once

    def _check_ip(ip):
        # 1️⃣ TCP check
        for port in tcp_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    if s.connect_ex((ip, port)) == 0:
                        return ip
            except Exception:
                continue

        # 2️⃣ Ping fallback only for small subnets (<50 hosts)
        if len(ips) <= 50 and _ping(ip, timeout_ms=300):
            return ip

        return None

    alive_ips = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(max_workers, len(ips))) as ex:
        for ip in ex.map(_check_ip, ips):
            if ip:
                alive_ips.append(ip)

    # ---- Windows-only: filter out IPs without a MAC in ARP table ----
    if IS_WINDOWS:
        alive_ips = [ip for ip in alive_ips if ip_mac.get(ip)]

    return alive_ips

def discover_network(subnet, local_ip=None, do_port_scan=False, fast=False, ports=None):
    """
    Discover hosts on a subnet. Works for Ethernet and Wi-Fi.
    - Uses TCP ports + ICMP ping fallback.
    - Pre-populates ARP table to detect devices that block ping/TCP.
    """

    if ports is None:
        ports = COMMON_PORTS_TCP + COMMON_PORTS_UDP

    if subnet is None and local_ip:
        subnet = guess_subnet(local_ip, 24)

    port_timeout = 0.6
    tcp_timeout = 0.3

    if not subnet:
        logging.warning("No subnet provided, skipping scan.")
        return []

    # ---- Step 0: Pre-populate ARP cache ----
    ips = [str(ip) for ip in subnet.hosts()]
    logging.info("")
    logging.info(f"Pre-pinging {len(ips)} IPs to populate ARP cache")
    with concurrent.futures.ThreadPoolExecutor(max_workers=200) as ex:
        list(ex.map(lambda ip: _ping(ip, timeout_ms=300), ips))

    # ---- Step 1: Parallel ping + TCP sweep ----
    def _fast_alive(ip):
        tcp_hits = 0
        tcp_ports = [22, 53, 139, 161, 443, 445]

        for port in tcp_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(tcp_timeout)
                    if s.connect_ex((ip, port)) == 0:
                        tcp_hits += 1
            except Exception:
                pass

        if tcp_hits >= 1:
            return ip

    alive_ips = []
    max_threads = min(128, len(ips))  # 128 is aggressive but safe
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as ex:
        for result in ex.map(_fast_alive, ips):
            if result:
                alive_ips.append(result)

    # ---- Step 2: Skip local IP ----
    if local_ip and local_ip in alive_ips:
        alive_ips.remove(local_ip)

    # ---- Step 3: Parse ARP table for MACs ----
    ip_mac = _parse_arp_table()

    devices = []

    # ---- Step 4: Scan open ports (if enabled) and resolve hostnames ----
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as ex:
        port_futures = {}
        for ip in alive_ips:
            if do_port_scan:
                port_futures[ip] = ex.submit(_scan_ports, ip, ports, port_timeout, 200)

        for ip in alive_ips:
            hostname = _resolve_hostname(ip, timeout=1.0) if not fast else "N/A"
            mac = ip_mac.get(ip)
            open_ports = []
            if do_port_scan and ip in port_futures:
                try:
                    open_ports = port_futures[ip].result(timeout=10)
                except Exception:
                    open_ports = []

            devices.append({
                "ip": ip,
                "hostname": hostname,
                "mac": mac,
                "alive": True,
                "open_ports": open_ports
            })

    # ---- Step 5: Include ARP-only hosts (TCP-blocked / firewalled) ----
    existing_ips = {d["ip"] for d in devices}

    for ip, mac in ip_mac.items():
        try:
            ip_obj = ipaddress.ip_address(ip)

            # Must be inside scanned subnet
            if ip_obj not in subnet:
                continue

            # Skip broadcast address
            if ip == str(subnet.broadcast_address):
                continue

            # Skip already-detected TCP hosts
            if ip in existing_ips:
                continue

            # Skip invalid MACs
            if not mac or mac.lower().startswith("ff-ff"):
                continue

            devices.append({
                "ip": ip,
                "hostname": "N/A",
                "mac": mac,
                "alive": False,  # TCP didn’t respond
                "open_ports": []
            })

        except ValueError:
            continue

    # ---- Step 6: Sort by IP ----
    return sorted(devices, key=lambda x: socket.inet_aton(x["ip"]))

def _highlight_risky_ports(ports: Iterable[int]) -> List[str]:
    mapping = {}
    return [f"{p}({mapping.get(p,'')})" if p in mapping else str(p) for p in ports]

def _first_interface() -> Optional[str]:
    """Return the first non-loopback interface name on Linux or Windows."""
    system = platform.system().lower()
    try:
        if system == "linux":
            out = subprocess.check_output(["ip", "link"], text=True)
            m = re.findall(r"^\d+: (\S+):", out, re.MULTILINE)
            for iface in m:
                if iface != "lo":
                    return _limit_str(iface)
        elif system == "windows":
            cmd = [
                "powershell",
                "-Command",
                "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} "
                "| Select-Object -First 1 -ExpandProperty Name"
            ]
            out = subprocess.check_output(cmd, text=True).strip()
            if out:
                return _limit_str(out)
    except Exception:
        return None
    return None

def _primary_mac() -> Optional[str]:
    """Return primary system MAC address (best-effort, cross-platform)."""
    try:
        mac = uuid.getnode()
        return ":".join(f"{(mac >> i) & 0xff:02x}" for i in range(40, -1, -8))
    except Exception:
        return None

# ======= Connection Inspector (Controlled) =======
def _get_process_name(pid):
    try:
        return psutil.Process(pid).name()
    except Exception:
        return "N/A"

def _detect_direction(laddr_ip: str, raddr_ip: str, local_subnet: Optional[ipaddress.IPv4Network] = None) -> str:
    """
    Detects if connection is IN (incoming) or OUT (outgoing)
    - laddr_ip = local IP
    - raddr_ip = remote IP
    - local_subnet = optional, for strict LAN check
    Returns: 'IN', 'OUT', or 'LAN'
    """
    try:
        l_ip = ipaddress.ip_address(laddr_ip)
        r_ip = ipaddress.ip_address(raddr_ip)

        if local_subnet:
            if r_ip in local_subnet:
                return "LAN"
            elif l_ip in local_subnet:
                return "OUT"
            else:
                return "IN"

        # Fallback using is_private
        if r_ip.is_private:
            return "LAN"
        elif l_ip.is_private:
            return "OUT"
        else:
            return "IN"

    except ValueError:
        return "OUT"  # default fallback
    
def start_connection_inspector(
    interval: float = 1.0,
    ports: Optional[List[int]] = None,
    timeout: int = 0,
    skip_time_wait: bool = True
):
    stop_event = threading.Event()
    ports_set = set(ports) if ports else None
    seen = set()

    _, local_ip = _get_default_interface_and_ip()
    local_ip = local_ip or "0.0.0.0"
    local_subnet = guess_subnet(local_ip, 24)

    def _inspector():
        logging.info("")
        logging.info(
            f"=== Connection Inspector started "
            f"(ports: {ports if ports else 'all'}) ==="
        )

        start_time = time.time()

        while not stop_event.is_set():
            now = time.time()

            try:
                for conn in psutil.net_connections(kind="inet"):

                    # must have local address
                    if not conn.laddr:
                        continue

                    proto = "UDP" if conn.type == socket.SOCK_DGRAM else "TCP"

                    l_ip = conn.laddr.ip
                    l_port = conn.laddr.port

                    r_ip = conn.raddr.ip if conn.raddr else None
                    r_port = conn.raddr.port if conn.raddr else None

                    # FIX 1: TIME_WAIT filter (TCP only)
                    if skip_time_wait and proto == "TCP" and conn.status == "TIME_WAIT":
                        continue

                    # FIX 2: PORT FILTER (safe for UDP too)
                    if ports_set:
                        if l_port not in ports_set and (r_port not in ports_set if r_port else True):
                            continue

                    # FIX 3: CLEAN NOISE FILTER (DO NOT kill UDP)
                    if _is_noise_traffic(conn):
                        continue

                    # FIX 4: LISTEN CLEANUP (only TCP logic)
                    if conn.status == "LISTEN":
                        if l_ip in ("127.0.0.1", "::1", "0.0.0.0", "::"):
                            continue
                        if l_port in NOISE_PORTS:
                            continue

                    key = (conn.pid, l_ip, l_port, r_ip, r_port, conn.status)
                    if key in seen:
                        continue
                    seen.add(key)

                    proc_name = _get_process_name(conn.pid)

                    # FIX 5: CORRECT DIRECTION LOGIC
                    if conn.status == "LISTEN":
                        direction = "LISTEN"
                        src = f"{l_ip}:{l_port}"
                        dst = "*:*"

                    elif r_ip:
                        direction = _detect_direction(l_ip, r_ip, local_subnet)
                        src = f"{l_ip}:{l_port}"
                        dst = f"{r_ip}:{r_port}"

                    else:
                        direction = "LOCAL"
                        src = f"{l_ip}:{l_port}"
                        dst = "*:*"

                    # FINAL OUTPUT
                    logging.info(
                        f"[FLOW] {proto} {direction} {proc_name} "
                        f"{src} → {dst} ({conn.status})"
                    )

                # memory cleanup
                if len(seen) > 5000:
                    seen.clear()

            except Exception as e:
                logging.error(f"[Inspector Error] {e}")

            # timeout
            if timeout > 0 and (now - start_time) >= timeout:
                logging.info("Traffic flow timeout reached.")
                stop_event.set()
                break

            time.sleep(min(interval, 0.2))

        logging.info("=== Traffic flow stopped ===")

    thread = threading.Thread(target=_inspector, daemon=True)
    thread.start()
    return stop_event, thread

# ======= SMB Scanner =======
def smb_detect(ip: str, timeout: float = 0.5) -> bool:
    """
    Quick SMB availability check (no auth, no exploitation).
    """
    ports = [445, 139]

    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)

                if s.connect_ex((ip, port)) == 0:
                    return True

        except Exception:
            pass

    return False

def smb_probe_shares(ip: str):
    """
    Safe SMB share enumeration using Windows 'net view'.

    No authentication.
    No exploitation.

    Returns:
    {
        "anonymous": bool,
        "shares": [share1, share2, ...]
    }
    """

    try:
        import subprocess

        result = subprocess.run(
            ["net", "view", f"\\\\{ip}"],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode != 0:
            return {
                "anonymous": False,
                "shares": []
            }

        shares = []

        for line in result.stdout.splitlines():

            line = line.strip()

            if (
                not line
                or "Share name" in line
                or "The command completed" in line
                or line.startswith("---")
            ):
                continue

            parts = line.split()

            if not parts:
                continue

            share_name = parts[0]

            # Skip hidden/admin shares
            if share_name.endswith("$"):
                continue

            shares.append(share_name)

        return {
            "anonymous": True,
            "shares": shares
        }

    except Exception:
        pass

    return {
        "anonymous": False,
        "shares": []
    }

def smb_scan(subnet, local_ip=None, timeout: float = 0.3):
    """
    Scan subnet for SMB-capable devices.

    Lightweight.
    No authentication.
    No exploitation.
    """

    if not subnet:
        print("No subnet provided.")
        return []

    ips = [str(ip) for ip in subnet.hosts()]
    results = []

    def check(ip):

        # Skip local machine
        if local_ip and ip == local_ip:
            return None

        try:
            for port in (445, 139):

                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

                    s.settimeout(timeout)

                    if s.connect_ex((ip, port)) == 0:

                        share_info = smb_probe_shares(ip)

                        return {
                            "ip": ip,
                            "port": port,
                            "type": "SMB" if port == 445 else "NETBIOS",
                            "shares": share_info["shares"],
                            "anonymous": share_info["anonymous"]
                        }

        except Exception:
            pass

        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as ex:
        for res in ex.map(check, ips):
            if res:
                results.append(res)

    return results

# ======= Print Setup =======
def test_print(
    subnet: Optional[ipaddress.IPv4Network] = None,
    local_ip: Optional[str] = None,
    do_port_scan: bool = True,
    fast: bool = True,
    ports: Optional[Iterable[int]] = None,
    silent: bool = False,
) -> list:

    if subnet is None and local_ip:
        subnet = guess_subnet(local_ip, 24)

    devices = discover_network(
        subnet=subnet,
        local_ip=local_ip,
        do_port_scan=do_port_scan,
        fast=fast,
        ports=ports
    )

    if silent:
        return devices

    # --- Print table ---
    headers = ["IP Address", "Hostname", "MAC", "Alive", "Open Ports"]
    col_widths = [15, 20, 20, 10, 45]

    def _trim(s: str, w: int) -> str:
        return (s[: w - 3] + "...") if len(s) > w else s

    header_line = "  ".join(h.center(w) for h, w in zip(headers, col_widths))
    sep_line = "–" * len(header_line)
    logging.info("")
    logging.info(f"Scanned subnet: {subnet} — found {len(devices)} devices")
    logging.info(sep_line)
    logging.info(header_line)
    logging.info(sep_line)

    seen_ips = set()
    for d in devices:
        ip = d["ip"]
        if ip in seen_ips:
            continue
        seen_ips.add(ip)

        host = _trim(d.get("hostname") or "N/A", col_widths[1])
        mac = _trim(d.get("mac") or "N/A", col_widths[2])
        alive = str(d["alive"])
        if d.get("open_ports"):
            ports_str = ", ".join(_highlight_risky_ports(d["open_ports"]))
        else:
            ports_str = "N/A"
        ports_str = _trim(ports_str, col_widths[4])

        logging.info(
            f"{ip.ljust(col_widths[0])}  {host.center(col_widths[1])}  "
            f"{mac.center(col_widths[2])}  {alive.center(col_widths[3])}  {ports_str.center(col_widths[4])}"
        )

    logging.info(sep_line)
    return devices

def print_devices(devices: list):
    # Same logic as test_print, just the printing part
    headers = ["IP Address", "Hostname", "MAC", "Alive", "Open Ports"]
    col_widths = [15, 20, 20, 10, 45]

    def _trim(s: str, w: int) -> str:
        return (s[: w - 3] + "...") if len(s) > w else s

    header_line = "  ".join(h.center(w) for h, w in zip(headers, col_widths))
    sep_line = "–" * len(header_line)

    logging.info(sep_line)
    logging.info(header_line)
    logging.info(sep_line)

    seen_ips = set()
    for d in devices:
        ip = d["ip"]
        if ip in seen_ips:
            continue
        seen_ips.add(ip)

        host = _trim(d.get("hostname") or "N/A", col_widths[1])
        mac = _trim(d.get("mac") or "N/A", col_widths[2])
        alive = str(d["alive"])
        ports_str = _trim(
            ", ".join(_highlight_risky_ports(d.get("open_ports", []))) if d.get("open_ports") else "N/A",
            col_widths[4]
        )

        logging.info(
            f"{ip.ljust(col_widths[0])}  {host.center(col_widths[1])}  "
            f"{mac.center(col_widths[2])}  {alive.center(col_widths[3])}  {ports_str.center(col_widths[4])}"
        )

    logging.info(sep_line)

# --- Define private IP check ---
def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

# ======= Main =======
if __name__ == "__main__":
    ensure_console(f"Net Scanner Core")

    log_level = logging.DEBUG if "--debug" in sys.argv else logging.INFO
    log_file = None
    if "--log" in sys.argv:
        idx = sys.argv.index("--log")
        if idx + 1 < len(sys.argv):
            log_file = sys.argv[idx + 1]
        else:
            log_file = "scan.log"

    setup_logger(level=log_level, logfile=log_file)
    scan_lock = threading.Lock()

    # --- Detect local IP and subnet ---
    print(f"MIT License – © 2025 Menahem Levinski\n")
    interface, local = _get_default_interface_and_ip()
    mac = _primary_mac()
    logging.info(f"Net Scanner Core v{version}\n")
    logging.info(f"Interface: {interface or 'N/A'}")
    logging.info(f"Local MAC: {mac or 'N/A'}")   
    logging.info(f"Local Adapter IP: {local or 'N/A'}")

    # ---- Detect local subnet ----
    if isinstance(local, str) and local.startswith("169.254."):
        logging.warning("APIPA detected (169.254.x.x). No DHCP lease — LAN scan disabled.")
        subnet = None

    elif isinstance(local, str) and "." in local:
        try:
            addrs = psutil.net_if_addrs()
            netmask = None

            for addr in addrs.get(interface, []):
                if addr.family == socket.AF_INET and addr.address == local:
                    netmask = addr.netmask
                    break

            if netmask:
                subnet = ipaddress.ip_network(
                    f"{local}/{netmask}",
                    strict=False
                )
                logging.info(f"Detected Subnet: {subnet}")
            else:
                logging.warning("Unable to determine network mask — LAN scan disabled.")
                subnet = None

        except Exception:
            logging.warning("Unable to determine local subnet — LAN scan disabled.")
            subnet = None

    else:
        logging.warning("Subnet detection skipped (IPv6 or no IP)")
        subnet = None

    # --- Initialize target_ips variable ---
    target_ips = None

# --- Ask user which scan to perform (LAN or custom) ---
MAX_RANGE_SIZE = 512
scan_results = {}

# --- Helper functions ---
def _ip_range_from_full_ips(start_ip: str, end_ip: str) -> List[str]:
    a = ipaddress.IPv4Address(start_ip)
    b = ipaddress.IPv4Address(end_ip)
    if int(b) < int(a):
        raise ValueError("End IP is smaller than start IP")
    size = int(b) - int(a) + 1
    if size > MAX_RANGE_SIZE:
        raise ValueError(f"Range too large ({size} IPs); max is {MAX_RANGE_SIZE}")
    return [str(ipaddress.IPv4Address(int(a) + i)) for i in range(size)]

# ---- Main scan loop ----
def show_menu():
    title = "Commands (case-insensitive):"
    print("\n" + title)
    print("–" * len(title))

    print(f"{'scan -L':10} LAN scan (devices and ports)")
    print(f"{'scan -R':10} Custom IP range scan")
    print(f"{'scan -S':10} SMB / NetBIOS scan (LAN only)")
    print(f"{'scan -T':10} HTTP service scan (LAN only)")
    print(f"{'scan -X':10} Device traffic flow")
    print(f"{'help':10} Show menu")
    print(f"{'exit':10} Exit")
    
show_menu()

while True:
    scan_mode = input("\n> ").strip().lower()

    if scan_mode not in {"scan -l", "scan -r", "scan -s", "scan -t", "scan -x", "help", "exit", ""}:
        print("Invalid command!")
        continue

    elif scan_mode == "":
        continue

    elif scan_mode == "help":
        show_menu()
        continue

    elif scan_mode == "exit":
        input("\nGoodbye! Press Enter to exit...")
        sys.exit(0)
            
    if scan_mode == "scan -l":
        choice = input("\nStart full LAN scan? (Y/N): ").strip().upper()
        if choice not in ("Y", "N"):
            print("Invalid choice!")
            continue
        if choice != "Y":
            print("LAN scan cancelled.")
            continue

        scan_results.clear()
        spinner = Spinner("Running LAN scan")
        spinner.start()
        start = time.time()
        try:
            results = test_print(
                subnet=subnet,
                local_ip=local,
                do_port_scan=True,
                fast=True
            )
            for d in results:
                key = d.get("ip") or d.get("mac")
                if key and key not in scan_results:
                    scan_results[key] = d
        finally:
            spinner.stop()
            elapsed = time.time() - start
            logging.info(f"LAN scan finished in {elapsed:.1f}s")

    elif scan_mode == "scan -r":
        print("\nCustom scan options:")
        print("Format options:")
        print(" - Single IP (example: 1.1.1.1)")
        print(" - IP Range  (example: 1.1.1.1-1.1.1.50)\n")

        raw = input("Enter target (single IP or range): ").strip()
        target_ips = []

        try:
            if "-" in raw:
                start_ip, end_ip = map(str.strip, raw.split("-", 1))
                ipaddress.ip_address(start_ip)
                ipaddress.ip_address(end_ip)
                target_ips = _ip_range_from_full_ips(start_ip, end_ip)
            else:
                ipaddress.ip_address(raw)
                target_ips = [raw]
        except Exception as e:
            print(f"Invalid input: {e}")
            continue

        print(f"\nTarget IPs: {len(target_ips)}")
        print(", ".join(target_ips[:10]) + (" ..." if len(target_ips) > 10 else ""))
        
        logging.info("")
        logging.info(f"Starting custom scan for {len(target_ips)} targets...")

        scan_results.clear()
        ip_mac = _parse_arp_table()

        spinner = Spinner("Running custom scan")
        spinner.start()
        start = time.time()

        # ONLY CHANGE: parallel loop
        def process_ip(ip):

            # 0 Skip local IP
            if local and ip == local:
                logging.info(f"\n[SKIP] {ip} is local — skipping.")
                return

            # 1 Only scan private IPs
            if not is_private_ip(ip):
                logging.info(f"\n[SKIP] {ip} is not private — skipping.")
                return

            # 2 ICMP + ARP filter (UNCHANGED LOGIC)
            if ip not in ip_mac and not _ping(ip, timeout_ms=400):
                return

            # 3 Convert to /32 subnet for test_print
            single_subnet = ipaddress.ip_network(f"{ip}/32")

            # 4 Run silent scan (UNCHANGED)
            try:
                results = test_print(
                    subnet=single_subnet,
                    local_ip=local,
                    do_port_scan=True,
                    fast=True,
                    silent=True
                )
            except Exception as e:
                logging.error(f"[ERROR] Scan failed for {ip}: {e}")
                return

            # 5 Collect results (UNCHANGED)
            if results:
                for d in results:
                    key = d.get("ip") or d.get("mac")
                    if key:
                        with scan_lock:
                            if key not in scan_results:
                                scan_results[key] = d

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
                list(ex.map(process_ip, target_ips))

        finally:
            spinner.stop()
            elapsed = time.time() - start

            if scan_results:
                logging.info(
                    f"Custom scan finished in {elapsed:.1f}s — found {len(scan_results)} devices."
                )
                devices_snapshot = list(scan_results.values())
                print_devices(devices_snapshot)
            else:
                print(f"Custom scan finished in {elapsed:.1f}s - No devices found.")

    elif scan_mode == "scan -s":

        if not subnet:
            logging.info("No subnet detected.")
            continue
        logging.info("")
        logging.info("Scanning SMB / NetBIOS services...\n")

        spinner = Spinner("Running SMB scan")
        spinner.start()
        start = time.time()

        try:
            results = smb_scan(subnet, local_ip=local)

        finally:
            spinner.stop()

        elapsed = time.time() - start

        if results:
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

        else:
            logging.info("No SMB devices found.")

    elif scan_mode == "scan -t":

        if not subnet:
            logging.info("No subnet detected.")
            continue

        ips = [str(ip) for ip in subnet.hosts()]

        logging.info("")
        logging.info(f"Pre-filtering {len(ips)} hosts (ICMP + ARP)...\n")

        alive_ips = set()
        ip_mac = _parse_arp_table()

        # STEP 1A: ICMP check
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as ex:
            for ip, ok in zip(ips, ex.map(_ping, ips)):
                if ok:
                    alive_ips.add(ip)

        # STEP 1B: ARP fallback (THIS is what makes DG appear)
        for ip in ip_mac.keys():
            if ip in ips:
                alive_ips.add(ip)

        alive_ips = list(alive_ips)

        logging.info(f"Alive hosts: {len(alive_ips)}\n")

        results = []

        spinner = Spinner("Scanning HTTP services")
        spinner.start()
        start = time.time()

        try:
            def check(ip):
                return (ip, http_probe(ip, timeout=2))

            with concurrent.futures.ThreadPoolExecutor(max_workers=80) as ex:
                for ip, res in ex.map(check, alive_ips):
                    if res:
                        results.append({
                            "ip": ip,
                            "url": res["url"],
                            "status": res["status"],
                            "server": res["server"]
                        })

        finally:
            spinner.stop()

        for r in results:
            logging.info(f"[HTTP] {r['ip']} → {r['status']} {r['server']}")
            
    elif scan_mode == "scan -x":
        # --- Ask for timeout ---
        try:
            timeout = int(input("\nSelect timeout (10-300 seconds, 0 = unlimited): ").strip())
            if timeout < 0 or timeout > 300:
                print("Invalid timeout, using default 0 (unlimited).")
                timeout = 0
        except ValueError:
            print("Invalid timeout, using default 0 (unlimited).")
            timeout = 0

        # --- Ask for ports ---
        raw_ports = input(f"\nType which ports to inspect (for example: 80, 443) or press Enter for all ports: ").strip()
        if raw_ports:
            try:
                ports_to_monitor = [int(p.strip()) for p in raw_ports.split(",") if p.strip()]
            except ValueError:
                print("Invalid port list, falling back to all ports.")
                ports_to_monitor = None
        else:
            ports_to_monitor = None

        stop_event, thread = start_connection_inspector(interval=2, ports=ports_to_monitor)

        try:
            print("\nTraffic flow running... Press ENTER to stop or Ctrl+C")
            input()  # Wait for ENTER or Ctrl+C
        except KeyboardInterrupt:
            print("\nStopping due to keyboard interrupt...")
        finally:
            stop_event.set()
            thread.join()
        
    export = input("\nExport logs to text file? (Y to export, Enter to skip): ").strip().lower()
    if export == "y":
        # Generate timestamp for filename
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        export_path = f"scan_log_export_{timestamp}.txt"
        
        # Write log buffer to file
        with open(export_path, "w", encoding="utf-8") as f:
            f.write(log_buffer.getvalue())
        
        print(f"Logs exported → {export_path}")
        continue
