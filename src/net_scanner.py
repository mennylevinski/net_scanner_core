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
import shutil
import struct
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

version = "1.9.5"

try:
    from VersionChecker import fetch_latest_version

    fetch_latest_version(version)

except ImportError:
    pass

except Exception as e:
    pass

log_buffer = io.StringIO()
now = datetime.datetime.now().replace(microsecond=0)

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
)

def _is_noise_traffic(conn) -> bool:
    try:
        is_udp = conn.type == socket.SOCK_DGRAM
        if not is_udp and conn.status not in ("ESTABLISHED", "CLOSE_WAIT", "SYN_SENT", "LISTEN"):
            return True

        l_ip = conn.laddr.ip if conn.laddr else ""
        r_ip = conn.raddr.ip if conn.raddr else ""

        l_port = conn.laddr.port if conn.laddr else 0

        # Loopback, unspecified, APIPA, and IPv6 link-local noise
        if l_ip in ("::", "::1") or r_ip in ("::", "::1"):
            return True
        if isinstance(l_ip, str) and l_ip.startswith(NOISE_IP_PREFIXES):
            return True
        if isinstance(r_ip, str) and r_ip.startswith(NOISE_IP_PREFIXES):
            return True

        # Service discovery ports
        if l_port in NOISE_PORTS:
            return True

        # UDP broadcast / unbound socket noise
        if is_udp and not conn.raddr:
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
        f"http://{ip}:8080",
        f"http://{ip}:8000",
        f"https://{ip}",
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

MAX_SUBNET_HOSTS = 512

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
                    ip, mac = m.group(1), m.group(2).replace("-", ":").lower()
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

_HAS_NMBLOOKUP = bool(not IS_WINDOWS and shutil.which("nmblookup"))
_HAS_AVAHI = bool(not IS_WINDOWS and shutil.which("avahi-resolve-address"))


def _encode_dns_name(name: str) -> bytes:
    """Encode a dotted hostname into DNS wire format."""
    out = bytearray()
    for part in name.split("."):
        b = part.encode("ascii", errors="ignore")
        out.append(len(b))
        out.extend(b)
    out.append(0)
    return bytes(out)


def _decode_dns_name(data: bytes, offset: int):
    """Decode a DNS wire-format name (handling compression pointers)."""
    labels = []
    jumped = False
    orig_offset = offset
    seen = set()
    while offset < len(data):
        if offset in seen:
            break
        seen.add(offset)
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                orig_offset = offset + 2
            offset = ptr
            jumped = True
        else:
            offset += 1
            labels.append(data[offset:offset + length].decode("utf-8", errors="replace"))
            offset += length
    return ".".join(labels), (orig_offset if jumped else offset)


def _nbns_lookup(ip: str, timeout: float = 0.5) -> Optional[str]:
    """Resolve hostname via NetBIOS Node Status Request (UDP 137)."""
    packet = UDP_PROBES[137]
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(packet, (ip, 137))
            data, _ = s.recvfrom(1024)
            if len(data) < 12:
                return None
            qdcount, ancount = struct.unpack("!HH", data[4:8])
            off = 12
            for _ in range(qdcount):
                _, off = _decode_dns_name(data, off)
                off += 4
            fallback = None
            for _ in range(ancount):
                if off >= len(data):
                    break
                _, off = _decode_dns_name(data, off)
                if off + 10 > len(data):
                    break
                rtype, _, _, _ = struct.unpack("!HHIH", data[off:off + 10])
                off += 10
                if rtype == 0x0021 and off < len(data):
                    num_names = data[off]
                    pos = off + 1
                    for _ in range(num_names):
                        if pos + 18 > len(data):
                            break
                        raw_name = data[pos:pos + 15]
                        suffix = data[pos + 15]
                        flags = struct.unpack("!H", data[pos + 16:pos + 18])[0]
                        is_group = bool(flags & 0x8000)
                        if not is_group:
                            name = raw_name.decode("ascii", errors="ignore").strip()
                            if name and not name.startswith("*") and name != "__MSBROWSE__":
                                if suffix == 0x00:
                                    return name
                                if suffix == 0x20 and fallback is None:
                                    fallback = name
                        pos += 18
                    return fallback
    except Exception:
        pass
    return None


def _mdns_lookup(ip: str, timeout: float = 0.5) -> Optional[str]:
    """Resolve hostname via direct unicast mDNS PTR query (UDP 5353)."""
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return None
        rev = ".".join(reversed(parts)) + ".in-addr.arpa"
        qname = _encode_dns_name(rev)
        pkt = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" + qname + b"\x00\x0c\x80\x01"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(pkt, (ip, 5353))
            data, addr = s.recvfrom(2048)
            if addr[0] == ip and len(data) > 12:
                qdcount, ancount = struct.unpack("!HH", data[4:8])
                off = 12
                for _ in range(qdcount):
                    _, off = _decode_dns_name(data, off)
                    off += 4
                for _ in range(ancount):
                    if off + 10 > len(data):
                        break
                    _, off = _decode_dns_name(data, off)
                    if off + 10 > len(data):
                        break
                    rtype, _, _, rdlen = struct.unpack("!HHIH", data[off:off + 10])
                    off += 10
                    if rtype == 12:
                        host, _ = _decode_dns_name(data, off)
                        host = host.rstrip(".")
                        if host and host != ip:
                            return host
                    off += rdlen
    except Exception:
        pass
    return None


def _resolve_hostname(ip: str, timeout: float = 0.8) -> str:
    """Resolve IP to hostname using rDNS, mDNS, and NetBIOS within strict timeout."""
    results = {}
    lock = threading.Lock()
    done = threading.Event()
    remaining = [3]

    def _finish(key: str, val: Optional[str]):
        with lock:
            if val and val != ip:
                results[key] = val
                done.set()
            remaining[0] -= 1
            if remaining[0] <= 0:
                done.set()

    def _run_rdns():
        val = None
        try:
            val = socket.gethostbyaddr(ip)[0]
        except Exception:
            pass
        _finish("rdns", val)

    def _run_nbns():
        _finish("nbns", _nbns_lookup(ip, timeout=timeout))

    def _run_mdns():
        _finish("mdns", _mdns_lookup(ip, timeout=timeout))

    for fn in (_run_rdns, _run_nbns, _run_mdns):
        threading.Thread(target=fn, daemon=True).start()

    done.wait(timeout=timeout)
    with lock:
        resolved = results.get("rdns") or results.get("mdns") or results.get("nbns")
    if resolved:
        return resolved

    # Linux-only fallbacks (e.g., local Avahi daemon cache)
    if not IS_WINDOWS:
        if _HAS_AVAHI:
            try:
                result = subprocess.check_output(
                    ["avahi-resolve-address", ip],
                    stderr=subprocess.DEVNULL,
                    timeout=timeout,
                    text=True
                ).strip()
                parts = result.split()
                if len(parts) >= 2:
                    host = parts[-1].rstrip(".")
                    if host and host != ip:
                        return host
            except Exception:
                pass

        if _HAS_NMBLOOKUP:
            try:
                result = subprocess.check_output(
                    ["nmblookup", "-A", ip],
                    stderr=subprocess.DEVNULL,
                    timeout=timeout,
                    text=True
                )
                for line in result.splitlines():
                    if "<00>" in line and "GROUP" not in line:
                        parts = line.split()
                        if parts:
                            return parts[0]
            except Exception:
                pass

    return "N/A"

UDP_PROBES: Dict[int, bytes] = {
    53: b"\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03",
    69: b"\x00\x01test\x00octet\x00",
    123: b"\x1b" + 47 * b"\0",
    137: b"\x80\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00!\x00\x01",
    161: b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",
    162: b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",
    520: b"\x01\x01\x00\x00" + 20 * b"\x00",
    1434: b"\x02",
    1900: b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n',
    5353: b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01",
    5683: b"\x40\x01\x12\x34",
    11211: b"\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n",
    27015: b"\xff\xff\xff\xffTSource Engine Query\x00",
}

def _scan_ports(ip: str, ports: Iterable[int], timeout: float = 0.5, max_workers: int = 100) -> List[int]:
    open_ports = []
    ports_list = list(ports)
    if not ports_list:
        return []

    def _try_port(port: int) -> Optional[int]:
        if port in COMMON_PORTS_UDP or port in UDP_PROBES:
            try:
                probe = UDP_PROBES.get(port, b"\x00")
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(timeout)
                    s.sendto(probe, (ip, port))
                    data, _ = s.recvfrom(1024)
                    if data:
                        return port
            except Exception:
                pass

        if port not in COMMON_PORTS_UDP or port in COMMON_PORTS_TCP:
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

def _scan_ips_incremental(
    ips: List[str],
    subnet: Optional[ipaddress.IPv4Network] = None,
    local_ip: Optional[str] = None,
    do_port_scan: bool = False,
    fast: bool = False,
    ports: Optional[Iterable[int]] = None,
    on_device=None,
    include_arp_only: bool = True,
    check_arp_fallback: bool = False,
    tcp_timeout: float = 0.3,
    port_timeout: float = 0.6,
) -> List[dict]:
    """
    Incrementally probe each IP in parallel and invoke `on_device(device)`
    as soon as each host finishes discovery, port scanning, and hostname resolution.
    Returns the full sorted list of discovered devices.
    """
    if not ips:
        return []

    if ports is None:
        ports = COMMON_PORTS_TCP + COMMON_PORTS_UDP
    else:
        ports = list(ports)

    ip_mac = _parse_arp_table()
    arp_lock = threading.Lock()
    last_arp_refresh = [time.monotonic()]
    ping_sem = threading.Semaphore(64)

    emitted_ips = set()
    emitted_lock = threading.Lock()
    callback_lock = threading.Lock()
    devices: List[dict] = []

    def _emit(device: dict):
        with emitted_lock:
            if device["ip"] in emitted_ips:
                return
            emitted_ips.add(device["ip"])
            devices.append(device)
        if on_device:
            with callback_lock:
                on_device(device)

    def _get_mac(ip: str) -> Optional[str]:
        with arp_lock:
            mac = ip_mac.get(ip)
            if mac:
                return mac
            now_mono = time.monotonic()
            if now_mono - last_arp_refresh[0] >= 0.25:
                ip_mac.update(_parse_arp_table())
                last_arp_refresh[0] = now_mono
                return ip_mac.get(ip)
        return None

    def _probe_host(ip: str):
        if local_ip and ip == local_ip:
            return

        tcp_alive = False
        for port in (22, 53, 80, 139, 443, 445):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(tcp_timeout)
                    if s.connect_ex((ip, port)) == 0:
                        tcp_alive = True
                        break
            except Exception:
                pass

        ping_alive = False
        if not tcp_alive:
            with ping_sem:
                ping_alive = _ping(ip, timeout_ms=300)

        in_arp = False
        if not tcp_alive and not ping_alive and check_arp_fallback:
            with arp_lock:
                in_arp = ip in ip_mac

        if not tcp_alive and not ping_alive and not in_arp:
            return

        alive = tcp_alive or ping_alive

        # Resolve hostname in parallel with port scan for this host
        hostname_box = ["N/A"]
        host_thread = None
        if not fast:
            def _do_host():
                hostname_box[0] = _resolve_hostname(ip, timeout=0.9)
            host_thread = threading.Thread(target=_do_host, daemon=True)
            host_thread.start()

        open_ports = _scan_ports(ip, ports, port_timeout, 64) if do_port_scan else []

        if host_thread is not None:
            host_thread.join(timeout=1.5)

        mac = _get_mac(ip)

        _emit({
            "ip": ip,
            "hostname": hostname_box[0],
            "mac": mac,
            "alive": alive,
            "open_ports": open_ports,
        })

    interrupted = False
    worker_count = min(100, len(ips))
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=worker_count)
    futures = [ex.submit(_probe_host, ip) for ip in ips]
    try:
        for fut in concurrent.futures.as_completed(futures):
            try:
                fut.result()
            except Exception:
                pass
    except KeyboardInterrupt:
        interrupted = True
        for fut in futures:
            fut.cancel()
        raise
    finally:
        ex.shutdown(wait=not interrupted)

    # ---- Include ARP-only hosts (TCP/ICMP-blocked / firewalled) ----
    if include_arp_only and subnet is not None:
        fresh_arp = _parse_arp_table()
        with emitted_lock:
            already = set(emitted_ips)
        arp_only = []
        for ip, mac in fresh_arp.items():
            try:
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj not in subnet:
                    continue
                if ip == str(subnet.broadcast_address):
                    continue
                if local_ip and ip == local_ip:
                    continue
                if ip in already:
                    continue
                if not mac or mac.lower().replace("-", ":").startswith("ff:ff"):
                    continue
                arp_only.append((ip, mac))
            except ValueError:
                continue

        if arp_only:
            def _finish_arp_only(ip_mac_pair):
                ip, mac = ip_mac_pair
                hostname = _resolve_hostname(ip, timeout=0.9) if not fast else "N/A"
                _emit({
                    "ip": ip,
                    "hostname": hostname,
                    "mac": mac,
                    "alive": False,
                    "open_ports": [],
                })

            arp_ex = concurrent.futures.ThreadPoolExecutor(max_workers=min(50, len(arp_only)))
            arp_futures = [arp_ex.submit(_finish_arp_only, item) for item in arp_only]
            arp_interrupted = False
            try:
                for fut in concurrent.futures.as_completed(arp_futures):
                    try:
                        fut.result()
                    except Exception:
                        pass
            except KeyboardInterrupt:
                arp_interrupted = True
                for fut in arp_futures:
                    fut.cancel()
                raise
            finally:
                arp_ex.shutdown(wait=not arp_interrupted)

    return sorted(devices, key=lambda x: socket.inet_aton(x["ip"]))


def _clamp_subnet(
    subnet: Optional[ipaddress.IPv4Network],
    local_ip: Optional[str] = None,
    action: str = "scan",
) -> Optional[ipaddress.IPv4Network]:
    """Clamp oversized subnets to /24 around local_ip, or return None if unbounded."""
    if subnet is None or subnet.num_addresses <= MAX_SUBNET_HOSTS:
        return subnet
    if local_ip:
        logging.warning(
            f"Subnet {subnet} is too large ({subnet.num_addresses} addresses). "
            f"Restricting {action} to /24 around {local_ip} to prevent system freeze."
        )
        return guess_subnet(local_ip, 24)
    logging.error(
        f"Subnet {subnet} is too large ({subnet.num_addresses} addresses; max is {MAX_SUBNET_HOSTS}). "
        f"Aborting {action} to prevent system freeze."
    )
    return None

def discover_network(subnet, local_ip=None, do_port_scan=False, fast=False, ports=None, on_device=None):
    """
    Discover hosts on a subnet incrementally. Works for Ethernet and Wi-Fi.
    - Uses TCP ports + ICMP ping + ARP table to detect hosts.
    - Emits each discovered host immediately via `on_device(device)` if provided.
    """

    if subnet is None and local_ip:
        subnet = guess_subnet(local_ip, 24)

    if not subnet:
        logging.warning("No subnet provided, skipping scan.")
        return []

    subnet = _clamp_subnet(subnet, local_ip=local_ip, action="LAN scan")
    if not subnet:
        return []

    ips = [str(ip) for ip in subnet.hosts()]
    return _scan_ips_incremental(
        ips=ips,
        subnet=subnet,
        local_ip=local_ip,
        do_port_scan=do_port_scan,
        fast=fast,
        ports=ports,
        on_device=on_device,
        include_arp_only=True,
    )

def _highlight_risky_ports(ports: Iterable[int]) -> List[str]:
    mapping = {}
    return [f"{p}({mapping.get(p,'')})" if p in mapping else str(p) for p in ports]

def _primary_mac() -> Optional[str]:
    """Return primary system MAC address (best-effort, cross-platform)."""
    try:
        mac = uuid.getnode()
        return ":".join(f"{(mac >> i) & 0xff:02x}" for i in range(40, -1, -8))
    except Exception:
        return None

# ======= Connection Inspector (Controlled) =======
def _get_process_name(pid):
    if pid is None:
        return "N/A"
    try:
        return psutil.Process(pid).name()
    except Exception:
        return "N/A"

def _detect_direction(
    laddr_ip: str,
    raddr_ip: str,
    local_subnet: Optional[ipaddress.IPv4Network] = None,
    is_server_side: bool = False,
) -> str:
    """
    Detects if connection is IN (incoming), OUT (outgoing), or LAN.
    - laddr_ip = local IP
    - raddr_ip = remote IP
    - local_subnet = optional, for strict LAN check
    - is_server_side = True when local endpoint matches an active listening socket
    Returns: 'IN', 'OUT', or 'LAN'
    """
    if is_server_side:
        return "IN"

    try:
        r_ip = ipaddress.ip_address(raddr_ip)

        if local_subnet:
            if r_ip in local_subnet:
                return "LAN"
            return "OUT"

        if r_ip.is_private:
            return "LAN"
        return "OUT"

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
                conns = psutil.net_connections(kind="inet")
                listen_set = {
                    (c.pid, c.laddr.port, c.laddr.ip)
                    for c in conns
                    if c.status == "LISTEN" and c.laddr and c.pid is not None
                }

                for conn in conns:

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

                    # FIX 4: LISTEN CLEANUP (skip wildcard-bound listeners)
                    if conn.status == "LISTEN" and l_ip == "0.0.0.0":
                        continue

                    key = (conn.pid, l_ip, l_port, r_ip, r_port, conn.status)
                    if key in seen:
                        continue
                    seen.add(key)

                    proc_name = _get_process_name(conn.pid)

                    # FIX 5: CORRECT DIRECTION AND PACKET ENDPOINTS
                    if conn.status == "LISTEN":
                        direction = "LISTEN"
                        src = f"{l_ip}:{l_port}"
                        dst = "*:*"

                    elif r_ip:
                        is_server_side = (
                            conn.pid is not None
                            and conn.status in ("ESTABLISHED", "CLOSE_WAIT")
                            and (
                                (conn.pid, l_port, l_ip) in listen_set
                                or (conn.pid, l_port, "0.0.0.0") in listen_set
                                or (conn.pid, l_port, "::") in listen_set
                            )
                        )
                        direction = _detect_direction(
                            l_ip,
                            r_ip,
                            local_subnet,
                            is_server_side=is_server_side,
                        )

                        if direction == "IN":
                            src = f"{r_ip}:{r_port}"
                            dst = f"{l_ip}:{l_port}"
                        else:
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

            time.sleep(interval)

        logging.info("=== Traffic flow stopped ===")

    thread = threading.Thread(target=_inspector, daemon=True)
    thread.start()
    return stop_event, thread

# ======= SMB Scanner =======
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

    subnet = _clamp_subnet(subnet, local_ip=local_ip, action="SMB scan")
    if not subnet:
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
_TABLE_HEADERS = ["IP Address", "Hostname", "MAC", "Alive", "Open Ports"]
_TABLE_COL_WIDTHS = [15, 20, 20, 10, 45]


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
) -> list:

    if subnet is None and local_ip:
        subnet = guess_subnet(local_ip, 24)

    if silent:
        return discover_network(
            subnet=subnet,
            local_ip=local_ip,
            do_port_scan=do_port_scan,
            fast=fast,
            ports=ports,
            on_device=on_device,
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
        )
    finally:
        logging.info(sep_line)
        logging.info(f"Found {len(seen_ips)} devices")

    return devices


def print_devices(devices: list):
    sep_line = _print_table_header()
    seen_ips = set()
    for d in devices:
        ip = d["ip"]
        if ip in seen_ips:
            continue
        seen_ips.add(ip)
        logging.info(_format_device_row(d))
    logging.info(sep_line)

# --- Define private IP check ---
def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

# --- Helper functions ---
def _ip_range_from_full_ips(start_ip: str, end_ip: str) -> List[str]:
    a = ipaddress.IPv4Address(start_ip)
    b = ipaddress.IPv4Address(end_ip)
    if int(b) < int(a):
        raise ValueError("End IP is smaller than start IP")
    size = int(b) - int(a) + 1
    if size > MAX_SUBNET_HOSTS:
        raise ValueError(f"Range too large ({size} IPs); max is {MAX_SUBNET_HOSTS}")
    return [str(ipaddress.IPv4Address(int(a) + i)) for i in range(size)]

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

# ======= Main =======
def main():
    ensure_console("Net Scanner Core")

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
    scan_results = {}

    # --- Detect local IP and subnet ---
    print("MIT License – © 2026 Menahem Levinski\n")
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
                subnet = _clamp_subnet(subnet, local_ip=local, action="LAN scan")
                if subnet:
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
            start = time.time()

            def _record_device(d):
                key = d.get("ip") or d.get("mac")
                if key:
                    with scan_lock:
                        if key not in scan_results:
                            scan_results[key] = d

            try:
                test_print(
                    subnet=subnet,
                    local_ip=local,
                    do_port_scan=True,
                    fast=False,
                    on_device=_record_device,
                )
            except KeyboardInterrupt:
                print("\nLAN scan interrupted — partial results preserved.")
            finally:
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
            valid_ips = []
            for ip in target_ips:
                if local and ip == local:
                    logging.info(f"[SKIP] {ip} is local — skipping.")
                    continue
                if not is_private_ip(ip):
                    logging.info(f"[SKIP] {ip} is not private — skipping.")
                    continue
                valid_ips.append(ip)

            start = time.time()
            if valid_ips:
                sep_line = _print_table_header()

                def _stream_custom(d):
                    key = d.get("ip") or d.get("mac")
                    with scan_lock:
                        if key and key not in scan_results:
                            scan_results[key] = d
                        logging.info(_format_device_row(d))

                try:
                    _scan_ips_incremental(
                        ips=valid_ips,
                        subnet=None,
                        local_ip=local,
                        do_port_scan=True,
                        fast=False,
                        on_device=_stream_custom,
                        include_arp_only=False,
                        check_arp_fallback=True,
                    )
                except KeyboardInterrupt:
                    print("\nCustom scan interrupted — partial results preserved.")
                finally:
                    logging.info(sep_line)

            elapsed = time.time() - start
            if scan_results:
                logging.info(
                    f"Custom scan finished in {elapsed:.1f}s — found {len(scan_results)} devices."
                )
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

            target_subnet = _clamp_subnet(subnet, local_ip=local, action="HTTP scan")
            if not target_subnet:
                continue

            ips = [str(ip) for ip in target_subnet.hosts()]

            logging.info("")
            logging.info(f"Pre-filtering {len(ips)} hosts (ICMP + ARP)...\n")

            alive_ips = set()
            ip_mac = _parse_arp_table()

            # STEP 1A: ICMP check
            ping_workers = min(len(ips), 64)
            with concurrent.futures.ThreadPoolExecutor(max_workers=ping_workers) as ex:
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
            raw_ports = input("\nType which ports to inspect (for example: 80, 443) or press Enter for all ports: ").strip()
            if raw_ports:
                try:
                    ports_to_monitor = [int(p.strip()) for p in raw_ports.split(",") if p.strip()]
                except ValueError:
                    print("Invalid port list, falling back to all ports.")
                    ports_to_monitor = None
            else:
                ports_to_monitor = None

            stop_event, thread = start_connection_inspector(interval=2, ports=ports_to_monitor, timeout=timeout)

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
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            export_path = f"scan_log_export_{timestamp}.txt"

            with open(export_path, "w", encoding="utf-8") as f:
                f.write(log_buffer.getvalue())

            print(f"Logs exported → {export_path}")


if __name__ == "__main__":
    main()
