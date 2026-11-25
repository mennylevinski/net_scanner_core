"""Network interface detection, IP/subnet utilities, ICMP ping, ARP parsing, and hostname resolution."""

import ipaddress
import logging
import re
import shutil
import socket
import struct
import subprocess
import threading
import uuid
from typing import Dict, List, Optional, Tuple

import psutil

from .config import (
    IS_LINUX,
    IS_MACOS,
    IS_WINDOWS,
    MAX_SUBNET_HOSTS,
    UDP_PROBES,
    _run_check_output,
    _subproc_kwargs_hide_window,
)

_HAS_NMBLOOKUP = bool(not IS_WINDOWS and shutil.which("nmblookup"))
_HAS_AVAHI = bool(not IS_WINDOWS and shutil.which("avahi-resolve-address"))
_HAS_IP_CMD = bool(not IS_WINDOWS and shutil.which("ip"))


def _get_default_interface_and_ip() -> Tuple[Optional[str], Optional[str]]:
    """
    Detect the active network adapter and its IPv4 address.
    Tries routing socket first, then falls back to active non-loopback IPv4
    interfaces via psutil so air-gapped / offline LANs still work.
    """
    try:
        addrs = psutil.net_if_addrs()
    except Exception:
        return None, None

    # 1) Route-based detection (works when a default gateway exists)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        for iface, addr_list in addrs.items():
            for addr in addr_list:
                if addr.family == socket.AF_INET and addr.address == local_ip:
                    return iface, local_ip
    except Exception:
        pass

    # 2) Offline / air-gapped fallback: pick first UP non-loopback, non-APIPA IPv4 interface
    try:
        stats = psutil.net_if_stats()
    except Exception:
        stats = {}

    apipa_fallback: Tuple[Optional[str], Optional[str]] = (None, None)
    for iface, addr_list in addrs.items():
        st = stats.get(iface)
        if st is not None and not st.isup:
            continue
        for addr in addr_list:
            if addr.family != socket.AF_INET:
                continue
            ip = addr.address
            if not ip or ip.startswith("127.") or ip == "0.0.0.0":
                continue
            if ip.startswith("169.254."):
                if apipa_fallback == (None, None):
                    apipa_fallback = (iface, ip)
                continue
            return iface, ip

    return apipa_fallback


def _primary_mac(interface: Optional[str] = None) -> Optional[str]:
    """Return the MAC address of the given interface (or primary active interface)."""
    af_link = getattr(psutil, "AF_LINK", None)
    try:
        addrs = psutil.net_if_addrs()
        candidates = [interface] if interface and interface in addrs else list(addrs.keys())
        for iface in candidates:
            for addr in addrs.get(iface, []):
                if af_link is not None and addr.family == af_link:
                    mac = (addr.address or "").strip().replace("-", ":").lower()
                    if re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", mac) and mac != "00:00:00:00:00:00":
                        return mac
    except Exception:
        pass

    try:
        mac_int = uuid.getnode()
        return ":".join(f"{(mac_int >> i) & 0xFF:02x}" for i in range(40, -1, -8))
    except Exception:
        return None


def guess_subnet(ip: Optional[str], mask_bits: int = 24) -> ipaddress.IPv4Network:
    if not ip:
        return ipaddress.ip_network("0.0.0.0/0")
    return ipaddress.ip_network(f"{ip}/{mask_bits}", strict=False)


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


def detect_local_subnet(interface: Optional[str], local_ip: Optional[str]) -> Optional[ipaddress.IPv4Network]:
    """Determine the local IPv4 subnet for the detected interface, respecting APIPA and size caps."""
    if isinstance(local_ip, str) and local_ip.startswith("169.254."):
        logging.warning("APIPA detected (169.254.x.x). No DHCP lease — LAN scan disabled.")
        return None

    if isinstance(local_ip, str) and "." in local_ip:
        try:
            addrs = psutil.net_if_addrs()
            netmask = None
            for addr in addrs.get(interface, []):
                if addr.family == socket.AF_INET and addr.address == local_ip:
                    netmask = addr.netmask
                    break
            if netmask:
                subnet = ipaddress.ip_network(f"{local_ip}/{netmask}", strict=False)
                subnet = _clamp_subnet(subnet, local_ip=local_ip, action="LAN scan")
                if subnet:
                    logging.info(f"Detected Subnet: {subnet}")
                return subnet
            logging.warning("Unable to determine network mask — LAN scan disabled.")
            return None
        except Exception:
            logging.warning("Unable to determine local subnet — LAN scan disabled.")
            return None

    logging.warning("Subnet detection skipped (IPv6 or no IP)")
    return None


def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _ip_range_from_full_ips(start_ip: str, end_ip: str) -> List[str]:
    a = ipaddress.IPv4Address(start_ip)
    b = ipaddress.IPv4Address(end_ip)
    if int(b) < int(a):
        raise ValueError("End IP is smaller than start IP")
    size = int(b) - int(a) + 1
    if size > MAX_SUBNET_HOSTS:
        raise ValueError(f"Range too large ({size} IPs); max is {MAX_SUBNET_HOSTS}")
    return [str(ipaddress.IPv4Address(int(a) + i)) for i in range(size)]


def _parse_target_ips(raw: str) -> List[str]:
    """
    Parse a single IPv4 address, start-end IPv4 range, or IPv4 CIDR block
    (e.g., '192.168.1.10', '192.168.1.1-192.168.1.50', or '192.168.1.0/24').
    """
    raw = raw.strip()
    if not raw:
        raise ValueError("Empty target")

    if "/" in raw:
        net = ipaddress.IPv4Network(raw, strict=False)
        hosts = list(net.hosts()) or [net.network_address]
        if len(hosts) > MAX_SUBNET_HOSTS:
            raise ValueError(f"CIDR range too large ({len(hosts)} hosts); max is {MAX_SUBNET_HOSTS}")
        return [str(ip) for ip in hosts]

    if "-" in raw:
        start_ip, end_ip = map(str.strip, raw.split("-", 1))
        ipaddress.IPv4Address(start_ip)
        ipaddress.IPv4Address(end_ip)
        return _ip_range_from_full_ips(start_ip, end_ip)

    ipaddress.IPv4Address(raw)
    return [raw]


def _ping(ip: str, timeout_ms: int = 300) -> bool:
    """Send a single ICMP echo request using platform-appropriate sub-second timeouts."""
    if IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    elif IS_MACOS:
        # macOS ping -W takes milliseconds
        cmd = ["ping", "-c", "1", "-W", str(max(100, timeout_ms)), ip]
    elif IS_LINUX:
        # iputils ping supports fractional seconds for -W
        timeout_sec = max(0.2, timeout_ms / 1000.0)
        cmd = ["ping", "-c", "1", "-W", f"{timeout_sec:.2f}", ip]
    else:
        timeout_sec = max(1, timeout_ms // 1000)
        cmd = ["ping", "-c", "1", "-W", str(timeout_sec), ip]

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=max(1.5, timeout_ms / 1000.0 + 1.0),
            **_subproc_kwargs_hide_window(),
        )
        if result.returncode == 0:
            return True
        # Fallback for BusyBox/older Linux ping that rejects fractional -W
        if IS_LINUX and result.returncode == 2:
            fallback_cmd = ["ping", "-c", "1", "-W", str(max(1, (timeout_ms + 999) // 1000)), ip]
            fb = subprocess.run(
                fallback_cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=max(2.0, timeout_ms / 1000.0 + 1.5),
            )
            return fb.returncode == 0
    except Exception:
        pass
    return False


def _parse_arp_output(out: str, is_windows: bool) -> Dict[str, str]:
    """Parse ARP / neighbor table text into an {ip: lowercase_colon_mac} mapping."""
    ip_to_mac: Dict[str, str] = {}
    if is_windows:
        for line in out.splitlines():
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{14,17})", line)
            if m:
                ip_to_mac[m.group(1)] = m.group(2).replace("-", ":").lower()
    else:
        for line in out.splitlines():
            # `ip neigh show` format: "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+dev\s+\S+\s+lladdr\s+([0-9a-fA-F:]{17})", line)
            if m:
                ip_to_mac[m.group(1)] = m.group(2).lower()
                continue
            # Legacy `arp -a` format: "? (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0"
            m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]{17})", line)
            if m:
                ip_to_mac[m.group(1)] = m.group(2).lower()
    return ip_to_mac


def _parse_arp_table() -> Dict[str, str]:
    """Read the OS ARP / neighbor cache (Windows `arp -a`, Linux `ip neigh` with `arp -a` fallback)."""
    if IS_WINDOWS:
        try:
            out = _run_check_output(["arp", "-a"], shell=False)
            return _parse_arp_output(out, is_windows=True)
        except Exception:
            return {}

    if _HAS_IP_CMD:
        try:
            out = _run_check_output(["ip", "neigh", "show"], shell=False)
            parsed = _parse_arp_output(out, is_windows=False)
            if parsed:
                return parsed
        except Exception:
            pass

    try:
        out = _run_check_output(["arp", "-a"], shell=False)
        return _parse_arp_output(out, is_windows=False)
    except Exception:
        return {}


def _encode_dns_name(name: str) -> bytes:
    """Encode a dotted hostname into DNS wire format."""
    out = bytearray()
    for part in name.split("."):
        b = part.encode("ascii", errors="ignore")
        out.append(len(b))
        out.extend(b)
    out.append(0)
    return bytes(out)


def _decode_dns_name(data: bytes, offset: int) -> Tuple[str, int]:
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
    """Resolve IP to hostname using rDNS, mDNS, and NetBIOS within a strict timeout."""
    results: Dict[str, str] = {}
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

    if not IS_WINDOWS:
        if _HAS_AVAHI:
            try:
                result = subprocess.check_output(
                    ["avahi-resolve-address", ip],
                    stderr=subprocess.DEVNULL,
                    timeout=timeout,
                    text=True,
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
                    text=True,
                )
                for line in result.splitlines():
                    if "<00>" in line and "GROUP" not in line:
                        parts = line.split()
                        if parts:
                            return parts[0]
            except Exception:
                pass

    return "N/A"
