"""Configuration constants, port definitions, and OS detection helpers."""

import platform
import subprocess
from typing import Dict, List, Set, Tuple

VERSION = "1.9.8"
version = VERSION

# Common TCP ports (synchronized with PORTS.md)
COMMON_PORTS_TCP: List[int] = [
    20, 21, 22, 23, 53, 79, 80, 389, 443, 445, 636, 989, 990, 1080,
    1433, 1521, 2049, 2222, 2375, 2376, 3306, 3389, 5060, 5061, 5432,
    5601, 5900, 5985, 5986, 6379, 8000, 8008, 8080, 8081, 8443, 8888,
    9000, 9001, 9042, 10000, 10443, 27017, 30015,
]

# Common UDP ports (synchronized with PORTS.md, including dual-protocol ports)
COMMON_PORTS_UDP: List[int] = [
    53, 67, 68, 69, 111, 123, 137, 138, 161, 162, 389, 500, 514, 520,
    1434, 1900, 2049, 3478, 4500, 5060, 5061, 5353, 5683, 11211, 27015,
]

COMMON_PORTS_TCP_SET: Set[int] = set(COMMON_PORTS_TCP)
COMMON_PORTS_UDP_SET: Set[int] = set(COMMON_PORTS_UDP)

# Protocol-specific UDP probe payloads
UDP_PROBES: Dict[int, bytes] = {
    53: b"\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03",
    69: b"\x00\x01test\x00octet\x00",
    123: b"\x1b" + 47 * b"\0",
    137: b"\x80\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00!\x00\x01",
    161: b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",
    162: b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",
    389: b"\x30\x25\x02\x01\x01\x63\x20\x04\x00\x0a\x01\x00\x0a\x01\x00\x02\x01\x00\x02\x01\x00\x01\x01\x00\x87\x0bobjectClass\x30\x00",
    520: b"\x01\x01\x00\x00" + 20 * b"\x00",
    1434: b"\x02",
    1900: b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n',
    5060: b"OPTIONS sip:nm SIP/2.0\r\nVia: SIP/2.0/UDP nm;branch=z9hG4bK-1\r\nFrom: <sip:nm@nm>;tag=root\r\nTo: <sip:nm@nm>\r\nCall-ID: 1@nm\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n",
    5353: b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01",
    5683: b"\x40\x01\x12\x34",
    11211: b"\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n",
    27015: b"\xff\xff\xff\xffTSource Engine Query\x00",
}

# High-risk / sensitive services highlighted in scan tables
RISKY_PORTS: Dict[int, str] = {
    21: "FTP",
    23: "Telnet",
    69: "TFTP",
    161: "SNMP",
    445: "SMB",
    1433: "MSSQL",
    2049: "NFS",
    2375: "Docker!",
    3306: "MySQL",
    3389: "RDP",
    5432: "Postgres",
    5900: "VNC",
    5985: "WinRM",
    6379: "Redis",
    11211: "Memcached",
    27017: "MongoDB",
}

# Connection Inspector noise filters
NOISE_PORTS: Set[int] = {
    5353,          # mDNS
    1900,          # SSDP / UPnP
    123,           # NTP
    137, 138, 139, # NetBIOS / SMB noise
    0,
}

NOISE_IP_PREFIXES: Tuple[str, ...] = (
    "127.",      # loopback
    "169.254.",  # APIPA
    "fe80:",     # IPv6 link-local
)

MAX_SUBNET_HOSTS: int = 512

# Global concurrency ceilings to prevent FD/socket exhaustion
MAX_HOST_WORKERS: int = 64
MAX_PORT_SOCKETS: int = 256
MAX_PING_WORKERS: int = 64

# OS detection
_SYSTEM = platform.system().lower()
IS_WINDOWS: bool = _SYSTEM.startswith("win")
IS_LINUX: bool = _SYSTEM == "linux"
IS_MACOS: bool = _SYSTEM == "darwin"

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


def _run_check_output(cmd, shell: bool = False, **kwargs) -> str:
    base_kwargs = {"text": True, "encoding": "utf-8", "errors": "ignore", "shell": shell}
    base_kwargs.update(_subproc_kwargs_hide_window())
    base_kwargs.update(kwargs)
    return subprocess.check_output(cmd, **base_kwargs)
