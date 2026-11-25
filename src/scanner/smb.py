"""Cross-platform SMB/NetBIOS discovery and non-intrusive share enumeration."""

import concurrent.futures
import ipaddress
import re
import shutil
import socket
import subprocess
from typing import List, Optional

from .config import IS_WINDOWS, _subproc_kwargs_hide_window
from .network import _clamp_subnet

_HAS_SMBCLIENT = bool(not IS_WINDOWS and shutil.which("smbclient"))


def _parse_net_view_shares(stdout: str) -> List[str]:
    shares: List[str] = []
    for line in stdout.splitlines():
        line = line.strip()
        if (
            not line
            or "Share name" in line
            or "The command completed" in line
            or line.startswith("---")
            or line.startswith("Shared resources")
        ):
            continue
        parts = line.split()
        if not parts:
            continue
        share_name = parts[0]
        if share_name.endswith("$"):
            continue
        shares.append(share_name)
    return shares


def _parse_smbclient_shares(stdout: str) -> List[str]:
    shares: List[str] = []
    in_table = False
    for line in stdout.splitlines():
        stripped = line.strip()
        if re.match(r"^Sharename\s+Type", stripped):
            in_table = True
            continue
        if not in_table:
            continue
        if not stripped or stripped.startswith("---"):
            continue
        if stripped.startswith("SMB1") or stripped.startswith("Reconnecting"):
            break
        parts = stripped.split()
        if len(parts) >= 2 and parts[1] in ("Disk", "Printer", "IPC"):
            share_name = parts[0]
            if not share_name.endswith("$"):
                shares.append(share_name)
    return shares


def smb_probe_shares(ip: str) -> dict:
    """
    Safe anonymous SMB share enumeration (Windows `net view`, Linux `smbclient -N -L`).
    No authentication. No exploitation.
    """
    try:
        if IS_WINDOWS:
            result = subprocess.run(
                ["net", "view", f"\\\\{ip}"],
                capture_output=True,
                text=True,
                timeout=5,
                **_subproc_kwargs_hide_window(),
            )
            if result.returncode != 0:
                return {"anonymous": False, "shares": []}
            return {"anonymous": True, "shares": _parse_net_view_shares(result.stdout)}

        if _HAS_SMBCLIENT:
            result = subprocess.run(
                ["smbclient", "-N", "-L", f"//{ip}"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                return {"anonymous": False, "shares": []}
            return {"anonymous": True, "shares": _parse_smbclient_shares(result.stdout)}
    except Exception:
        pass

    return {"anonymous": False, "shares": []}


def smb_scan(
    subnet: Optional[ipaddress.IPv4Network],
    local_ip: Optional[str] = None,
    timeout: float = 0.3,
    on_result=None,
) -> List[dict]:
    """Scan subnet for SMB/NetBIOS-capable devices without authentication."""
    if not subnet:
        print("No subnet provided.")
        return []

    subnet = _clamp_subnet(subnet, local_ip=local_ip, action="SMB scan")
    if not subnet:
        return []

    ips = [str(ip) for ip in subnet.hosts()]
    results: List[dict] = []

    def check(ip: str) -> Optional[dict]:
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
                            "anonymous": share_info["anonymous"],
                        }
        except Exception:
            pass
        return None

    worker_count = min(64, len(ips)) if ips else 1
    with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as ex:
        for res in ex.map(check, ips):
            if res:
                results.append(res)
                if on_result:
                    on_result(res)

    return results
