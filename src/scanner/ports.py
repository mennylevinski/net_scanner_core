"""Bounded-concurrency TCP/UDP port scanner and risky-port highlighting."""

import concurrent.futures
import socket
import threading
from typing import Iterable, List, Optional, Tuple, Union

from .config import (
    COMMON_PORTS_TCP_SET,
    COMMON_PORTS_UDP_SET,
    MAX_PORT_SOCKETS,
    RISKY_PORTS,
    UDP_PROBES,
)

# Shared global semaphore to cap total concurrent probe sockets across all host threads
_PORT_SOCKET_SEM = threading.BoundedSemaphore(MAX_PORT_SOCKETS)

# Shared bounded executor so scanning 50+ hosts never spawns 50 * 64 nested threads
_SHARED_PORT_EXECUTOR: Optional[concurrent.futures.ThreadPoolExecutor] = None
_EXECUTOR_LOCK = threading.Lock()


def _get_port_executor() -> concurrent.futures.ThreadPoolExecutor:
    global _SHARED_PORT_EXECUTOR
    with _EXECUTOR_LOCK:
        if _SHARED_PORT_EXECUTOR is None or getattr(_SHARED_PORT_EXECUTOR, "_shutdown", False):
            _SHARED_PORT_EXECUTOR = concurrent.futures.ThreadPoolExecutor(
                max_workers=MAX_PORT_SOCKETS,
                thread_name_prefix="port-probe",
            )
        return _SHARED_PORT_EXECUTOR


def _probe_tcp(ip: str, port: int, timeout: float) -> bool:
    with _PORT_SOCKET_SEM:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                return s.connect_ex((ip, port)) == 0
        except Exception:
            return False


def _probe_udp(ip: str, port: int, timeout: float) -> bool:
    probe = UDP_PROBES.get(port, b"\x00")
    with _PORT_SOCKET_SEM:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(probe, (ip, port))
                data, _ = s.recvfrom(1024)
                return bool(data)
        except Exception:
            return False


def _scan_ports(
    ip: str,
    ports: Iterable[int],
    timeout: float = 0.5,
    max_workers: int = 64,
    include_proto: bool = True,
) -> List[Union[str, int]]:
    """
    Scan TCP and/or UDP ports on `ip` using a shared bounded thread pool and
    socket semaphore so concurrent multi-host scans never exhaust OS file descriptors.

    When `include_proto=True` (default), returns protocol-tagged entries such as
    ["53/tcp", "53/udp", "80/tcp"]. When `include_proto=False`, returns sorted ints.
    """
    unique_ports = sorted(set(int(p) for p in ports))
    if not unique_ports:
        return []

    tasks: List[Tuple[int, str]] = []
    for port in unique_ports:
        scan_udp = port in COMMON_PORTS_UDP_SET or port in UDP_PROBES
        scan_tcp = (port in COMMON_PORTS_TCP_SET) or (not scan_udp)
        if scan_tcp:
            tasks.append((port, "tcp"))
        if scan_udp:
            tasks.append((port, "udp"))

    def _run_task(task: Tuple[int, str]) -> Optional[Tuple[int, str]]:
        p, proto = task
        if proto == "tcp":
            return task if _probe_tcp(ip, p, timeout) else None
        return task if _probe_udp(ip, p, timeout) else None

    executor = _get_port_executor()
    futures = [executor.submit(_run_task, t) for t in tasks]
    hits: List[Tuple[int, str]] = []
    for fut in concurrent.futures.as_completed(futures):
        try:
            res = fut.result()
            if res is not None:
                hits.append(res)
        except Exception:
            pass

    hits.sort(key=lambda item: (item[0], item[1]))
    if include_proto:
        return [f"{p}/{proto}" for p, proto in hits]
    return sorted({p for p, _ in hits})


def _highlight_risky_ports(ports: Iterable[Union[int, str]]) -> List[str]:
    """Annotate high-risk open ports with their service name (supports int or 'port/proto')."""
    out: List[str] = []
    for item in ports:
        if isinstance(item, int):
            port_num = item
            label = str(item)
        else:
            label = str(item)
            try:
                port_num = int(label.split("/", 1)[0])
            except ValueError:
                out.append(label)
                continue
        risk = RISKY_PORTS.get(port_num)
        out.append(f"{label}({risk})" if risk else label)
    return out
