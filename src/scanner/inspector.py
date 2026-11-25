"""Real-time local TCP/UDP traffic flow inspector with bounded deduplication."""

import collections
import ipaddress
import logging
import socket
import threading
import time
from typing import List, Optional, Tuple

import psutil

from .config import NOISE_IP_PREFIXES, NOISE_PORTS
from .network import _get_default_interface_and_ip, detect_local_subnet, guess_subnet

MAX_SEEN_FLOWS = 5000


def _is_noise_traffic(conn) -> bool:
    try:
        is_udp = conn.type == socket.SOCK_DGRAM
        if not is_udp and conn.status not in ("ESTABLISHED", "CLOSE_WAIT", "SYN_SENT", "LISTEN"):
            return True

        l_ip = conn.laddr.ip if conn.laddr else ""
        r_ip = conn.raddr.ip if conn.raddr else ""
        l_port = conn.laddr.port if conn.laddr else 0

        if l_ip in ("::", "::1") or r_ip in ("::", "::1"):
            return True
        if isinstance(l_ip, str) and l_ip.startswith(NOISE_IP_PREFIXES):
            return True
        if isinstance(r_ip, str) and r_ip.startswith(NOISE_IP_PREFIXES):
            return True

        if l_port in NOISE_PORTS:
            return True

        if is_udp and not conn.raddr:
            return True

        return False
    except Exception:
        return True


def _get_process_name(pid) -> str:
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
    Detect if a connection is IN (incoming), OUT (outgoing), or LAN.
    - is_server_side = True when local endpoint matches an active listening socket
    """
    if is_server_side:
        return "IN"

    try:
        r_ip = ipaddress.ip_address(raddr_ip)

        if local_subnet and r_ip.version == local_subnet.version:
            if r_ip in local_subnet:
                return "LAN"
            return "OUT"

        if r_ip.is_private:
            return "LAN"
        return "OUT"
    except ValueError:
        return "OUT"


def start_connection_inspector(
    interval: float = 0.2,
    ports: Optional[List[int]] = None,
    timeout: int = 0,
    skip_time_wait: bool = True,
    local_subnet: Optional[ipaddress.IPv4Network] = None,
    on_flow=None,
) -> Tuple[threading.Event, threading.Thread]:
    """
    Start a background connection inspector thread.
    - Uses `stop_event.wait(interval)` for responsive stopping.
    - Uses a bounded OrderedDict (FIFO) for deduplication to prevent burst re-logging.
    """
    stop_event = threading.Event()
    ports_set = set(ports) if ports else None
    seen: "collections.OrderedDict[tuple, None]" = collections.OrderedDict()

    if local_subnet is None:
        iface, local_ip = _get_default_interface_and_ip()
        local_subnet = detect_local_subnet(iface, local_ip) or (
            guess_subnet(local_ip, 24) if local_ip else None
        )

    def _inspector():
        logging.info("")
        logging.info(
            f"=== Connection Inspector started "
            f"(interval: {interval}s, ports: {ports if ports else 'all'}) ==="
        )

        start_time = time.monotonic()

        while not stop_event.is_set():
            try:
                conns = psutil.net_connections(kind="inet")
                listen_set = {
                    (c.pid, c.laddr.port, c.laddr.ip)
                    for c in conns
                    if c.status == "LISTEN" and c.laddr and c.pid is not None
                }

                for conn in conns:
                    if not conn.laddr:
                        continue

                    proto = "UDP" if conn.type == socket.SOCK_DGRAM else "TCP"
                    l_ip = conn.laddr.ip
                    l_port = conn.laddr.port
                    r_ip = conn.raddr.ip if conn.raddr else None
                    r_port = conn.raddr.port if conn.raddr else None

                    if skip_time_wait and proto == "TCP" and conn.status == "TIME_WAIT":
                        continue

                    if ports_set:
                        if l_port not in ports_set and (r_port not in ports_set if r_port else True):
                            continue

                    if _is_noise_traffic(conn):
                        continue

                    if conn.status == "LISTEN" and l_ip == "0.0.0.0":
                        continue

                    key = (conn.pid, l_ip, l_port, r_ip, r_port, conn.status)
                    if key in seen:
                        continue
                    seen[key] = None
                    if len(seen) > MAX_SEEN_FLOWS:
                        seen.popitem(last=False)

                    proc_name = _get_process_name(conn.pid)

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

                    if on_flow:
                        on_flow({
                            "proto": proto,
                            "direction": direction,
                            "process": proc_name,
                            "src": src,
                            "dst": dst,
                            "status": conn.status,
                        })

                    logging.info(
                        f"[FLOW] {proto} {direction} {proc_name} "
                        f"{src} → {dst} ({conn.status})"
                    )

            except Exception as e:
                logging.error(f"[Inspector Error] {e}")

            elapsed = time.monotonic() - start_time
            if timeout > 0 and elapsed >= timeout:
                logging.info("Traffic flow timeout reached.")
                stop_event.set()
                break

            wait_time = interval
            if timeout > 0:
                wait_time = min(interval, max(0.0, timeout - elapsed))
            stop_event.wait(wait_time)

        logging.info("=== Traffic flow stopped ===")

    thread = threading.Thread(target=_inspector, daemon=True)
    thread.start()
    return stop_event, thread
