"""Incremental host discovery combining TCP probes, ICMP ping, ARP, hostname, and port scans."""

import concurrent.futures
import ipaddress
import logging
import socket
import threading
import time
from typing import Iterable, List, Optional

from .config import (
    COMMON_PORTS_TCP,
    COMMON_PORTS_UDP,
    MAX_HOST_WORKERS,
    MAX_PING_WORKERS,
)
from .network import _clamp_subnet, _parse_arp_table, _ping, _resolve_hostname, guess_subnet
from .ports import _scan_ports


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
        ports_list = sorted(set(COMMON_PORTS_TCP) | set(COMMON_PORTS_UDP))
    else:
        ports_list = sorted(set(int(p) for p in ports))

    ip_mac = _parse_arp_table()
    arp_lock = threading.Lock()
    last_arp_refresh = [time.monotonic()]
    ping_sem = threading.Semaphore(MAX_PING_WORKERS)

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

        open_ports = _scan_ports(ip, ports_list, port_timeout) if do_port_scan else []

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
    worker_count = min(MAX_HOST_WORKERS, len(ips))
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

            arp_ex = concurrent.futures.ThreadPoolExecutor(max_workers=min(32, len(arp_only)))
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


def discover_network(
    subnet: Optional[ipaddress.IPv4Network],
    local_ip: Optional[str] = None,
    do_port_scan: bool = False,
    fast: bool = False,
    ports: Optional[Iterable[int]] = None,
    on_device=None,
    allow_guess: bool = False,
) -> List[dict]:
    """
    Discover hosts on a subnet incrementally. Works for Ethernet and Wi-Fi.
    - Uses TCP ports + ICMP ping + ARP table to detect hosts.
    - Emits each discovered host immediately via `on_device(device)` if provided.
    """
    if subnet is None and allow_guess and local_ip and not local_ip.startswith("169.254."):
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
