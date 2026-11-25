"""Fast HTTP/HTTPS service probing and incremental subnet HTTP scanning."""

import concurrent.futures
import ipaddress
import logging
import socket
import threading
from typing import Dict, List, Optional, Tuple, Union

import requests
import urllib3

from .config import MAX_PING_WORKERS
from .network import _clamp_subnet, _parse_arp_table, _ping

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_HTTP_TARGETS: List[Tuple[str, int]] = [
    ("http", 80),
    ("http", 8080),
    ("http", 8000),
    ("https", 443),
    ("https", 8443),
    ("https", 10443),
]


def _port_open_fast(ip: str, port: int, timeout: float = 0.35) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, port)) == 0
    except Exception:
        return False


def _format_url(scheme: str, ip: str, port: int) -> str:
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        return f"{scheme}://{ip}"
    return f"{scheme}://{ip}:{port}"


def _probe_single_url(url: str, headers: Dict[str, str], timeout: float) -> Optional[dict]:
    """Use HEAD first to avoid downloading response bodies; fall back to streaming GET on 405/501."""
    r = requests.head(
        url,
        headers=headers,
        timeout=(min(1.5, timeout), timeout),
        allow_redirects=True,
        verify=False,
    )
    if r.status_code in (405, 501):
        with requests.get(
            url,
            headers=headers,
            timeout=(min(1.5, timeout), timeout),
            allow_redirects=True,
            verify=False,
            stream=True,
        ) as gr:
            return {
                "url": url,
                "status": gr.status_code,
                "server": gr.headers.get("Server", "Unknown"),
            }
    return {
        "url": url,
        "status": r.status_code,
        "server": r.headers.get("Server", "Unknown"),
    }


def http_probe(
    ip: str,
    timeout: float = 2.0,
    find_all: bool = False,
    precheck_ports: bool = True,
) -> Optional[Union[dict, List[dict]]]:
    """
    Probe common HTTP/HTTPS ports on `ip`.
    - Pre-checks TCP reachability so non-web hosts return quickly instead of stalling.
    - Uses HEAD (with streaming GET fallback) and retries over HTTP on SSLError.
    """
    headers = {"User-Agent": "Mozilla/5.0 (NetworkScanner)"}
    matches: List[dict] = []

    for scheme, port in _HTTP_TARGETS:
        if precheck_ports and not _port_open_fast(ip, port, timeout=min(0.4, timeout)):
            continue

        url = _format_url(scheme, ip, port)
        try:
            hit = _probe_single_url(url, headers, timeout)
            if hit:
                if not find_all:
                    return hit
                matches.append(hit)
        except requests.exceptions.SSLError:
            if scheme == "https":
                fallback_url = _format_url("http", ip, port)
                try:
                    hit = _probe_single_url(fallback_url, headers, timeout)
                    if hit:
                        if not find_all:
                            return hit
                        matches.append(hit)
                except requests.exceptions.RequestException:
                    continue
        except requests.exceptions.RequestException:
            continue

    if find_all:
        return matches
    return None


def http_scan_subnet(
    subnet: Optional[ipaddress.IPv4Network],
    local_ip: Optional[str] = None,
    timeout: float = 2.0,
    on_result=None,
) -> List[dict]:
    """
    Discover alive hosts via ICMP ping followed by fresh ARP cache lookup,
    then stream HTTP/HTTPS probe results incrementally.
    """
    if not subnet:
        logging.info("No subnet detected.")
        return []

    target_subnet = _clamp_subnet(subnet, local_ip=local_ip, action="HTTP scan")
    if not target_subnet:
        return []

    ips = [str(ip) for ip in target_subnet.hosts()]
    ips_set = set(ips)

    logging.info("")
    logging.info(f"Pre-filtering {len(ips)} hosts (ICMP + ARP)...\n")

    alive_ips = set()

    # STEP 1A: ICMP sweep first so OS ARP cache is populated
    ping_workers = min(len(ips), MAX_PING_WORKERS) if ips else 1
    with concurrent.futures.ThreadPoolExecutor(max_workers=ping_workers) as ex:
        for ip, ok in zip(ips, ex.map(_ping, ips)):
            if ok:
                alive_ips.add(ip)

    # STEP 1B: Fresh ARP lookup after ping sweep (O(1) membership via ips_set)
    ip_mac = _parse_arp_table()
    for ip, mac in ip_mac.items():
        if ip in ips_set and mac and not mac.lower().startswith("ff:ff"):
            alive_ips.add(ip)

    alive_list = sorted(alive_ips, key=socket.inet_aton)
    logging.info(f"Alive hosts: {len(alive_list)}\n")

    if not alive_list:
        return []

    results: List[dict] = []
    res_lock = threading.Lock()

    def _check(ip: str):
        hits = http_probe(ip, timeout=timeout, find_all=True)
        for hit in hits or []:
            record = {
                "ip": ip,
                "url": hit["url"],
                "status": hit["status"],
                "server": hit["server"],
            }
            with res_lock:
                results.append(record)
                if on_result:
                    on_result(record)

    worker_count = min(64, len(alive_list))
    with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as ex:
        futures = [ex.submit(_check, ip) for ip in alive_list]
        for fut in concurrent.futures.as_completed(futures):
            try:
                fut.result()
            except Exception:
                pass

    results.sort(key=lambda r: (socket.inet_aton(r["ip"]), r["url"]))
    return results
