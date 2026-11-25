"""Net Scanner Core modular package."""

from .config import (
    COMMON_PORTS_TCP,
    COMMON_PORTS_UDP,
    IS_LINUX,
    IS_MACOS,
    IS_WINDOWS,
    MAX_SUBNET_HOSTS,
    NOISE_IP_PREFIXES,
    NOISE_PORTS,
    RISKY_PORTS,
    UDP_PROBES,
    VERSION,
    version,
)

__all__ = [
    "VERSION",
    "version",
    "COMMON_PORTS_TCP",
    "COMMON_PORTS_UDP",
    "UDP_PROBES",
    "RISKY_PORTS",
    "NOISE_PORTS",
    "NOISE_IP_PREFIXES",
    "MAX_SUBNET_HOSTS",
    "IS_WINDOWS",
    "IS_LINUX",
    "IS_MACOS",
]
