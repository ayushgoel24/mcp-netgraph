"""Data models for NetGraph."""

from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network

# Type aliases for dual-stack support
IPAddress = IPv4Address | IPv6Address
IPNetwork = IPv4Network | IPv6Network

__all__ = [
    "IPAddress",
    "IPNetwork",
    "IPv4Address",
    "IPv4Network",
    "IPv6Address",
    "IPv6Network",
]
