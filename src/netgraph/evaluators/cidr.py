"""CIDR matching utilities for IPv4 and IPv6 addresses."""

from functools import lru_cache
from ipaddress import (
    AddressValueError,
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
    ip_address,
    ip_network,
)
from typing import Literal

# Type aliases
IPAddress = IPv4Address | IPv6Address
IPNetwork = IPv4Network | IPv6Network
AddressFamily = Literal["IPv4", "IPv6"]


class CIDRMatcher:
    """Utilities for matching IP addresses against CIDR blocks.

    All methods support both IPv4 and IPv6 addresses. Address family
    mismatches (e.g., IPv4 address against IPv6 CIDR) return False
    rather than raising errors.
    """

    @staticmethod
    @lru_cache(maxsize=1024)
    def matches(ip: str, cidr: str) -> bool:
        """Check if an IP address falls within a CIDR block.

        Args:
            ip: IP address string (IPv4 or IPv6)
            cidr: CIDR block string (IPv4 or IPv6)

        Returns:
            True if the IP is within the CIDR block, False otherwise.
            Returns False for address family mismatches.

        Examples:
            >>> CIDRMatcher.matches("10.0.1.50", "10.0.0.0/16")
            True
            >>> CIDRMatcher.matches("192.168.1.1", "10.0.0.0/16")
            False
            >>> CIDRMatcher.matches("2001:db8::1", "2001:db8::/32")
            True
        """
        try:
            addr = ip_address(ip)
            network = ip_network(cidr, strict=False)

            # Address family mismatch returns False
            if addr.version != network.version:
                return False

            return addr in network
        except (AddressValueError, ValueError):
            return False

    @staticmethod
    def matches_any(ip: str, cidrs: list[str]) -> bool:
        """Check if an IP address matches any CIDR in a list.

        Args:
            ip: IP address string
            cidrs: List of CIDR block strings

        Returns:
            True if the IP matches any CIDR, False otherwise.
        """
        return any(CIDRMatcher.matches(ip, cidr) for cidr in cidrs)

    @staticmethod
    def most_specific_match(ip: str, cidrs: list[str]) -> str | None:
        """Find the most specific (longest prefix) matching CIDR.

        This implements Longest Prefix Match (LPM) algorithm used
        for route selection.

        Args:
            ip: IP address string
            cidrs: List of CIDR block strings to match against

        Returns:
            The CIDR with the longest prefix length that contains
            the IP, or None if no match.

        Examples:
            >>> CIDRMatcher.most_specific_match(
            ...     "10.0.1.50",
            ...     ["10.0.0.0/8", "10.0.0.0/16", "10.0.1.0/24"]
            ... )
            '10.0.1.0/24'
        """
        try:
            addr = ip_address(ip)
        except (AddressValueError, ValueError):
            return None

        matches: list[tuple[str, int]] = []

        for cidr in cidrs:
            try:
                network = ip_network(cidr, strict=False)
                # Skip address family mismatches
                if addr.version != network.version:
                    continue
                if addr in network:
                    matches.append((cidr, network.prefixlen))
            except (AddressValueError, ValueError):
                continue

        if not matches:
            return None

        # Sort by prefix length descending, return longest match
        matches.sort(key=lambda x: x[1], reverse=True)
        return matches[0][0]

    @staticmethod
    def validate_cidr(cidr: str) -> bool:
        """Check if a string is a valid CIDR block.

        Requires explicit prefix notation (e.g., "10.0.0.0/16").
        Plain IP addresses without a prefix are not considered valid CIDRs.

        Args:
            cidr: String to validate

        Returns:
            True if valid CIDR notation with explicit prefix, False otherwise.
        """
        # Require explicit prefix notation
        if "/" not in cidr:
            return False

        try:
            ip_network(cidr, strict=False)
            return True
        except (AddressValueError, ValueError):
            return False

    @staticmethod
    def validate_ip(ip: str) -> bool:
        """Check if a string is a valid IP address.

        Args:
            ip: String to validate

        Returns:
            True if valid IPv4 or IPv6 address, False otherwise.
        """
        try:
            ip_address(ip)
            return True
        except (AddressValueError, ValueError):
            return False

    @staticmethod
    def get_address_family(ip_or_cidr: str) -> AddressFamily | None:
        """Determine the address family of an IP or CIDR.

        Args:
            ip_or_cidr: IP address or CIDR block string

        Returns:
            "IPv4" or "IPv6" if valid, None otherwise.
        """
        # Try as IP address first
        try:
            addr = ip_address(ip_or_cidr)
            return "IPv4" if addr.version == 4 else "IPv6"
        except (AddressValueError, ValueError):
            pass

        # Try as CIDR
        try:
            network = ip_network(ip_or_cidr, strict=False)
            return "IPv4" if network.version == 4 else "IPv6"
        except (AddressValueError, ValueError):
            return None

    @staticmethod
    def get_prefix_length(cidr: str) -> int | None:
        """Get the prefix length of a CIDR block.

        Args:
            cidr: CIDR block string

        Returns:
            Prefix length (0-32 for IPv4, 0-128 for IPv6), or None if invalid.
        """
        try:
            network = ip_network(cidr, strict=False)
            return network.prefixlen
        except (AddressValueError, ValueError):
            return None

    @staticmethod
    def is_same_family(ip: str, cidr: str) -> bool:
        """Check if an IP and CIDR are the same address family.

        Args:
            ip: IP address string
            cidr: CIDR block string

        Returns:
            True if both are IPv4 or both are IPv6, False otherwise.
        """
        ip_family = CIDRMatcher.get_address_family(ip)
        cidr_family = CIDRMatcher.get_address_family(cidr)

        if ip_family is None or cidr_family is None:
            return False

        return ip_family == cidr_family

    @staticmethod
    def clear_cache() -> None:
        """Clear the LRU cache for matches().

        Useful for testing or when memory needs to be freed.
        """
        CIDRMatcher.matches.cache_clear()
