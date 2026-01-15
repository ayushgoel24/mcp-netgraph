"""Prefix list fixtures for NetGraph integration tests.

This module provides test fixtures for AWS Managed Prefix Lists,
which are commonly used in Security Group and Route Table rules.

Common AWS-managed prefix lists:
- com.amazonaws.region.s3 (S3 gateway endpoints)
- com.amazonaws.global.cloudfront.origin-facing (CloudFront edge)
- com.amazonaws.region.dynamodb (DynamoDB gateway endpoints)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# =============================================================================
# Prefix List IDs
# =============================================================================

# AWS-managed prefix lists (simulated)
PL_S3_US_EAST_1 = "pl-63a5400a"  # Actual AWS S3 prefix list ID format
PL_DYNAMODB_US_EAST_1 = "pl-02cd2c6b"  # Actual AWS DynamoDB format
PL_CLOUDFRONT = "pl-3b927c52"  # CloudFront origin-facing

# Customer-managed prefix lists
PL_CORPORATE_NETWORK = "pl-corp12345"
PL_TRUSTED_PARTNERS = "pl-partner123"
PL_BLOCKED_IPS = "pl-blocked123"
PL_VPN_CLIENTS = "pl-vpn1234567"
PL_OFFICE_LOCATIONS = "pl-office1234"
PL_EMPTY = "pl-empty12345"

# Cross-account prefix list
PL_CROSS_ACCOUNT = "pl-crossacct1"
CROSS_ACCOUNT_OWNER = "987654321098"


# =============================================================================
# Fixture Data Classes
# =============================================================================


@dataclass
class PrefixListEntry:
    """A single entry in a prefix list."""

    cidr: str
    description: str = ""


@dataclass
class PrefixListFixture:
    """Managed Prefix List fixture data."""

    prefix_list_id: str
    prefix_list_name: str
    owner_id: str
    address_family: str  # "IPv4" or "IPv6"
    max_entries: int
    entries: list[PrefixListEntry] = field(default_factory=list)
    state: str = "create-complete"
    tags: dict[str, str] = field(default_factory=dict)
    version: int = 1

    @property
    def current_entries(self) -> int:
        return len(self.entries)


# =============================================================================
# AWS-Managed Prefix Lists
# =============================================================================


def create_s3_prefix_list(region: str = "us-east-1") -> PrefixListFixture:
    """Create an S3 gateway endpoint prefix list.

    These are AWS-managed and contain the IP ranges for S3 in the region.
    In reality, these are dynamically managed by AWS.
    """
    # Simulated S3 IP ranges (not real, for testing only)
    entries = [
        PrefixListEntry(cidr="52.216.0.0/15", description="S3 us-east-1"),
        PrefixListEntry(cidr="54.231.0.0/16", description="S3 us-east-1"),
        PrefixListEntry(cidr="3.5.0.0/19", description="S3 us-east-1 new"),
    ]

    return PrefixListFixture(
        prefix_list_id=PL_S3_US_EAST_1,
        prefix_list_name=f"com.amazonaws.{region}.s3",
        owner_id="AWS",
        address_family="IPv4",
        max_entries=100,
        entries=entries,
        tags={"aws:service": "s3"},
    )


def create_dynamodb_prefix_list(region: str = "us-east-1") -> PrefixListFixture:
    """Create a DynamoDB gateway endpoint prefix list."""
    entries = [
        PrefixListEntry(cidr="52.94.0.0/22", description="DynamoDB us-east-1"),
    ]

    return PrefixListFixture(
        prefix_list_id=PL_DYNAMODB_US_EAST_1,
        prefix_list_name=f"com.amazonaws.{region}.dynamodb",
        owner_id="AWS",
        address_family="IPv4",
        max_entries=50,
        entries=entries,
        tags={"aws:service": "dynamodb"},
    )


def create_cloudfront_prefix_list() -> PrefixListFixture:
    """Create a CloudFront origin-facing prefix list.

    This contains IP ranges that CloudFront uses to connect to origins.
    Useful for restricting origin access to only CloudFront.
    """
    # Simulated CloudFront IP ranges (subset of real ranges)
    entries = [
        PrefixListEntry(cidr="13.32.0.0/15", description="CloudFront edge"),
        PrefixListEntry(cidr="13.35.0.0/16", description="CloudFront edge"),
        PrefixListEntry(cidr="18.154.0.0/15", description="CloudFront edge"),
        PrefixListEntry(cidr="52.46.0.0/18", description="CloudFront edge"),
        PrefixListEntry(cidr="52.84.0.0/15", description="CloudFront edge"),
        PrefixListEntry(cidr="64.252.64.0/18", description="CloudFront edge"),
        PrefixListEntry(cidr="99.84.0.0/16", description="CloudFront edge"),
        PrefixListEntry(cidr="130.176.0.0/16", description="CloudFront edge"),
        PrefixListEntry(cidr="205.251.192.0/19", description="CloudFront edge"),
    ]

    return PrefixListFixture(
        prefix_list_id=PL_CLOUDFRONT,
        prefix_list_name="com.amazonaws.global.cloudfront.origin-facing",
        owner_id="AWS",
        address_family="IPv4",
        max_entries=200,
        entries=entries,
        tags={"aws:service": "cloudfront"},
    )


# =============================================================================
# Customer-Managed Prefix Lists
# =============================================================================


def create_corporate_network_prefix_list(
    account_id: str = "123456789012",
) -> PrefixListFixture:
    """Create a prefix list for corporate network ranges.

    Common use case: Allow traffic only from corporate IP ranges.
    """
    entries = [
        PrefixListEntry(cidr="10.0.0.0/8", description="Internal RFC1918"),
        PrefixListEntry(cidr="172.16.0.0/12", description="Internal RFC1918"),
        PrefixListEntry(cidr="192.168.0.0/16", description="Internal RFC1918"),
        PrefixListEntry(cidr="203.0.113.0/24", description="Corporate office"),
        PrefixListEntry(cidr="198.51.100.0/24", description="Corporate datacenter"),
    ]

    return PrefixListFixture(
        prefix_list_id=PL_CORPORATE_NETWORK,
        prefix_list_name="corporate-networks",
        owner_id=account_id,
        address_family="IPv4",
        max_entries=50,
        entries=entries,
        tags={"Name": "corporate-networks", "ManagedBy": "security-team"},
    )


def create_trusted_partners_prefix_list(
    account_id: str = "123456789012",
) -> PrefixListFixture:
    """Create a prefix list for trusted partner IP ranges."""
    entries = [
        PrefixListEntry(cidr="198.51.100.128/25", description="Partner A"),
        PrefixListEntry(cidr="203.0.113.64/26", description="Partner B"),
        PrefixListEntry(cidr="192.0.2.0/24", description="Partner C - TEST-NET-1"),
    ]

    return PrefixListFixture(
        prefix_list_id=PL_TRUSTED_PARTNERS,
        prefix_list_name="trusted-partners",
        owner_id=account_id,
        address_family="IPv4",
        max_entries=25,
        entries=entries,
        tags={"Name": "trusted-partners", "ManagedBy": "partnerships"},
    )


def create_blocked_ips_prefix_list(
    account_id: str = "123456789012",
) -> PrefixListFixture:
    """Create a prefix list for blocked/malicious IP ranges.

    Used in NACL deny rules.
    """
    entries = [
        PrefixListEntry(cidr="192.0.2.100/32", description="Known attacker"),
        PrefixListEntry(cidr="198.51.100.200/32", description="Blocked scanner"),
        PrefixListEntry(cidr="203.0.113.0/28", description="Suspicious range"),
    ]

    return PrefixListFixture(
        prefix_list_id=PL_BLOCKED_IPS,
        prefix_list_name="blocked-ips",
        owner_id=account_id,
        address_family="IPv4",
        max_entries=100,
        entries=entries,
        tags={"Name": "blocked-ips", "ManagedBy": "security-operations"},
    )


def create_vpn_clients_prefix_list(
    account_id: str = "123456789012",
) -> PrefixListFixture:
    """Create a prefix list for VPN client IP ranges."""
    entries = [
        PrefixListEntry(cidr="10.100.0.0/16", description="VPN client pool"),
        PrefixListEntry(cidr="10.101.0.0/16", description="VPN client pool backup"),
    ]

    return PrefixListFixture(
        prefix_list_id=PL_VPN_CLIENTS,
        prefix_list_name="vpn-clients",
        owner_id=account_id,
        address_family="IPv4",
        max_entries=10,
        entries=entries,
        tags={"Name": "vpn-clients", "ManagedBy": "networking"},
    )


def create_office_locations_prefix_list(
    account_id: str = "123456789012",
) -> PrefixListFixture:
    """Create a prefix list for office location IP ranges."""
    entries = [
        PrefixListEntry(cidr="203.0.113.10/32", description="HQ Office - NYC"),
        PrefixListEntry(cidr="203.0.113.20/32", description="Branch Office - SF"),
        PrefixListEntry(cidr="203.0.113.30/32", description="Branch Office - London"),
        PrefixListEntry(cidr="203.0.113.40/32", description="Branch Office - Tokyo"),
    ]

    return PrefixListFixture(
        prefix_list_id=PL_OFFICE_LOCATIONS,
        prefix_list_name="office-locations",
        owner_id=account_id,
        address_family="IPv4",
        max_entries=20,
        entries=entries,
        tags={"Name": "office-locations", "ManagedBy": "facilities"},
    )


def create_empty_prefix_list(account_id: str = "123456789012") -> PrefixListFixture:
    """Create an empty prefix list.

    Useful for testing edge cases where prefix list exists but has no entries.
    """
    return PrefixListFixture(
        prefix_list_id=PL_EMPTY,
        prefix_list_name="empty-prefix-list",
        owner_id=account_id,
        address_family="IPv4",
        max_entries=10,
        entries=[],
        tags={"Name": "empty-prefix-list"},
    )


def create_cross_account_prefix_list() -> PrefixListFixture:
    """Create a prefix list owned by another account.

    Tests cross-account prefix list resolution scenarios.
    """
    entries = [
        PrefixListEntry(cidr="10.200.0.0/16", description="Partner VPC range"),
    ]

    return PrefixListFixture(
        prefix_list_id=PL_CROSS_ACCOUNT,
        prefix_list_name="cross-account-shared",
        owner_id=CROSS_ACCOUNT_OWNER,
        address_family="IPv4",
        max_entries=10,
        entries=entries,
        tags={"Name": "cross-account-shared"},
    )


# =============================================================================
# IPv6 Prefix Lists
# =============================================================================


def create_ipv6_corporate_prefix_list(
    account_id: str = "123456789012",
) -> PrefixListFixture:
    """Create an IPv6 prefix list for corporate ranges."""
    entries = [
        PrefixListEntry(cidr="2001:db8::/32", description="Documentation range"),
        PrefixListEntry(cidr="2001:db8:1234::/48", description="Corporate IPv6"),
    ]

    return PrefixListFixture(
        prefix_list_id="pl-ipv6corp12",
        prefix_list_name="corporate-ipv6",
        owner_id=account_id,
        address_family="IPv6",
        max_entries=20,
        entries=entries,
        tags={"Name": "corporate-ipv6"},
    )


# =============================================================================
# AWS Response Builders
# =============================================================================


def build_describe_managed_prefix_lists_response(
    prefix_lists: list[PrefixListFixture],
) -> dict[str, Any]:
    """Build a mock describe_managed_prefix_lists response."""
    return {
        "PrefixLists": [
            {
                "PrefixListId": pl.prefix_list_id,
                "PrefixListName": pl.prefix_list_name,
                "OwnerId": pl.owner_id,
                "AddressFamily": pl.address_family,
                "MaxEntries": pl.max_entries,
                "State": pl.state,
                "Version": pl.version,
                "Tags": [{"Key": k, "Value": v} for k, v in pl.tags.items()],
            }
            for pl in prefix_lists
        ]
    }


def build_get_managed_prefix_list_entries_response(
    prefix_list: PrefixListFixture,
) -> dict[str, Any]:
    """Build a mock get_managed_prefix_list_entries response."""
    return {
        "Entries": [
            {"Cidr": entry.cidr, "Description": entry.description}
            for entry in prefix_list.entries
        ]
    }


# =============================================================================
# Fixture Collections
# =============================================================================


def get_all_aws_prefix_lists(region: str = "us-east-1") -> list[PrefixListFixture]:
    """Get all AWS-managed prefix lists for a region."""
    return [
        create_s3_prefix_list(region),
        create_dynamodb_prefix_list(region),
        create_cloudfront_prefix_list(),
    ]


def get_all_customer_prefix_lists(
    account_id: str = "123456789012",
) -> list[PrefixListFixture]:
    """Get all customer-managed prefix lists."""
    return [
        create_corporate_network_prefix_list(account_id),
        create_trusted_partners_prefix_list(account_id),
        create_blocked_ips_prefix_list(account_id),
        create_vpn_clients_prefix_list(account_id),
        create_office_locations_prefix_list(account_id),
        create_empty_prefix_list(account_id),
        create_ipv6_corporate_prefix_list(account_id),
    ]


def get_all_prefix_lists(
    account_id: str = "123456789012",
    region: str = "us-east-1",
) -> list[PrefixListFixture]:
    """Get all prefix lists (AWS + customer managed)."""
    return get_all_aws_prefix_lists(region) + get_all_customer_prefix_lists(account_id)


# =============================================================================
# Prefix List Lookup Helpers
# =============================================================================


class PrefixListRegistry:
    """Registry for looking up prefix lists by ID.

    Use this in tests to resolve prefix list references in SG rules.
    """

    def __init__(self, prefix_lists: list[PrefixListFixture] | None = None):
        self._prefix_lists: dict[str, PrefixListFixture] = {}
        if prefix_lists:
            for pl in prefix_lists:
                self._prefix_lists[pl.prefix_list_id] = pl

    def add(self, prefix_list: PrefixListFixture) -> None:
        """Add a prefix list to the registry."""
        self._prefix_lists[prefix_list.prefix_list_id] = prefix_list

    def get(self, prefix_list_id: str) -> PrefixListFixture | None:
        """Get a prefix list by ID."""
        return self._prefix_lists.get(prefix_list_id)

    def get_cidrs(self, prefix_list_id: str) -> list[str]:
        """Get CIDRs for a prefix list ID.

        Returns empty list if prefix list not found.
        """
        pl = self.get(prefix_list_id)
        if pl is None:
            return []
        return [entry.cidr for entry in pl.entries]

    def resolve_to_cidrs(self, prefix_list_ids: list[str]) -> list[str]:
        """Resolve multiple prefix list IDs to their CIDRs."""
        cidrs = []
        for pl_id in prefix_list_ids:
            cidrs.extend(self.get_cidrs(pl_id))
        return cidrs

    def contains_ip(self, prefix_list_id: str, ip: str) -> bool:
        """Check if an IP is contained in any CIDR of the prefix list.

        This is a simple implementation for testing. In production,
        use the CIDRMatcher from netgraph.evaluators.cidr.
        """
        import ipaddress

        cidrs = self.get_cidrs(prefix_list_id)
        try:
            ip_addr = ipaddress.ip_address(ip)
            for cidr in cidrs:
                if ip_addr in ipaddress.ip_network(cidr, strict=False):
                    return True
        except ValueError:
            return False
        return False


def create_default_prefix_list_registry(
    account_id: str = "123456789012",
    region: str = "us-east-1",
) -> PrefixListRegistry:
    """Create a registry with all default prefix lists."""
    return PrefixListRegistry(get_all_prefix_lists(account_id, region))
