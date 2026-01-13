"""AWS resource models for Security Groups, NACLs, Route Tables, etc."""

from ipaddress import ip_network
from typing import Literal, Protocol, runtime_checkable

from pydantic import BaseModel, Field


@runtime_checkable
class PrefixListResolver(Protocol):
    """Protocol for resolving prefix list CIDRs.

    This minimal protocol allows SGRule.resolve_cidrs() to work with
    any AWS client that implements get_prefix_list_cidrs().
    """

    async def get_prefix_list_cidrs(self, prefix_list_id: str) -> list[str]:
        """Resolve a prefix list ID to its CIDR entries."""
        ...


class NetworkConstants:
    """Constants for network protocol handling."""

    # Ephemeral port range for return traffic verification
    # TCP/UDP connections use ephemeral ports for return traffic
    EPHEMERAL_PORT_MIN: int = 1024
    EPHEMERAL_PORT_MAX: int = 65535

    # Protocol numbers (as used in NACL rules)
    PROTO_TCP: str = "6"
    PROTO_UDP: str = "17"
    PROTO_ICMP: str = "1"
    PROTO_ICMPV6: str = "58"
    PROTO_ALL: str = "-1"


class SGRule(BaseModel):
    """Security Group rule with support for:
    - IPv4 CIDR
    - IPv6 CIDR
    - Managed Prefix Lists
    - Security Group references
    """

    rule_id: str
    direction: Literal["inbound", "outbound"]
    ip_protocol: str  # "tcp", "udp", "icmp", "icmpv6", or "-1" for all
    from_port: int
    to_port: int

    # One of these will be set (mutually exclusive)
    cidr_ipv4: str | None = None
    cidr_ipv6: str | None = None
    prefix_list_id: str | None = None  # Managed Prefix List (pl-xxx)
    referenced_sg_id: str | None = None  # SG-to-SG rules

    description: str | None = None

    def matches_port(self, port: int) -> bool:
        """Check if rule covers the given port."""
        if self.ip_protocol == "-1":  # All traffic
            return True
        return self.from_port <= port <= self.to_port

    async def resolve_cidrs(self, aws_client: PrefixListResolver) -> list[str]:
        """Resolve this rule to a list of CIDRs.

        For prefix lists, fetches the actual CIDR entries from AWS.
        """
        if self.cidr_ipv4:
            return [self.cidr_ipv4]
        if self.cidr_ipv6:
            return [self.cidr_ipv6]
        if self.prefix_list_id:
            return await aws_client.get_prefix_list_cidrs(self.prefix_list_id)
        return []


class NACLRule(BaseModel):
    """Network ACL rule with IPv4 and IPv6 support."""

    rule_number: int = Field(..., ge=1, le=32766)
    rule_action: Literal["allow", "deny"]
    direction: Literal["inbound", "outbound"]
    protocol: str  # "-1" for all, "6" for TCP, "17" for UDP

    # One of these will be set
    cidr_block: str | None = None  # IPv4
    ipv6_cidr_block: str | None = None  # IPv6

    from_port: int | None = None  # None for all ports
    to_port: int | None = None

    @property
    def effective_cidr(self) -> str | None:
        """Return whichever CIDR is set."""
        return self.cidr_block or self.ipv6_cidr_block


class Route(BaseModel):
    """Route table entry."""

    destination_cidr: str  # IPv4 or IPv6 CIDR
    target_id: str  # igw-xxx, nat-xxx, pcx-xxx, local, etc.
    target_type: Literal["igw", "nat", "peering", "tgw", "local", "eni", "instance"]
    state: Literal["active", "blackhole"] = "active"

    @property
    def prefix_length(self) -> int:
        """Get prefix length for LPM sorting."""
        return ip_network(self.destination_cidr, strict=False).prefixlen


class RouteTable(BaseModel):
    """Route table with all routes."""

    route_table_id: str
    vpc_id: str
    routes: list[Route]
    subnet_associations: list[str] = Field(default_factory=list)


class SecurityGroup(BaseModel):
    """Complete Security Group with all rules."""

    sg_id: str
    vpc_id: str
    name: str
    description: str
    inbound_rules: list[SGRule]
    outbound_rules: list[SGRule]


class NetworkACL(BaseModel):
    """Complete NACL with all rules."""

    nacl_id: str
    vpc_id: str
    is_default: bool
    inbound_rules: list[NACLRule]
    outbound_rules: list[NACLRule]
    subnet_associations: list[str] = Field(default_factory=list)


class ManagedPrefixList(BaseModel):
    """AWS Managed Prefix List."""

    prefix_list_id: str
    prefix_list_name: str
    address_family: Literal["IPv4", "IPv6"]
    max_entries: int
    entries: list[str]  # List of CIDRs
    owner_id: str
    state: str
