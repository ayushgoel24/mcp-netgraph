"""Graph data models for NetGraph topology representation."""

from datetime import datetime
from enum import Enum
from ipaddress import IPv4Address, IPv6Address
from typing import Literal

from pydantic import BaseModel, Field

# Local type alias to avoid circular import with __init__.py
IPAddress = IPv4Address | IPv6Address


class NodeType(str, Enum):
    """Types of nodes in the VPC topology graph."""

    INSTANCE = "instance"
    ENI = "eni"
    SUBNET = "subnet"
    INTERNET_GATEWAY = "igw"
    NAT_GATEWAY = "nat"
    VPC_PEERING = "peering"
    TRANSIT_GATEWAY = "tgw"


class EdgeType(str, Enum):
    """Types of edges (relationships) in the topology graph."""

    ROUTE = "route"
    ATTACHMENT = "attachment"
    ASSOCIATION = "association"


class InstanceAttributes(BaseModel):
    """Attributes specific to EC2 instances."""

    private_ip: IPAddress
    private_ipv6: IPv6Address | None = None
    public_ip: IPv4Address | None = None
    public_ipv6: IPv6Address | None = None
    security_group_ids: list[str]
    subnet_id: str
    eni_ids: list[str]
    tags: dict[str, str] = Field(default_factory=dict)


class ENIAttributes(BaseModel):
    """Attributes specific to Elastic Network Interfaces."""

    private_ip: IPAddress
    private_ipv6: IPv6Address | None = None
    public_ip: IPv4Address | None = None
    security_group_ids: list[str]
    subnet_id: str
    attachment_id: str | None = None


class SubnetAttributes(BaseModel):
    """Attributes specific to subnets."""

    cidr_block: str  # IPv4 CIDR
    ipv6_cidr_block: str | None = None  # IPv6 CIDR
    availability_zone: str
    route_table_id: str
    nacl_id: str
    is_public: bool = Field(False, description="True if route table has route to IGW")


class GatewayAttributes(BaseModel):
    """Attributes for IGW, NAT, VPC Peering, and Transit Gateway."""

    gateway_type: Literal["igw", "nat", "peering", "tgw"]
    # For VPC Peering
    peer_vpc_id: str | None = None
    peer_account_id: str | None = None
    peer_region: str | None = None
    # For NAT Gateway
    elastic_ip: IPv4Address | None = None


class GraphNode(BaseModel):
    """Represents a node in the VPC topology graph."""

    id: str = Field(..., description="AWS resource ID")
    node_type: NodeType
    vpc_id: str
    account_id: str
    region: str
    arn: str | None = Field(None, description="Full ARN for console lookup")
    cached_at: datetime = Field(default_factory=datetime.utcnow)

    # Type-specific attributes stored as typed unions
    instance_attrs: InstanceAttributes | None = None
    eni_attrs: ENIAttributes | None = None
    subnet_attrs: SubnetAttributes | None = None
    gateway_attrs: GatewayAttributes | None = None


class GraphEdge(BaseModel):
    """Represents a directed edge (routing path) in the graph."""

    source_id: str
    target_id: str
    edge_type: EdgeType
    route_table_id: str | None = None
    destination_cidr: str | None = Field(
        None, description="CIDR block this route matches (IPv4 or IPv6)"
    )
    prefix_length: int = Field(
        0, description="CIDR prefix length for LPM sorting (longer = more specific)"
    )
