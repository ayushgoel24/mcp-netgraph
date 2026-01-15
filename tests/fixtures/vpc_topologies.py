"""VPC topology fixtures for NetGraph integration tests.

This module provides comprehensive test fixtures representing various
AWS VPC topologies for end-to-end testing of path analysis scenarios.

Topology Types:
- Simple: Single VPC with public/private subnets
- Multi-tier: Web, app, and database tiers
- Peered: Two VPCs connected via peering
- Complex: Multiple VPCs with NAT, IGW, and TGW
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# =============================================================================
# AWS Resource ID Constants
# =============================================================================

# Account and Region
ACCOUNT_ID = "123456789012"
PEER_ACCOUNT_ID = "987654321098"
REGION = "us-east-1"

# VPC IDs
VPC_MAIN = "vpc-main12345"
VPC_PEER = "vpc-peer12345"
VPC_ISOLATED = "vpc-iso12345"

# Subnet IDs - Main VPC
SUBNET_PUBLIC_1 = "subnet-pub1main"
SUBNET_PUBLIC_2 = "subnet-pub2main"
SUBNET_PRIVATE_1 = "subnet-prv1main"
SUBNET_PRIVATE_2 = "subnet-prv2main"
SUBNET_DATABASE = "subnet-dbmain12"

# Subnet IDs - Peer VPC
SUBNET_PEER_PUBLIC = "subnet-pubpeer1"
SUBNET_PEER_PRIVATE = "subnet-prvpeer1"

# Gateway IDs
IGW_MAIN = "igw-main12345"
IGW_PEER = "igw-peer12345"
NAT_MAIN = "nat-main12345"
NAT_PEER = "nat-peer12345"

# Peering
PEERING_MAIN_TO_PEER = "pcx-mainpeer12"

# Transit Gateway
TGW_MAIN = "tgw-main12345"
TGW_ATTACHMENT_MAIN = "tgw-attach-main"
TGW_ATTACHMENT_PEER = "tgw-attach-peer"

# Route Tables
RTB_PUBLIC_MAIN = "rtb-pubmain12"
RTB_PRIVATE_MAIN = "rtb-prvmain12"
RTB_DATABASE_MAIN = "rtb-dbmain123"
RTB_PUBLIC_PEER = "rtb-pubpeer12"
RTB_PRIVATE_PEER = "rtb-prvpeer12"

# Security Groups
SG_WEB = "sg-web1234567"
SG_APP = "sg-app1234567"
SG_DATABASE = "sg-db12345678"
SG_BASTION = "sg-bastion123"
SG_PEER_WEB = "sg-peerweb123"
SG_PEER_APP = "sg-peerapp123"
SG_ALLOW_ALL = "sg-allowall12"
SG_DENY_ALL = "sg-denyall123"

# NACLs
NACL_PUBLIC = "acl-pubmain12"
NACL_PRIVATE = "acl-prvmain12"
NACL_DATABASE = "acl-dbmain123"
NACL_PEER = "acl-peer12345"
NACL_BLOCK_EPHEMERAL = "acl-blockeph1"

# EC2 Instances
INSTANCE_WEB_1 = "i-web1234567890"
INSTANCE_WEB_2 = "i-web2345678901"
INSTANCE_APP_1 = "i-app1234567890"
INSTANCE_APP_2 = "i-app2345678901"
INSTANCE_DB_1 = "i-db12345678901"
INSTANCE_BASTION = "i-bastion123456"
INSTANCE_PEER_WEB = "i-peerweb12345"
INSTANCE_PEER_APP = "i-peerapp12345"

# ENIs
ENI_WEB_1 = "eni-web1234567"
ENI_WEB_2 = "eni-web2345678"
ENI_APP_1 = "eni-app1234567"
ENI_APP_2 = "eni-app2345678"
ENI_DB_1 = "eni-db12345678"
ENI_BASTION = "eni-bastion123"
ENI_NAT_MAIN = "eni-natmain12"
ENI_PEER_WEB = "eni-peerweb12"
ENI_PEER_APP = "eni-peerapp12"

# Prefix Lists
PREFIX_LIST_CLOUDFRONT = "pl-cloudfront1"
PREFIX_LIST_S3 = "pl-s3region123"

# IP Addresses
IP_WEB_1_PRIVATE = "10.0.1.10"
IP_WEB_1_PUBLIC = "54.123.45.67"
IP_WEB_2_PRIVATE = "10.0.1.11"
IP_WEB_2_PUBLIC = "54.123.45.68"
IP_APP_1_PRIVATE = "10.0.2.10"
IP_APP_2_PRIVATE = "10.0.2.11"
IP_DB_1_PRIVATE = "10.0.3.10"
IP_BASTION_PRIVATE = "10.0.1.50"
IP_BASTION_PUBLIC = "54.123.45.100"
IP_NAT_MAIN_PRIVATE = "10.0.1.100"
IP_NAT_MAIN_PUBLIC = "54.123.45.200"
IP_PEER_WEB_PRIVATE = "172.16.1.10"
IP_PEER_WEB_PUBLIC = "52.100.200.10"
IP_PEER_APP_PRIVATE = "172.16.2.10"

# CIDR Blocks
CIDR_VPC_MAIN = "10.0.0.0/16"
CIDR_VPC_PEER = "172.16.0.0/16"
CIDR_PUBLIC_1 = "10.0.1.0/24"
CIDR_PUBLIC_2 = "10.0.4.0/24"
CIDR_PRIVATE_1 = "10.0.2.0/24"
CIDR_PRIVATE_2 = "10.0.5.0/24"
CIDR_DATABASE = "10.0.3.0/24"
CIDR_PEER_PUBLIC = "172.16.1.0/24"
CIDR_PEER_PRIVATE = "172.16.2.0/24"
CIDR_INTERNET = "0.0.0.0/0"


# =============================================================================
# Fixture Data Classes
# =============================================================================


@dataclass
class SubnetFixture:
    """Subnet fixture data."""

    subnet_id: str
    vpc_id: str
    cidr_block: str
    availability_zone: str
    route_table_id: str
    nacl_id: str
    map_public_ip: bool = False
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class InstanceFixture:
    """EC2 instance fixture data."""

    instance_id: str
    vpc_id: str
    subnet_id: str
    private_ip: str
    public_ip: str | None
    security_group_ids: list[str]
    eni_id: str
    state: str = "running"
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class SecurityGroupFixture:
    """Security group fixture data."""

    sg_id: str
    vpc_id: str
    name: str
    inbound_rules: list[dict[str, Any]]
    outbound_rules: list[dict[str, Any]]
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class NACLFixture:
    """Network ACL fixture data."""

    nacl_id: str
    vpc_id: str
    inbound_rules: list[dict[str, Any]]
    outbound_rules: list[dict[str, Any]]
    subnet_associations: list[str] = field(default_factory=list)
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class RouteTableFixture:
    """Route table fixture data."""

    route_table_id: str
    vpc_id: str
    routes: list[dict[str, Any]]
    subnet_associations: list[str] = field(default_factory=list)
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class VPCTopology:
    """Complete VPC topology for testing."""

    vpc_id: str
    cidr_block: str
    account_id: str
    region: str
    subnets: list[SubnetFixture]
    instances: list[InstanceFixture]
    security_groups: list[SecurityGroupFixture]
    nacls: list[NACLFixture]
    route_tables: list[RouteTableFixture]
    igw_id: str | None = None
    nat_gw_id: str | None = None
    peering_connections: list[dict[str, Any]] = field(default_factory=list)
    transit_gateway_attachments: list[dict[str, Any]] = field(default_factory=list)
    tags: dict[str, str] = field(default_factory=dict)


# =============================================================================
# Security Group Rule Builders
# =============================================================================


def sg_rule_allow_port(
    port: int,
    protocol: str = "tcp",
    cidr: str = "0.0.0.0/0",
    description: str = "",
) -> dict[str, Any]:
    """Create an SG rule allowing a specific port."""
    return {
        "ip_protocol": protocol,
        "from_port": port,
        "to_port": port,
        "cidr_ipv4": cidr,
        "description": description or f"Allow {protocol}/{port}",
    }


def sg_rule_allow_port_range(
    from_port: int,
    to_port: int,
    protocol: str = "tcp",
    cidr: str = "0.0.0.0/0",
    description: str = "",
) -> dict[str, Any]:
    """Create an SG rule allowing a port range."""
    return {
        "ip_protocol": protocol,
        "from_port": from_port,
        "to_port": to_port,
        "cidr_ipv4": cidr,
        "description": description or f"Allow {protocol}/{from_port}-{to_port}",
    }


def sg_rule_allow_sg_reference(
    referenced_sg_id: str,
    port: int | None = None,
    protocol: str = "-1",
    description: str = "",
) -> dict[str, Any]:
    """Create an SG rule allowing traffic from another security group."""
    rule: dict[str, Any] = {
        "ip_protocol": protocol,
        "referenced_group_id": referenced_sg_id,
        "description": description or f"Allow from {referenced_sg_id}",
    }
    if port is not None:
        rule["from_port"] = port
        rule["to_port"] = port
    return rule


def sg_rule_allow_prefix_list(
    prefix_list_id: str,
    port: int,
    protocol: str = "tcp",
    description: str = "",
) -> dict[str, Any]:
    """Create an SG rule allowing traffic from a prefix list."""
    return {
        "ip_protocol": protocol,
        "from_port": port,
        "to_port": port,
        "prefix_list_id": prefix_list_id,
        "description": description or f"Allow from {prefix_list_id}",
    }


def sg_rule_allow_all_outbound() -> dict[str, Any]:
    """Create an SG rule allowing all outbound traffic."""
    return {
        "ip_protocol": "-1",
        "cidr_ipv4": "0.0.0.0/0",
        "description": "Allow all outbound",
    }


# =============================================================================
# NACL Rule Builders
# =============================================================================


def nacl_rule_allow(
    rule_number: int,
    cidr: str,
    protocol: str = "-1",
    port_range: tuple[int, int] | None = None,
) -> dict[str, Any]:
    """Create an NACL rule allowing traffic."""
    rule: dict[str, Any] = {
        "rule_number": rule_number,
        "rule_action": "allow",
        "protocol": protocol,
        "cidr_block": cidr,
    }
    if port_range:
        rule["port_range_from"] = port_range[0]
        rule["port_range_to"] = port_range[1]
    return rule


def nacl_rule_deny(
    rule_number: int,
    cidr: str,
    protocol: str = "-1",
    port_range: tuple[int, int] | None = None,
) -> dict[str, Any]:
    """Create an NACL rule denying traffic."""
    rule: dict[str, Any] = {
        "rule_number": rule_number,
        "rule_action": "deny",
        "protocol": protocol,
        "cidr_block": cidr,
    }
    if port_range:
        rule["port_range_from"] = port_range[0]
        rule["port_range_to"] = port_range[1]
    return rule


def nacl_default_deny() -> dict[str, Any]:
    """Create the default NACL deny rule (rule *)."""
    return {
        "rule_number": 32767,
        "rule_action": "deny",
        "protocol": "-1",
        "cidr_block": "0.0.0.0/0",
    }


# =============================================================================
# Route Builders
# =============================================================================


def route_local(cidr: str) -> dict[str, Any]:
    """Create a local route."""
    return {
        "destination_cidr_block": cidr,
        "gateway_id": "local",
        "state": "active",
        "origin": "CreateRouteTable",
    }


def route_igw(cidr: str, igw_id: str) -> dict[str, Any]:
    """Create a route to an Internet Gateway."""
    return {
        "destination_cidr_block": cidr,
        "gateway_id": igw_id,
        "state": "active",
        "origin": "CreateRoute",
    }


def route_nat(cidr: str, nat_id: str) -> dict[str, Any]:
    """Create a route to a NAT Gateway."""
    return {
        "destination_cidr_block": cidr,
        "nat_gateway_id": nat_id,
        "state": "active",
        "origin": "CreateRoute",
    }


def route_peering(cidr: str, pcx_id: str) -> dict[str, Any]:
    """Create a route to a VPC Peering Connection."""
    return {
        "destination_cidr_block": cidr,
        "vpc_peering_connection_id": pcx_id,
        "state": "active",
        "origin": "CreateRoute",
    }


def route_tgw(cidr: str, tgw_id: str) -> dict[str, Any]:
    """Create a route to a Transit Gateway."""
    return {
        "destination_cidr_block": cidr,
        "transit_gateway_id": tgw_id,
        "state": "active",
        "origin": "CreateRoute",
    }


def route_blackhole(cidr: str) -> dict[str, Any]:
    """Create a blackhole route (e.g., deleted peering)."""
    return {
        "destination_cidr_block": cidr,
        "state": "blackhole",
        "origin": "CreateRoute",
    }


# =============================================================================
# Simple VPC Topology (Public + Private subnets)
# =============================================================================


def create_simple_vpc_topology() -> VPCTopology:
    """Create a simple VPC with public and private subnets.

    Topology:
    - VPC: 10.0.0.0/16
    - Public subnet: 10.0.1.0/24 (web server with public IP)
    - Private subnet: 10.0.2.0/24 (app server, NAT for internet)
    - IGW for public subnet
    - NAT GW for private subnet

    Use cases:
    - Web server accessible from internet on port 443
    - App server can reach internet via NAT
    - Web -> App on port 8080 allowed
    """
    subnets = [
        SubnetFixture(
            subnet_id=SUBNET_PUBLIC_1,
            vpc_id=VPC_MAIN,
            cidr_block=CIDR_PUBLIC_1,
            availability_zone=f"{REGION}a",
            route_table_id=RTB_PUBLIC_MAIN,
            nacl_id=NACL_PUBLIC,
            map_public_ip=True,
            tags={"Name": "public-subnet-1"},
        ),
        SubnetFixture(
            subnet_id=SUBNET_PRIVATE_1,
            vpc_id=VPC_MAIN,
            cidr_block=CIDR_PRIVATE_1,
            availability_zone=f"{REGION}a",
            route_table_id=RTB_PRIVATE_MAIN,
            nacl_id=NACL_PRIVATE,
            map_public_ip=False,
            tags={"Name": "private-subnet-1"},
        ),
    ]

    instances = [
        InstanceFixture(
            instance_id=INSTANCE_WEB_1,
            vpc_id=VPC_MAIN,
            subnet_id=SUBNET_PUBLIC_1,
            private_ip=IP_WEB_1_PRIVATE,
            public_ip=IP_WEB_1_PUBLIC,
            security_group_ids=[SG_WEB],
            eni_id=ENI_WEB_1,
            tags={"Name": "web-server-1", "Environment": "production"},
        ),
        InstanceFixture(
            instance_id=INSTANCE_APP_1,
            vpc_id=VPC_MAIN,
            subnet_id=SUBNET_PRIVATE_1,
            private_ip=IP_APP_1_PRIVATE,
            public_ip=None,
            security_group_ids=[SG_APP],
            eni_id=ENI_APP_1,
            tags={"Name": "app-server-1", "Environment": "production"},
        ),
    ]

    security_groups = [
        SecurityGroupFixture(
            sg_id=SG_WEB,
            vpc_id=VPC_MAIN,
            name="web-sg",
            inbound_rules=[
                sg_rule_allow_port(443, cidr="0.0.0.0/0", description="HTTPS from internet"),
                sg_rule_allow_port(80, cidr="0.0.0.0/0", description="HTTP from internet"),
            ],
            outbound_rules=[sg_rule_allow_all_outbound()],
            tags={"Name": "web-sg"},
        ),
        SecurityGroupFixture(
            sg_id=SG_APP,
            vpc_id=VPC_MAIN,
            name="app-sg",
            inbound_rules=[
                sg_rule_allow_port(8080, cidr=CIDR_PUBLIC_1, description="From web tier"),
                sg_rule_allow_sg_reference(SG_WEB, port=8080, protocol="tcp", description="From web SG"),
            ],
            outbound_rules=[sg_rule_allow_all_outbound()],
            tags={"Name": "app-sg"},
        ),
    ]

    nacls = [
        NACLFixture(
            nacl_id=NACL_PUBLIC,
            vpc_id=VPC_MAIN,
            inbound_rules=[
                nacl_rule_allow(100, "0.0.0.0/0", "tcp", (443, 443)),
                nacl_rule_allow(110, "0.0.0.0/0", "tcp", (80, 80)),
                nacl_rule_allow(120, "0.0.0.0/0", "tcp", (1024, 65535)),  # Ephemeral
                nacl_default_deny(),
            ],
            outbound_rules=[
                nacl_rule_allow(100, "0.0.0.0/0", "-1"),  # Allow all outbound
                nacl_default_deny(),
            ],
            subnet_associations=[SUBNET_PUBLIC_1],
            tags={"Name": "public-nacl"},
        ),
        NACLFixture(
            nacl_id=NACL_PRIVATE,
            vpc_id=VPC_MAIN,
            inbound_rules=[
                nacl_rule_allow(100, CIDR_PUBLIC_1, "tcp", (8080, 8080)),
                nacl_rule_allow(110, "0.0.0.0/0", "tcp", (1024, 65535)),  # Return from NAT
                nacl_default_deny(),
            ],
            outbound_rules=[
                nacl_rule_allow(100, "0.0.0.0/0", "-1"),
                nacl_default_deny(),
            ],
            subnet_associations=[SUBNET_PRIVATE_1],
            tags={"Name": "private-nacl"},
        ),
    ]

    route_tables = [
        RouteTableFixture(
            route_table_id=RTB_PUBLIC_MAIN,
            vpc_id=VPC_MAIN,
            routes=[
                route_local(CIDR_VPC_MAIN),
                route_igw("0.0.0.0/0", IGW_MAIN),
            ],
            subnet_associations=[SUBNET_PUBLIC_1],
            tags={"Name": "public-rtb"},
        ),
        RouteTableFixture(
            route_table_id=RTB_PRIVATE_MAIN,
            vpc_id=VPC_MAIN,
            routes=[
                route_local(CIDR_VPC_MAIN),
                route_nat("0.0.0.0/0", NAT_MAIN),
            ],
            subnet_associations=[SUBNET_PRIVATE_1],
            tags={"Name": "private-rtb"},
        ),
    ]

    return VPCTopology(
        vpc_id=VPC_MAIN,
        cidr_block=CIDR_VPC_MAIN,
        account_id=ACCOUNT_ID,
        region=REGION,
        subnets=subnets,
        instances=instances,
        security_groups=security_groups,
        nacls=nacls,
        route_tables=route_tables,
        igw_id=IGW_MAIN,
        nat_gw_id=NAT_MAIN,
        tags={"Name": "main-vpc", "Environment": "production"},
    )


# =============================================================================
# Multi-Tier VPC Topology (Web, App, Database)
# =============================================================================


def create_multi_tier_topology() -> VPCTopology:
    """Create a multi-tier VPC with web, app, and database tiers.

    Topology:
    - VPC: 10.0.0.0/16
    - Public subnet: 10.0.1.0/24 (web, bastion)
    - App subnet: 10.0.2.0/24 (app servers)
    - Database subnet: 10.0.3.0/24 (database, most restrictive)

    Use cases:
    - Internet -> Web on 443
    - Web -> App on 8080
    - App -> Database on 5432 (PostgreSQL)
    - Bastion -> App on 22 (SSH)
    - Database has NO internet access
    """
    subnets = [
        SubnetFixture(
            subnet_id=SUBNET_PUBLIC_1,
            vpc_id=VPC_MAIN,
            cidr_block=CIDR_PUBLIC_1,
            availability_zone=f"{REGION}a",
            route_table_id=RTB_PUBLIC_MAIN,
            nacl_id=NACL_PUBLIC,
            map_public_ip=True,
            tags={"Name": "web-subnet", "Tier": "web"},
        ),
        SubnetFixture(
            subnet_id=SUBNET_PRIVATE_1,
            vpc_id=VPC_MAIN,
            cidr_block=CIDR_PRIVATE_1,
            availability_zone=f"{REGION}a",
            route_table_id=RTB_PRIVATE_MAIN,
            nacl_id=NACL_PRIVATE,
            map_public_ip=False,
            tags={"Name": "app-subnet", "Tier": "app"},
        ),
        SubnetFixture(
            subnet_id=SUBNET_DATABASE,
            vpc_id=VPC_MAIN,
            cidr_block=CIDR_DATABASE,
            availability_zone=f"{REGION}a",
            route_table_id=RTB_DATABASE_MAIN,
            nacl_id=NACL_DATABASE,
            map_public_ip=False,
            tags={"Name": "database-subnet", "Tier": "database"},
        ),
    ]

    instances = [
        InstanceFixture(
            instance_id=INSTANCE_WEB_1,
            vpc_id=VPC_MAIN,
            subnet_id=SUBNET_PUBLIC_1,
            private_ip=IP_WEB_1_PRIVATE,
            public_ip=IP_WEB_1_PUBLIC,
            security_group_ids=[SG_WEB],
            eni_id=ENI_WEB_1,
            tags={"Name": "web-server-1", "Tier": "web"},
        ),
        InstanceFixture(
            instance_id=INSTANCE_BASTION,
            vpc_id=VPC_MAIN,
            subnet_id=SUBNET_PUBLIC_1,
            private_ip=IP_BASTION_PRIVATE,
            public_ip=IP_BASTION_PUBLIC,
            security_group_ids=[SG_BASTION],
            eni_id=ENI_BASTION,
            tags={"Name": "bastion", "Tier": "management"},
        ),
        InstanceFixture(
            instance_id=INSTANCE_APP_1,
            vpc_id=VPC_MAIN,
            subnet_id=SUBNET_PRIVATE_1,
            private_ip=IP_APP_1_PRIVATE,
            public_ip=None,
            security_group_ids=[SG_APP],
            eni_id=ENI_APP_1,
            tags={"Name": "app-server-1", "Tier": "app"},
        ),
        InstanceFixture(
            instance_id=INSTANCE_DB_1,
            vpc_id=VPC_MAIN,
            subnet_id=SUBNET_DATABASE,
            private_ip=IP_DB_1_PRIVATE,
            public_ip=None,
            security_group_ids=[SG_DATABASE],
            eni_id=ENI_DB_1,
            tags={"Name": "database-1", "Tier": "database"},
        ),
    ]

    security_groups = [
        SecurityGroupFixture(
            sg_id=SG_WEB,
            vpc_id=VPC_MAIN,
            name="web-sg",
            inbound_rules=[
                sg_rule_allow_port(443, cidr="0.0.0.0/0"),
                sg_rule_allow_port(80, cidr="0.0.0.0/0"),
            ],
            outbound_rules=[sg_rule_allow_all_outbound()],
        ),
        SecurityGroupFixture(
            sg_id=SG_BASTION,
            vpc_id=VPC_MAIN,
            name="bastion-sg",
            inbound_rules=[
                sg_rule_allow_port(22, cidr="0.0.0.0/0", description="SSH from anywhere"),
            ],
            outbound_rules=[sg_rule_allow_all_outbound()],
        ),
        SecurityGroupFixture(
            sg_id=SG_APP,
            vpc_id=VPC_MAIN,
            name="app-sg",
            inbound_rules=[
                sg_rule_allow_sg_reference(SG_WEB, port=8080, protocol="tcp"),
                sg_rule_allow_sg_reference(SG_BASTION, port=22, protocol="tcp"),
            ],
            outbound_rules=[sg_rule_allow_all_outbound()],
        ),
        SecurityGroupFixture(
            sg_id=SG_DATABASE,
            vpc_id=VPC_MAIN,
            name="database-sg",
            inbound_rules=[
                sg_rule_allow_sg_reference(SG_APP, port=5432, protocol="tcp"),
            ],
            outbound_rules=[
                # Database should only respond to established connections
                sg_rule_allow_port_range(1024, 65535, protocol="tcp", cidr=CIDR_PRIVATE_1),
            ],
        ),
    ]

    nacls = [
        NACLFixture(
            nacl_id=NACL_PUBLIC,
            vpc_id=VPC_MAIN,
            inbound_rules=[
                nacl_rule_allow(100, "0.0.0.0/0", "tcp", (443, 443)),
                nacl_rule_allow(110, "0.0.0.0/0", "tcp", (80, 80)),
                nacl_rule_allow(120, "0.0.0.0/0", "tcp", (22, 22)),
                nacl_rule_allow(130, "0.0.0.0/0", "tcp", (1024, 65535)),
                nacl_default_deny(),
            ],
            outbound_rules=[
                nacl_rule_allow(100, "0.0.0.0/0", "-1"),
                nacl_default_deny(),
            ],
            subnet_associations=[SUBNET_PUBLIC_1],
        ),
        NACLFixture(
            nacl_id=NACL_PRIVATE,
            vpc_id=VPC_MAIN,
            inbound_rules=[
                nacl_rule_allow(100, CIDR_PUBLIC_1, "tcp", (8080, 8080)),
                nacl_rule_allow(110, CIDR_PUBLIC_1, "tcp", (22, 22)),
                nacl_rule_allow(120, CIDR_DATABASE, "tcp", (1024, 65535)),  # Return from DB
                nacl_rule_allow(130, "0.0.0.0/0", "tcp", (1024, 65535)),  # Return from NAT
                nacl_default_deny(),
            ],
            outbound_rules=[
                nacl_rule_allow(100, "0.0.0.0/0", "-1"),
                nacl_default_deny(),
            ],
            subnet_associations=[SUBNET_PRIVATE_1],
        ),
        NACLFixture(
            nacl_id=NACL_DATABASE,
            vpc_id=VPC_MAIN,
            inbound_rules=[
                nacl_rule_allow(100, CIDR_PRIVATE_1, "tcp", (5432, 5432)),
                nacl_default_deny(),
            ],
            outbound_rules=[
                nacl_rule_allow(100, CIDR_PRIVATE_1, "tcp", (1024, 65535)),
                nacl_default_deny(),
            ],
            subnet_associations=[SUBNET_DATABASE],
        ),
    ]

    route_tables = [
        RouteTableFixture(
            route_table_id=RTB_PUBLIC_MAIN,
            vpc_id=VPC_MAIN,
            routes=[
                route_local(CIDR_VPC_MAIN),
                route_igw("0.0.0.0/0", IGW_MAIN),
            ],
            subnet_associations=[SUBNET_PUBLIC_1],
        ),
        RouteTableFixture(
            route_table_id=RTB_PRIVATE_MAIN,
            vpc_id=VPC_MAIN,
            routes=[
                route_local(CIDR_VPC_MAIN),
                route_nat("0.0.0.0/0", NAT_MAIN),
            ],
            subnet_associations=[SUBNET_PRIVATE_1],
        ),
        RouteTableFixture(
            route_table_id=RTB_DATABASE_MAIN,
            vpc_id=VPC_MAIN,
            routes=[
                route_local(CIDR_VPC_MAIN),
                # No internet route - isolated
            ],
            subnet_associations=[SUBNET_DATABASE],
        ),
    ]

    return VPCTopology(
        vpc_id=VPC_MAIN,
        cidr_block=CIDR_VPC_MAIN,
        account_id=ACCOUNT_ID,
        region=REGION,
        subnets=subnets,
        instances=instances,
        security_groups=security_groups,
        nacls=nacls,
        route_tables=route_tables,
        igw_id=IGW_MAIN,
        nat_gw_id=NAT_MAIN,
        tags={"Name": "multi-tier-vpc"},
    )


# =============================================================================
# VPC Peering Topology
# =============================================================================


def create_peered_vpc_topology() -> tuple[VPCTopology, VPCTopology]:
    """Create two VPCs connected via peering.

    Topology:
    - Main VPC: 10.0.0.0/16 (has web server)
    - Peer VPC: 172.16.0.0/16 (has app server)
    - Peering connection between them

    Use cases:
    - Web in main VPC -> App in peer VPC on port 8080
    - Both VPCs have internet access via their own IGWs
    """
    # Main VPC
    main_subnets = [
        SubnetFixture(
            subnet_id=SUBNET_PUBLIC_1,
            vpc_id=VPC_MAIN,
            cidr_block=CIDR_PUBLIC_1,
            availability_zone=f"{REGION}a",
            route_table_id=RTB_PUBLIC_MAIN,
            nacl_id=NACL_PUBLIC,
            map_public_ip=True,
        ),
    ]

    main_instances = [
        InstanceFixture(
            instance_id=INSTANCE_WEB_1,
            vpc_id=VPC_MAIN,
            subnet_id=SUBNET_PUBLIC_1,
            private_ip=IP_WEB_1_PRIVATE,
            public_ip=IP_WEB_1_PUBLIC,
            security_group_ids=[SG_WEB],
            eni_id=ENI_WEB_1,
            tags={"Name": "web-main"},
        ),
    ]

    main_security_groups = [
        SecurityGroupFixture(
            sg_id=SG_WEB,
            vpc_id=VPC_MAIN,
            name="web-sg",
            inbound_rules=[sg_rule_allow_port(443, cidr="0.0.0.0/0")],
            outbound_rules=[sg_rule_allow_all_outbound()],
        ),
    ]

    main_nacls = [
        NACLFixture(
            nacl_id=NACL_PUBLIC,
            vpc_id=VPC_MAIN,
            inbound_rules=[
                nacl_rule_allow(100, "0.0.0.0/0", "-1"),
                nacl_default_deny(),
            ],
            outbound_rules=[
                nacl_rule_allow(100, "0.0.0.0/0", "-1"),
                nacl_default_deny(),
            ],
        ),
    ]

    main_route_tables = [
        RouteTableFixture(
            route_table_id=RTB_PUBLIC_MAIN,
            vpc_id=VPC_MAIN,
            routes=[
                route_local(CIDR_VPC_MAIN),
                route_igw("0.0.0.0/0", IGW_MAIN),
                route_peering(CIDR_VPC_PEER, PEERING_MAIN_TO_PEER),
            ],
        ),
    ]

    main_vpc = VPCTopology(
        vpc_id=VPC_MAIN,
        cidr_block=CIDR_VPC_MAIN,
        account_id=ACCOUNT_ID,
        region=REGION,
        subnets=main_subnets,
        instances=main_instances,
        security_groups=main_security_groups,
        nacls=main_nacls,
        route_tables=main_route_tables,
        igw_id=IGW_MAIN,
        peering_connections=[
            {
                "pcx_id": PEERING_MAIN_TO_PEER,
                "requester_vpc_id": VPC_MAIN,
                "accepter_vpc_id": VPC_PEER,
                "status": "active",
            }
        ],
    )

    # Peer VPC
    peer_subnets = [
        SubnetFixture(
            subnet_id=SUBNET_PEER_PRIVATE,
            vpc_id=VPC_PEER,
            cidr_block=CIDR_PEER_PRIVATE,
            availability_zone=f"{REGION}a",
            route_table_id=RTB_PRIVATE_PEER,
            nacl_id=NACL_PEER,
            map_public_ip=False,
        ),
    ]

    peer_instances = [
        InstanceFixture(
            instance_id=INSTANCE_PEER_APP,
            vpc_id=VPC_PEER,
            subnet_id=SUBNET_PEER_PRIVATE,
            private_ip=IP_PEER_APP_PRIVATE,
            public_ip=None,
            security_group_ids=[SG_PEER_APP],
            eni_id=ENI_PEER_APP,
            tags={"Name": "app-peer"},
        ),
    ]

    peer_security_groups = [
        SecurityGroupFixture(
            sg_id=SG_PEER_APP,
            vpc_id=VPC_PEER,
            name="peer-app-sg",
            inbound_rules=[
                sg_rule_allow_port(8080, cidr=CIDR_VPC_MAIN, description="From main VPC"),
            ],
            outbound_rules=[sg_rule_allow_all_outbound()],
        ),
    ]

    peer_nacls = [
        NACLFixture(
            nacl_id=NACL_PEER,
            vpc_id=VPC_PEER,
            inbound_rules=[
                nacl_rule_allow(100, CIDR_VPC_MAIN, "tcp", (8080, 8080)),
                nacl_rule_allow(110, "0.0.0.0/0", "tcp", (1024, 65535)),
                nacl_default_deny(),
            ],
            outbound_rules=[
                nacl_rule_allow(100, "0.0.0.0/0", "-1"),
                nacl_default_deny(),
            ],
        ),
    ]

    peer_route_tables = [
        RouteTableFixture(
            route_table_id=RTB_PRIVATE_PEER,
            vpc_id=VPC_PEER,
            routes=[
                route_local(CIDR_VPC_PEER),
                route_nat("0.0.0.0/0", NAT_PEER),
                route_peering(CIDR_VPC_MAIN, PEERING_MAIN_TO_PEER),
            ],
        ),
    ]

    peer_vpc = VPCTopology(
        vpc_id=VPC_PEER,
        cidr_block=CIDR_VPC_PEER,
        account_id=ACCOUNT_ID,
        region=REGION,
        subnets=peer_subnets,
        instances=peer_instances,
        security_groups=peer_security_groups,
        nacls=peer_nacls,
        route_tables=peer_route_tables,
        nat_gw_id=NAT_PEER,
        peering_connections=[
            {
                "pcx_id": PEERING_MAIN_TO_PEER,
                "requester_vpc_id": VPC_MAIN,
                "accepter_vpc_id": VPC_PEER,
                "status": "active",
            }
        ],
    )

    return main_vpc, peer_vpc


# =============================================================================
# Edge Case Topologies
# =============================================================================


def create_nacl_blocks_ephemeral_topology() -> VPCTopology:
    """Create a topology where NACL blocks ephemeral return ports.

    This is the Staff Engineer fix scenario where forward path is allowed
    but NACL blocks return traffic on ephemeral ports (1024-65535).
    """
    subnets = [
        SubnetFixture(
            subnet_id=SUBNET_PUBLIC_1,
            vpc_id=VPC_MAIN,
            cidr_block=CIDR_PUBLIC_1,
            availability_zone=f"{REGION}a",
            route_table_id=RTB_PUBLIC_MAIN,
            nacl_id=NACL_BLOCK_EPHEMERAL,
            map_public_ip=True,
        ),
    ]

    instances = [
        InstanceFixture(
            instance_id=INSTANCE_WEB_1,
            vpc_id=VPC_MAIN,
            subnet_id=SUBNET_PUBLIC_1,
            private_ip=IP_WEB_1_PRIVATE,
            public_ip=IP_WEB_1_PUBLIC,
            security_group_ids=[SG_ALLOW_ALL],
            eni_id=ENI_WEB_1,
        ),
    ]

    security_groups = [
        SecurityGroupFixture(
            sg_id=SG_ALLOW_ALL,
            vpc_id=VPC_MAIN,
            name="allow-all-sg",
            inbound_rules=[{"ip_protocol": "-1", "cidr_ipv4": "0.0.0.0/0"}],
            outbound_rules=[{"ip_protocol": "-1", "cidr_ipv4": "0.0.0.0/0"}],
        ),
    ]

    nacls = [
        NACLFixture(
            nacl_id=NACL_BLOCK_EPHEMERAL,
            vpc_id=VPC_MAIN,
            inbound_rules=[
                nacl_rule_allow(100, "0.0.0.0/0", "tcp", (443, 443)),
                nacl_rule_allow(110, "0.0.0.0/0", "tcp", (80, 80)),
                # MISSING: ephemeral ports (1024-65535) - this blocks return traffic!
                nacl_default_deny(),
            ],
            outbound_rules=[
                nacl_rule_allow(100, "0.0.0.0/0", "-1"),
                nacl_default_deny(),
            ],
        ),
    ]

    route_tables = [
        RouteTableFixture(
            route_table_id=RTB_PUBLIC_MAIN,
            vpc_id=VPC_MAIN,
            routes=[
                route_local(CIDR_VPC_MAIN),
                route_igw("0.0.0.0/0", IGW_MAIN),
            ],
        ),
    ]

    return VPCTopology(
        vpc_id=VPC_MAIN,
        cidr_block=CIDR_VPC_MAIN,
        account_id=ACCOUNT_ID,
        region=REGION,
        subnets=subnets,
        instances=instances,
        security_groups=security_groups,
        nacls=nacls,
        route_tables=route_tables,
        igw_id=IGW_MAIN,
    )


def create_asymmetric_routing_topology() -> VPCTopology:
    """Create a topology with asymmetric routing (no return route).

    This is the Principal Engineer fix scenario where the destination
    subnet has no route back to the source IP.
    """
    subnets = [
        SubnetFixture(
            subnet_id=SUBNET_PUBLIC_1,
            vpc_id=VPC_MAIN,
            cidr_block=CIDR_PUBLIC_1,
            availability_zone=f"{REGION}a",
            route_table_id=RTB_PUBLIC_MAIN,
            nacl_id=NACL_PUBLIC,
            map_public_ip=True,
        ),
        SubnetFixture(
            subnet_id=SUBNET_PRIVATE_1,
            vpc_id=VPC_MAIN,
            cidr_block=CIDR_PRIVATE_1,
            availability_zone=f"{REGION}a",
            route_table_id=RTB_PRIVATE_MAIN,
            nacl_id=NACL_PRIVATE,
            map_public_ip=False,
        ),
    ]

    instances = [
        InstanceFixture(
            instance_id=INSTANCE_WEB_1,
            vpc_id=VPC_MAIN,
            subnet_id=SUBNET_PUBLIC_1,
            private_ip=IP_WEB_1_PRIVATE,
            public_ip=IP_WEB_1_PUBLIC,
            security_group_ids=[SG_ALLOW_ALL],
            eni_id=ENI_WEB_1,
        ),
        InstanceFixture(
            instance_id=INSTANCE_APP_1,
            vpc_id=VPC_MAIN,
            subnet_id=SUBNET_PRIVATE_1,
            private_ip=IP_APP_1_PRIVATE,
            public_ip=None,
            security_group_ids=[SG_ALLOW_ALL],
            eni_id=ENI_APP_1,
        ),
    ]

    security_groups = [
        SecurityGroupFixture(
            sg_id=SG_ALLOW_ALL,
            vpc_id=VPC_MAIN,
            name="allow-all-sg",
            inbound_rules=[{"ip_protocol": "-1", "cidr_ipv4": "0.0.0.0/0"}],
            outbound_rules=[{"ip_protocol": "-1", "cidr_ipv4": "0.0.0.0/0"}],
        ),
    ]

    nacls = [
        NACLFixture(
            nacl_id=NACL_PUBLIC,
            vpc_id=VPC_MAIN,
            inbound_rules=[nacl_rule_allow(100, "0.0.0.0/0", "-1"), nacl_default_deny()],
            outbound_rules=[nacl_rule_allow(100, "0.0.0.0/0", "-1"), nacl_default_deny()],
        ),
        NACLFixture(
            nacl_id=NACL_PRIVATE,
            vpc_id=VPC_MAIN,
            inbound_rules=[nacl_rule_allow(100, "0.0.0.0/0", "-1"), nacl_default_deny()],
            outbound_rules=[nacl_rule_allow(100, "0.0.0.0/0", "-1"), nacl_default_deny()],
        ),
    ]

    route_tables = [
        RouteTableFixture(
            route_table_id=RTB_PUBLIC_MAIN,
            vpc_id=VPC_MAIN,
            routes=[
                route_local(CIDR_VPC_MAIN),
                route_igw("0.0.0.0/0", IGW_MAIN),
            ],
        ),
        RouteTableFixture(
            route_table_id=RTB_PRIVATE_MAIN,
            vpc_id=VPC_MAIN,
            routes=[
                # Only has local route - no route back to public subnet's external traffic!
                route_local(CIDR_PRIVATE_1),  # Very restrictive - only this subnet
                # Missing: route_local(CIDR_VPC_MAIN) which would allow return to public subnet
            ],
        ),
    ]

    return VPCTopology(
        vpc_id=VPC_MAIN,
        cidr_block=CIDR_VPC_MAIN,
        account_id=ACCOUNT_ID,
        region=REGION,
        subnets=subnets,
        instances=instances,
        security_groups=security_groups,
        nacls=nacls,
        route_tables=route_tables,
        igw_id=IGW_MAIN,
    )


def create_routing_loop_topology() -> VPCTopology:
    """Create a topology with a routing loop.

    Two subnets have routes pointing at each other for the same destination,
    creating an infinite loop.
    """
    subnets = [
        SubnetFixture(
            subnet_id=SUBNET_PUBLIC_1,
            vpc_id=VPC_MAIN,
            cidr_block=CIDR_PUBLIC_1,
            availability_zone=f"{REGION}a",
            route_table_id=RTB_PUBLIC_MAIN,
            nacl_id=NACL_PUBLIC,
        ),
        SubnetFixture(
            subnet_id=SUBNET_PUBLIC_2,
            vpc_id=VPC_MAIN,
            cidr_block=CIDR_PUBLIC_2,
            availability_zone=f"{REGION}b",
            route_table_id=RTB_PRIVATE_MAIN,
            nacl_id=NACL_PUBLIC,
        ),
    ]

    instances = [
        InstanceFixture(
            instance_id=INSTANCE_WEB_1,
            vpc_id=VPC_MAIN,
            subnet_id=SUBNET_PUBLIC_1,
            private_ip=IP_WEB_1_PRIVATE,
            public_ip=None,
            security_group_ids=[SG_ALLOW_ALL],
            eni_id=ENI_WEB_1,
        ),
    ]

    security_groups = [
        SecurityGroupFixture(
            sg_id=SG_ALLOW_ALL,
            vpc_id=VPC_MAIN,
            name="allow-all-sg",
            inbound_rules=[{"ip_protocol": "-1", "cidr_ipv4": "0.0.0.0/0"}],
            outbound_rules=[{"ip_protocol": "-1", "cidr_ipv4": "0.0.0.0/0"}],
        ),
    ]

    nacls = [
        NACLFixture(
            nacl_id=NACL_PUBLIC,
            vpc_id=VPC_MAIN,
            inbound_rules=[nacl_rule_allow(100, "0.0.0.0/0", "-1"), nacl_default_deny()],
            outbound_rules=[nacl_rule_allow(100, "0.0.0.0/0", "-1"), nacl_default_deny()],
        ),
    ]

    # Route tables that create a loop for destination 8.8.8.8
    route_tables = [
        RouteTableFixture(
            route_table_id=RTB_PUBLIC_MAIN,
            vpc_id=VPC_MAIN,
            routes=[
                route_local(CIDR_VPC_MAIN),
                # Route to 8.8.8.0/24 via ENI in subnet 2 (which will route back)
                {
                    "destination_cidr_block": "8.8.8.0/24",
                    "network_interface_id": ENI_WEB_2,
                    "state": "active",
                },
            ],
        ),
        RouteTableFixture(
            route_table_id=RTB_PRIVATE_MAIN,
            vpc_id=VPC_MAIN,
            routes=[
                route_local(CIDR_VPC_MAIN),
                # Route to 8.8.8.0/24 via ENI in subnet 1 (creates loop)
                {
                    "destination_cidr_block": "8.8.8.0/24",
                    "network_interface_id": ENI_WEB_1,
                    "state": "active",
                },
            ],
        ),
    ]

    return VPCTopology(
        vpc_id=VPC_MAIN,
        cidr_block=CIDR_VPC_MAIN,
        account_id=ACCOUNT_ID,
        region=REGION,
        subnets=subnets,
        instances=instances,
        security_groups=security_groups,
        nacls=nacls,
        route_tables=route_tables,
    )


def create_transit_gateway_topology() -> VPCTopology:
    """Create a topology with a Transit Gateway attachment.

    This tests the UNKNOWN return when path goes through TGW.
    """
    subnets = [
        SubnetFixture(
            subnet_id=SUBNET_PRIVATE_1,
            vpc_id=VPC_MAIN,
            cidr_block=CIDR_PRIVATE_1,
            availability_zone=f"{REGION}a",
            route_table_id=RTB_PRIVATE_MAIN,
            nacl_id=NACL_PRIVATE,
        ),
    ]

    instances = [
        InstanceFixture(
            instance_id=INSTANCE_APP_1,
            vpc_id=VPC_MAIN,
            subnet_id=SUBNET_PRIVATE_1,
            private_ip=IP_APP_1_PRIVATE,
            public_ip=None,
            security_group_ids=[SG_ALLOW_ALL],
            eni_id=ENI_APP_1,
        ),
    ]

    security_groups = [
        SecurityGroupFixture(
            sg_id=SG_ALLOW_ALL,
            vpc_id=VPC_MAIN,
            name="allow-all-sg",
            inbound_rules=[{"ip_protocol": "-1", "cidr_ipv4": "0.0.0.0/0"}],
            outbound_rules=[{"ip_protocol": "-1", "cidr_ipv4": "0.0.0.0/0"}],
        ),
    ]

    nacls = [
        NACLFixture(
            nacl_id=NACL_PRIVATE,
            vpc_id=VPC_MAIN,
            inbound_rules=[nacl_rule_allow(100, "0.0.0.0/0", "-1"), nacl_default_deny()],
            outbound_rules=[nacl_rule_allow(100, "0.0.0.0/0", "-1"), nacl_default_deny()],
        ),
    ]

    route_tables = [
        RouteTableFixture(
            route_table_id=RTB_PRIVATE_MAIN,
            vpc_id=VPC_MAIN,
            routes=[
                route_local(CIDR_VPC_MAIN),
                route_tgw("0.0.0.0/0", TGW_MAIN),  # All traffic via TGW
            ],
        ),
    ]

    return VPCTopology(
        vpc_id=VPC_MAIN,
        cidr_block=CIDR_VPC_MAIN,
        account_id=ACCOUNT_ID,
        region=REGION,
        subnets=subnets,
        instances=instances,
        security_groups=security_groups,
        nacls=nacls,
        route_tables=route_tables,
        transit_gateway_attachments=[
            {
                "tgw_id": TGW_MAIN,
                "attachment_id": TGW_ATTACHMENT_MAIN,
                "vpc_id": VPC_MAIN,
                "state": "available",
            }
        ],
    )


# =============================================================================
# AWS Response Builders
# =============================================================================


def build_describe_instances_response(topology: VPCTopology) -> dict[str, Any]:
    """Build a mock describe_instances response from topology."""
    reservations = []
    for instance in topology.instances:
        reservations.append(
            {
                "ReservationId": f"r-{instance.instance_id[-8:]}",
                "Instances": [
                    {
                        "InstanceId": instance.instance_id,
                        "VpcId": instance.vpc_id,
                        "SubnetId": instance.subnet_id,
                        "PrivateIpAddress": instance.private_ip,
                        "PublicIpAddress": instance.public_ip,
                        "State": {"Name": instance.state},
                        "SecurityGroups": [
                            {"GroupId": sg_id} for sg_id in instance.security_group_ids
                        ],
                        "NetworkInterfaces": [
                            {
                                "NetworkInterfaceId": instance.eni_id,
                                "PrivateIpAddress": instance.private_ip,
                                "SubnetId": instance.subnet_id,
                                "Groups": [
                                    {"GroupId": sg_id}
                                    for sg_id in instance.security_group_ids
                                ],
                            }
                        ],
                        "Tags": [
                            {"Key": k, "Value": v} for k, v in instance.tags.items()
                        ],
                    }
                ],
            }
        )
    return {"Reservations": reservations}


def build_describe_subnets_response(topology: VPCTopology) -> dict[str, Any]:
    """Build a mock describe_subnets response from topology."""
    subnets = []
    for subnet in topology.subnets:
        subnets.append(
            {
                "SubnetId": subnet.subnet_id,
                "VpcId": subnet.vpc_id,
                "CidrBlock": subnet.cidr_block,
                "AvailabilityZone": subnet.availability_zone,
                "MapPublicIpOnLaunch": subnet.map_public_ip,
                "Tags": [{"Key": k, "Value": v} for k, v in subnet.tags.items()],
            }
        )
    return {"Subnets": subnets}


def build_describe_security_groups_response(topology: VPCTopology) -> dict[str, Any]:
    """Build a mock describe_security_groups response from topology."""
    groups = []
    for sg in topology.security_groups:
        groups.append(
            {
                "GroupId": sg.sg_id,
                "VpcId": sg.vpc_id,
                "GroupName": sg.name,
                "IpPermissions": [_build_ip_permission(r) for r in sg.inbound_rules],
                "IpPermissionsEgress": [
                    _build_ip_permission(r) for r in sg.outbound_rules
                ],
                "Tags": [{"Key": k, "Value": v} for k, v in sg.tags.items()],
            }
        )
    return {"SecurityGroups": groups}


def _build_ip_permission(rule: dict[str, Any]) -> dict[str, Any]:
    """Build an IpPermission from a rule dict."""
    perm: dict[str, Any] = {
        "IpProtocol": rule.get("ip_protocol", "-1"),
    }

    if "from_port" in rule:
        perm["FromPort"] = rule["from_port"]
    if "to_port" in rule:
        perm["ToPort"] = rule["to_port"]

    if "cidr_ipv4" in rule:
        perm["IpRanges"] = [
            {
                "CidrIp": rule["cidr_ipv4"],
                "Description": rule.get("description", ""),
            }
        ]
    elif "cidr_ipv6" in rule:
        perm["Ipv6Ranges"] = [
            {
                "CidrIpv6": rule["cidr_ipv6"],
                "Description": rule.get("description", ""),
            }
        ]
    elif "referenced_group_id" in rule:
        perm["UserIdGroupPairs"] = [
            {
                "GroupId": rule["referenced_group_id"],
                "Description": rule.get("description", ""),
            }
        ]
    elif "prefix_list_id" in rule:
        perm["PrefixListIds"] = [
            {
                "PrefixListId": rule["prefix_list_id"],
                "Description": rule.get("description", ""),
            }
        ]

    return perm


def build_describe_network_acls_response(topology: VPCTopology) -> dict[str, Any]:
    """Build a mock describe_network_acls response from topology."""
    acls = []
    for nacl in topology.nacls:
        entries = []

        for rule in nacl.inbound_rules:
            entry = {
                "RuleNumber": rule["rule_number"],
                "RuleAction": rule["rule_action"],
                "Protocol": rule.get("protocol", "-1"),
                "CidrBlock": rule.get("cidr_block", "0.0.0.0/0"),
                "Egress": False,
            }
            if "port_range_from" in rule:
                entry["PortRange"] = {
                    "From": rule["port_range_from"],
                    "To": rule["port_range_to"],
                }
            entries.append(entry)

        for rule in nacl.outbound_rules:
            entry = {
                "RuleNumber": rule["rule_number"],
                "RuleAction": rule["rule_action"],
                "Protocol": rule.get("protocol", "-1"),
                "CidrBlock": rule.get("cidr_block", "0.0.0.0/0"),
                "Egress": True,
            }
            if "port_range_from" in rule:
                entry["PortRange"] = {
                    "From": rule["port_range_from"],
                    "To": rule["port_range_to"],
                }
            entries.append(entry)

        acls.append(
            {
                "NetworkAclId": nacl.nacl_id,
                "VpcId": nacl.vpc_id,
                "Entries": entries,
                "Associations": [
                    {"SubnetId": sid, "NetworkAclAssociationId": f"aclassoc-{sid[-8:]}"}
                    for sid in nacl.subnet_associations
                ],
                "Tags": [{"Key": k, "Value": v} for k, v in nacl.tags.items()],
            }
        )
    return {"NetworkAcls": acls}


def build_describe_route_tables_response(topology: VPCTopology) -> dict[str, Any]:
    """Build a mock describe_route_tables response from topology."""
    tables = []
    for rtb in topology.route_tables:
        routes = []
        for route in rtb.routes:
            r: dict[str, Any] = {
                "DestinationCidrBlock": route.get("destination_cidr_block"),
                "State": route.get("state", "active"),
                "Origin": route.get("origin", "CreateRoute"),
            }
            if "gateway_id" in route:
                r["GatewayId"] = route["gateway_id"]
            if "nat_gateway_id" in route:
                r["NatGatewayId"] = route["nat_gateway_id"]
            if "vpc_peering_connection_id" in route:
                r["VpcPeeringConnectionId"] = route["vpc_peering_connection_id"]
            if "transit_gateway_id" in route:
                r["TransitGatewayId"] = route["transit_gateway_id"]
            if "network_interface_id" in route:
                r["NetworkInterfaceId"] = route["network_interface_id"]
            routes.append(r)

        tables.append(
            {
                "RouteTableId": rtb.route_table_id,
                "VpcId": rtb.vpc_id,
                "Routes": routes,
                "Associations": [
                    {
                        "RouteTableAssociationId": f"rtbassoc-{sid[-8:]}",
                        "SubnetId": sid,
                        "RouteTableId": rtb.route_table_id,
                    }
                    for sid in rtb.subnet_associations
                ],
                "Tags": [{"Key": k, "Value": v} for k, v in rtb.tags.items()],
            }
        )
    return {"RouteTables": tables}
