"""Tests for AWS resource models."""

from unittest.mock import AsyncMock

import pytest
from pydantic import ValidationError

from netgraph.models.aws_resources import (
    ManagedPrefixList,
    NACLRule,
    NetworkACL,
    NetworkConstants,
    Route,
    RouteTable,
    SecurityGroup,
    SGRule,
)


class TestNetworkConstants:
    """Tests for NetworkConstants."""

    def test_ephemeral_port_range(self) -> None:
        """Ephemeral port range is defined correctly."""
        assert NetworkConstants.EPHEMERAL_PORT_MIN == 1024
        assert NetworkConstants.EPHEMERAL_PORT_MAX == 65535

    def test_protocol_numbers(self) -> None:
        """Protocol numbers match AWS conventions."""
        assert NetworkConstants.PROTO_TCP == "6"
        assert NetworkConstants.PROTO_UDP == "17"
        assert NetworkConstants.PROTO_ICMP == "1"
        assert NetworkConstants.PROTO_ICMPV6 == "58"
        assert NetworkConstants.PROTO_ALL == "-1"


class TestSGRule:
    """Tests for Security Group Rule model."""

    def test_cidr_ipv4_rule(self) -> None:
        """Can create rule with IPv4 CIDR."""
        rule = SGRule(
            rule_id="rule-1",
            direction="inbound",
            ip_protocol="tcp",
            from_port=443,
            to_port=443,
            cidr_ipv4="10.0.0.0/16",
        )
        assert rule.cidr_ipv4 == "10.0.0.0/16"
        assert rule.cidr_ipv6 is None

    def test_cidr_ipv6_rule(self) -> None:
        """Can create rule with IPv6 CIDR."""
        rule = SGRule(
            rule_id="rule-1",
            direction="inbound",
            ip_protocol="tcp",
            from_port=443,
            to_port=443,
            cidr_ipv6="2001:db8::/32",
        )
        assert rule.cidr_ipv6 == "2001:db8::/32"
        assert rule.cidr_ipv4 is None

    def test_prefix_list_rule(self) -> None:
        """Can create rule with prefix list reference."""
        rule = SGRule(
            rule_id="rule-1",
            direction="inbound",
            ip_protocol="tcp",
            from_port=443,
            to_port=443,
            prefix_list_id="pl-12345",
        )
        assert rule.prefix_list_id == "pl-12345"

    def test_sg_reference_rule(self) -> None:
        """Can create rule with security group reference."""
        rule = SGRule(
            rule_id="rule-1",
            direction="inbound",
            ip_protocol="tcp",
            from_port=443,
            to_port=443,
            referenced_sg_id="sg-other123",
        )
        assert rule.referenced_sg_id == "sg-other123"

    def test_all_traffic_rule(self) -> None:
        """All traffic rule with protocol -1."""
        rule = SGRule(
            rule_id="rule-1",
            direction="outbound",
            ip_protocol="-1",
            from_port=0,
            to_port=65535,
            cidr_ipv4="0.0.0.0/0",
        )
        assert rule.ip_protocol == "-1"

    def test_matches_port_exact(self) -> None:
        """matches_port returns True for port in range."""
        rule = SGRule(
            rule_id="rule-1",
            direction="inbound",
            ip_protocol="tcp",
            from_port=443,
            to_port=443,
            cidr_ipv4="10.0.0.0/16",
        )
        assert rule.matches_port(443) is True
        assert rule.matches_port(80) is False

    def test_matches_port_range(self) -> None:
        """matches_port works with port ranges."""
        rule = SGRule(
            rule_id="rule-1",
            direction="inbound",
            ip_protocol="tcp",
            from_port=1024,
            to_port=65535,
            cidr_ipv4="10.0.0.0/16",
        )
        assert rule.matches_port(8080) is True
        assert rule.matches_port(443) is False

    def test_matches_port_all_traffic(self) -> None:
        """matches_port returns True for all traffic rule."""
        rule = SGRule(
            rule_id="rule-1",
            direction="outbound",
            ip_protocol="-1",
            from_port=0,
            to_port=65535,
            cidr_ipv4="0.0.0.0/0",
        )
        assert rule.matches_port(443) is True
        assert rule.matches_port(22) is True
        assert rule.matches_port(1) is True

    @pytest.mark.asyncio
    async def test_resolve_cidrs_ipv4(self) -> None:
        """resolve_cidrs returns IPv4 CIDR."""
        rule = SGRule(
            rule_id="rule-1",
            direction="inbound",
            ip_protocol="tcp",
            from_port=443,
            to_port=443,
            cidr_ipv4="10.0.0.0/16",
        )
        mock_client = AsyncMock()
        cidrs = await rule.resolve_cidrs(mock_client)
        assert cidrs == ["10.0.0.0/16"]

    @pytest.mark.asyncio
    async def test_resolve_cidrs_ipv6(self) -> None:
        """resolve_cidrs returns IPv6 CIDR."""
        rule = SGRule(
            rule_id="rule-1",
            direction="inbound",
            ip_protocol="tcp",
            from_port=443,
            to_port=443,
            cidr_ipv6="2001:db8::/32",
        )
        mock_client = AsyncMock()
        cidrs = await rule.resolve_cidrs(mock_client)
        assert cidrs == ["2001:db8::/32"]

    @pytest.mark.asyncio
    async def test_resolve_cidrs_prefix_list(self) -> None:
        """resolve_cidrs fetches from AWS for prefix list."""
        rule = SGRule(
            rule_id="rule-1",
            direction="inbound",
            ip_protocol="tcp",
            from_port=443,
            to_port=443,
            prefix_list_id="pl-12345",
        )
        mock_client = AsyncMock()
        mock_client.get_prefix_list_cidrs.return_value = [
            "10.0.0.0/16",
            "192.168.0.0/16",
        ]

        cidrs = await rule.resolve_cidrs(mock_client)
        assert cidrs == ["10.0.0.0/16", "192.168.0.0/16"]
        mock_client.get_prefix_list_cidrs.assert_called_once_with("pl-12345")

    @pytest.mark.asyncio
    async def test_resolve_cidrs_sg_reference(self) -> None:
        """resolve_cidrs returns empty for SG reference."""
        rule = SGRule(
            rule_id="rule-1",
            direction="inbound",
            ip_protocol="tcp",
            from_port=443,
            to_port=443,
            referenced_sg_id="sg-other123",
        )
        mock_client = AsyncMock()
        cidrs = await rule.resolve_cidrs(mock_client)
        assert cidrs == []


class TestNACLRule:
    """Tests for Network ACL Rule model."""

    def test_allow_rule_ipv4(self) -> None:
        """Can create allow rule with IPv4 CIDR."""
        rule = NACLRule(
            rule_number=100,
            rule_action="allow",
            direction="inbound",
            protocol="6",
            cidr_block="10.0.0.0/16",
            from_port=443,
            to_port=443,
        )
        assert rule.rule_action == "allow"
        assert rule.cidr_block == "10.0.0.0/16"

    def test_deny_rule_ipv6(self) -> None:
        """Can create deny rule with IPv6 CIDR."""
        rule = NACLRule(
            rule_number=100,
            rule_action="deny",
            direction="inbound",
            protocol="6",
            ipv6_cidr_block="2001:db8::/32",
            from_port=22,
            to_port=22,
        )
        assert rule.rule_action == "deny"
        assert rule.ipv6_cidr_block == "2001:db8::/32"

    def test_all_traffic_rule(self) -> None:
        """All traffic rule with no port restriction."""
        rule = NACLRule(
            rule_number=100,
            rule_action="allow",
            direction="outbound",
            protocol="-1",
            cidr_block="0.0.0.0/0",
        )
        assert rule.protocol == "-1"
        assert rule.from_port is None
        assert rule.to_port is None

    def test_rule_number_validation_min(self) -> None:
        """Rule number must be at least 1."""
        with pytest.raises(ValidationError):
            NACLRule(
                rule_number=0,
                rule_action="allow",
                direction="inbound",
                protocol="6",
                cidr_block="10.0.0.0/16",
            )

    def test_rule_number_validation_max(self) -> None:
        """Rule number must be at most 32766."""
        with pytest.raises(ValidationError):
            NACLRule(
                rule_number=32767,
                rule_action="allow",
                direction="inbound",
                protocol="6",
                cidr_block="10.0.0.0/16",
            )

    def test_effective_cidr_ipv4(self) -> None:
        """effective_cidr returns IPv4 CIDR when set."""
        rule = NACLRule(
            rule_number=100,
            rule_action="allow",
            direction="inbound",
            protocol="6",
            cidr_block="10.0.0.0/16",
        )
        assert rule.effective_cidr == "10.0.0.0/16"

    def test_effective_cidr_ipv6(self) -> None:
        """effective_cidr returns IPv6 CIDR when set."""
        rule = NACLRule(
            rule_number=100,
            rule_action="allow",
            direction="inbound",
            protocol="6",
            ipv6_cidr_block="2001:db8::/32",
        )
        assert rule.effective_cidr == "2001:db8::/32"

    def test_effective_cidr_none(self) -> None:
        """effective_cidr returns None when neither set."""
        rule = NACLRule(
            rule_number=100,
            rule_action="allow",
            direction="inbound",
            protocol="-1",
        )
        assert rule.effective_cidr is None


class TestRoute:
    """Tests for Route model."""

    def test_basic_route(self) -> None:
        """Can create basic route."""
        route = Route(
            destination_cidr="10.0.0.0/16",
            target_id="local",
            target_type="local",
        )
        assert route.destination_cidr == "10.0.0.0/16"
        assert route.state == "active"

    def test_igw_route(self) -> None:
        """Internet gateway route."""
        route = Route(
            destination_cidr="0.0.0.0/0",
            target_id="igw-12345",
            target_type="igw",
        )
        assert route.target_type == "igw"

    def test_nat_route(self) -> None:
        """NAT gateway route."""
        route = Route(
            destination_cidr="0.0.0.0/0",
            target_id="nat-12345",
            target_type="nat",
        )
        assert route.target_type == "nat"

    def test_peering_route(self) -> None:
        """VPC peering route."""
        route = Route(
            destination_cidr="172.16.0.0/16",
            target_id="pcx-12345",
            target_type="peering",
        )
        assert route.target_type == "peering"

    def test_blackhole_route(self) -> None:
        """Blackhole route state."""
        route = Route(
            destination_cidr="192.168.0.0/16",
            target_id="pcx-12345",
            target_type="peering",
            state="blackhole",
        )
        assert route.state == "blackhole"

    def test_ipv6_route(self) -> None:
        """IPv6 route."""
        route = Route(
            destination_cidr="::/0",
            target_id="igw-12345",
            target_type="igw",
        )
        assert route.destination_cidr == "::/0"

    def test_prefix_length_ipv4(self) -> None:
        """prefix_length property for IPv4."""
        route = Route(
            destination_cidr="10.0.1.0/24",
            target_id="nat-12345",
            target_type="nat",
        )
        assert route.prefix_length == 24

    def test_prefix_length_ipv6(self) -> None:
        """prefix_length property for IPv6."""
        route = Route(
            destination_cidr="2001:db8::/32",
            target_id="local",
            target_type="local",
        )
        assert route.prefix_length == 32

    def test_prefix_length_default_route(self) -> None:
        """prefix_length for default route is 0."""
        route = Route(
            destination_cidr="0.0.0.0/0",
            target_id="igw-12345",
            target_type="igw",
        )
        assert route.prefix_length == 0


class TestRouteTable:
    """Tests for RouteTable model."""

    def test_minimal_route_table(self) -> None:
        """Can create route table with required fields."""
        rt = RouteTable(
            route_table_id="rtb-12345",
            vpc_id="vpc-12345",
            routes=[],
        )
        assert rt.route_table_id == "rtb-12345"
        assert rt.subnet_associations == []

    def test_route_table_with_routes(self) -> None:
        """Route table with multiple routes."""
        rt = RouteTable(
            route_table_id="rtb-12345",
            vpc_id="vpc-12345",
            routes=[
                Route(
                    destination_cidr="10.0.0.0/16",
                    target_id="local",
                    target_type="local",
                ),
                Route(
                    destination_cidr="0.0.0.0/0",
                    target_id="igw-12345",
                    target_type="igw",
                ),
            ],
            subnet_associations=["subnet-12345"],
        )
        assert len(rt.routes) == 2
        assert rt.subnet_associations == ["subnet-12345"]


class TestSecurityGroup:
    """Tests for SecurityGroup model."""

    def test_minimal_security_group(self) -> None:
        """Can create security group with required fields."""
        sg = SecurityGroup(
            sg_id="sg-12345",
            vpc_id="vpc-12345",
            name="test-sg",
            description="Test security group",
            inbound_rules=[],
            outbound_rules=[],
        )
        assert sg.sg_id == "sg-12345"
        assert sg.name == "test-sg"

    def test_security_group_with_rules(self) -> None:
        """Security group with inbound and outbound rules."""
        sg = SecurityGroup(
            sg_id="sg-12345",
            vpc_id="vpc-12345",
            name="web-sg",
            description="Web server security group",
            inbound_rules=[
                SGRule(
                    rule_id="rule-in-1",
                    direction="inbound",
                    ip_protocol="tcp",
                    from_port=443,
                    to_port=443,
                    cidr_ipv4="0.0.0.0/0",
                ),
            ],
            outbound_rules=[
                SGRule(
                    rule_id="rule-out-1",
                    direction="outbound",
                    ip_protocol="-1",
                    from_port=0,
                    to_port=65535,
                    cidr_ipv4="0.0.0.0/0",
                ),
            ],
        )
        assert len(sg.inbound_rules) == 1
        assert len(sg.outbound_rules) == 1


class TestNetworkACL:
    """Tests for NetworkACL model."""

    def test_minimal_nacl(self) -> None:
        """Can create NACL with required fields."""
        nacl = NetworkACL(
            nacl_id="acl-12345",
            vpc_id="vpc-12345",
            is_default=False,
            inbound_rules=[],
            outbound_rules=[],
        )
        assert nacl.nacl_id == "acl-12345"
        assert nacl.is_default is False

    def test_default_nacl(self) -> None:
        """Default NACL flag."""
        nacl = NetworkACL(
            nacl_id="acl-default",
            vpc_id="vpc-12345",
            is_default=True,
            inbound_rules=[],
            outbound_rules=[],
        )
        assert nacl.is_default is True

    def test_nacl_with_rules(self) -> None:
        """NACL with inbound and outbound rules."""
        nacl = NetworkACL(
            nacl_id="acl-12345",
            vpc_id="vpc-12345",
            is_default=False,
            inbound_rules=[
                NACLRule(
                    rule_number=100,
                    rule_action="allow",
                    direction="inbound",
                    protocol="6",
                    cidr_block="10.0.0.0/16",
                    from_port=443,
                    to_port=443,
                ),
                NACLRule(
                    rule_number=32766,
                    rule_action="deny",
                    direction="inbound",
                    protocol="-1",
                    cidr_block="0.0.0.0/0",
                ),
            ],
            outbound_rules=[
                NACLRule(
                    rule_number=100,
                    rule_action="allow",
                    direction="outbound",
                    protocol="-1",
                    cidr_block="0.0.0.0/0",
                ),
            ],
            subnet_associations=["subnet-12345"],
        )
        assert len(nacl.inbound_rules) == 2
        assert len(nacl.outbound_rules) == 1
        assert nacl.subnet_associations == ["subnet-12345"]


class TestManagedPrefixList:
    """Tests for ManagedPrefixList model."""

    def test_ipv4_prefix_list(self) -> None:
        """IPv4 managed prefix list."""
        pl = ManagedPrefixList(
            prefix_list_id="pl-12345",
            prefix_list_name="my-prefix-list",
            address_family="IPv4",
            max_entries=10,
            entries=["10.0.0.0/16", "192.168.0.0/16"],
            owner_id="123456789012",
            state="create-complete",
        )
        assert pl.address_family == "IPv4"
        assert len(pl.entries) == 2

    def test_ipv6_prefix_list(self) -> None:
        """IPv6 managed prefix list."""
        pl = ManagedPrefixList(
            prefix_list_id="pl-67890",
            prefix_list_name="my-ipv6-prefix-list",
            address_family="IPv6",
            max_entries=5,
            entries=["2001:db8::/32", "2001:db8:abcd::/48"],
            owner_id="123456789012",
            state="create-complete",
        )
        assert pl.address_family == "IPv6"
        assert len(pl.entries) == 2

    def test_aws_managed_prefix_list(self) -> None:
        """AWS-managed prefix list (e.g., S3 endpoints)."""
        pl = ManagedPrefixList(
            prefix_list_id="pl-63a5400a",
            prefix_list_name="com.amazonaws.us-east-1.s3",
            address_family="IPv4",
            max_entries=1000,
            entries=["52.216.0.0/15", "54.231.0.0/17"],
            owner_id="AWS",
            state="create-complete",
        )
        assert pl.owner_id == "AWS"
        assert "s3" in pl.prefix_list_name
