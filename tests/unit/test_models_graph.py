"""Tests for graph data models."""

from datetime import datetime
from ipaddress import IPv4Address, IPv6Address

from netgraph.models.graph import (
    EdgeType,
    ENIAttributes,
    GatewayAttributes,
    GraphEdge,
    GraphNode,
    InstanceAttributes,
    NodeType,
    SubnetAttributes,
)


class TestNodeType:
    """Tests for NodeType enum."""

    def test_all_node_types_defined(self) -> None:
        """All expected node types exist."""
        expected = {"instance", "eni", "subnet", "igw", "nat", "peering", "tgw"}
        actual = {nt.value for nt in NodeType}
        assert actual == expected

    def test_node_type_string_enum(self) -> None:
        """NodeType values are strings."""
        assert NodeType.INSTANCE.value == "instance"
        assert NodeType.TRANSIT_GATEWAY.value == "tgw"

    def test_node_type_from_string(self) -> None:
        """Can create NodeType from string value."""
        assert NodeType("instance") == NodeType.INSTANCE
        assert NodeType("tgw") == NodeType.TRANSIT_GATEWAY


class TestEdgeType:
    """Tests for EdgeType enum."""

    def test_all_edge_types_defined(self) -> None:
        """All expected edge types exist."""
        expected = {"route", "attachment", "association"}
        actual = {et.value for et in EdgeType}
        assert actual == expected

    def test_edge_type_from_string(self) -> None:
        """Can create EdgeType from string value."""
        assert EdgeType("route") == EdgeType.ROUTE


class TestInstanceAttributes:
    """Tests for InstanceAttributes model."""

    def test_minimal_instance(self) -> None:
        """Can create instance with required fields only."""
        attrs = InstanceAttributes(
            private_ip=IPv4Address("10.0.1.50"),
            security_group_ids=["sg-12345"],
            subnet_id="subnet-12345",
            eni_ids=["eni-12345"],
        )
        assert attrs.private_ip == IPv4Address("10.0.1.50")
        assert attrs.tags == {}

    def test_instance_with_ipv6(self) -> None:
        """Instance can have IPv6 addresses."""
        attrs = InstanceAttributes(
            private_ip=IPv4Address("10.0.1.50"),
            private_ipv6=IPv6Address("2001:db8::1"),
            public_ipv6=IPv6Address("2001:db8::2"),
            security_group_ids=["sg-12345"],
            subnet_id="subnet-12345",
            eni_ids=["eni-12345"],
        )
        assert attrs.private_ipv6 == IPv6Address("2001:db8::1")

    def test_instance_with_tags(self) -> None:
        """Instance can have tags."""
        attrs = InstanceAttributes(
            private_ip=IPv4Address("10.0.1.50"),
            security_group_ids=["sg-12345"],
            subnet_id="subnet-12345",
            eni_ids=["eni-12345"],
            tags={"Name": "web-server", "Environment": "prod"},
        )
        assert attrs.tags["Name"] == "web-server"

    def test_instance_ipv6_as_primary(self) -> None:
        """Instance can have IPv6 as primary IP."""
        attrs = InstanceAttributes(
            private_ip=IPv6Address("2001:db8::1"),
            security_group_ids=["sg-12345"],
            subnet_id="subnet-12345",
            eni_ids=["eni-12345"],
        )
        assert attrs.private_ip == IPv6Address("2001:db8::1")


class TestENIAttributes:
    """Tests for ENIAttributes model."""

    def test_minimal_eni(self) -> None:
        """Can create ENI with required fields only."""
        attrs = ENIAttributes(
            private_ip=IPv4Address("10.0.1.100"),
            security_group_ids=["sg-12345"],
            subnet_id="subnet-12345",
        )
        assert attrs.private_ip == IPv4Address("10.0.1.100")
        assert attrs.attachment_id is None

    def test_eni_with_attachment(self) -> None:
        """ENI can have attachment ID."""
        attrs = ENIAttributes(
            private_ip=IPv4Address("10.0.1.100"),
            security_group_ids=["sg-12345"],
            subnet_id="subnet-12345",
            attachment_id="eni-attach-12345",
        )
        assert attrs.attachment_id == "eni-attach-12345"


class TestSubnetAttributes:
    """Tests for SubnetAttributes model."""

    def test_minimal_subnet(self) -> None:
        """Can create subnet with required fields only."""
        attrs = SubnetAttributes(
            cidr_block="10.0.1.0/24",
            availability_zone="us-east-1a",
            route_table_id="rtb-12345",
            nacl_id="acl-12345",
        )
        assert attrs.cidr_block == "10.0.1.0/24"
        assert attrs.is_public is False

    def test_subnet_with_ipv6(self) -> None:
        """Subnet can have IPv6 CIDR block."""
        attrs = SubnetAttributes(
            cidr_block="10.0.1.0/24",
            ipv6_cidr_block="2001:db8:abcd:0001::/64",
            availability_zone="us-east-1a",
            route_table_id="rtb-12345",
            nacl_id="acl-12345",
        )
        assert attrs.ipv6_cidr_block == "2001:db8:abcd:0001::/64"

    def test_public_subnet(self) -> None:
        """Subnet can be marked as public."""
        attrs = SubnetAttributes(
            cidr_block="10.0.1.0/24",
            availability_zone="us-east-1a",
            route_table_id="rtb-12345",
            nacl_id="acl-12345",
            is_public=True,
        )
        assert attrs.is_public is True


class TestGatewayAttributes:
    """Tests for GatewayAttributes model."""

    def test_igw_attributes(self) -> None:
        """Internet Gateway attributes."""
        attrs = GatewayAttributes(gateway_type="igw")
        assert attrs.gateway_type == "igw"
        assert attrs.peer_vpc_id is None

    def test_nat_gateway_attributes(self) -> None:
        """NAT Gateway attributes with elastic IP."""
        attrs = GatewayAttributes(
            gateway_type="nat",
            elastic_ip=IPv4Address("54.123.45.67"),
        )
        assert attrs.gateway_type == "nat"
        assert attrs.elastic_ip == IPv4Address("54.123.45.67")

    def test_peering_attributes(self) -> None:
        """VPC Peering connection attributes."""
        attrs = GatewayAttributes(
            gateway_type="peering",
            peer_vpc_id="vpc-peer123",
            peer_account_id="123456789012",
            peer_region="us-west-2",
        )
        assert attrs.gateway_type == "peering"
        assert attrs.peer_vpc_id == "vpc-peer123"
        assert attrs.peer_account_id == "123456789012"

    def test_tgw_attributes(self) -> None:
        """Transit Gateway attributes."""
        attrs = GatewayAttributes(gateway_type="tgw")
        assert attrs.gateway_type == "tgw"


class TestGraphNode:
    """Tests for GraphNode model."""

    def test_minimal_node(self) -> None:
        """Can create node with required fields only."""
        node = GraphNode(
            id="i-12345",
            node_type=NodeType.INSTANCE,
            vpc_id="vpc-12345",
            account_id="123456789012",
            region="us-east-1",
        )
        assert node.id == "i-12345"
        assert node.node_type == NodeType.INSTANCE
        assert node.arn is None

    def test_node_with_cached_at(self) -> None:
        """Node has cached_at timestamp."""
        before = datetime.utcnow()
        node = GraphNode(
            id="i-12345",
            node_type=NodeType.INSTANCE,
            vpc_id="vpc-12345",
            account_id="123456789012",
            region="us-east-1",
        )
        after = datetime.utcnow()
        assert before <= node.cached_at <= after

    def test_node_with_instance_attributes(self) -> None:
        """Node can have instance-specific attributes."""
        instance_attrs = InstanceAttributes(
            private_ip=IPv4Address("10.0.1.50"),
            security_group_ids=["sg-12345"],
            subnet_id="subnet-12345",
            eni_ids=["eni-12345"],
        )
        node = GraphNode(
            id="i-12345",
            node_type=NodeType.INSTANCE,
            vpc_id="vpc-12345",
            account_id="123456789012",
            region="us-east-1",
            instance_attrs=instance_attrs,
        )
        assert node.instance_attrs is not None
        assert node.instance_attrs.private_ip == IPv4Address("10.0.1.50")

    def test_node_with_arn(self) -> None:
        """Node can have ARN for console lookup."""
        node = GraphNode(
            id="i-12345",
            node_type=NodeType.INSTANCE,
            vpc_id="vpc-12345",
            account_id="123456789012",
            region="us-east-1",
            arn="arn:aws:ec2:us-east-1:123456789012:instance/i-12345",
        )
        assert node.arn == "arn:aws:ec2:us-east-1:123456789012:instance/i-12345"

    def test_node_serialization(self) -> None:
        """Node can be serialized to dict/JSON."""
        node = GraphNode(
            id="subnet-12345",
            node_type=NodeType.SUBNET,
            vpc_id="vpc-12345",
            account_id="123456789012",
            region="us-east-1",
            subnet_attrs=SubnetAttributes(
                cidr_block="10.0.1.0/24",
                availability_zone="us-east-1a",
                route_table_id="rtb-12345",
                nacl_id="acl-12345",
            ),
        )
        data = node.model_dump()
        assert data["id"] == "subnet-12345"
        assert data["node_type"] == "subnet"
        assert data["subnet_attrs"]["cidr_block"] == "10.0.1.0/24"


class TestGraphEdge:
    """Tests for GraphEdge model."""

    def test_minimal_edge(self) -> None:
        """Can create edge with required fields only."""
        edge = GraphEdge(
            source_id="i-12345",
            target_id="igw-12345",
            edge_type=EdgeType.ROUTE,
        )
        assert edge.source_id == "i-12345"
        assert edge.target_id == "igw-12345"
        assert edge.prefix_length == 0

    def test_route_edge_with_cidr(self) -> None:
        """Route edge can have destination CIDR."""
        edge = GraphEdge(
            source_id="subnet-12345",
            target_id="igw-12345",
            edge_type=EdgeType.ROUTE,
            route_table_id="rtb-12345",
            destination_cidr="0.0.0.0/0",
            prefix_length=0,
        )
        assert edge.destination_cidr == "0.0.0.0/0"
        assert edge.prefix_length == 0

    def test_route_edge_with_ipv6_cidr(self) -> None:
        """Route edge can have IPv6 destination CIDR."""
        edge = GraphEdge(
            source_id="subnet-12345",
            target_id="igw-12345",
            edge_type=EdgeType.ROUTE,
            route_table_id="rtb-12345",
            destination_cidr="::/0",
            prefix_length=0,
        )
        assert edge.destination_cidr == "::/0"

    def test_edge_with_prefix_length(self) -> None:
        """Edge can have prefix length for LPM sorting."""
        edge = GraphEdge(
            source_id="subnet-12345",
            target_id="nat-12345",
            edge_type=EdgeType.ROUTE,
            route_table_id="rtb-12345",
            destination_cidr="10.0.1.0/24",
            prefix_length=24,
        )
        assert edge.prefix_length == 24

    def test_attachment_edge(self) -> None:
        """Attachment type edge."""
        edge = GraphEdge(
            source_id="i-12345",
            target_id="eni-12345",
            edge_type=EdgeType.ATTACHMENT,
        )
        assert edge.edge_type == EdgeType.ATTACHMENT

    def test_association_edge(self) -> None:
        """Association type edge."""
        edge = GraphEdge(
            source_id="subnet-12345",
            target_id="rtb-12345",
            edge_type=EdgeType.ASSOCIATION,
        )
        assert edge.edge_type == EdgeType.ASSOCIATION

    def test_edge_serialization(self) -> None:
        """Edge can be serialized to dict/JSON."""
        edge = GraphEdge(
            source_id="subnet-12345",
            target_id="igw-12345",
            edge_type=EdgeType.ROUTE,
            destination_cidr="0.0.0.0/0",
            prefix_length=0,
        )
        data = edge.model_dump()
        assert data["source_id"] == "subnet-12345"
        assert data["edge_type"] == "route"
