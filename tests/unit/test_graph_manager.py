"""Tests for GraphManager with read-through cache."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from ipaddress import IPv4Address, IPv6Address
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from netgraph.aws.client import AWSClient, RetryConfig
from netgraph.aws.fetcher import EC2Fetcher
from netgraph.core.graph_manager import CacheEntry, GraphManager
from netgraph.models import (
    EdgeType,
    GraphEdge,
    GraphNode,
    NetworkACL,
    NodeType,
    RouteTable,
    SecurityGroup,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_ec2_client() -> MagicMock:
    """Create a mock EC2 client."""
    return MagicMock()


@pytest.fixture
def mock_aws_client(mock_ec2_client: MagicMock) -> AWSClient:
    """Create a mock AWSClient."""
    return AWSClient(
        ec2=mock_ec2_client,
        region="us-east-1",
        account_id="123456789012",
    )


@pytest.fixture
def mock_fetcher(mock_aws_client: AWSClient) -> EC2Fetcher:
    """Create an EC2Fetcher with mock client."""
    fetcher = EC2Fetcher(
        client=mock_aws_client,
        retry_config=RetryConfig(initial_delay=0.01, max_retries=1, jitter=False),
    )
    return fetcher


@pytest.fixture
def graph_manager(mock_fetcher: EC2Fetcher) -> GraphManager:
    """Create a GraphManager for testing."""
    return GraphManager(
        fetcher=mock_fetcher,
        region="us-east-1",
        account_id="123456789012",
        ttl_seconds=60,
    )


@pytest.fixture
def sample_instance_data() -> dict[str, Any]:
    """Sample AWS EC2 instance data."""
    return {
        "InstanceId": "i-1234567890abcdef0",
        "VpcId": "vpc-12345678",
        "SubnetId": "subnet-12345678",
        "PrivateIpAddress": "10.0.1.100",
        "PublicIpAddress": "54.23.45.67",
        "SecurityGroups": [{"GroupId": "sg-12345678"}],
        "NetworkInterfaces": [
            {
                "NetworkInterfaceId": "eni-12345678",
                "Ipv6Addresses": [{"Ipv6Address": "2001:db8::1"}],
            }
        ],
        "Tags": [{"Key": "Name", "Value": "test-instance"}],
    }


@pytest.fixture
def sample_eni_data() -> dict[str, Any]:
    """Sample AWS ENI data."""
    return {
        "NetworkInterfaceId": "eni-12345678",
        "VpcId": "vpc-12345678",
        "SubnetId": "subnet-12345678",
        "PrivateIpAddress": "10.0.1.100",
        "Association": {"PublicIp": "54.23.45.67"},
        "Groups": [{"GroupId": "sg-12345678"}],
        "Ipv6Addresses": [{"Ipv6Address": "2001:db8::1"}],
        "Attachment": {"AttachmentId": "eni-attach-12345678"},
    }


@pytest.fixture
def sample_subnet_data() -> dict[str, Any]:
    """Sample AWS subnet data."""
    return {
        "SubnetId": "subnet-12345678",
        "VpcId": "vpc-12345678",
        "CidrBlock": "10.0.1.0/24",
        "AvailabilityZone": "us-east-1a",
        "Ipv6CidrBlockAssociationSet": [
            {
                "Ipv6CidrBlock": "2001:db8:1::/64",
                "Ipv6CidrBlockState": {"State": "associated"},
            }
        ],
    }


@pytest.fixture
def sample_sg_data() -> dict[str, Any]:
    """Sample AWS security group data."""
    return {
        "GroupId": "sg-12345678",
        "VpcId": "vpc-12345678",
        "GroupName": "test-sg",
        "Description": "Test security group",
        "IpPermissions": [
            {
                "IpProtocol": "tcp",
                "FromPort": 443,
                "ToPort": 443,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
        "IpPermissionsEgress": [
            {
                "IpProtocol": "-1",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    }


@pytest.fixture
def sample_nacl_data() -> dict[str, Any]:
    """Sample AWS NACL data."""
    return {
        "NetworkAclId": "acl-12345678",
        "VpcId": "vpc-12345678",
        "IsDefault": False,
        "Entries": [
            {
                "RuleNumber": 100,
                "RuleAction": "allow",
                "Egress": False,
                "Protocol": "6",
                "CidrBlock": "0.0.0.0/0",
                "PortRange": {"From": 443, "To": 443},
            },
            {
                "RuleNumber": 100,
                "RuleAction": "allow",
                "Egress": True,
                "Protocol": "-1",
                "CidrBlock": "0.0.0.0/0",
            },
        ],
        "Associations": [{"SubnetId": "subnet-12345678"}],
    }


@pytest.fixture
def sample_route_table_data() -> dict[str, Any]:
    """Sample AWS route table data."""
    return {
        "RouteTableId": "rtb-12345678",
        "VpcId": "vpc-12345678",
        "Routes": [
            {
                "DestinationCidrBlock": "10.0.0.0/16",
                "GatewayId": "local",
                "State": "active",
            },
            {
                "DestinationCidrBlock": "0.0.0.0/0",
                "GatewayId": "igw-12345678",
                "State": "active",
            },
        ],
        "Associations": [
            {"SubnetId": "subnet-12345678", "Main": False},
        ],
    }


# =============================================================================
# CacheEntry Tests
# =============================================================================


class TestCacheEntry:
    """Tests for CacheEntry dataclass."""

    def test_cache_entry_creation(self) -> None:
        """CacheEntry stores data with timestamp."""
        data = {"key": "value"}
        entry = CacheEntry(data=data)

        assert entry.data == data
        assert entry.cached_at is not None

    def test_cache_entry_not_expired(self) -> None:
        """CacheEntry is not expired within TTL."""
        entry = CacheEntry(data="test")

        assert not entry.is_expired(ttl_seconds=60)

    def test_cache_entry_expired(self) -> None:
        """CacheEntry is expired after TTL."""
        # Create entry with old timestamp
        old_time = datetime(2020, 1, 1, tzinfo=timezone.utc)
        entry = CacheEntry(data="test", cached_at=old_time)

        assert entry.is_expired(ttl_seconds=60)

    def test_cache_entry_zero_ttl_always_expired(self) -> None:
        """CacheEntry with TTL=0 is always expired."""
        entry = CacheEntry(data="test")

        assert entry.is_expired(ttl_seconds=0)

    def test_age_seconds(self) -> None:
        """age_seconds returns time since caching."""
        entry = CacheEntry(data="test")

        # Age should be very small (just created)
        assert entry.age_seconds >= 0
        assert entry.age_seconds < 1


# =============================================================================
# GraphManager Initialization Tests
# =============================================================================


class TestGraphManagerInit:
    """Tests for GraphManager initialization."""

    def test_init_with_defaults(self, mock_fetcher: EC2Fetcher) -> None:
        """GraphManager initializes with default TTL."""
        gm = GraphManager(fetcher=mock_fetcher)

        assert gm.fetcher is mock_fetcher
        assert gm._ttl_seconds == 60
        assert gm._graph.number_of_nodes() == 0
        assert gm._graph.number_of_edges() == 0

    def test_init_with_custom_ttl(self, mock_fetcher: EC2Fetcher) -> None:
        """GraphManager accepts custom TTL."""
        gm = GraphManager(fetcher=mock_fetcher, ttl_seconds=120)

        assert gm._ttl_seconds == 120

    def test_init_uses_fetcher_region(self, mock_fetcher: EC2Fetcher) -> None:
        """GraphManager uses fetcher's region by default."""
        gm = GraphManager(fetcher=mock_fetcher)

        assert gm.region == "us-east-1"

    def test_init_custom_region(self, mock_fetcher: EC2Fetcher) -> None:
        """GraphManager accepts custom region."""
        gm = GraphManager(fetcher=mock_fetcher, region="eu-west-1")

        assert gm.region == "eu-west-1"


# =============================================================================
# Cache Hit/Miss Tests
# =============================================================================


class TestCacheHitMiss:
    """Tests for cache hit and miss behavior."""

    @pytest.mark.asyncio
    async def test_cache_miss_triggers_fetch(
        self,
        graph_manager: GraphManager,
        sample_instance_data: dict[str, Any],
    ) -> None:
        """Cache miss triggers AWS fetch."""
        graph_manager.fetcher.describe_instances_by_id = AsyncMock(
            return_value=sample_instance_data
        )

        node = await graph_manager.get_node("i-1234567890abcdef0")

        assert node is not None
        assert node.id == "i-1234567890abcdef0"
        graph_manager.fetcher.describe_instances_by_id.assert_called_once_with(
            "i-1234567890abcdef0"
        )

    @pytest.mark.asyncio
    async def test_cache_hit_returns_cached_data(
        self,
        graph_manager: GraphManager,
        sample_instance_data: dict[str, Any],
    ) -> None:
        """Cache hit returns cached data without AWS call."""
        graph_manager.fetcher.describe_instances_by_id = AsyncMock(
            return_value=sample_instance_data
        )

        # First call - cache miss
        node1 = await graph_manager.get_node("i-1234567890abcdef0")
        # Second call - cache hit
        node2 = await graph_manager.get_node("i-1234567890abcdef0")

        assert node1 is node2.data if hasattr(node2, "data") else node1 == node2
        # Should only be called once (cache hit on second call)
        assert graph_manager.fetcher.describe_instances_by_id.call_count == 1

    @pytest.mark.asyncio
    async def test_force_refresh_bypasses_cache(
        self,
        graph_manager: GraphManager,
        sample_instance_data: dict[str, Any],
    ) -> None:
        """force_refresh=True bypasses cache."""
        graph_manager.fetcher.describe_instances_by_id = AsyncMock(
            return_value=sample_instance_data
        )

        # First call
        await graph_manager.get_node("i-1234567890abcdef0")
        # Second call with force_refresh
        await graph_manager.get_node("i-1234567890abcdef0", force_refresh=True)

        # Should be called twice due to force_refresh
        assert graph_manager.fetcher.describe_instances_by_id.call_count == 2

    @pytest.mark.asyncio
    async def test_cache_stats_updated_on_hit(
        self,
        graph_manager: GraphManager,
        sample_instance_data: dict[str, Any],
    ) -> None:
        """Cache statistics updated on hit."""
        graph_manager.fetcher.describe_instances_by_id = AsyncMock(
            return_value=sample_instance_data
        )

        # First call - miss
        await graph_manager.get_node("i-1234567890abcdef0")
        # Second call - hit
        await graph_manager.get_node("i-1234567890abcdef0")

        stats = graph_manager.cache_stats
        assert stats.hits >= 1
        assert stats.misses >= 1

    @pytest.mark.asyncio
    async def test_unknown_resource_type_returns_none(
        self,
        graph_manager: GraphManager,
    ) -> None:
        """Unknown resource type returns None."""
        node = await graph_manager.get_node("unknown-12345678")

        assert node is None


# =============================================================================
# TTL Expiry Tests
# =============================================================================


class TestTTLExpiry:
    """Tests for TTL-based cache expiry."""

    @pytest.mark.asyncio
    async def test_ttl_expiry_triggers_refresh(
        self,
        mock_fetcher: EC2Fetcher,
        sample_instance_data: dict[str, Any],
    ) -> None:
        """Expired cache entry triggers refresh."""
        # Use very short TTL
        gm = GraphManager(fetcher=mock_fetcher, ttl_seconds=0)
        mock_fetcher.describe_instances_by_id = AsyncMock(
            return_value=sample_instance_data
        )

        # First call
        await gm.get_node("i-1234567890abcdef0")
        # Second call should also fetch (TTL=0 always expired)
        await gm.get_node("i-1234567890abcdef0")

        assert mock_fetcher.describe_instances_by_id.call_count == 2

    def test_set_ttl_updates_config(self, graph_manager: GraphManager) -> None:
        """set_ttl updates the TTL configuration."""
        graph_manager.set_ttl(120)

        assert graph_manager._ttl_seconds == 120

    def test_invalidate_expired_removes_stale_entries(
        self,
        graph_manager: GraphManager,
    ) -> None:
        """invalidate_expired removes entries past TTL."""
        # Add an entry with old timestamp
        old_time = datetime(2020, 1, 1, tzinfo=timezone.utc)
        graph_manager._node_cache["old-entry"] = CacheEntry(
            data="test", cached_at=old_time
        )
        graph_manager._node_cache["new-entry"] = CacheEntry(data="test")

        removed = graph_manager.invalidate_expired()

        assert removed == 1
        assert "old-entry" not in graph_manager._node_cache
        assert "new-entry" in graph_manager._node_cache


# =============================================================================
# Node Fetch Tests
# =============================================================================


class TestNodeFetch:
    """Tests for fetching different node types."""

    @pytest.mark.asyncio
    async def test_fetch_instance(
        self,
        graph_manager: GraphManager,
        sample_instance_data: dict[str, Any],
    ) -> None:
        """Fetches EC2 instance and creates GraphNode."""
        graph_manager.fetcher.describe_instances_by_id = AsyncMock(
            return_value=sample_instance_data
        )

        node = await graph_manager.get_node("i-1234567890abcdef0")

        assert node is not None
        assert node.node_type == NodeType.INSTANCE
        assert node.instance_attrs is not None
        assert node.instance_attrs.private_ip == IPv4Address("10.0.1.100")
        assert node.instance_attrs.public_ip == IPv4Address("54.23.45.67")

    @pytest.mark.asyncio
    async def test_fetch_eni(
        self,
        graph_manager: GraphManager,
        sample_eni_data: dict[str, Any],
    ) -> None:
        """Fetches ENI and creates GraphNode."""
        graph_manager.fetcher.describe_network_interface_by_id = AsyncMock(
            return_value=sample_eni_data
        )

        node = await graph_manager.get_node("eni-12345678")

        assert node is not None
        assert node.node_type == NodeType.ENI
        assert node.eni_attrs is not None
        assert node.eni_attrs.private_ip == IPv4Address("10.0.1.100")

    @pytest.mark.asyncio
    async def test_fetch_subnet(
        self,
        graph_manager: GraphManager,
        sample_subnet_data: dict[str, Any],
        sample_route_table_data: dict[str, Any],
        sample_nacl_data: dict[str, Any],
    ) -> None:
        """Fetches subnet and creates GraphNode with associations."""
        graph_manager.fetcher.describe_subnet_by_id = AsyncMock(
            return_value=sample_subnet_data
        )
        graph_manager.fetcher.describe_route_tables = AsyncMock(
            return_value=[sample_route_table_data]
        )
        graph_manager.fetcher.describe_network_acls = AsyncMock(
            return_value=[sample_nacl_data]
        )

        node = await graph_manager.get_node("subnet-12345678")

        assert node is not None
        assert node.node_type == NodeType.SUBNET
        assert node.subnet_attrs is not None
        assert node.subnet_attrs.cidr_block == "10.0.1.0/24"

    @pytest.mark.asyncio
    async def test_fetch_nonexistent_returns_none(
        self,
        graph_manager: GraphManager,
    ) -> None:
        """Fetching nonexistent resource returns None."""
        graph_manager.fetcher.describe_instances_by_id = AsyncMock(return_value=None)

        node = await graph_manager.get_node("i-nonexistent")

        assert node is None


# =============================================================================
# Security Group Tests
# =============================================================================


class TestSecurityGroup:
    """Tests for security group fetching."""

    @pytest.mark.asyncio
    async def test_get_security_group(
        self,
        graph_manager: GraphManager,
        sample_sg_data: dict[str, Any],
    ) -> None:
        """Fetches security group and parses rules."""
        graph_manager.fetcher.describe_security_group_by_id = AsyncMock(
            return_value=sample_sg_data
        )

        sg = await graph_manager.get_security_group("sg-12345678")

        assert sg is not None
        assert isinstance(sg, SecurityGroup)
        assert sg.sg_id == "sg-12345678"
        assert len(sg.inbound_rules) == 1
        assert sg.inbound_rules[0].from_port == 443

    @pytest.mark.asyncio
    async def test_security_group_cached(
        self,
        graph_manager: GraphManager,
        sample_sg_data: dict[str, Any],
    ) -> None:
        """Security group is cached after fetch."""
        graph_manager.fetcher.describe_security_group_by_id = AsyncMock(
            return_value=sample_sg_data
        )

        await graph_manager.get_security_group("sg-12345678")
        await graph_manager.get_security_group("sg-12345678")

        assert graph_manager.fetcher.describe_security_group_by_id.call_count == 1


# =============================================================================
# Route Table Tests
# =============================================================================


class TestRouteTable:
    """Tests for route table fetching."""

    @pytest.mark.asyncio
    async def test_get_route_table(
        self,
        graph_manager: GraphManager,
        sample_route_table_data: dict[str, Any],
    ) -> None:
        """Fetches route table and parses routes."""
        graph_manager.fetcher.describe_route_table_by_id = AsyncMock(
            return_value=sample_route_table_data
        )

        rt = await graph_manager.get_route_table("rtb-12345678")

        assert rt is not None
        assert isinstance(rt, RouteTable)
        assert rt.route_table_id == "rtb-12345678"
        assert len(rt.routes) == 2


# =============================================================================
# NACL Tests
# =============================================================================


class TestNACL:
    """Tests for NACL fetching."""

    @pytest.mark.asyncio
    async def test_get_nacl(
        self,
        graph_manager: GraphManager,
        sample_nacl_data: dict[str, Any],
    ) -> None:
        """Fetches NACL and parses rules."""
        graph_manager.fetcher.describe_nacl_by_id = AsyncMock(
            return_value=sample_nacl_data
        )

        nacl = await graph_manager.get_nacl("acl-12345678")

        assert nacl is not None
        assert isinstance(nacl, NetworkACL)
        assert nacl.nacl_id == "acl-12345678"
        assert len(nacl.inbound_rules) == 1
        assert len(nacl.outbound_rules) == 1


# =============================================================================
# Edge Tests
# =============================================================================


class TestEdges:
    """Tests for edge management."""

    def test_add_edge(self, graph_manager: GraphManager) -> None:
        """add_edge creates edge in graph."""
        graph_manager.add_edge(
            source_id="subnet-1",
            target_id="igw-1",
            edge_type=EdgeType.ROUTE,
            destination_cidr="0.0.0.0/0",
            prefix_length=0,
        )

        assert graph_manager._graph.has_edge("subnet-1", "igw-1")

    def test_get_outbound_edges(self, graph_manager: GraphManager) -> None:
        """get_outbound_edges returns edges from node."""
        graph_manager.add_edge(
            source_id="subnet-1",
            target_id="igw-1",
            edge_type=EdgeType.ROUTE,
        )
        graph_manager.add_edge(
            source_id="subnet-1",
            target_id="nat-1",
            edge_type=EdgeType.ROUTE,
        )

        edges = graph_manager.get_outbound_edges("subnet-1")

        assert len(edges) == 2
        assert all(isinstance(e, GraphEdge) for e in edges)

    def test_get_outbound_edges_empty(self, graph_manager: GraphManager) -> None:
        """get_outbound_edges returns empty list for unknown node."""
        edges = graph_manager.get_outbound_edges("unknown-node")

        assert edges == []


# =============================================================================
# Cache Invalidation Tests
# =============================================================================


class TestCacheInvalidation:
    """Tests for cache invalidation."""

    @pytest.mark.asyncio
    async def test_invalidate_specific_entry(
        self,
        graph_manager: GraphManager,
        sample_instance_data: dict[str, Any],
    ) -> None:
        """invalidate() removes specific cache entry."""
        graph_manager.fetcher.describe_instances_by_id = AsyncMock(
            return_value=sample_instance_data
        )

        # Cache the node
        await graph_manager.get_node("i-1234567890abcdef0")
        assert "i-1234567890abcdef0" in graph_manager._node_cache

        # Invalidate
        graph_manager.invalidate("i-1234567890abcdef0")

        assert "i-1234567890abcdef0" not in graph_manager._node_cache

    def test_invalidate_all(self, graph_manager: GraphManager) -> None:
        """invalidate() with no args clears all caches."""
        # Add entries to various caches
        graph_manager._node_cache["node-1"] = CacheEntry(data="test")
        graph_manager._security_group_cache["sg-1"] = CacheEntry(data="test")
        graph_manager._route_table_cache["rt-1"] = CacheEntry(data="test")
        graph_manager._nacl_cache["nacl-1"] = CacheEntry(data="test")

        graph_manager.invalidate()

        assert len(graph_manager._node_cache) == 0
        assert len(graph_manager._security_group_cache) == 0
        assert len(graph_manager._route_table_cache) == 0
        assert len(graph_manager._nacl_cache) == 0


# =============================================================================
# Cache Stats Tests
# =============================================================================


class TestCacheStats:
    """Tests for cache statistics."""

    def test_cache_stats_initial(self, graph_manager: GraphManager) -> None:
        """Initial cache stats are zeros."""
        stats = graph_manager.cache_stats

        assert stats.hits == 0
        assert stats.misses == 0
        assert stats.expired == 0
        assert stats.size == 0

    @pytest.mark.asyncio
    async def test_cache_stats_after_operations(
        self,
        graph_manager: GraphManager,
        sample_instance_data: dict[str, Any],
    ) -> None:
        """Cache stats reflect operations."""
        graph_manager.fetcher.describe_instances_by_id = AsyncMock(
            return_value=sample_instance_data
        )

        # Miss
        await graph_manager.get_node("i-1234567890abcdef0")
        # Hit
        await graph_manager.get_node("i-1234567890abcdef0")

        stats = graph_manager.cache_stats
        assert stats.hits >= 1
        assert stats.misses >= 1
        assert stats.size >= 1

    def test_cache_stats_ttl(self, graph_manager: GraphManager) -> None:
        """Cache stats include TTL setting."""
        stats = graph_manager.cache_stats

        assert stats.ttl_seconds == 60


# =============================================================================
# Build Topology Tests
# =============================================================================


class TestBuildTopology:
    """Tests for topology pre-warming."""

    @pytest.mark.asyncio
    async def test_build_topology_success(
        self,
        graph_manager: GraphManager,
        sample_instance_data: dict[str, Any],
        sample_subnet_data: dict[str, Any],
        sample_sg_data: dict[str, Any],
        sample_nacl_data: dict[str, Any],
        sample_route_table_data: dict[str, Any],
    ) -> None:
        """build_topology pre-warms cache."""
        # Mock all the fetcher methods
        graph_manager.fetcher.describe_instances = AsyncMock(
            return_value=[sample_instance_data]
        )
        graph_manager.fetcher.describe_subnets = AsyncMock(
            return_value=[sample_subnet_data]
        )
        graph_manager.fetcher.describe_security_groups = AsyncMock(
            return_value=[sample_sg_data]
        )
        graph_manager.fetcher.describe_network_acls = AsyncMock(
            return_value=[sample_nacl_data]
        )
        graph_manager.fetcher.describe_route_tables = AsyncMock(
            return_value=[sample_route_table_data]
        )
        graph_manager.fetcher.describe_internet_gateways = AsyncMock(return_value=[])
        graph_manager.fetcher.describe_nat_gateways = AsyncMock(return_value=[])
        graph_manager.fetcher.describe_network_interfaces = AsyncMock(return_value=[])

        result = await graph_manager.build_topology(vpc_ids=["vpc-12345678"])

        assert result.success
        assert "vpc-12345678" in result.vpc_ids_processed
        assert result.node_count >= 0
        assert result.duration_seconds >= 0

    @pytest.mark.asyncio
    async def test_build_topology_with_fetch_warnings(
        self,
        graph_manager: GraphManager,
    ) -> None:
        """build_topology captures fetch failures as warnings."""
        # Individual fetch failures are captured as warnings, not overall failure
        graph_manager.fetcher.describe_instances = AsyncMock(
            side_effect=Exception("API error")
        )
        graph_manager.fetcher.describe_subnets = AsyncMock(
            side_effect=Exception("API error")
        )
        graph_manager.fetcher.describe_security_groups = AsyncMock(
            side_effect=Exception("API error")
        )
        graph_manager.fetcher.describe_network_acls = AsyncMock(
            side_effect=Exception("API error")
        )
        graph_manager.fetcher.describe_route_tables = AsyncMock(
            side_effect=Exception("API error")
        )
        graph_manager.fetcher.describe_internet_gateways = AsyncMock(
            side_effect=Exception("API error")
        )
        graph_manager.fetcher.describe_nat_gateways = AsyncMock(
            side_effect=Exception("API error")
        )
        graph_manager.fetcher.describe_network_interfaces = AsyncMock(
            side_effect=Exception("API error")
        )

        result = await graph_manager.build_topology(vpc_ids=["vpc-12345678"])

        # VPC is still processed, but with warnings
        assert result.success
        assert "vpc-12345678" in result.vpc_ids_processed
        assert len(result.warnings) > 0
        assert any("API error" in w for w in result.warnings)


# =============================================================================
# Helper Method Tests
# =============================================================================


class TestHelperMethods:
    """Tests for helper methods."""

    @pytest.mark.asyncio
    async def test_resolve_to_eni_from_instance(
        self,
        graph_manager: GraphManager,
        sample_instance_data: dict[str, Any],
        sample_eni_data: dict[str, Any],
    ) -> None:
        """resolve_to_eni returns primary ENI for instance."""
        graph_manager.fetcher.describe_instances_by_id = AsyncMock(
            return_value=sample_instance_data
        )
        graph_manager.fetcher.describe_network_interface_by_id = AsyncMock(
            return_value=sample_eni_data
        )

        eni = await graph_manager.resolve_to_eni("i-1234567890abcdef0")

        assert eni is not None
        assert eni.node_type == NodeType.ENI

    @pytest.mark.asyncio
    async def test_resolve_to_eni_from_eni(
        self,
        graph_manager: GraphManager,
        sample_eni_data: dict[str, Any],
    ) -> None:
        """resolve_to_eni returns ENI directly for ENI ID."""
        graph_manager.fetcher.describe_network_interface_by_id = AsyncMock(
            return_value=sample_eni_data
        )

        eni = await graph_manager.resolve_to_eni("eni-12345678")

        assert eni is not None
        assert eni.node_type == NodeType.ENI

    @pytest.mark.asyncio
    async def test_find_eni_by_ip(
        self,
        graph_manager: GraphManager,
        sample_eni_data: dict[str, Any],
    ) -> None:
        """find_eni_by_ip returns ENI with matching IP."""
        # First cache an ENI
        graph_manager.fetcher.describe_network_interface_by_id = AsyncMock(
            return_value=sample_eni_data
        )
        await graph_manager.get_node("eni-12345678")

        eni = await graph_manager.find_eni_by_ip("10.0.1.100")

        assert eni is not None
        assert eni.eni_attrs is not None
        assert eni.eni_attrs.private_ip == IPv4Address("10.0.1.100")

    @pytest.mark.asyncio
    async def test_find_eni_by_ip_not_found(
        self,
        graph_manager: GraphManager,
    ) -> None:
        """find_eni_by_ip returns None when IP not found."""
        eni = await graph_manager.find_eni_by_ip("192.168.1.1")

        assert eni is None

    @pytest.mark.asyncio
    async def test_get_subnet_convenience(
        self,
        graph_manager: GraphManager,
        sample_subnet_data: dict[str, Any],
        sample_route_table_data: dict[str, Any],
        sample_nacl_data: dict[str, Any],
    ) -> None:
        """get_subnet is convenience method for subnet nodes."""
        graph_manager.fetcher.describe_subnet_by_id = AsyncMock(
            return_value=sample_subnet_data
        )
        graph_manager.fetcher.describe_route_tables = AsyncMock(
            return_value=[sample_route_table_data]
        )
        graph_manager.fetcher.describe_network_acls = AsyncMock(
            return_value=[sample_nacl_data]
        )

        node = await graph_manager.get_subnet("subnet-12345678")

        assert node is not None
        assert node.subnet_attrs is not None


# =============================================================================
# Gateway Fetch Tests
# =============================================================================


class TestGatewayFetch:
    """Tests for fetching gateway nodes."""

    @pytest.mark.asyncio
    async def test_fetch_igw(
        self,
        graph_manager: GraphManager,
    ) -> None:
        """Fetches Internet Gateway and creates GraphNode."""
        graph_manager.fetcher.describe_internet_gateways = AsyncMock(
            return_value=[
                {
                    "InternetGatewayId": "igw-12345678",
                    "Attachments": [{"VpcId": "vpc-12345678"}],
                }
            ]
        )

        node = await graph_manager.get_node("igw-12345678")

        assert node is not None
        assert node.node_type == NodeType.INTERNET_GATEWAY
        assert node.gateway_attrs is not None
        assert node.gateway_attrs.gateway_type == "igw"

    @pytest.mark.asyncio
    async def test_fetch_nat_gateway(
        self,
        graph_manager: GraphManager,
    ) -> None:
        """Fetches NAT Gateway and creates GraphNode."""
        graph_manager.fetcher.describe_nat_gateways = AsyncMock(
            return_value=[
                {
                    "NatGatewayId": "nat-12345678",
                    "VpcId": "vpc-12345678",
                    "NatGatewayAddresses": [{"PublicIp": "54.23.45.67"}],
                }
            ]
        )

        node = await graph_manager.get_node("nat-12345678")

        assert node is not None
        assert node.node_type == NodeType.NAT_GATEWAY
        assert node.gateway_attrs is not None
        assert node.gateway_attrs.elastic_ip == IPv4Address("54.23.45.67")

    @pytest.mark.asyncio
    async def test_fetch_vpc_peering(
        self,
        graph_manager: GraphManager,
    ) -> None:
        """Fetches VPC Peering and creates GraphNode."""
        graph_manager.fetcher.describe_vpc_peering_connections = AsyncMock(
            return_value=[
                {
                    "VpcPeeringConnectionId": "pcx-12345678",
                    "AccepterVpcInfo": {"VpcId": "vpc-12345678"},
                    "RequesterVpcInfo": {
                        "VpcId": "vpc-87654321",
                        "OwnerId": "987654321098",
                        "Region": "us-west-2",
                    },
                }
            ]
        )

        node = await graph_manager.get_node("pcx-12345678")

        assert node is not None
        assert node.node_type == NodeType.VPC_PEERING
        assert node.gateway_attrs is not None
        assert node.gateway_attrs.peer_vpc_id == "vpc-87654321"

    @pytest.mark.asyncio
    async def test_fetch_transit_gateway(
        self,
        graph_manager: GraphManager,
    ) -> None:
        """Fetches Transit Gateway and creates GraphNode."""
        graph_manager.fetcher.describe_transit_gateways = AsyncMock(
            return_value=[
                {
                    "TransitGatewayId": "tgw-12345678",
                    "OwnerId": "123456789012",
                }
            ]
        )

        node = await graph_manager.get_node("tgw-12345678")

        assert node is not None
        assert node.node_type == NodeType.TRANSIT_GATEWAY
        assert node.gateway_attrs is not None
        assert node.gateway_attrs.gateway_type == "tgw"
