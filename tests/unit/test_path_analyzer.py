"""Tests for PathAnalyzer - deterministic network path analysis."""

from __future__ import annotations

from ipaddress import IPv4Address
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from netgraph.aws.client import AWSClient, RetryConfig
from netgraph.aws.fetcher import EC2Fetcher
from netgraph.core.graph_manager import GraphManager
from netgraph.core.path_analyzer import PathAnalyzer, TraversalContext
from netgraph.models import (
    ENIAttributes,
    GatewayAttributes,
    GraphNode,
    NACLRule,
    NetworkACL,
    NodeType,
    PathStatus,
    Route,
    RouteTable,
    SecurityGroup,
    SGRule,
    SubnetAttributes,
)
from netgraph.models.errors import (
    CrossAccountSGResolutionError,
    PermissionDeniedError,
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
def path_analyzer(graph_manager: GraphManager) -> PathAnalyzer:
    """Create a PathAnalyzer for testing."""
    return PathAnalyzer(graph=graph_manager)


@pytest.fixture
def source_eni() -> GraphNode:
    """Sample source ENI node."""
    return GraphNode(
        id="eni-source123",
        node_type=NodeType.ENI,
        vpc_id="vpc-12345678",
        account_id="123456789012",
        region="us-east-1",
        eni_attrs=ENIAttributes(
            private_ip=IPv4Address("10.0.1.100"),
            security_group_ids=["sg-source123"],
            subnet_id="subnet-source123",
        ),
    )


@pytest.fixture
def dest_eni() -> GraphNode:
    """Sample destination ENI node."""
    return GraphNode(
        id="eni-dest456",
        node_type=NodeType.ENI,
        vpc_id="vpc-12345678",
        account_id="123456789012",
        region="us-east-1",
        eni_attrs=ENIAttributes(
            private_ip=IPv4Address("10.0.2.50"),
            security_group_ids=["sg-dest456"],
            subnet_id="subnet-dest456",
        ),
    )


@pytest.fixture
def source_subnet() -> GraphNode:
    """Sample source subnet node."""
    return GraphNode(
        id="subnet-source123",
        node_type=NodeType.SUBNET,
        vpc_id="vpc-12345678",
        account_id="123456789012",
        region="us-east-1",
        subnet_attrs=SubnetAttributes(
            cidr_block="10.0.1.0/24",
            availability_zone="us-east-1a",
            route_table_id="rtb-source123",
            nacl_id="acl-source123",
        ),
    )


@pytest.fixture
def dest_subnet() -> GraphNode:
    """Sample destination subnet node."""
    return GraphNode(
        id="subnet-dest456",
        node_type=NodeType.SUBNET,
        vpc_id="vpc-12345678",
        account_id="123456789012",
        region="us-east-1",
        subnet_attrs=SubnetAttributes(
            cidr_block="10.0.2.0/24",
            availability_zone="us-east-1b",
            route_table_id="rtb-dest456",
            nacl_id="acl-dest456",
        ),
    )


@pytest.fixture
def allow_all_sg() -> SecurityGroup:
    """Security group that allows all traffic."""
    return SecurityGroup(
        sg_id="sg-allowall",
        vpc_id="vpc-12345678",
        name="allow-all",
        description="Allows all traffic",
        inbound_rules=[
            SGRule(
                rule_id="sg-allowall-in-1",
                direction="inbound",
                ip_protocol="-1",
                from_port=0,
                to_port=65535,
                cidr_ipv4="0.0.0.0/0",
            )
        ],
        outbound_rules=[
            SGRule(
                rule_id="sg-allowall-out-1",
                direction="outbound",
                ip_protocol="-1",
                from_port=0,
                to_port=65535,
                cidr_ipv4="0.0.0.0/0",
            )
        ],
    )


@pytest.fixture
def deny_all_sg() -> SecurityGroup:
    """Security group with no rules (implicit deny)."""
    return SecurityGroup(
        sg_id="sg-denyall",
        vpc_id="vpc-12345678",
        name="deny-all",
        description="Denies all traffic (no rules)",
        inbound_rules=[],
        outbound_rules=[],
    )


@pytest.fixture
def allow_all_nacl() -> NetworkACL:
    """NACL that allows all traffic."""
    return NetworkACL(
        nacl_id="acl-allowall",
        vpc_id="vpc-12345678",
        is_default=True,
        inbound_rules=[
            NACLRule(
                rule_number=100,
                rule_action="allow",
                direction="inbound",
                protocol="-1",
                cidr_block="0.0.0.0/0",
            )
        ],
        outbound_rules=[
            NACLRule(
                rule_number=100,
                rule_action="allow",
                direction="outbound",
                protocol="-1",
                cidr_block="0.0.0.0/0",
            )
        ],
    )


@pytest.fixture
def local_route_table() -> RouteTable:
    """Route table with local route only."""
    return RouteTable(
        route_table_id="rtb-local",
        vpc_id="vpc-12345678",
        routes=[
            Route(
                destination_cidr="10.0.0.0/16",
                target_id="local",
                target_type="local",
            )
        ],
    )


@pytest.fixture
def igw_route_table() -> RouteTable:
    """Route table with IGW route for internet access."""
    return RouteTable(
        route_table_id="rtb-igw",
        vpc_id="vpc-12345678",
        routes=[
            Route(
                destination_cidr="10.0.0.0/16",
                target_id="local",
                target_type="local",
            ),
            Route(
                destination_cidr="0.0.0.0/0",
                target_id="igw-12345678",
                target_type="igw",
            ),
        ],
    )


# =============================================================================
# Test TraversalContext
# =============================================================================


class TestTraversalContext:
    """Tests for TraversalContext dataclass."""

    def test_default_initialization(self) -> None:
        """Test TraversalContext with defaults."""
        ctx = TraversalContext(
            source_id="i-12345",
            source_ip="10.0.1.100",
            dest_ip="10.0.2.50",
            port=443,
            protocol="tcp",
        )
        assert ctx.source_id == "i-12345"
        assert ctx.source_ip == "10.0.1.100"
        assert ctx.dest_ip == "10.0.2.50"
        assert ctx.port == 443
        assert ctx.protocol == "tcp"
        assert ctx.force_refresh is False
        assert ctx.visited_nodes == set()
        assert ctx.hops == []
        assert ctx.hop_counter == 0

    def test_visited_nodes_tracking(self) -> None:
        """Test visited nodes set behavior."""
        ctx = TraversalContext(
            source_id="i-12345",
            source_ip="10.0.1.100",
            dest_ip="10.0.2.50",
            port=443,
            protocol="tcp",
        )
        ctx.visited_nodes.add("eni-123")
        ctx.visited_nodes.add("subnet-456")
        assert "eni-123" in ctx.visited_nodes
        assert "subnet-456" in ctx.visited_nodes
        assert len(ctx.visited_nodes) == 2


# =============================================================================
# Test PathAnalyzer Initialization
# =============================================================================


class TestPathAnalyzerInit:
    """Tests for PathAnalyzer initialization."""

    def test_init_with_defaults(self, graph_manager: GraphManager) -> None:
        """Test PathAnalyzer with default max_hops."""
        analyzer = PathAnalyzer(graph=graph_manager)
        assert analyzer.graph == graph_manager
        assert analyzer.max_hops == 50

    def test_init_custom_max_hops(self, graph_manager: GraphManager) -> None:
        """Test PathAnalyzer with custom max_hops."""
        analyzer = PathAnalyzer(graph=graph_manager, max_hops=10)
        assert analyzer.max_hops == 10


# =============================================================================
# Test REACHABLE Paths
# =============================================================================


class TestReachablePaths:
    """Tests for paths that should be REACHABLE."""

    @pytest.mark.asyncio
    async def test_local_subnet_reachable(
        self,
        path_analyzer: PathAnalyzer,
        source_eni: GraphNode,
        allow_all_sg: SecurityGroup,
        source_subnet: GraphNode,
    ) -> None:
        """Test traffic within same subnet is reachable."""
        # Mock the graph manager methods
        path_analyzer.graph.resolve_to_eni = AsyncMock(return_value=source_eni)
        path_analyzer.graph.get_subnet = AsyncMock(return_value=source_subnet)
        path_analyzer.graph.get_security_group = AsyncMock(return_value=allow_all_sg)
        path_analyzer.graph.find_eni_by_ip = AsyncMock(return_value=source_eni)

        result = await path_analyzer.analyze(
            source_id="eni-source123",
            dest_ip="10.0.1.50",  # Same subnet
            port=443,
            protocol="tcp",
        )

        assert result.status == PathStatus.REACHABLE
        assert len(result.hops) >= 1

    @pytest.mark.asyncio
    async def test_cross_subnet_reachable(
        self,
        path_analyzer: PathAnalyzer,
        source_eni: GraphNode,
        dest_eni: GraphNode,
        source_subnet: GraphNode,
        dest_subnet: GraphNode,
        allow_all_sg: SecurityGroup,
        allow_all_nacl: NetworkACL,
        local_route_table: RouteTable,
    ) -> None:
        """Test traffic to different subnet via local route is reachable."""
        # Mock the graph manager methods
        path_analyzer.graph.resolve_to_eni = AsyncMock(return_value=source_eni)

        def get_subnet_mock(subnet_id: str, **_kwargs: Any) -> GraphNode | None:
            if subnet_id == "subnet-source123":
                return source_subnet
            if subnet_id == "subnet-dest456":
                return dest_subnet
            return None

        path_analyzer.graph.get_subnet = AsyncMock(side_effect=get_subnet_mock)
        path_analyzer.graph.get_security_group = AsyncMock(return_value=allow_all_sg)
        path_analyzer.graph.get_nacl = AsyncMock(return_value=allow_all_nacl)
        path_analyzer.graph.get_route_table = AsyncMock(return_value=local_route_table)
        path_analyzer.graph.find_eni_by_ip = AsyncMock(return_value=dest_eni)

        result = await path_analyzer.analyze(
            source_id="eni-source123",
            dest_ip="10.0.2.50",  # Different subnet
            port=443,
            protocol="tcp",
        )

        assert result.status == PathStatus.REACHABLE

    @pytest.mark.asyncio
    async def test_internet_egress_reachable(
        self,
        path_analyzer: PathAnalyzer,
        source_eni: GraphNode,
        source_subnet: GraphNode,
        allow_all_sg: SecurityGroup,
        allow_all_nacl: NetworkACL,
        igw_route_table: RouteTable,
    ) -> None:
        """Test traffic to internet via IGW is reachable."""
        path_analyzer.graph.resolve_to_eni = AsyncMock(return_value=source_eni)
        path_analyzer.graph.get_subnet = AsyncMock(return_value=source_subnet)
        path_analyzer.graph.get_security_group = AsyncMock(return_value=allow_all_sg)
        path_analyzer.graph.get_nacl = AsyncMock(return_value=allow_all_nacl)
        path_analyzer.graph.get_route_table = AsyncMock(return_value=igw_route_table)
        path_analyzer.graph.get_node = AsyncMock(
            return_value=GraphNode(
                id="igw-12345678",
                node_type=NodeType.INTERNET_GATEWAY,
                vpc_id="vpc-12345678",
                account_id="123456789012",
                region="us-east-1",
                gateway_attrs=GatewayAttributes(gateway_type="igw"),
            )
        )
        path_analyzer.graph.find_eni_by_ip = AsyncMock(return_value=None)

        result = await path_analyzer.analyze(
            source_id="eni-source123",
            dest_ip="8.8.8.8",  # Public IP
            port=443,
            protocol="tcp",
        )

        assert result.status == PathStatus.REACHABLE
        # Should have IGW in the path
        igw_hops = [h for h in result.hops if h.node_type == NodeType.INTERNET_GATEWAY]
        assert len(igw_hops) >= 1


# =============================================================================
# Test BLOCKED Paths
# =============================================================================


class TestBlockedPaths:
    """Tests for paths that should be BLOCKED."""

    @pytest.mark.asyncio
    async def test_blocked_by_sg_egress(
        self,
        path_analyzer: PathAnalyzer,
        source_eni: GraphNode,
        source_subnet: GraphNode,
        deny_all_sg: SecurityGroup,
        allow_all_nacl: NetworkACL,
        local_route_table: RouteTable,
    ) -> None:
        """Test traffic blocked by source SG egress rules."""
        path_analyzer.graph.resolve_to_eni = AsyncMock(return_value=source_eni)
        path_analyzer.graph.get_subnet = AsyncMock(return_value=source_subnet)
        path_analyzer.graph.get_security_group = AsyncMock(return_value=deny_all_sg)
        path_analyzer.graph.get_nacl = AsyncMock(return_value=allow_all_nacl)
        path_analyzer.graph.get_route_table = AsyncMock(return_value=local_route_table)

        result = await path_analyzer.analyze(
            source_id="eni-source123",
            dest_ip="10.0.2.50",
            port=443,
            protocol="tcp",
        )

        assert result.status == PathStatus.BLOCKED
        assert result.blocked_at is not None
        assert result.blocked_at.sg_eval is not None
        assert result.blocked_at.sg_eval.allowed is False

    @pytest.mark.asyncio
    async def test_blocked_by_nacl_outbound(
        self,
        path_analyzer: PathAnalyzer,
        source_eni: GraphNode,
        source_subnet: GraphNode,
        allow_all_sg: SecurityGroup,
        local_route_table: RouteTable,
    ) -> None:
        """Test traffic blocked by source NACL outbound rules."""
        deny_nacl = NetworkACL(
            nacl_id="acl-deny",
            vpc_id="vpc-12345678",
            is_default=False,
            inbound_rules=[
                NACLRule(
                    rule_number=100,
                    rule_action="allow",
                    direction="inbound",
                    protocol="-1",
                    cidr_block="0.0.0.0/0",
                )
            ],
            outbound_rules=[
                NACLRule(
                    rule_number=100,
                    rule_action="deny",
                    direction="outbound",
                    protocol="-1",
                    cidr_block="0.0.0.0/0",
                )
            ],
        )

        path_analyzer.graph.resolve_to_eni = AsyncMock(return_value=source_eni)
        path_analyzer.graph.get_subnet = AsyncMock(return_value=source_subnet)
        path_analyzer.graph.get_security_group = AsyncMock(return_value=allow_all_sg)
        path_analyzer.graph.get_nacl = AsyncMock(return_value=deny_nacl)
        path_analyzer.graph.get_route_table = AsyncMock(return_value=local_route_table)

        result = await path_analyzer.analyze(
            source_id="eni-source123",
            dest_ip="10.0.2.50",
            port=443,
            protocol="tcp",
        )

        assert result.status == PathStatus.BLOCKED
        assert result.blocked_at is not None
        assert result.blocked_at.nacl_eval is not None
        assert result.blocked_at.nacl_eval.allowed is False

    @pytest.mark.asyncio
    async def test_blocked_by_no_route(
        self,
        path_analyzer: PathAnalyzer,
        source_eni: GraphNode,
        source_subnet: GraphNode,
        allow_all_sg: SecurityGroup,
        allow_all_nacl: NetworkACL,
    ) -> None:
        """Test traffic blocked when no route to destination."""
        # Route table with only local route, no internet route
        no_route_table = RouteTable(
            route_table_id="rtb-noroute",
            vpc_id="vpc-12345678",
            routes=[
                Route(
                    destination_cidr="10.0.1.0/24",
                    target_id="local",
                    target_type="local",
                )
            ],
        )

        path_analyzer.graph.resolve_to_eni = AsyncMock(return_value=source_eni)
        path_analyzer.graph.get_subnet = AsyncMock(return_value=source_subnet)
        path_analyzer.graph.get_security_group = AsyncMock(return_value=allow_all_sg)
        path_analyzer.graph.get_nacl = AsyncMock(return_value=allow_all_nacl)
        path_analyzer.graph.get_route_table = AsyncMock(return_value=no_route_table)

        result = await path_analyzer.analyze(
            source_id="eni-source123",
            dest_ip="8.8.8.8",  # No route to this
            port=443,
            protocol="tcp",
        )

        assert result.status == PathStatus.BLOCKED
        assert result.blocked_at is not None
        assert result.blocked_at.route_eval is not None
        assert result.blocked_at.route_eval.allowed is False

    @pytest.mark.asyncio
    async def test_blocked_by_sg_ingress(
        self,
        path_analyzer: PathAnalyzer,
        source_eni: GraphNode,
        dest_eni: GraphNode,
        source_subnet: GraphNode,
        dest_subnet: GraphNode,
        allow_all_sg: SecurityGroup,
        deny_all_sg: SecurityGroup,
        allow_all_nacl: NetworkACL,
        local_route_table: RouteTable,
    ) -> None:
        """Test traffic blocked by destination SG ingress rules."""

        def get_subnet_mock(subnet_id: str, **_kwargs: Any) -> GraphNode | None:
            if subnet_id == "subnet-source123":
                return source_subnet
            if subnet_id == "subnet-dest456":
                return dest_subnet
            return None

        def get_sg_mock(sg_id: str, **_kwargs: Any) -> SecurityGroup | None:
            if sg_id == "sg-source123":
                return allow_all_sg
            if sg_id == "sg-dest456":
                return deny_all_sg  # Destination blocks ingress
            return None

        path_analyzer.graph.resolve_to_eni = AsyncMock(return_value=source_eni)
        path_analyzer.graph.get_subnet = AsyncMock(side_effect=get_subnet_mock)
        path_analyzer.graph.get_security_group = AsyncMock(side_effect=get_sg_mock)
        path_analyzer.graph.get_nacl = AsyncMock(return_value=allow_all_nacl)
        path_analyzer.graph.get_route_table = AsyncMock(return_value=local_route_table)
        path_analyzer.graph.find_eni_by_ip = AsyncMock(return_value=dest_eni)

        result = await path_analyzer.analyze(
            source_id="eni-source123",
            dest_ip="10.0.2.50",
            port=443,
            protocol="tcp",
        )

        assert result.status == PathStatus.BLOCKED
        assert result.blocked_at is not None


# =============================================================================
# Test Loop Detection
# =============================================================================


class TestLoopDetection:
    """Tests for routing loop detection."""

    @pytest.mark.asyncio
    async def test_loop_detected_and_blocked(
        self,
        path_analyzer: PathAnalyzer,
        source_eni: GraphNode,
        source_subnet: GraphNode,
        allow_all_sg: SecurityGroup,
        allow_all_nacl: NetworkACL,
    ) -> None:
        """Test that routing loops are detected and return BLOCKED."""
        # Create a route table that routes back to the same node (simulated loop)
        loop_route_table = RouteTable(
            route_table_id="rtb-loop",
            vpc_id="vpc-12345678",
            routes=[
                Route(
                    destination_cidr="10.0.0.0/16",
                    target_id="local",
                    target_type="local",
                ),
                Route(
                    destination_cidr="0.0.0.0/0",
                    target_id="eni-source123",  # Routes back to source ENI
                    target_type="eni",
                ),
            ],
        )

        path_analyzer.graph.resolve_to_eni = AsyncMock(return_value=source_eni)
        path_analyzer.graph.get_subnet = AsyncMock(return_value=source_subnet)
        path_analyzer.graph.get_security_group = AsyncMock(return_value=allow_all_sg)
        path_analyzer.graph.get_nacl = AsyncMock(return_value=allow_all_nacl)
        path_analyzer.graph.get_route_table = AsyncMock(return_value=loop_route_table)
        path_analyzer.graph.get_node = AsyncMock(return_value=source_eni)

        result = await path_analyzer.analyze(
            source_id="eni-source123",
            dest_ip="8.8.8.8",
            port=443,
            protocol="tcp",
        )

        assert result.status == PathStatus.BLOCKED
        # Check that the blocking reason mentions loop
        if result.blocked_at and result.blocked_at.route_eval:
            assert "loop" in result.blocked_at.route_eval.reason.lower()


# =============================================================================
# Test UNKNOWN Paths
# =============================================================================


class TestUnknownPaths:
    """Tests for paths that should return UNKNOWN."""

    @pytest.mark.asyncio
    async def test_unknown_on_permission_denied(
        self,
        path_analyzer: PathAnalyzer,
    ) -> None:
        """Test that PermissionDeniedError returns UNKNOWN status."""
        path_analyzer.graph.resolve_to_eni = AsyncMock(
            side_effect=PermissionDeniedError(
                message="Access denied to eni-123",
                resource_id="eni-123",
                operation="DescribeNetworkInterfaces",
            )
        )

        result = await path_analyzer.analyze(
            source_id="eni-source123",
            dest_ip="10.0.2.50",
            port=443,
            protocol="tcp",
        )

        assert result.status == PathStatus.UNKNOWN
        assert result.unknown_reason is not None
        assert "denied" in result.unknown_reason.lower()

    @pytest.mark.asyncio
    async def test_unknown_on_cross_account_sg(
        self,
        path_analyzer: PathAnalyzer,
        source_eni: GraphNode,
    ) -> None:
        """Test that CrossAccountSGResolutionError returns UNKNOWN."""
        path_analyzer.graph.resolve_to_eni = AsyncMock(return_value=source_eni)
        path_analyzer.graph.get_subnet = AsyncMock(
            side_effect=CrossAccountSGResolutionError(
                message="Cannot resolve cross-account SG sg-peer123",
                sg_id="sg-peer123",
                referencing_sg_id="sg-source123",
            )
        )

        result = await path_analyzer.analyze(
            source_id="eni-source123",
            dest_ip="10.0.2.50",
            port=443,
            protocol="tcp",
        )

        assert result.status == PathStatus.UNKNOWN
        assert result.unknown_reason is not None

    @pytest.mark.asyncio
    async def test_unknown_on_tgw_traversal(
        self,
        path_analyzer: PathAnalyzer,
        source_eni: GraphNode,
        source_subnet: GraphNode,
        allow_all_sg: SecurityGroup,
        allow_all_nacl: NetworkACL,
    ) -> None:
        """Test that Transit Gateway traversal returns UNKNOWN."""
        tgw_route_table = RouteTable(
            route_table_id="rtb-tgw",
            vpc_id="vpc-12345678",
            routes=[
                Route(
                    destination_cidr="10.0.0.0/16",
                    target_id="local",
                    target_type="local",
                ),
                Route(
                    destination_cidr="0.0.0.0/0",
                    target_id="tgw-12345678",
                    target_type="tgw",
                ),
            ],
        )

        path_analyzer.graph.resolve_to_eni = AsyncMock(return_value=source_eni)
        path_analyzer.graph.get_subnet = AsyncMock(return_value=source_subnet)
        path_analyzer.graph.get_security_group = AsyncMock(return_value=allow_all_sg)
        path_analyzer.graph.get_nacl = AsyncMock(return_value=allow_all_nacl)
        path_analyzer.graph.get_route_table = AsyncMock(return_value=tgw_route_table)

        result = await path_analyzer.analyze(
            source_id="eni-source123",
            dest_ip="8.8.8.8",
            port=443,
            protocol="tcp",
        )

        assert result.status == PathStatus.UNKNOWN
        assert result.unknown_reason is not None
        assert "transit gateway" in result.unknown_reason.lower()

    @pytest.mark.asyncio
    async def test_unknown_source_not_found(
        self,
        path_analyzer: PathAnalyzer,
    ) -> None:
        """Test UNKNOWN when source cannot be resolved."""
        path_analyzer.graph.resolve_to_eni = AsyncMock(return_value=None)

        result = await path_analyzer.analyze(
            source_id="eni-nonexistent",
            dest_ip="10.0.2.50",
            port=443,
            protocol="tcp",
        )

        assert result.status == PathStatus.UNKNOWN
        assert result.unknown_reason is not None


# =============================================================================
# Test Gateway Traversal
# =============================================================================


class TestGatewayTraversal:
    """Tests for traversal through different gateway types."""

    @pytest.mark.asyncio
    async def test_nat_gateway_traversal(
        self,
        path_analyzer: PathAnalyzer,
        source_eni: GraphNode,
        source_subnet: GraphNode,
        allow_all_sg: SecurityGroup,
        allow_all_nacl: NetworkACL,
    ) -> None:
        """Test traffic routed through NAT Gateway."""
        nat_route_table = RouteTable(
            route_table_id="rtb-nat",
            vpc_id="vpc-12345678",
            routes=[
                Route(
                    destination_cidr="10.0.0.0/16",
                    target_id="local",
                    target_type="local",
                ),
                Route(
                    destination_cidr="0.0.0.0/0",
                    target_id="nat-12345678",
                    target_type="nat",
                ),
            ],
        )

        nat_node = GraphNode(
            id="nat-12345678",
            node_type=NodeType.NAT_GATEWAY,
            vpc_id="vpc-12345678",
            account_id="123456789012",
            region="us-east-1",
            gateway_attrs=GatewayAttributes(
                gateway_type="nat",
                elastic_ip=IPv4Address("54.1.2.3"),
            ),
        )

        path_analyzer.graph.resolve_to_eni = AsyncMock(return_value=source_eni)
        path_analyzer.graph.get_subnet = AsyncMock(return_value=source_subnet)
        path_analyzer.graph.get_security_group = AsyncMock(return_value=allow_all_sg)
        path_analyzer.graph.get_nacl = AsyncMock(return_value=allow_all_nacl)
        path_analyzer.graph.get_route_table = AsyncMock(return_value=nat_route_table)
        path_analyzer.graph.get_node = AsyncMock(return_value=nat_node)
        path_analyzer.graph.find_eni_by_ip = AsyncMock(return_value=None)

        result = await path_analyzer.analyze(
            source_id="eni-source123",
            dest_ip="8.8.8.8",
            port=443,
            protocol="tcp",
        )

        assert result.status == PathStatus.REACHABLE
        # Verify NAT is in the path
        nat_hops = [h for h in result.hops if h.node_type == NodeType.NAT_GATEWAY]
        assert len(nat_hops) >= 1

    @pytest.mark.asyncio
    async def test_vpc_peering_traversal(
        self,
        path_analyzer: PathAnalyzer,
        source_eni: GraphNode,
        allow_all_sg: SecurityGroup,
        allow_all_nacl: NetworkACL,
    ) -> None:
        """Test traffic routed through VPC Peering."""
        # Update source subnet to use the peering route table
        source_subnet_with_peering = GraphNode(
            id="subnet-source123",
            node_type=NodeType.SUBNET,
            vpc_id="vpc-12345678",
            account_id="123456789012",
            region="us-east-1",
            subnet_attrs=SubnetAttributes(
                cidr_block="10.0.1.0/24",
                availability_zone="us-east-1a",
                route_table_id="rtb-peering",
                nacl_id="acl-source123",
            ),
        )

        peering_route_table = RouteTable(
            route_table_id="rtb-peering",
            vpc_id="vpc-12345678",
            routes=[
                Route(
                    destination_cidr="10.0.0.0/16",
                    target_id="local",
                    target_type="local",
                ),
                Route(
                    destination_cidr="172.16.0.0/16",
                    target_id="pcx-12345678",
                    target_type="peering",
                ),
            ],
        )

        peering_node = GraphNode(
            id="pcx-12345678",
            node_type=NodeType.VPC_PEERING,
            vpc_id="vpc-12345678",
            account_id="123456789012",
            region="us-east-1",
            gateway_attrs=GatewayAttributes(
                gateway_type="peering",
                peer_vpc_id="vpc-peer87654321",
                peer_account_id="123456789012",  # Same account
                peer_region="us-east-1",
            ),
        )

        path_analyzer.graph.resolve_to_eni = AsyncMock(return_value=source_eni)
        path_analyzer.graph.get_subnet = AsyncMock(return_value=source_subnet_with_peering)
        path_analyzer.graph.get_security_group = AsyncMock(return_value=allow_all_sg)
        path_analyzer.graph.get_nacl = AsyncMock(return_value=allow_all_nacl)
        path_analyzer.graph.get_route_table = AsyncMock(return_value=peering_route_table)
        path_analyzer.graph.get_node = AsyncMock(return_value=peering_node)

        result = await path_analyzer.analyze(
            source_id="eni-source123",
            dest_ip="172.16.1.50",
            port=443,
            protocol="tcp",
        )

        assert result.status == PathStatus.REACHABLE
        # Verify peering is in the path
        peering_hops = [h for h in result.hops if h.node_type == NodeType.VPC_PEERING]
        assert len(peering_hops) >= 1


# =============================================================================
# Test NACL Return Path Verification
# =============================================================================


class TestNACLReturnPath:
    """Tests for NACL return path verification (ephemeral ports)."""

    @pytest.mark.asyncio
    async def test_blocked_by_nacl_return_path(
        self,
        path_analyzer: PathAnalyzer,
        source_eni: GraphNode,
        dest_eni: GraphNode,
        source_subnet: GraphNode,
        dest_subnet: GraphNode,
        allow_all_sg: SecurityGroup,
        local_route_table: RouteTable,
    ) -> None:
        """Test traffic blocked by NACL not allowing return ephemeral ports."""
        # NACL that allows inbound but blocks outbound (return) traffic
        no_return_nacl = NetworkACL(
            nacl_id="acl-noreturn",
            vpc_id="vpc-12345678",
            is_default=False,
            inbound_rules=[
                NACLRule(
                    rule_number=100,
                    rule_action="allow",
                    direction="inbound",
                    protocol="-1",
                    cidr_block="0.0.0.0/0",
                )
            ],
            outbound_rules=[
                # Only allow ports 1-1023, blocking ephemeral ports
                NACLRule(
                    rule_number=100,
                    rule_action="allow",
                    direction="outbound",
                    protocol="6",  # TCP
                    cidr_block="0.0.0.0/0",
                    from_port=1,
                    to_port=1023,
                )
            ],
        )

        allow_all_nacl = NetworkACL(
            nacl_id="acl-allowall",
            vpc_id="vpc-12345678",
            is_default=True,
            inbound_rules=[
                NACLRule(
                    rule_number=100,
                    rule_action="allow",
                    direction="inbound",
                    protocol="-1",
                    cidr_block="0.0.0.0/0",
                )
            ],
            outbound_rules=[
                NACLRule(
                    rule_number=100,
                    rule_action="allow",
                    direction="outbound",
                    protocol="-1",
                    cidr_block="0.0.0.0/0",
                )
            ],
        )

        def get_subnet_mock(subnet_id: str, **_kwargs: Any) -> GraphNode | None:
            if subnet_id == "subnet-source123":
                return source_subnet
            if subnet_id == "subnet-dest456":
                return dest_subnet
            return None

        def get_nacl_mock(nacl_id: str, **_kwargs: Any) -> NetworkACL | None:
            if nacl_id == "acl-source123":
                return allow_all_nacl
            if nacl_id == "acl-dest456":
                return no_return_nacl  # Destination blocks return
            return None

        path_analyzer.graph.resolve_to_eni = AsyncMock(return_value=source_eni)
        path_analyzer.graph.get_subnet = AsyncMock(side_effect=get_subnet_mock)
        path_analyzer.graph.get_security_group = AsyncMock(return_value=allow_all_sg)
        path_analyzer.graph.get_nacl = AsyncMock(side_effect=get_nacl_mock)
        path_analyzer.graph.get_route_table = AsyncMock(return_value=local_route_table)
        path_analyzer.graph.find_eni_by_ip = AsyncMock(return_value=dest_eni)

        result = await path_analyzer.analyze(
            source_id="eni-source123",
            dest_ip="10.0.2.50",
            port=443,
            protocol="tcp",
        )

        assert result.status == PathStatus.BLOCKED
        # Check that blocking reason mentions ephemeral ports
        if result.blocked_at and result.blocked_at.nacl_eval:
            assert "ephemeral" in result.blocked_at.nacl_eval.reason.lower()


# =============================================================================
# Test Reverse Route Verification
# =============================================================================


class TestReverseRouteVerification:
    """Tests for reverse route verification (asymmetric routing)."""

    @pytest.mark.asyncio
    async def test_blocked_by_asymmetric_routing(
        self,
        path_analyzer: PathAnalyzer,
        source_eni: GraphNode,
        dest_eni: GraphNode,
        source_subnet: GraphNode,
        dest_subnet: GraphNode,
        allow_all_sg: SecurityGroup,
        allow_all_nacl: NetworkACL,
        local_route_table: RouteTable,
    ) -> None:
        """Test traffic blocked when destination has no return route."""
        # Destination route table has no route back to source
        dest_route_table = RouteTable(
            route_table_id="rtb-dest-noreturn",
            vpc_id="vpc-12345678",
            routes=[
                Route(
                    destination_cidr="10.0.2.0/24",  # Only local subnet
                    target_id="local",
                    target_type="local",
                ),
                # No route to 10.0.1.0/24 (source subnet)
            ],
        )

        def get_subnet_mock(subnet_id: str, **_kwargs: Any) -> GraphNode | None:
            if subnet_id == "subnet-source123":
                return source_subnet
            if subnet_id == "subnet-dest456":
                return dest_subnet
            return None

        def get_rt_mock(rt_id: str, **_kwargs: Any) -> RouteTable | None:
            if rt_id == "rtb-source123":
                return local_route_table
            if rt_id == "rtb-dest456":
                return dest_route_table  # No return route
            return None

        path_analyzer.graph.resolve_to_eni = AsyncMock(return_value=source_eni)
        path_analyzer.graph.get_subnet = AsyncMock(side_effect=get_subnet_mock)
        path_analyzer.graph.get_security_group = AsyncMock(return_value=allow_all_sg)
        path_analyzer.graph.get_nacl = AsyncMock(return_value=allow_all_nacl)
        path_analyzer.graph.get_route_table = AsyncMock(side_effect=get_rt_mock)
        path_analyzer.graph.find_eni_by_ip = AsyncMock(return_value=dest_eni)

        result = await path_analyzer.analyze(
            source_id="eni-source123",
            dest_ip="10.0.2.50",
            port=443,
            protocol="tcp",
        )

        assert result.status == PathStatus.BLOCKED
        # Check that blocking reason mentions asymmetric/return route
        if result.blocked_at and result.blocked_at.route_eval:
            reason = result.blocked_at.route_eval.reason.lower()
            assert "no route" in reason or "asymmetric" in reason


# =============================================================================
# Test Human Summary Generation
# =============================================================================


class TestHumanSummary:
    """Tests for human-readable summary generation."""

    @pytest.mark.asyncio
    async def test_reachable_summary(
        self,
        path_analyzer: PathAnalyzer,
        source_eni: GraphNode,
        allow_all_sg: SecurityGroup,
        source_subnet: GraphNode,
    ) -> None:
        """Test summary for REACHABLE path."""
        path_analyzer.graph.resolve_to_eni = AsyncMock(return_value=source_eni)
        path_analyzer.graph.get_subnet = AsyncMock(return_value=source_subnet)
        path_analyzer.graph.get_security_group = AsyncMock(return_value=allow_all_sg)
        path_analyzer.graph.find_eni_by_ip = AsyncMock(return_value=source_eni)

        result = await path_analyzer.analyze(
            source_id="eni-source123",
            dest_ip="10.0.1.50",
            port=443,
            protocol="tcp",
        )

        assert result.status == PathStatus.REACHABLE
        summary = result.generate_human_summary()
        assert "Traffic Allowed" in summary

    @pytest.mark.asyncio
    async def test_blocked_summary(
        self,
        path_analyzer: PathAnalyzer,
        source_eni: GraphNode,
        deny_all_sg: SecurityGroup,
        source_subnet: GraphNode,
    ) -> None:
        """Test summary for BLOCKED path."""
        path_analyzer.graph.resolve_to_eni = AsyncMock(return_value=source_eni)
        path_analyzer.graph.get_subnet = AsyncMock(return_value=source_subnet)
        path_analyzer.graph.get_security_group = AsyncMock(return_value=deny_all_sg)

        result = await path_analyzer.analyze(
            source_id="eni-source123",
            dest_ip="10.0.2.50",
            port=443,
            protocol="tcp",
        )

        assert result.status == PathStatus.BLOCKED
        summary = result.generate_human_summary()
        assert "Traffic Blocked" in summary

    @pytest.mark.asyncio
    async def test_unknown_summary(
        self,
        path_analyzer: PathAnalyzer,
    ) -> None:
        """Test summary for UNKNOWN path."""
        path_analyzer.graph.resolve_to_eni = AsyncMock(return_value=None)

        result = await path_analyzer.analyze(
            source_id="eni-nonexistent",
            dest_ip="10.0.2.50",
            port=443,
            protocol="tcp",
        )

        assert result.status == PathStatus.UNKNOWN
        summary = result.generate_human_summary()
        assert "Cannot determine" in summary


# =============================================================================
# Test force_refresh Parameter
# =============================================================================


class TestForceRefresh:
    """Tests for force_refresh parameter propagation."""

    @pytest.mark.asyncio
    async def test_force_refresh_propagates(
        self,
        path_analyzer: PathAnalyzer,
        source_eni: GraphNode,
        source_subnet: GraphNode,
        allow_all_sg: SecurityGroup,
    ) -> None:
        """Test that force_refresh=True propagates to all calls."""
        path_analyzer.graph.resolve_to_eni = AsyncMock(return_value=source_eni)
        path_analyzer.graph.get_subnet = AsyncMock(return_value=source_subnet)
        path_analyzer.graph.get_security_group = AsyncMock(return_value=allow_all_sg)
        path_analyzer.graph.find_eni_by_ip = AsyncMock(return_value=source_eni)

        await path_analyzer.analyze(
            source_id="eni-source123",
            dest_ip="10.0.1.50",
            port=443,
            protocol="tcp",
            force_refresh=True,
        )

        # Verify force_refresh was passed
        path_analyzer.graph.resolve_to_eni.assert_called()
        call_kwargs = path_analyzer.graph.resolve_to_eni.call_args.kwargs
        assert call_kwargs.get("force_refresh") is True
