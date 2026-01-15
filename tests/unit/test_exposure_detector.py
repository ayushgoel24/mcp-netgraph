"""Unit tests for exposure_detector.py.

Tests cover all methods in the ExposureDetector class including:
- Exposure detection logic
- Severity classification
- Remediation generation
- Path building
"""

from __future__ import annotations

from ipaddress import IPv4Address
from unittest.mock import AsyncMock, MagicMock

import pytest

from netgraph.core.exposure_detector import (
    CRITICAL_PORTS,
    HIGH_SEVERITY_PORTS,
    ExposureDetector,
)
from netgraph.models import (
    ENIAttributes,
    GraphNode,
    NodeType,
    Route,
    RouteTable,
    SecurityGroup,
    SGRule,
    SubnetAttributes,
)

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_graph_manager() -> MagicMock:
    """Create a mock GraphManager."""
    graph = MagicMock()
    graph.region = "us-east-1"
    graph.account_id = "123456789012"
    return graph


@pytest.fixture
def mock_fetcher() -> MagicMock:
    """Create a mock EC2Fetcher."""
    return MagicMock()


@pytest.fixture
def detector(mock_graph_manager: MagicMock, mock_fetcher: MagicMock) -> ExposureDetector:
    """Create an ExposureDetector instance with mocks."""
    return ExposureDetector(graph=mock_graph_manager, fetcher=mock_fetcher)


@pytest.fixture
def sample_eni_node() -> GraphNode:
    """Create a sample ENI GraphNode."""
    return GraphNode(
        id="eni-12345678",
        node_type=NodeType.ENI,
        vpc_id="vpc-12345678",
        account_id="123456789012",
        region="us-east-1",
        eni_attrs=ENIAttributes(
            subnet_id="subnet-abc12345",
            private_ip=IPv4Address("10.0.1.100"),
            public_ip=IPv4Address("54.1.2.3"),
            security_group_ids=["sg-12345678"],
        ),
    )


@pytest.fixture
def sample_subnet_node() -> GraphNode:
    """Create a sample Subnet GraphNode."""
    return GraphNode(
        id="subnet-abc12345",
        node_type=NodeType.SUBNET,
        vpc_id="vpc-12345678",
        account_id="123456789012",
        region="us-east-1",
        subnet_attrs=SubnetAttributes(
            availability_zone="us-east-1a",
            cidr_block="10.0.1.0/24",
            route_table_id="rtb-12345678",
            nacl_id="acl-12345678",
        ),
    )


@pytest.fixture
def sample_route_table() -> RouteTable:
    """Create a sample RouteTable with IGW route."""
    return RouteTable(
        route_table_id="rtb-12345678",
        vpc_id="vpc-12345678",
        routes=[
            Route(
                destination_cidr="0.0.0.0/0",
                target_id="igw-12345678",
                target_type="igw",
            ),
            Route(
                destination_cidr="10.0.0.0/16",
                target_id="local",
                target_type="local",
            ),
        ],
    )


@pytest.fixture
def sample_security_group() -> SecurityGroup:
    """Create a sample SecurityGroup allowing port 22."""
    return SecurityGroup(
        sg_id="sg-12345678",
        name="test-sg",
        description="Test security group",
        vpc_id="vpc-12345678",
        inbound_rules=[
            SGRule(
                rule_id="sgr-12345678",
                direction="inbound",
                ip_protocol="tcp",
                from_port=22,
                to_port=22,
                cidr_ipv4="0.0.0.0/0",
            ),
        ],
        outbound_rules=[],
    )


# =============================================================================
# Test Initialization
# =============================================================================


class TestExposureDetectorInit:
    """Tests for ExposureDetector initialization."""

    def test_init_stores_graph(
        self, mock_graph_manager: MagicMock, mock_fetcher: MagicMock
    ) -> None:
        """Verify graph is stored."""
        detector = ExposureDetector(graph=mock_graph_manager, fetcher=mock_fetcher)
        assert detector.graph is mock_graph_manager

    def test_init_stores_fetcher(
        self, mock_graph_manager: MagicMock, mock_fetcher: MagicMock
    ) -> None:
        """Verify fetcher is stored."""
        detector = ExposureDetector(graph=mock_graph_manager, fetcher=mock_fetcher)
        assert detector.fetcher is mock_fetcher


# =============================================================================
# Test Severity Classification
# =============================================================================


class TestSeverityClassification:
    """Tests for _determine_severity method."""

    @pytest.mark.parametrize("port", list(CRITICAL_PORTS))
    def test_critical_ports(self, detector: ExposureDetector, port: int) -> None:
        """Critical ports should return critical severity."""
        assert detector._determine_severity(port) == "critical"

    @pytest.mark.parametrize("port", list(HIGH_SEVERITY_PORTS))
    def test_high_severity_ports(self, detector: ExposureDetector, port: int) -> None:
        """High severity ports should return high severity."""
        assert detector._determine_severity(port) == "high"

    @pytest.mark.parametrize("port", [80, 443, 53, 123])
    def test_medium_severity_ports(self, detector: ExposureDetector, port: int) -> None:
        """Well-known ports under 1024 should return medium severity."""
        assert detector._determine_severity(port) == "medium"

    @pytest.mark.parametrize("port", [1024, 3000, 8080, 65535])
    def test_low_severity_ports(self, detector: ExposureDetector, port: int) -> None:
        """High ports should return low severity."""
        assert detector._determine_severity(port) == "low"


# =============================================================================
# Test Remediation Generation
# =============================================================================


class TestRemediationGeneration:
    """Tests for _generate_remediation method."""

    def test_critical_port_remediation(self, detector: ExposureDetector) -> None:
        """Critical ports should have bastion/VPN advice."""
        result = detector._generate_remediation(22, ["sg-12345678"])
        assert "CRITICAL" in result
        assert "port 22" in result
        assert "bastion" in result.lower() or "VPN" in result

    def test_high_severity_remediation(self, detector: ExposureDetector) -> None:
        """High severity ports should mention disabling protocol."""
        result = detector._generate_remediation(23, ["sg-12345678"])
        assert "HIGH" in result
        assert "port 23" in result
        assert "disabling" in result

    def test_default_remediation(self, detector: ExposureDetector) -> None:
        """Other ports should have generic review advice."""
        result = detector._generate_remediation(8080, ["sg-12345678"])
        assert "Review" in result
        assert "port 8080" in result

    def test_multiple_security_groups(self, detector: ExposureDetector) -> None:
        """Multiple SGs should be listed."""
        result = detector._generate_remediation(22, ["sg-1", "sg-2", "sg-3"])
        assert "sg-1" in result
        assert "sg-2" in result
        assert "sg-3" in result

    def test_security_groups_truncation(self, detector: ExposureDetector) -> None:
        """More than 3 SGs should be truncated."""
        result = detector._generate_remediation(22, ["sg-1", "sg-2", "sg-3", "sg-4", "sg-5"])
        assert "sg-1" in result
        assert "sg-2" in result
        assert "sg-3" in result
        assert "2 more" in result


# =============================================================================
# Test ARN Building
# =============================================================================


class TestArnBuilding:
    """Tests for _build_arn method."""

    def test_build_arn_format(self, detector: ExposureDetector) -> None:
        """ARN should have correct format."""
        arn = detector._build_arn("eni-12345678")
        assert arn == "arn:aws:ec2:us-east-1:123456789012:network-interface/eni-12345678"

    def test_build_arn_uses_graph_region(self, mock_fetcher: MagicMock) -> None:
        """ARN should use graph's region."""
        graph = MagicMock()
        graph.region = "eu-west-1"
        graph.account_id = "111111111111"
        detector = ExposureDetector(graph=graph, fetcher=mock_fetcher)

        arn = detector._build_arn("eni-test")
        assert "eu-west-1" in arn
        assert "111111111111" in arn


# =============================================================================
# Test Resource Name Extraction
# =============================================================================


class TestResourceNameExtraction:
    """Tests for _get_resource_name method."""

    def test_returns_none(self, detector: ExposureDetector, sample_eni_node: GraphNode) -> None:
        """Currently always returns None as tags aren't stored."""
        result = detector._get_resource_name(sample_eni_node)
        assert result is None


# =============================================================================
# Test Exposure Path Building
# =============================================================================


class TestExposurePathBuilding:
    """Tests for _build_exposure_path method."""

    def test_build_path_with_igw(
        self,
        detector: ExposureDetector,
        sample_eni_node: GraphNode,
        sample_subnet_node: GraphNode,
        sample_route_table: RouteTable,
    ) -> None:
        """Path should include ENI, subnet, and IGW."""
        path = detector._build_exposure_path(
            sample_eni_node, sample_subnet_node, sample_route_table
        )
        assert path == ["eni-12345678", "subnet-abc12345", "igw-12345678"]

    def test_build_path_no_subnet_attrs(
        self,
        detector: ExposureDetector,
        sample_eni_node: GraphNode,
        sample_route_table: RouteTable,
    ) -> None:
        """Path without subnet attrs should only include ENI."""
        subnet_no_attrs = GraphNode(
            id="subnet-abc12345",
            node_type=NodeType.SUBNET,
            vpc_id="vpc-12345678",
            account_id="123456789012",
            region="us-east-1",
        )
        path = detector._build_exposure_path(sample_eni_node, subnet_no_attrs, sample_route_table)
        # ENI is always included, and IGW from routes
        assert path[0] == "eni-12345678"
        assert "igw-12345678" in path

    def test_build_path_no_igw_route(
        self,
        detector: ExposureDetector,
        sample_eni_node: GraphNode,
        sample_subnet_node: GraphNode,
    ) -> None:
        """Path without IGW route should not include gateway."""
        route_table = RouteTable(
            route_table_id="rtb-12345678",
            vpc_id="vpc-12345678",
            routes=[
                Route(
                    destination_cidr="10.0.0.0/16",
                    target_id="local",
                    target_type="local",
                ),
            ],
        )
        path = detector._build_exposure_path(sample_eni_node, sample_subnet_node, route_table)
        assert "igw" not in str(path).lower()


# =============================================================================
# Test Allowing Rules Extraction
# =============================================================================


class TestAllowingRulesExtraction:
    """Tests for _get_allowing_rules method."""

    def test_extract_matching_rule(
        self, detector: ExposureDetector, sample_security_group: SecurityGroup
    ) -> None:
        """Should extract rule ID when port matches."""
        rules = detector._get_allowing_rules([sample_security_group], 22, "tcp")
        assert "sgr-12345678" in rules

    def test_no_match_different_port(
        self, detector: ExposureDetector, sample_security_group: SecurityGroup
    ) -> None:
        """Should not extract rule when port doesn't match."""
        rules = detector._get_allowing_rules([sample_security_group], 443, "tcp")
        assert rules == []

    def test_no_match_different_protocol(
        self, detector: ExposureDetector, sample_security_group: SecurityGroup
    ) -> None:
        """Should not extract rule when protocol doesn't match."""
        rules = detector._get_allowing_rules([sample_security_group], 22, "udp")
        assert rules == []

    def test_match_all_protocols(self, detector: ExposureDetector) -> None:
        """Should match rule with protocol -1 (all)."""
        sg = SecurityGroup(
            sg_id="sg-12345678",
            name="test-sg",
            description="Test security group",
            vpc_id="vpc-12345678",
            inbound_rules=[
                SGRule(
                    rule_id="sgr-all",
                    direction="inbound",
                    ip_protocol="-1",
                    from_port=0,
                    to_port=65535,
                    cidr_ipv4="0.0.0.0/0",
                ),
            ],
            outbound_rules=[],
        )
        rules = detector._get_allowing_rules([sg], 22, "tcp")
        assert "sgr-all" in rules

    def test_match_ipv6_cidr(self, detector: ExposureDetector) -> None:
        """Should match rule with IPv6 ::/0."""
        sg = SecurityGroup(
            sg_id="sg-12345678",
            name="test-sg",
            description="Test security group",
            vpc_id="vpc-12345678",
            inbound_rules=[
                SGRule(
                    rule_id="sgr-ipv6",
                    direction="inbound",
                    ip_protocol="tcp",
                    from_port=443,
                    to_port=443,
                    cidr_ipv6="::/0",
                ),
            ],
            outbound_rules=[],
        )
        rules = detector._get_allowing_rules([sg], 443, "tcp")
        assert "sgr-ipv6" in rules

    def test_no_match_private_cidr(self, detector: ExposureDetector) -> None:
        """Should not match rule with private CIDR."""
        sg = SecurityGroup(
            sg_id="sg-12345678",
            name="test-sg",
            description="Test security group",
            vpc_id="vpc-12345678",
            inbound_rules=[
                SGRule(
                    rule_id="sgr-private",
                    direction="inbound",
                    ip_protocol="tcp",
                    from_port=22,
                    to_port=22,
                    cidr_ipv4="10.0.0.0/8",
                ),
            ],
            outbound_rules=[],
        )
        rules = detector._get_allowing_rules([sg], 22, "tcp")
        assert rules == []

    def test_port_range_match(self, detector: ExposureDetector) -> None:
        """Should match when port is within range."""
        sg = SecurityGroup(
            sg_id="sg-12345678",
            name="test-sg",
            description="Test security group",
            vpc_id="vpc-12345678",
            inbound_rules=[
                SGRule(
                    rule_id="sgr-range",
                    direction="inbound",
                    ip_protocol="tcp",
                    from_port=8000,
                    to_port=9000,
                    cidr_ipv4="0.0.0.0/0",
                ),
            ],
            outbound_rules=[],
        )
        rules = detector._get_allowing_rules([sg], 8080, "tcp")
        assert "sgr-range" in rules

    def test_multiple_sgs_multiple_rules(self, detector: ExposureDetector) -> None:
        """Should extract rules from multiple security groups."""
        sg1 = SecurityGroup(
            sg_id="sg-1",
            name="sg-1",
            description="Test security group 1",
            vpc_id="vpc-12345678",
            inbound_rules=[
                SGRule(
                    rule_id="sgr-1",
                    direction="inbound",
                    ip_protocol="tcp",
                    from_port=22,
                    to_port=22,
                    cidr_ipv4="0.0.0.0/0",
                ),
            ],
            outbound_rules=[],
        )
        sg2 = SecurityGroup(
            sg_id="sg-2",
            name="sg-2",
            description="Test security group 2",
            vpc_id="vpc-12345678",
            inbound_rules=[
                SGRule(
                    rule_id="sgr-2",
                    direction="inbound",
                    ip_protocol="tcp",
                    from_port=22,
                    to_port=22,
                    cidr_ipv4="0.0.0.0/0",
                ),
            ],
            outbound_rules=[],
        )
        rules = detector._get_allowing_rules([sg1, sg2], 22, "tcp")
        assert "sgr-1" in rules
        assert "sgr-2" in rules


# =============================================================================
# Test Get VPC ENIs
# =============================================================================


class TestGetVPCENIs:
    """Tests for _get_vpc_enis method."""

    @pytest.mark.asyncio
    async def test_fetches_enis_from_vpc(
        self,
        detector: ExposureDetector,
        sample_eni_node: GraphNode,
    ) -> None:
        """Should fetch ENIs from the VPC."""
        detector.fetcher.describe_network_interfaces = AsyncMock(
            return_value=[{"NetworkInterfaceId": "eni-12345678"}]
        )
        detector.graph.get_node = AsyncMock(return_value=sample_eni_node)

        enis = await detector._get_vpc_enis("vpc-12345678", force_refresh=False)

        assert len(enis) == 1
        assert enis[0].id == "eni-12345678"

    @pytest.mark.asyncio
    async def test_filters_by_vpc_id(
        self,
        detector: ExposureDetector,
    ) -> None:
        """Should pass VPC filter to AWS call."""
        detector.fetcher.describe_network_interfaces = AsyncMock(return_value=[])
        detector.graph.get_node = AsyncMock(return_value=None)

        await detector._get_vpc_enis("vpc-specific", force_refresh=False)

        detector.fetcher.describe_network_interfaces.assert_called_once_with(
            filters=[{"Name": "vpc-id", "Values": ["vpc-specific"]}]
        )

    @pytest.mark.asyncio
    async def test_skips_eni_without_id(
        self,
        detector: ExposureDetector,
    ) -> None:
        """Should skip ENIs without NetworkInterfaceId."""
        detector.fetcher.describe_network_interfaces = AsyncMock(
            return_value=[{"Description": "No ID"}]
        )
        detector.graph.get_node = AsyncMock()

        enis = await detector._get_vpc_enis("vpc-12345678", force_refresh=False)

        assert len(enis) == 0
        detector.graph.get_node.assert_not_called()

    @pytest.mark.asyncio
    async def test_skips_eni_without_attrs(
        self,
        detector: ExposureDetector,
    ) -> None:
        """Should skip ENIs without eni_attrs."""
        detector.fetcher.describe_network_interfaces = AsyncMock(
            return_value=[{"NetworkInterfaceId": "eni-12345678"}]
        )
        # Return node without eni_attrs
        node = GraphNode(
            id="eni-12345678",
            node_type=NodeType.ENI,
            vpc_id="vpc-12345678",
            account_id="123456789012",
            region="us-east-1",
        )
        detector.graph.get_node = AsyncMock(return_value=node)

        enis = await detector._get_vpc_enis("vpc-12345678", force_refresh=False)

        assert len(enis) == 0


# =============================================================================
# Test Get Security Groups
# =============================================================================


class TestGetSecurityGroups:
    """Tests for _get_security_groups method."""

    @pytest.mark.asyncio
    async def test_fetches_security_groups(
        self,
        detector: ExposureDetector,
        sample_security_group: SecurityGroup,
    ) -> None:
        """Should fetch security groups by ID."""
        detector.graph.get_security_group = AsyncMock(return_value=sample_security_group)

        sgs = await detector._get_security_groups(["sg-12345678"], force_refresh=False)

        assert len(sgs) == 1
        assert sgs[0].sg_id == "sg-12345678"

    @pytest.mark.asyncio
    async def test_skips_none_results(
        self,
        detector: ExposureDetector,
        sample_security_group: SecurityGroup,
    ) -> None:
        """Should skip None results from get_security_group."""
        detector.graph.get_security_group = AsyncMock(side_effect=[sample_security_group, None])

        sgs = await detector._get_security_groups(["sg-1", "sg-2"], force_refresh=False)

        assert len(sgs) == 1


# =============================================================================
# Test Check ENI Exposure
# =============================================================================


class TestCheckENIExposure:
    """Tests for _check_eni_exposure method."""

    @pytest.mark.asyncio
    async def test_returns_none_without_eni_attrs(
        self,
        detector: ExposureDetector,
    ) -> None:
        """Should return None if ENI has no attrs."""
        eni = GraphNode(
            id="eni-12345678",
            node_type=NodeType.ENI,
            vpc_id="vpc-12345678",
            account_id="123456789012",
            region="us-east-1",
        )
        result = await detector._check_eni_exposure(
            eni=eni, port=22, protocol="tcp", force_refresh=False
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_returns_none_without_subnet(
        self,
        detector: ExposureDetector,
        sample_eni_node: GraphNode,
    ) -> None:
        """Should return None if subnet not found."""
        detector.graph.get_subnet = AsyncMock(return_value=None)

        result = await detector._check_eni_exposure(
            eni=sample_eni_node, port=22, protocol="tcp", force_refresh=False
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_returns_none_without_route_table(
        self,
        detector: ExposureDetector,
        sample_eni_node: GraphNode,
        sample_subnet_node: GraphNode,
    ) -> None:
        """Should return None if route table not found."""
        detector.graph.get_subnet = AsyncMock(return_value=sample_subnet_node)
        detector.graph.get_route_table = AsyncMock(return_value=None)

        result = await detector._check_eni_exposure(
            eni=sample_eni_node, port=22, protocol="tcp", force_refresh=False
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_returns_none_without_igw_route(
        self,
        detector: ExposureDetector,
        sample_eni_node: GraphNode,
        sample_subnet_node: GraphNode,
    ) -> None:
        """Should return None if no IGW route exists."""
        detector.graph.get_subnet = AsyncMock(return_value=sample_subnet_node)

        # Route table without IGW route
        route_table = RouteTable(
            route_table_id="rtb-12345678",
            vpc_id="vpc-12345678",
            routes=[
                Route(
                    destination_cidr="10.0.0.0/16",
                    target_id="local",
                    target_type="local",
                ),
            ],
        )
        detector.graph.get_route_table = AsyncMock(return_value=route_table)

        result = await detector._check_eni_exposure(
            eni=sample_eni_node, port=22, protocol="tcp", force_refresh=False
        )
        assert result is None


# =============================================================================
# Test Find Exposed (Integration)
# =============================================================================


class TestFindExposed:
    """Tests for find_exposed method."""

    @pytest.mark.asyncio
    async def test_returns_empty_result_no_enis(
        self,
        detector: ExposureDetector,
    ) -> None:
        """Should return empty result when no ENIs in VPC."""
        detector.fetcher.describe_network_interfaces = AsyncMock(return_value=[])

        result = await detector.find_exposed(vpc_id="vpc-12345678", port=22, protocol="tcp")

        assert result.total_exposed == 0
        assert result.total_resources_scanned == 0
        assert "No resources exposed" in result.summary

    @pytest.mark.asyncio
    async def test_returns_result_structure(
        self,
        detector: ExposureDetector,
    ) -> None:
        """Should return proper result structure."""
        detector.fetcher.describe_network_interfaces = AsyncMock(return_value=[])

        result = await detector.find_exposed(vpc_id="vpc-12345678", port=443, protocol="tcp")

        assert result.vpc_id == "vpc-12345678"
        assert result.port == 443
        assert result.protocol == "tcp"
        assert result.scan_duration_seconds >= 0
        assert isinstance(result.exposed_resources, list)

    @pytest.mark.asyncio
    async def test_counts_severity(
        self,
        detector: ExposureDetector,
        sample_eni_node: GraphNode,
        sample_subnet_node: GraphNode,
        sample_route_table: RouteTable,
        sample_security_group: SecurityGroup,
    ) -> None:
        """Should count severity levels correctly."""
        # Set up mocks for a fully exposed ENI
        detector.fetcher.describe_network_interfaces = AsyncMock(
            return_value=[{"NetworkInterfaceId": "eni-12345678"}]
        )
        detector.graph.get_node = AsyncMock(return_value=sample_eni_node)
        detector.graph.get_subnet = AsyncMock(return_value=sample_subnet_node)
        detector.graph.get_route_table = AsyncMock(return_value=sample_route_table)
        detector.graph.get_security_group = AsyncMock(return_value=sample_security_group)

        # Mock SecurityGroupEvaluator
        from unittest.mock import patch

        with patch(
            "netgraph.core.exposure_detector.SecurityGroupEvaluator.evaluate_ingress"
        ) as mock_eval:
            mock_eval.return_value = MagicMock(allowed=True)

            result = await detector.find_exposed(vpc_id="vpc-12345678", port=22, protocol="tcp")

            assert result.total_exposed == 1
            assert result.critical_severity_count == 1
            assert "critical" in result.summary


# =============================================================================
# Test Constants
# =============================================================================


class TestConstants:
    """Tests for module constants."""

    def test_critical_ports_defined(self) -> None:
        """Critical ports should include SSH, RDP, databases."""
        assert 22 in CRITICAL_PORTS  # SSH
        assert 3389 in CRITICAL_PORTS  # RDP
        assert 5432 in CRITICAL_PORTS  # PostgreSQL
        assert 3306 in CRITICAL_PORTS  # MySQL
        assert 6379 in CRITICAL_PORTS  # Redis

    def test_high_severity_ports_defined(self) -> None:
        """High severity ports should include legacy protocols."""
        assert 23 in HIGH_SEVERITY_PORTS  # Telnet
        assert 21 in HIGH_SEVERITY_PORTS  # FTP
        assert 25 in HIGH_SEVERITY_PORTS  # SMTP
        assert 445 in HIGH_SEVERITY_PORTS  # SMB
