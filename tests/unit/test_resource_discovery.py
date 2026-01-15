"""Unit tests for ResourceDiscovery module.

Tests cover:
- Resource type normalization
- Tag matching
- Name pattern matching
- Finding instances, ENIs, subnets, IGWs, NATs, peering, TGWs
- Result truncation
- Filter application
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from netgraph.core.resource_discovery import (
    RESOURCE_TYPE_MAP,
    ResourceDiscovery,
)
from netgraph.models import NodeType

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_graph() -> MagicMock:
    """Create a mock GraphManager."""
    graph = MagicMock()
    graph.region = "us-east-1"
    graph.account_id = "123456789012"
    return graph


@pytest.fixture
def mock_fetcher() -> AsyncMock:
    """Create a mock EC2Fetcher."""
    return AsyncMock()


@pytest.fixture
def discovery(mock_graph: MagicMock, mock_fetcher: AsyncMock) -> ResourceDiscovery:
    """Create ResourceDiscovery instance with mocks."""
    return ResourceDiscovery(graph=mock_graph, fetcher=mock_fetcher)


@pytest.fixture
def sample_instances() -> list[dict[str, Any]]:
    """Sample EC2 instance data."""
    return [
        {
            "InstanceId": "i-web12345",
            "PrivateIpAddress": "10.0.1.10",
            "PublicIpAddress": "54.1.2.3",
            "SubnetId": "subnet-pub1",
            "Placement": {"AvailabilityZone": "us-east-1a"},
            "Tags": [
                {"Key": "Name", "Value": "web-server-1"},
                {"Key": "Environment", "Value": "production"},
                {"Key": "Tier", "Value": "web"},
            ],
        },
        {
            "InstanceId": "i-app12345",
            "PrivateIpAddress": "10.0.2.10",
            "SubnetId": "subnet-priv1",
            "Placement": {"AvailabilityZone": "us-east-1b"},
            "Tags": [
                {"Key": "Name", "Value": "app-server-1"},
                {"Key": "Environment", "Value": "production"},
                {"Key": "Tier", "Value": "app"},
            ],
        },
        {
            "InstanceId": "i-dev12345",
            "PrivateIpAddress": "10.0.3.10",
            "SubnetId": "subnet-dev1",
            "Placement": {"AvailabilityZone": "us-east-1a"},
            "Tags": [
                {"Key": "Name", "Value": "dev-server-1"},
                {"Key": "Environment", "Value": "development"},
            ],
        },
    ]


@pytest.fixture
def sample_enis() -> list[dict[str, Any]]:
    """Sample ENI data."""
    return [
        {
            "NetworkInterfaceId": "eni-web12345",
            "PrivateIpAddress": "10.0.1.20",
            "SubnetId": "subnet-pub1",
            "AvailabilityZone": "us-east-1a",
            "Association": {"PublicIp": "54.1.2.4"},
            "TagSet": [
                {"Key": "Name", "Value": "web-eni"},
                {"Key": "Environment", "Value": "production"},
            ],
        },
        {
            "NetworkInterfaceId": "eni-app12345",
            "PrivateIpAddress": "10.0.2.20",
            "SubnetId": "subnet-priv1",
            "AvailabilityZone": "us-east-1b",
            "TagSet": [
                {"Key": "Name", "Value": "app-eni"},
                {"Key": "Environment", "Value": "production"},
            ],
        },
    ]


@pytest.fixture
def sample_subnets() -> list[dict[str, Any]]:
    """Sample subnet data."""
    return [
        {
            "SubnetId": "subnet-pub1",
            "AvailabilityZone": "us-east-1a",
            "Tags": [
                {"Key": "Name", "Value": "public-subnet-1"},
                {"Key": "Tier", "Value": "public"},
            ],
        },
        {
            "SubnetId": "subnet-priv1",
            "AvailabilityZone": "us-east-1b",
            "Tags": [
                {"Key": "Name", "Value": "private-subnet-1"},
                {"Key": "Tier", "Value": "private"},
            ],
        },
    ]


@pytest.fixture
def sample_igws() -> list[dict[str, Any]]:
    """Sample Internet Gateway data."""
    return [
        {
            "InternetGatewayId": "igw-main12345",
            "Tags": [
                {"Key": "Name", "Value": "main-igw"},
                {"Key": "Environment", "Value": "production"},
            ],
        },
    ]


@pytest.fixture
def sample_nats() -> list[dict[str, Any]]:
    """Sample NAT Gateway data."""
    return [
        {
            "NatGatewayId": "nat-main12345",
            "SubnetId": "subnet-pub1",
            "NatGatewayAddresses": [{"PublicIp": "54.1.2.5"}],
            "Tags": [
                {"Key": "Name", "Value": "main-nat"},
                {"Key": "Environment", "Value": "production"},
            ],
        },
    ]


@pytest.fixture
def sample_peerings() -> list[dict[str, Any]]:
    """Sample VPC peering data."""
    return [
        {
            "VpcPeeringConnectionId": "pcx-main12345",
            "RequesterVpcInfo": {"VpcId": "vpc-main"},
            "AccepterVpcInfo": {"VpcId": "vpc-peer"},
            "Tags": [
                {"Key": "Name", "Value": "main-to-peer"},
                {"Key": "Environment", "Value": "production"},
            ],
        },
        {
            "VpcPeeringConnectionId": "pcx-other12345",
            "RequesterVpcInfo": {"VpcId": "vpc-other"},
            "AccepterVpcInfo": {"VpcId": "vpc-different"},
            "Tags": [
                {"Key": "Name", "Value": "other-peering"},
            ],
        },
    ]


@pytest.fixture
def sample_tgw_attachments() -> list[dict[str, Any]]:
    """Sample TGW attachment data."""
    return [
        {
            "TransitGatewayAttachmentId": "tgw-attach-1",
            "TransitGatewayId": "tgw-main12345",
        },
    ]


@pytest.fixture
def sample_tgws() -> list[dict[str, Any]]:
    """Sample Transit Gateway data."""
    return [
        {
            "TransitGatewayId": "tgw-main12345",
            "TransitGatewayArn": "arn:aws:ec2:us-east-1:123456789012:transit-gateway/tgw-main12345",
            "Tags": [
                {"Key": "Name", "Value": "main-tgw"},
                {"Key": "Environment", "Value": "production"},
            ],
        },
    ]


# =============================================================================
# Resource Type Normalization Tests
# =============================================================================


class TestResourceTypeNormalization:
    """Tests for _normalize_resource_types method."""

    def test_normalize_returns_all_types_when_none(self, discovery: ResourceDiscovery) -> None:
        """Should return all searchable types when no types specified."""
        result = discovery._normalize_resource_types(None)

        assert NodeType.INSTANCE in result
        assert NodeType.ENI in result
        assert NodeType.SUBNET in result
        assert NodeType.INTERNET_GATEWAY in result
        assert NodeType.NAT_GATEWAY in result
        assert NodeType.VPC_PEERING in result
        assert NodeType.TRANSIT_GATEWAY in result

    def test_normalize_returns_all_types_when_empty(self, discovery: ResourceDiscovery) -> None:
        """Should return all types when empty list provided."""
        result = discovery._normalize_resource_types([])

        assert len(result) == 7  # All searchable types

    def test_normalize_single_type(self, discovery: ResourceDiscovery) -> None:
        """Should normalize single type correctly."""
        result = discovery._normalize_resource_types(["instance"])
        assert result == {NodeType.INSTANCE}

    def test_normalize_multiple_types(self, discovery: ResourceDiscovery) -> None:
        """Should normalize multiple types correctly."""
        result = discovery._normalize_resource_types(["instance", "eni", "subnet"])

        assert NodeType.INSTANCE in result
        assert NodeType.ENI in result
        assert NodeType.SUBNET in result
        assert len(result) == 3

    def test_normalize_case_insensitive(self, discovery: ResourceDiscovery) -> None:
        """Should handle case-insensitive type names."""
        result = discovery._normalize_resource_types(["INSTANCE", "Eni", "SubNet"])

        assert NodeType.INSTANCE in result
        assert NodeType.ENI in result
        assert NodeType.SUBNET in result

    def test_normalize_ignores_unknown_types(self, discovery: ResourceDiscovery) -> None:
        """Should ignore unknown type names."""
        result = discovery._normalize_resource_types(["instance", "unknown", "invalid"])
        assert result == {NodeType.INSTANCE}

    def test_resource_type_map_complete(self) -> None:
        """Verify RESOURCE_TYPE_MAP has all expected mappings."""
        assert "instance" in RESOURCE_TYPE_MAP
        assert "eni" in RESOURCE_TYPE_MAP
        assert "subnet" in RESOURCE_TYPE_MAP
        assert "igw" in RESOURCE_TYPE_MAP
        assert "nat" in RESOURCE_TYPE_MAP
        assert "peering" in RESOURCE_TYPE_MAP
        assert "tgw" in RESOURCE_TYPE_MAP


# =============================================================================
# Tag Matching Tests
# =============================================================================


class TestTagMatching:
    """Tests for _matches_tags method."""

    def test_matches_tags_returns_true_when_no_filter(self, discovery: ResourceDiscovery) -> None:
        """Should return True when no filter tags provided."""
        resource_tags = {"Name": "test", "Environment": "prod"}
        assert discovery._matches_tags(resource_tags, None) is True

    def test_matches_tags_returns_true_when_empty_filter(
        self, discovery: ResourceDiscovery
    ) -> None:
        """Should return True when empty filter dict provided."""
        resource_tags = {"Name": "test", "Environment": "prod"}
        assert discovery._matches_tags(resource_tags, {}) is True

    def test_matches_tags_single_tag_match(self, discovery: ResourceDiscovery) -> None:
        """Should match when single tag matches."""
        resource_tags = {"Name": "test", "Environment": "production"}
        filter_tags = {"Environment": "production"}
        assert discovery._matches_tags(resource_tags, filter_tags) is True

    def test_matches_tags_multiple_tags_match(self, discovery: ResourceDiscovery) -> None:
        """Should match when all filter tags match."""
        resource_tags = {"Name": "test", "Environment": "production", "Tier": "web"}
        filter_tags = {"Environment": "production", "Tier": "web"}
        assert discovery._matches_tags(resource_tags, filter_tags) is True

    def test_matches_tags_partial_match_fails(self, discovery: ResourceDiscovery) -> None:
        """Should fail when only some filter tags match."""
        resource_tags = {"Name": "test", "Environment": "production"}
        filter_tags = {"Environment": "production", "Tier": "web"}
        assert discovery._matches_tags(resource_tags, filter_tags) is False

    def test_matches_tags_no_match(self, discovery: ResourceDiscovery) -> None:
        """Should fail when no tags match."""
        resource_tags = {"Name": "test", "Environment": "development"}
        filter_tags = {"Environment": "production"}
        assert discovery._matches_tags(resource_tags, filter_tags) is False

    def test_matches_tags_empty_resource_tags(self, discovery: ResourceDiscovery) -> None:
        """Should fail when resource has no tags but filter requires some."""
        resource_tags: dict[str, str] = {}
        filter_tags = {"Environment": "production"}
        assert discovery._matches_tags(resource_tags, filter_tags) is False


# =============================================================================
# Name Pattern Matching Tests
# =============================================================================


class TestNamePatternMatching:
    """Tests for _matches_name_pattern method."""

    def test_matches_pattern_returns_true_when_no_pattern(
        self, discovery: ResourceDiscovery
    ) -> None:
        """Should return True when no pattern provided."""
        assert discovery._matches_name_pattern("web-server-1", None) is True

    def test_matches_pattern_exact_match(self, discovery: ResourceDiscovery) -> None:
        """Should match exact name."""
        assert discovery._matches_name_pattern("web-server-1", "web-server-1") is True

    def test_matches_pattern_wildcard_prefix(self, discovery: ResourceDiscovery) -> None:
        """Should match with wildcard prefix."""
        assert discovery._matches_name_pattern("web-server-1", "web-*") is True
        assert discovery._matches_name_pattern("app-server-1", "web-*") is False

    def test_matches_pattern_wildcard_suffix(self, discovery: ResourceDiscovery) -> None:
        """Should match with wildcard suffix."""
        assert discovery._matches_name_pattern("web-server-1", "*-server-1") is True
        assert discovery._matches_name_pattern("web-server-2", "*-server-1") is False

    def test_matches_pattern_wildcard_middle(self, discovery: ResourceDiscovery) -> None:
        """Should match with wildcard in middle."""
        assert discovery._matches_name_pattern("web-server-1", "web-*-1") is True
        assert discovery._matches_name_pattern("app-server-1", "web-*-1") is False

    def test_matches_pattern_case_insensitive(self, discovery: ResourceDiscovery) -> None:
        """Should match case-insensitively."""
        assert discovery._matches_name_pattern("Web-Server-1", "web-*") is True
        assert discovery._matches_name_pattern("WEB-SERVER-1", "web-server-1") is True

    def test_matches_pattern_none_name(self, discovery: ResourceDiscovery) -> None:
        """Should return False when name is None and pattern provided."""
        assert discovery._matches_name_pattern(None, "web-*") is False

    def test_matches_pattern_empty_name(self, discovery: ResourceDiscovery) -> None:
        """Should return False when name is empty and pattern provided."""
        assert discovery._matches_name_pattern("", "web-*") is False

    def test_matches_pattern_question_mark_wildcard(self, discovery: ResourceDiscovery) -> None:
        """Should support ? wildcard for single character."""
        assert discovery._matches_name_pattern("web-server-1", "web-server-?") is True
        assert discovery._matches_name_pattern("web-server-10", "web-server-?") is False


# =============================================================================
# Tag Extraction Tests
# =============================================================================


class TestTagExtraction:
    """Tests for _extract_tags method."""

    def test_extract_tags_normal(self, discovery: ResourceDiscovery) -> None:
        """Should extract tags from AWS format."""
        tags_list = [
            {"Key": "Name", "Value": "test"},
            {"Key": "Environment", "Value": "production"},
        ]
        result = discovery._extract_tags(tags_list)

        assert result == {"Name": "test", "Environment": "production"}

    def test_extract_tags_empty_list(self, discovery: ResourceDiscovery) -> None:
        """Should return empty dict for empty list."""
        assert discovery._extract_tags([]) == {}

    def test_extract_tags_none(self, discovery: ResourceDiscovery) -> None:
        """Should return empty dict for None."""
        assert discovery._extract_tags(None) == {}

    def test_extract_tags_missing_key(self, discovery: ResourceDiscovery) -> None:
        """Should skip entries without Key."""
        tags_list = [
            {"Key": "Name", "Value": "test"},
            {"Value": "orphan"},  # Missing Key
        ]
        result = discovery._extract_tags(tags_list)
        assert result == {"Name": "test"}

    def test_extract_tags_empty_key(self, discovery: ResourceDiscovery) -> None:
        """Should skip entries with empty Key."""
        tags_list = [
            {"Key": "Name", "Value": "test"},
            {"Key": "", "Value": "empty"},
        ]
        result = discovery._extract_tags(tags_list)
        assert result == {"Name": "test"}


# =============================================================================
# Find Instances Tests
# =============================================================================


class TestFindInstances:
    """Tests for _find_instances method."""

    @pytest.mark.asyncio
    async def test_find_instances_returns_all(
        self,
        discovery: ResourceDiscovery,
        mock_fetcher: AsyncMock,
        sample_instances: list[dict[str, Any]],
    ) -> None:
        """Should return all instances when no filters."""
        mock_fetcher.describe_instances.return_value = sample_instances

        result = await discovery._find_instances("vpc-main", None, None)

        assert len(result) == 3
        assert result[0].id == "i-web12345"
        assert result[0].resource_type == NodeType.INSTANCE

    @pytest.mark.asyncio
    async def test_find_instances_filter_by_tags(
        self,
        discovery: ResourceDiscovery,
        mock_fetcher: AsyncMock,
        sample_instances: list[dict[str, Any]],
    ) -> None:
        """Should filter instances by tags."""
        mock_fetcher.describe_instances.return_value = sample_instances

        result = await discovery._find_instances("vpc-main", {"Environment": "production"}, None)

        assert len(result) == 2
        assert all(r.tags.get("Environment") == "production" for r in result)

    @pytest.mark.asyncio
    async def test_find_instances_filter_by_name(
        self,
        discovery: ResourceDiscovery,
        mock_fetcher: AsyncMock,
        sample_instances: list[dict[str, Any]],
    ) -> None:
        """Should filter instances by name pattern."""
        mock_fetcher.describe_instances.return_value = sample_instances

        result = await discovery._find_instances("vpc-main", None, "web-*")

        assert len(result) == 1
        assert result[0].name == "web-server-1"

    @pytest.mark.asyncio
    async def test_find_instances_combined_filters(
        self,
        discovery: ResourceDiscovery,
        mock_fetcher: AsyncMock,
        sample_instances: list[dict[str, Any]],
    ) -> None:
        """Should apply both tag and name filters."""
        mock_fetcher.describe_instances.return_value = sample_instances

        result = await discovery._find_instances(
            "vpc-main", {"Environment": "production"}, "*-server-*"
        )

        assert len(result) == 2

    @pytest.mark.asyncio
    async def test_find_instances_with_ips(
        self,
        discovery: ResourceDiscovery,
        mock_fetcher: AsyncMock,
        sample_instances: list[dict[str, Any]],
    ) -> None:
        """Should extract private and public IPs."""
        mock_fetcher.describe_instances.return_value = sample_instances

        result = await discovery._find_instances("vpc-main", None, "web-*")

        assert result[0].private_ip == "10.0.1.10"
        assert result[0].public_ip == "54.1.2.3"

    @pytest.mark.asyncio
    async def test_find_instances_skips_empty_id(
        self,
        discovery: ResourceDiscovery,
        mock_fetcher: AsyncMock,
    ) -> None:
        """Should skip instances without InstanceId."""
        mock_fetcher.describe_instances.return_value = [
            {"InstanceId": "i-valid", "Tags": []},
            {"Tags": []},  # Missing InstanceId
            {"InstanceId": "", "Tags": []},  # Empty InstanceId
        ]

        result = await discovery._find_instances("vpc-main", None, None)

        assert len(result) == 1
        assert result[0].id == "i-valid"


# =============================================================================
# Find ENIs Tests
# =============================================================================


class TestFindENIs:
    """Tests for _find_enis method."""

    @pytest.mark.asyncio
    async def test_find_enis_returns_all(
        self,
        discovery: ResourceDiscovery,
        mock_fetcher: AsyncMock,
        sample_enis: list[dict[str, Any]],
    ) -> None:
        """Should return all ENIs when no filters."""
        mock_fetcher.describe_network_interfaces.return_value = sample_enis

        result = await discovery._find_enis("vpc-main", None, None)

        assert len(result) == 2
        assert result[0].id == "eni-web12345"
        assert result[0].resource_type == NodeType.ENI

    @pytest.mark.asyncio
    async def test_find_enis_extracts_public_ip(
        self,
        discovery: ResourceDiscovery,
        mock_fetcher: AsyncMock,
        sample_enis: list[dict[str, Any]],
    ) -> None:
        """Should extract public IP from association."""
        mock_fetcher.describe_network_interfaces.return_value = sample_enis

        result = await discovery._find_enis("vpc-main", None, "web-*")

        assert result[0].public_ip == "54.1.2.4"

    @pytest.mark.asyncio
    async def test_find_enis_uses_tagset(
        self,
        discovery: ResourceDiscovery,
        mock_fetcher: AsyncMock,
        sample_enis: list[dict[str, Any]],
    ) -> None:
        """Should extract tags from TagSet (not Tags)."""
        mock_fetcher.describe_network_interfaces.return_value = sample_enis

        result = await discovery._find_enis("vpc-main", {"Environment": "production"}, None)

        assert len(result) == 2


# =============================================================================
# Find Subnets Tests
# =============================================================================


class TestFindSubnets:
    """Tests for _find_subnets method."""

    @pytest.mark.asyncio
    async def test_find_subnets_returns_all(
        self,
        discovery: ResourceDiscovery,
        mock_fetcher: AsyncMock,
        sample_subnets: list[dict[str, Any]],
    ) -> None:
        """Should return all subnets when no filters."""
        mock_fetcher.describe_subnets.return_value = sample_subnets

        result = await discovery._find_subnets("vpc-main", None, None)

        assert len(result) == 2
        assert result[0].resource_type == NodeType.SUBNET

    @pytest.mark.asyncio
    async def test_find_subnets_filter_by_name(
        self,
        discovery: ResourceDiscovery,
        mock_fetcher: AsyncMock,
        sample_subnets: list[dict[str, Any]],
    ) -> None:
        """Should filter subnets by name pattern."""
        mock_fetcher.describe_subnets.return_value = sample_subnets

        result = await discovery._find_subnets("vpc-main", None, "public-*")

        assert len(result) == 1
        assert result[0].name == "public-subnet-1"


# =============================================================================
# Find IGWs Tests
# =============================================================================


class TestFindIGWs:
    """Tests for _find_igws method."""

    @pytest.mark.asyncio
    async def test_find_igws_returns_all(
        self,
        discovery: ResourceDiscovery,
        mock_fetcher: AsyncMock,
        sample_igws: list[dict[str, Any]],
    ) -> None:
        """Should return IGWs attached to VPC."""
        mock_fetcher.describe_internet_gateways.return_value = sample_igws

        result = await discovery._find_igws("vpc-main", None, None)

        assert len(result) == 1
        assert result[0].id == "igw-main12345"
        assert result[0].resource_type == NodeType.INTERNET_GATEWAY


# =============================================================================
# Find NAT Gateways Tests
# =============================================================================


class TestFindNATGateways:
    """Tests for _find_nat_gateways method."""

    @pytest.mark.asyncio
    async def test_find_nat_gateways_returns_all(
        self,
        discovery: ResourceDiscovery,
        mock_fetcher: AsyncMock,
        sample_nats: list[dict[str, Any]],
    ) -> None:
        """Should return NAT Gateways in VPC."""
        mock_fetcher.describe_nat_gateways.return_value = sample_nats

        result = await discovery._find_nat_gateways("vpc-main", None, None)

        assert len(result) == 1
        assert result[0].id == "nat-main12345"
        assert result[0].resource_type == NodeType.NAT_GATEWAY

    @pytest.mark.asyncio
    async def test_find_nat_gateways_extracts_public_ip(
        self,
        discovery: ResourceDiscovery,
        mock_fetcher: AsyncMock,
        sample_nats: list[dict[str, Any]],
    ) -> None:
        """Should extract public IP from addresses."""
        mock_fetcher.describe_nat_gateways.return_value = sample_nats

        result = await discovery._find_nat_gateways("vpc-main", None, None)

        assert result[0].public_ip == "54.1.2.5"


# =============================================================================
# Find Peering Connections Tests
# =============================================================================


class TestFindPeeringConnections:
    """Tests for _find_peering_connections method."""

    @pytest.mark.asyncio
    async def test_find_peering_filters_by_vpc(
        self,
        discovery: ResourceDiscovery,
        mock_fetcher: AsyncMock,
        sample_peerings: list[dict[str, Any]],
    ) -> None:
        """Should only return peerings involving the VPC."""
        mock_fetcher.describe_vpc_peering_connections.return_value = sample_peerings

        result = await discovery._find_peering_connections("vpc-main", None, None)

        assert len(result) == 1
        assert result[0].id == "pcx-main12345"

    @pytest.mark.asyncio
    async def test_find_peering_includes_accepter_vpc(
        self,
        discovery: ResourceDiscovery,
        mock_fetcher: AsyncMock,
        sample_peerings: list[dict[str, Any]],
    ) -> None:
        """Should include peerings where VPC is accepter."""
        mock_fetcher.describe_vpc_peering_connections.return_value = sample_peerings

        result = await discovery._find_peering_connections("vpc-peer", None, None)

        assert len(result) == 1
        assert result[0].id == "pcx-main12345"


# =============================================================================
# Find Transit Gateways Tests
# =============================================================================


class TestFindTransitGateways:
    """Tests for _find_transit_gateways method."""

    @pytest.mark.asyncio
    async def test_find_tgws_via_attachments(
        self,
        discovery: ResourceDiscovery,
        mock_fetcher: AsyncMock,
        sample_tgw_attachments: list[dict[str, Any]],
        sample_tgws: list[dict[str, Any]],
    ) -> None:
        """Should find TGWs via attachments."""
        mock_fetcher.describe_transit_gateway_attachments.return_value = sample_tgw_attachments
        mock_fetcher.describe_transit_gateways.return_value = sample_tgws

        result = await discovery._find_transit_gateways("vpc-main", None, None)

        assert len(result) == 1
        assert result[0].id == "tgw-main12345"
        assert result[0].resource_type == NodeType.TRANSIT_GATEWAY

    @pytest.mark.asyncio
    async def test_find_tgws_no_attachments(
        self,
        discovery: ResourceDiscovery,
        mock_fetcher: AsyncMock,
    ) -> None:
        """Should return empty list when no TGW attachments."""
        mock_fetcher.describe_transit_gateway_attachments.return_value = []

        result = await discovery._find_transit_gateways("vpc-main", None, None)

        assert len(result) == 0


# =============================================================================
# Full Find Method Tests
# =============================================================================


class TestFindMethod:
    """Tests for the main find() method."""

    @pytest.mark.asyncio
    async def test_find_all_resource_types(
        self,
        discovery: ResourceDiscovery,
        mock_fetcher: AsyncMock,
        sample_instances: list[dict[str, Any]],
        sample_enis: list[dict[str, Any]],
        sample_subnets: list[dict[str, Any]],
        sample_igws: list[dict[str, Any]],
        sample_nats: list[dict[str, Any]],
        sample_peerings: list[dict[str, Any]],
        sample_tgw_attachments: list[dict[str, Any]],
        sample_tgws: list[dict[str, Any]],
    ) -> None:
        """Should search all resource types when none specified."""
        mock_fetcher.describe_instances.return_value = sample_instances
        mock_fetcher.describe_network_interfaces.return_value = sample_enis
        mock_fetcher.describe_subnets.return_value = sample_subnets
        mock_fetcher.describe_internet_gateways.return_value = sample_igws
        mock_fetcher.describe_nat_gateways.return_value = sample_nats
        mock_fetcher.describe_vpc_peering_connections.return_value = sample_peerings
        mock_fetcher.describe_transit_gateway_attachments.return_value = sample_tgw_attachments
        mock_fetcher.describe_transit_gateways.return_value = sample_tgws

        result = await discovery.find(vpc_id="vpc-main")

        # Should have resources from all types
        assert result.total_found > 0
        assert result.vpc_id == "vpc-main"

    @pytest.mark.asyncio
    async def test_find_specific_resource_type(
        self,
        discovery: ResourceDiscovery,
        mock_fetcher: AsyncMock,
        sample_instances: list[dict[str, Any]],
    ) -> None:
        """Should only search specified resource types."""
        mock_fetcher.describe_instances.return_value = sample_instances

        result = await discovery.find(
            vpc_id="vpc-main",
            resource_types=["instance"],
        )

        assert result.total_found == 3
        # Should only call describe_instances, not other describe methods
        mock_fetcher.describe_instances.assert_called_once()
        mock_fetcher.describe_network_interfaces.assert_not_called()

    @pytest.mark.asyncio
    async def test_find_truncates_results(
        self,
        discovery: ResourceDiscovery,
        mock_fetcher: AsyncMock,
    ) -> None:
        """Should truncate results at max_results."""
        # Create 60 instances
        many_instances = [{"InstanceId": f"i-{i:08d}", "Tags": []} for i in range(60)]
        mock_fetcher.describe_instances.return_value = many_instances

        result = await discovery.find(
            vpc_id="vpc-main",
            resource_types=["instance"],
            max_results=50,
        )

        assert result.total_found == 60
        assert len(result.resources) == 50
        assert result.truncated is True

    @pytest.mark.asyncio
    async def test_find_not_truncated(
        self,
        discovery: ResourceDiscovery,
        mock_fetcher: AsyncMock,
        sample_instances: list[dict[str, Any]],
    ) -> None:
        """Should not truncate when below max_results."""
        mock_fetcher.describe_instances.return_value = sample_instances

        result = await discovery.find(
            vpc_id="vpc-main",
            resource_types=["instance"],
            max_results=50,
        )

        assert result.total_found == 3
        assert len(result.resources) == 3
        assert result.truncated is False

    @pytest.mark.asyncio
    async def test_find_filters_applied(
        self,
        discovery: ResourceDiscovery,
        mock_fetcher: AsyncMock,
        sample_instances: list[dict[str, Any]],
    ) -> None:
        """Should include filters_applied in result."""
        mock_fetcher.describe_instances.return_value = sample_instances

        result = await discovery.find(
            vpc_id="vpc-main",
            resource_types=["instance"],
            tags={"Environment": "production"},
            name_pattern="web-*",
        )

        assert result.filters_applied["vpc_id"] == "vpc-main"
        assert result.filters_applied["resource_types"] == ["instance"]
        assert "name_pattern" in result.filters_applied
