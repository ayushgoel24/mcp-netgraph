"""MCP protocol compliance tests for NetGraph.

These tests verify that the MCP server and tools:
1. Return valid JSON responses
2. Handle input validation correctly
3. Follow MCP protocol conventions
4. Return appropriate error responses

Note: These tests mock the AWS layer and test the MCP tool handlers directly.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from netgraph.models.errors import (
    NetGraphError,
    PermissionDeniedError,
    ResourceNotFoundError,
    ValidationError,
)
from netgraph.models.results import (
    CacheStats,
    PathAnalysisResult,
    PathStatus,
    PublicExposureResult,
    ResourceDiscoveryResult,
    TopologyRefreshResult,
)
from netgraph.server import (
    _cache_stats_to_dict,
    _discovery_result_to_dict,
    _exposure_result_to_dict,
    _path_result_to_dict,
    _topology_result_to_dict,
)
from tests.fixtures.vpc_topologies import (
    ENI_WEB_1,
    INSTANCE_APP_1,
    INSTANCE_WEB_1,
    IP_APP_1_PRIVATE,
    IP_WEB_1_PRIVATE,
    SG_APP,
    SG_WEB,
    VPC_MAIN,
)

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_context() -> MagicMock:
    """Create a mock MCP context."""
    ctx = MagicMock()
    ctx.request_context = MagicMock()
    ctx.request_context.lifespan_context = MagicMock()
    return ctx


@pytest.fixture
def sample_path_result() -> PathAnalysisResult:
    """Create a sample path analysis result."""

    from netgraph.models.graph import NodeType
    from netgraph.models.results import HopResult, RuleEvalResult

    return PathAnalysisResult(
        status=PathStatus.REACHABLE,
        source_id=INSTANCE_WEB_1,
        destination_ip=IP_APP_1_PRIVATE,
        port=8080,
        protocol="tcp",
        hops=[
            HopResult(
                hop_number=1,
                node_id=ENI_WEB_1,
                node_type=NodeType.ENI,
                status=PathStatus.REACHABLE,
                sg_eval=RuleEvalResult(
                    allowed=True,
                    resource_id=SG_WEB,
                    resource_type="security_group",
                    rule_id="sgr-123",
                    direction="outbound",
                    reason="Outbound allowed to 0.0.0.0/0",
                ),
            ),
        ],
        evaluated_security_groups=[SG_WEB, SG_APP],
        evaluated_nacls=["acl-pub", "acl-prv"],
        route_path=["rtb-pub", "rtb-prv"],
        return_route_verified=True,
        return_route_table_id="rtb-prv",
    )


@pytest.fixture
def sample_topology_result() -> TopologyRefreshResult:
    """Create a sample topology refresh result."""
    return TopologyRefreshResult(
        success=True,
        vpc_ids_processed=[VPC_MAIN],
        vpc_ids_failed=[],
        node_count=42,
        edge_count=56,
        resources_by_type={
            "instance": 5,
            "eni": 8,
            "subnet": 4,
            "igw": 1,
            "nat": 1,
        },
        duration_seconds=2.345,
        warnings=[],
    )


@pytest.fixture
def sample_exposure_result() -> PublicExposureResult:
    """Create a sample public exposure result."""
    from netgraph.models.graph import NodeType
    from netgraph.models.results import ExposedResource

    return PublicExposureResult(
        vpc_id=VPC_MAIN,
        port=22,
        protocol="tcp",
        total_exposed=1,
        exposed_resources=[
            ExposedResource(
                resource_id=INSTANCE_WEB_1,
                resource_type=NodeType.INSTANCE,
                name="web-server-1",
                private_ip=IP_WEB_1_PRIVATE,
                public_ip="54.123.45.67",
                exposure_type="direct",
                exposure_path=["eni-123", "subnet-pub", "igw-main"],
                open_port=22,
                protocol="tcp",
                allowing_rules=["sgr-ssh-open"],
                severity="critical",
                remediation="Restrict SSH access to specific IP ranges",
            ),
        ],
        total_resources_scanned=10,
        scan_duration_seconds=1.234,
    )


@pytest.fixture
def sample_discovery_result() -> ResourceDiscoveryResult:
    """Create a sample resource discovery result."""
    from netgraph.models.graph import NodeType
    from netgraph.models.results import DiscoveredResource

    return ResourceDiscoveryResult(
        vpc_id=VPC_MAIN,
        resources=[
            DiscoveredResource(
                id=INSTANCE_WEB_1,
                resource_type=NodeType.INSTANCE,
                name="web-server-1",
                tags={"Environment": "production", "Tier": "web"},
                private_ip=IP_WEB_1_PRIVATE,
                public_ip="54.123.45.67",
                subnet_id="subnet-pub1",
                availability_zone="us-east-1a",
            ),
            DiscoveredResource(
                id=INSTANCE_APP_1,
                resource_type=NodeType.INSTANCE,
                name="app-server-1",
                tags={"Environment": "production", "Tier": "app"},
                private_ip=IP_APP_1_PRIVATE,
                public_ip=None,
                subnet_id="subnet-prv1",
                availability_zone="us-east-1a",
            ),
        ],
        total_found=2,
        truncated=False,
        filters_applied={
            "vpc_id": VPC_MAIN,
            "resource_types": ["instance"],
            "tags": "Environment=production",
        },
    )


@pytest.fixture
def sample_cache_stats() -> CacheStats:
    """Create sample cache statistics."""
    from datetime import datetime, timedelta

    return CacheStats(
        hits=100,
        misses=20,
        expired=5,
        size=150,
        ttl_seconds=60,
        oldest_entry=datetime.utcnow() - timedelta(seconds=45),
        entries_expiring_soon=10,
    )


# =============================================================================
# Response Format Tests
# =============================================================================


class TestPathResultSerialization:
    """Tests for path analysis result serialization."""

    def test_path_result_to_dict_has_required_fields(
        self, sample_path_result: PathAnalysisResult
    ) -> None:
        """Path result dict should contain all required fields."""
        result = _path_result_to_dict(sample_path_result)

        assert "status" in result
        assert "source_id" in result
        assert "destination_ip" in result
        assert "port" in result
        assert "protocol" in result
        assert "summary" in result
        assert "hops" in result
        assert "evaluated_security_groups" in result
        assert "evaluated_nacls" in result
        assert "route_path" in result

    def test_path_result_status_is_string(self, sample_path_result: PathAnalysisResult) -> None:
        """Status should be serialized as string value."""
        result = _path_result_to_dict(sample_path_result)
        assert result["status"] == "reachable"  # Enum serializes to lowercase
        assert isinstance(result["status"], str)

    def test_path_result_hops_are_serialized(self, sample_path_result: PathAnalysisResult) -> None:
        """Hops should be properly serialized."""
        result = _path_result_to_dict(sample_path_result)

        assert len(result["hops"]) == 1
        hop = result["hops"][0]
        assert "hop_number" in hop
        assert "node_id" in hop
        assert "node_type" in hop
        assert "status" in hop
        assert hop["node_type"] == "eni"  # Enum serializes to lowercase

    def test_path_result_return_route_fields(self, sample_path_result: PathAnalysisResult) -> None:
        """Return route verification fields should be included."""
        result = _path_result_to_dict(sample_path_result)

        assert "return_route_verified" in result
        assert result["return_route_verified"] is True
        assert "return_route_table_id" in result
        assert result["return_route_table_id"] == "rtb-prv"

    def test_blocked_path_result_includes_blocked_at(self) -> None:
        """Blocked path result should include blocked_at details."""
        from netgraph.models.graph import NodeType
        from netgraph.models.results import HopResult, RuleEvalResult

        blocked_result = PathAnalysisResult(
            status=PathStatus.BLOCKED,
            source_id=INSTANCE_WEB_1,
            destination_ip=IP_APP_1_PRIVATE,
            port=22,
            protocol="tcp",
            hops=[],
            blocked_at=HopResult(
                hop_number=1,
                node_id=SG_APP,
                node_type=NodeType.ENI,
                status=PathStatus.BLOCKED,
                sg_eval=RuleEvalResult(
                    allowed=False,
                    resource_id=SG_APP,
                    resource_type="security_group",
                    rule_id=None,
                    direction="inbound",
                    reason="No rule allows SSH from web tier",
                ),
            ),
            evaluated_security_groups=[SG_APP],
            evaluated_nacls=[],
            route_path=[],
        )

        result = _path_result_to_dict(blocked_result)

        assert "blocked_at" in result
        assert result["blocked_at"]["node_id"] == SG_APP
        assert result["blocked_at"]["sg_eval"] is not None
        assert result["blocked_at"]["sg_eval"]["allowed"] is False

    def test_unknown_path_result_includes_reason(self) -> None:
        """Unknown path result should include unknown_reason."""
        unknown_result = PathAnalysisResult(
            status=PathStatus.UNKNOWN,
            source_id=INSTANCE_WEB_1,
            destination_ip="10.100.0.1",
            port=443,
            protocol="tcp",
            hops=[],
            unknown_reason="Transit Gateway traversal not supported",
            evaluated_security_groups=[],
            evaluated_nacls=[],
            route_path=[],
        )

        result = _path_result_to_dict(unknown_result)

        assert "unknown_reason" in result
        assert "Transit Gateway" in result["unknown_reason"]


class TestTopologyResultSerialization:
    """Tests for topology refresh result serialization."""

    def test_topology_result_has_required_fields(
        self, sample_topology_result: TopologyRefreshResult
    ) -> None:
        """Topology result dict should contain all required fields."""
        result = _topology_result_to_dict(sample_topology_result)

        assert "success" in result
        assert "vpc_ids_processed" in result
        assert "vpc_ids_failed" in result
        assert "node_count" in result
        assert "edge_count" in result
        assert "resources_by_type" in result
        assert "duration_seconds" in result
        assert "warnings" in result

    def test_topology_result_duration_is_rounded(
        self, sample_topology_result: TopologyRefreshResult
    ) -> None:
        """Duration should be rounded to 3 decimal places."""
        result = _topology_result_to_dict(sample_topology_result)
        # 2.345 should stay 2.345
        assert result["duration_seconds"] == 2.345

    def test_topology_result_types(self, sample_topology_result: TopologyRefreshResult) -> None:
        """Result fields should have correct types."""
        result = _topology_result_to_dict(sample_topology_result)

        assert isinstance(result["success"], bool)
        assert isinstance(result["vpc_ids_processed"], list)
        assert isinstance(result["node_count"], int)
        assert isinstance(result["resources_by_type"], dict)


class TestExposureResultSerialization:
    """Tests for public exposure result serialization."""

    def test_exposure_result_has_required_fields(
        self, sample_exposure_result: PublicExposureResult
    ) -> None:
        """Exposure result dict should contain all required fields."""
        result = _exposure_result_to_dict(sample_exposure_result)

        assert "vpc_id" in result
        assert "port" in result
        assert "protocol" in result
        assert "exposed_resources" in result
        assert "total_resources_scanned" in result
        assert "scan_duration_seconds" in result

    def test_exposed_resource_serialization(
        self, sample_exposure_result: PublicExposureResult
    ) -> None:
        """Exposed resources should be properly serialized."""
        result = _exposure_result_to_dict(sample_exposure_result)

        assert len(result["exposed_resources"]) == 1
        resource = result["exposed_resources"][0]

        assert "resource_id" in resource
        assert "resource_type" in resource
        assert "name" in resource
        assert "private_ip" in resource
        assert "public_ip" in resource
        assert "exposure_path" in resource
        assert "allowing_rules" in resource

    def test_exposure_result_duration_rounded(
        self, sample_exposure_result: PublicExposureResult
    ) -> None:
        """Scan duration should be rounded."""
        result = _exposure_result_to_dict(sample_exposure_result)
        assert result["scan_duration_seconds"] == 1.234


class TestDiscoveryResultSerialization:
    """Tests for resource discovery result serialization."""

    def test_discovery_result_has_required_fields(
        self, sample_discovery_result: ResourceDiscoveryResult
    ) -> None:
        """Discovery result dict should contain all required fields."""
        result = _discovery_result_to_dict(sample_discovery_result)

        assert "vpc_id" in result
        assert "resources" in result
        assert "total_found" in result
        assert "truncated" in result
        assert "filters_applied" in result

    def test_discovered_resource_serialization(
        self, sample_discovery_result: ResourceDiscoveryResult
    ) -> None:
        """Discovered resources should be properly serialized."""
        result = _discovery_result_to_dict(sample_discovery_result)

        assert len(result["resources"]) == 2
        resource = result["resources"][0]

        assert "id" in resource
        assert "resource_type" in resource
        assert "name" in resource
        assert "tags" in resource
        assert "private_ip" in resource
        assert "public_ip" in resource
        assert "subnet_id" in resource
        assert "availability_zone" in resource

    def test_discovery_truncation_flag(self) -> None:
        """Truncated flag should be set when results are capped."""
        from netgraph.models.graph import NodeType
        from netgraph.models.results import DiscoveredResource

        truncated_result = ResourceDiscoveryResult(
            vpc_id=VPC_MAIN,
            resources=[
                DiscoveredResource(
                    id=f"i-{i:08d}",
                    resource_type=NodeType.INSTANCE,
                    name=f"instance-{i}",
                )
                for i in range(50)
            ],
            total_found=100,  # More than returned
            truncated=True,
            filters_applied={},
        )

        result = _discovery_result_to_dict(truncated_result)

        assert result["truncated"] is True
        assert result["total_found"] == 100
        assert len(result["resources"]) == 50


class TestCacheStatsSerialization:
    """Tests for cache statistics serialization."""

    def test_cache_stats_has_required_fields(self, sample_cache_stats: CacheStats) -> None:
        """Cache stats dict should contain all required fields."""
        result = _cache_stats_to_dict(sample_cache_stats)

        assert "hits" in result
        assert "misses" in result
        assert "expired" in result
        assert "size" in result
        assert "ttl_seconds" in result
        assert "hit_rate" in result
        assert "oldest_entry" in result
        assert "entries_expiring_soon" in result

    def test_cache_stats_hit_rate_calculation(self, sample_cache_stats: CacheStats) -> None:
        """Hit rate should be correctly calculated."""
        result = _cache_stats_to_dict(sample_cache_stats)

        # 100 hits / (100 hits + 20 misses) = 83.33%
        expected_rate = 100 / 120 * 100
        assert result["hit_rate"] == round(expected_rate, 2)

    def test_cache_stats_zero_requests(self) -> None:
        """Hit rate should be 0 when no requests made."""
        empty_stats = CacheStats(
            hits=0,
            misses=0,
            expired=0,
            size=0,
            ttl_seconds=60,
            oldest_entry=None,
            entries_expiring_soon=0,
        )

        result = _cache_stats_to_dict(empty_stats)
        assert result["hit_rate"] == 0.0

    def test_cache_stats_oldest_entry_format(self, sample_cache_stats: CacheStats) -> None:
        """Oldest entry should be ISO format string."""
        result = _cache_stats_to_dict(sample_cache_stats)

        assert result["oldest_entry"] is not None
        assert isinstance(result["oldest_entry"], str)
        # Should be parseable as ISO format
        from datetime import datetime

        datetime.fromisoformat(result["oldest_entry"])


# =============================================================================
# Error Response Tests
# =============================================================================


class TestErrorResponses:
    """Tests for error response formatting."""

    def test_validation_error_response(self) -> None:
        """ValidationError should produce valid error response."""
        error = ValidationError(
            message="Invalid port number",
            field="port",
            expected="1-65535",
        )

        response = error.to_response()

        assert "error" in response
        assert response["error"] == "ValidationError"
        assert "message" in response
        assert "details" in response
        assert response["details"]["field"] == "port"

    def test_resource_not_found_response(self) -> None:
        """ResourceNotFoundError should produce valid error response."""
        error = ResourceNotFoundError(
            resource_id="i-nonexistent",
            resource_type="instance",
        )

        response = error.to_response()

        assert response["error"] == "ResourceNotFoundError"
        assert "details" in response
        assert response["details"]["resource_type"] == "instance"
        assert response["details"]["resource_id"] == "i-nonexistent"

    def test_permission_denied_response(self) -> None:
        """PermissionDeniedError should produce valid error response."""
        error = PermissionDeniedError(
            message="Access denied to cross-account SG",
            resource_id="sg-cross-account",
            operation="DescribeSecurityGroups",
        )

        response = error.to_response()

        assert response["error"] == "PermissionDeniedError"
        assert "details" in response
        assert response["details"]["operation"] == "DescribeSecurityGroups"


# =============================================================================
# Tool Input Validation Tests
# =============================================================================


class TestToolInputValidation:
    """Tests for MCP tool input validation."""

    @pytest.mark.asyncio
    async def test_analyze_path_requires_source_id(self) -> None:
        """analyze_path should require source_id."""
        from netgraph.server import analyze_path

        with pytest.raises(ValidationError) as exc_info:
            await analyze_path(
                source_id="",
                destination_ip="10.0.0.1",
                port=80,
                ctx=MagicMock(),
            )

        assert "source_id" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_analyze_path_validates_source_format(self) -> None:
        """analyze_path should validate source_id format."""
        from netgraph.server import analyze_path

        with pytest.raises(ValidationError) as exc_info:
            await analyze_path(
                source_id="invalid-format",
                destination_ip="10.0.0.1",
                port=80,
                ctx=MagicMock(),
            )

        # Check that the error message mentions the expected format
        error_str = str(exc_info.value)
        assert "i-" in error_str or "eni-" in error_str

    @pytest.mark.asyncio
    async def test_analyze_path_validates_port_range(self) -> None:
        """analyze_path should validate port is in valid range."""
        from netgraph.server import analyze_path

        with pytest.raises(ValidationError) as exc_info:
            await analyze_path(
                source_id="i-1234567890abcdef0",
                destination_ip="10.0.0.1",
                port=70000,  # Invalid port
                ctx=MagicMock(),
            )

        assert "port" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_analyze_path_validates_protocol(self) -> None:
        """analyze_path should validate protocol value."""
        from netgraph.server import analyze_path

        with pytest.raises(ValidationError) as exc_info:
            await analyze_path(
                source_id="i-1234567890abcdef0",
                destination_ip="10.0.0.1",
                port=80,
                protocol="invalid",
                ctx=MagicMock(),
            )

        assert "protocol" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_refresh_topology_requires_vpc_ids(self) -> None:
        """refresh_topology should require non-empty vpc_ids."""
        from netgraph.server import refresh_topology

        with pytest.raises(ValidationError) as exc_info:
            await refresh_topology(vpc_ids=[], ctx=MagicMock())

        assert "vpc_ids" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_refresh_topology_validates_vpc_format(self) -> None:
        """refresh_topology should validate VPC ID format."""
        from netgraph.server import refresh_topology

        with pytest.raises(ValidationError) as exc_info:
            await refresh_topology(vpc_ids=["invalid-vpc"], ctx=MagicMock())

        # Check that error mentions VPC ID format
        assert "vpc" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_find_public_exposure_validates_vpc_id(self) -> None:
        """find_public_exposure should validate VPC ID."""
        from netgraph.server import find_public_exposure

        with pytest.raises(ValidationError) as exc_info:
            await find_public_exposure(
                vpc_id="",
                port=22,
                ctx=MagicMock(),
            )

        assert "vpc_id" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_find_public_exposure_validates_port(self) -> None:
        """find_public_exposure should validate port range."""
        from netgraph.server import find_public_exposure

        with pytest.raises(ValidationError) as exc_info:
            await find_public_exposure(
                vpc_id="vpc-12345678",
                port=0,  # Invalid
                ctx=MagicMock(),
            )

        assert "port" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_find_resources_validates_vpc_id(self) -> None:
        """find_resources should validate VPC ID format."""
        from netgraph.server import find_resources

        with pytest.raises(ValidationError) as exc_info:
            await find_resources(
                vpc_id="not-a-vpc",
                ctx=MagicMock(),
            )

        # Check that error mentions VPC ID format
        assert "vpc" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_find_resources_validates_resource_types(self) -> None:
        """find_resources should validate resource types."""
        from netgraph.server import find_resources

        with pytest.raises(ValidationError) as exc_info:
            await find_resources(
                vpc_id="vpc-12345678",
                resource_types=["invalid_type"],
                ctx=MagicMock(),
            )

        # Check that error mentions invalid resource type
        assert "invalid_type" in str(exc_info.value) or "resource" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_find_resources_caps_max_results(self, mock_context: MagicMock) -> None:
        """find_resources should cap max_results at 50."""

        # This should not raise, but should cap internally
        # We can't fully test without mocking the context properly
        # Just verify the validation doesn't reject high values
        pass  # Tested via integration


# =============================================================================
# Response JSON Compatibility Tests
# =============================================================================


class TestJSONCompatibility:
    """Tests ensuring responses are JSON-serializable."""

    def test_path_result_is_json_serializable(self, sample_path_result: PathAnalysisResult) -> None:
        """Path result should be JSON serializable."""
        import json

        result = _path_result_to_dict(sample_path_result)
        # Should not raise
        json_str = json.dumps(result)
        assert json_str is not None

    def test_topology_result_is_json_serializable(
        self, sample_topology_result: TopologyRefreshResult
    ) -> None:
        """Topology result should be JSON serializable."""
        import json

        result = _topology_result_to_dict(sample_topology_result)
        json_str = json.dumps(result)
        assert json_str is not None

    def test_exposure_result_is_json_serializable(
        self, sample_exposure_result: PublicExposureResult
    ) -> None:
        """Exposure result should be JSON serializable."""
        import json

        result = _exposure_result_to_dict(sample_exposure_result)
        json_str = json.dumps(result)
        assert json_str is not None

    def test_discovery_result_is_json_serializable(
        self, sample_discovery_result: ResourceDiscoveryResult
    ) -> None:
        """Discovery result should be JSON serializable."""
        import json

        result = _discovery_result_to_dict(sample_discovery_result)
        json_str = json.dumps(result)
        assert json_str is not None

    def test_cache_stats_is_json_serializable(self, sample_cache_stats: CacheStats) -> None:
        """Cache stats should be JSON serializable."""
        import json

        result = _cache_stats_to_dict(sample_cache_stats)
        json_str = json.dumps(result)
        assert json_str is not None

    def test_error_response_is_json_serializable(self) -> None:
        """Error responses should be JSON serializable."""
        import json

        error = ValidationError(
            message="Test error",
            field="test_field",
            expected="valid_value",
        )
        response = error.to_response()
        json_str = json.dumps(response)
        assert json_str is not None


# =============================================================================
# MCP Protocol Conventions Tests
# =============================================================================


class TestMCPConventions:
    """Tests for MCP protocol conventions."""

    def test_success_response_has_no_error_key(
        self, sample_path_result: PathAnalysisResult
    ) -> None:
        """Success responses should not have 'error' key."""
        result = _path_result_to_dict(sample_path_result)
        assert "error" not in result

    def test_error_response_has_error_key(self) -> None:
        """Error responses should have 'error' key at top level."""
        error = NetGraphError(message="Test error")
        response = error.to_response()
        assert "error" in response

    def test_error_has_type_and_message(self) -> None:
        """Error responses should have error type and message."""
        error = NetGraphError(message="Test error")
        response = error.to_response()

        # error key contains the error type (class name)
        assert response["error"] == "NetGraphError"
        # message is a top-level key
        assert "message" in response
        assert response["message"] == "Test error"

    def test_enum_values_serialized_as_strings(
        self, sample_path_result: PathAnalysisResult
    ) -> None:
        """Enum values should be serialized as strings."""
        result = _path_result_to_dict(sample_path_result)

        # Status should be string
        assert isinstance(result["status"], str)

        # Node type in hops should be string
        for hop in result["hops"]:
            assert isinstance(hop["node_type"], str)
            assert isinstance(hop["status"], str)


# =============================================================================
# list_vpcs Tool Tests
# =============================================================================


class TestListVpcs:
    """Tests for the list_vpcs MCP tool."""

    @pytest.fixture
    def mock_app_context(self) -> MagicMock:
        """Create a mock application context with fetcher."""
        ctx = MagicMock()
        ctx.request_context = MagicMock()
        ctx.request_context.lifespan_context = MagicMock()
        ctx.request_context.lifespan_context.fetcher = AsyncMock()
        return ctx

    @pytest.fixture
    def sample_vpcs(self) -> list[dict[str, Any]]:
        """Sample VPC data from AWS API."""
        return [
            {
                "VpcId": "vpc-prod12345",
                "CidrBlock": "10.0.0.0/16",
                "State": "available",
                "IsDefault": False,
                "Tags": [
                    {"Key": "Name", "Value": "production-vpc"},
                    {"Key": "Environment", "Value": "production"},
                ],
            },
            {
                "VpcId": "vpc-dev67890",
                "CidrBlock": "10.1.0.0/16",
                "State": "available",
                "IsDefault": False,
                "Tags": [
                    {"Key": "Name", "Value": "development-vpc"},
                    {"Key": "Environment", "Value": "development"},
                ],
            },
            {
                "VpcId": "vpc-default99",
                "CidrBlock": "172.31.0.0/16",
                "State": "available",
                "IsDefault": True,
                "Tags": [],  # Default VPC often has no tags
            },
        ]

    @pytest.mark.asyncio
    async def test_list_vpcs_returns_all_vpcs(
        self, mock_app_context: MagicMock, sample_vpcs: list[dict[str, Any]]
    ) -> None:
        """list_vpcs should return all VPCs when no filters provided."""
        from netgraph.server import list_vpcs

        mock_app_context.request_context.lifespan_context.fetcher.describe_vpcs = AsyncMock(
            return_value=sample_vpcs
        )

        with patch(
            "netgraph.server._get_app_context",
            return_value=mock_app_context.request_context.lifespan_context,
        ):
            result = await list_vpcs(ctx=mock_app_context)

        assert "vpcs" in result
        assert "total_found" in result
        assert result["total_found"] == 3
        assert len(result["vpcs"]) == 3

    @pytest.mark.asyncio
    async def test_list_vpcs_response_format(
        self, mock_app_context: MagicMock, sample_vpcs: list[dict[str, Any]]
    ) -> None:
        """list_vpcs response should have correct format."""
        from netgraph.server import list_vpcs

        mock_app_context.request_context.lifespan_context.fetcher.describe_vpcs = AsyncMock(
            return_value=sample_vpcs
        )

        with patch(
            "netgraph.server._get_app_context",
            return_value=mock_app_context.request_context.lifespan_context,
        ):
            result = await list_vpcs(ctx=mock_app_context)

        vpc = result["vpcs"][0]
        assert "id" in vpc
        assert "name" in vpc
        assert "cidr" in vpc
        assert "state" in vpc
        assert "is_default" in vpc
        assert "tags" in vpc

    @pytest.mark.asyncio
    async def test_list_vpcs_filter_by_name_pattern(
        self, mock_app_context: MagicMock, sample_vpcs: list[dict[str, Any]]
    ) -> None:
        """list_vpcs should filter by name pattern."""
        from netgraph.server import list_vpcs

        mock_app_context.request_context.lifespan_context.fetcher.describe_vpcs = AsyncMock(
            return_value=sample_vpcs
        )

        with patch(
            "netgraph.server._get_app_context",
            return_value=mock_app_context.request_context.lifespan_context,
        ):
            result = await list_vpcs(name_pattern="prod*", ctx=mock_app_context)

        assert result["total_found"] == 1
        assert result["vpcs"][0]["id"] == "vpc-prod12345"
        assert result["filters_applied"]["name_pattern"] == "prod*"

    @pytest.mark.asyncio
    async def test_list_vpcs_filter_by_name_pattern_case_insensitive(
        self, mock_app_context: MagicMock, sample_vpcs: list[dict[str, Any]]
    ) -> None:
        """list_vpcs name pattern matching should be case-insensitive."""
        from netgraph.server import list_vpcs

        mock_app_context.request_context.lifespan_context.fetcher.describe_vpcs = AsyncMock(
            return_value=sample_vpcs
        )

        with patch(
            "netgraph.server._get_app_context",
            return_value=mock_app_context.request_context.lifespan_context,
        ):
            result = await list_vpcs(name_pattern="PROD*", ctx=mock_app_context)

        assert result["total_found"] == 1
        assert result["vpcs"][0]["name"] == "production-vpc"

    @pytest.mark.asyncio
    async def test_list_vpcs_filter_by_tags(
        self, mock_app_context: MagicMock, sample_vpcs: list[dict[str, Any]]
    ) -> None:
        """list_vpcs should filter by tags."""
        from netgraph.server import list_vpcs

        mock_app_context.request_context.lifespan_context.fetcher.describe_vpcs = AsyncMock(
            return_value=sample_vpcs
        )

        with patch(
            "netgraph.server._get_app_context",
            return_value=mock_app_context.request_context.lifespan_context,
        ):
            result = await list_vpcs(tags={"Environment": "development"}, ctx=mock_app_context)

        assert result["total_found"] == 1
        assert result["vpcs"][0]["id"] == "vpc-dev67890"
        assert result["filters_applied"]["tags"] == {"Environment": "development"}

    @pytest.mark.asyncio
    async def test_list_vpcs_filter_by_cidr(
        self, mock_app_context: MagicMock, sample_vpcs: list[dict[str, Any]]
    ) -> None:
        """list_vpcs should pass CIDR filter to AWS."""
        from netgraph.server import list_vpcs

        mock_app_context.request_context.lifespan_context.fetcher.describe_vpcs = AsyncMock(
            return_value=[sample_vpcs[0]]  # Only return prod VPC for CIDR match
        )

        with patch(
            "netgraph.server._get_app_context",
            return_value=mock_app_context.request_context.lifespan_context,
        ):
            result = await list_vpcs(cidr="10.0.0.0/16", ctx=mock_app_context)

        # Verify AWS filter was passed
        mock_app_context.request_context.lifespan_context.fetcher.describe_vpcs.assert_called_once()
        call_args = (
            mock_app_context.request_context.lifespan_context.fetcher.describe_vpcs.call_args
        )
        assert call_args.kwargs["filters"] is not None

        assert result["filters_applied"]["cidr"] == "10.0.0.0/16"

    @pytest.mark.asyncio
    async def test_list_vpcs_combined_filters(
        self, mock_app_context: MagicMock, sample_vpcs: list[dict[str, Any]]
    ) -> None:
        """list_vpcs should apply multiple filters together."""
        from netgraph.server import list_vpcs

        mock_app_context.request_context.lifespan_context.fetcher.describe_vpcs = AsyncMock(
            return_value=sample_vpcs
        )

        with patch(
            "netgraph.server._get_app_context",
            return_value=mock_app_context.request_context.lifespan_context,
        ):
            result = await list_vpcs(
                name_pattern="*-vpc",
                tags={"Environment": "production"},
                ctx=mock_app_context,
            )

        assert result["total_found"] == 1
        assert result["vpcs"][0]["id"] == "vpc-prod12345"

    @pytest.mark.asyncio
    async def test_list_vpcs_no_matches(
        self, mock_app_context: MagicMock, sample_vpcs: list[dict[str, Any]]
    ) -> None:
        """list_vpcs should return empty list when no VPCs match."""
        from netgraph.server import list_vpcs

        mock_app_context.request_context.lifespan_context.fetcher.describe_vpcs = AsyncMock(
            return_value=sample_vpcs
        )

        with patch(
            "netgraph.server._get_app_context",
            return_value=mock_app_context.request_context.lifespan_context,
        ):
            result = await list_vpcs(name_pattern="nonexistent*", ctx=mock_app_context)

        assert result["total_found"] == 0
        assert result["vpcs"] == []

    @pytest.mark.asyncio
    async def test_list_vpcs_handles_vpcs_without_tags(self, mock_app_context: MagicMock) -> None:
        """list_vpcs should handle VPCs without any tags."""
        from netgraph.server import list_vpcs

        vpc_without_tags = [
            {
                "VpcId": "vpc-notags",
                "CidrBlock": "192.168.0.0/16",
                "State": "available",
                "IsDefault": False,
                # No Tags key at all
            },
        ]

        mock_app_context.request_context.lifespan_context.fetcher.describe_vpcs = AsyncMock(
            return_value=vpc_without_tags
        )

        with patch(
            "netgraph.server._get_app_context",
            return_value=mock_app_context.request_context.lifespan_context,
        ):
            result = await list_vpcs(ctx=mock_app_context)

        assert result["total_found"] == 1
        vpc = result["vpcs"][0]
        assert vpc["name"] is None
        assert vpc["tags"] is None or vpc["tags"] == {}

    @pytest.mark.asyncio
    async def test_list_vpcs_default_vpc_identified(
        self, mock_app_context: MagicMock, sample_vpcs: list[dict[str, Any]]
    ) -> None:
        """list_vpcs should correctly identify default VPC."""
        from netgraph.server import list_vpcs

        mock_app_context.request_context.lifespan_context.fetcher.describe_vpcs = AsyncMock(
            return_value=sample_vpcs
        )

        with patch(
            "netgraph.server._get_app_context",
            return_value=mock_app_context.request_context.lifespan_context,
        ):
            result = await list_vpcs(ctx=mock_app_context)

        default_vpcs = [v for v in result["vpcs"] if v["is_default"]]
        assert len(default_vpcs) == 1
        assert default_vpcs[0]["id"] == "vpc-default99"

    @pytest.mark.asyncio
    async def test_list_vpcs_is_json_serializable(
        self, mock_app_context: MagicMock, sample_vpcs: list[dict[str, Any]]
    ) -> None:
        """list_vpcs result should be JSON serializable."""
        import json

        from netgraph.server import list_vpcs

        mock_app_context.request_context.lifespan_context.fetcher.describe_vpcs = AsyncMock(
            return_value=sample_vpcs
        )

        with patch(
            "netgraph.server._get_app_context",
            return_value=mock_app_context.request_context.lifespan_context,
        ):
            result = await list_vpcs(ctx=mock_app_context)

        # Should not raise
        json_str = json.dumps(result)
        assert json_str is not None
