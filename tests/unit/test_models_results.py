"""Tests for result models including human summary generation."""

from datetime import datetime

from netgraph.models.graph import NodeType
from netgraph.models.results import (
    CacheStats,
    DiscoveredResource,
    ExposedResource,
    HopResult,
    PathAnalysisResult,
    PathStatus,
    PublicExposureResult,
    ResourceDiscoveryResult,
    RuleEvalResult,
    TopologyRefreshResult,
)


class TestPathStatus:
    """Tests for PathStatus enum."""

    def test_all_statuses_defined(self) -> None:
        """All expected path statuses exist."""
        expected = {"reachable", "blocked", "unknown"}
        actual = {ps.value for ps in PathStatus}
        assert actual == expected

    def test_status_from_string(self) -> None:
        """Can create PathStatus from string value."""
        assert PathStatus("reachable") == PathStatus.REACHABLE
        assert PathStatus("blocked") == PathStatus.BLOCKED
        assert PathStatus("unknown") == PathStatus.UNKNOWN


class TestRuleEvalResult:
    """Tests for RuleEvalResult model."""

    def test_allowed_result(self) -> None:
        """Can create allowed result."""
        result = RuleEvalResult(
            allowed=True,
            matched_rule_id="rule-123",
            resource_id="sg-12345",
            resource_type="security_group",
            direction="inbound",
            reason="Security Group sg-12345 allows TCP/443 from 10.0.0.0/16",
        )
        assert result.allowed is True
        assert result.matched_rule_id == "rule-123"

    def test_blocked_result(self) -> None:
        """Can create blocked result."""
        result = RuleEvalResult(
            allowed=False,
            matched_rule_id=None,
            resource_id="sg-12345",
            resource_type="security_group",
            direction="outbound",
            reason="No rule allows TCP/443 to 8.8.8.8",
        )
        assert result.allowed is False
        assert result.matched_rule_id is None

    def test_nacl_result(self) -> None:
        """Can create NACL evaluation result."""
        result = RuleEvalResult(
            allowed=True,
            matched_rule_id="rule-100",
            resource_id="acl-12345",
            resource_type="nacl",
            direction="inbound",
            reason="NACL acl-12345 rule 100 allows TCP/443",
        )
        assert result.resource_type == "nacl"

    def test_route_table_result(self) -> None:
        """Can create route table evaluation result."""
        result = RuleEvalResult(
            allowed=True,
            matched_rule_id=None,
            resource_id="rtb-12345",
            resource_type="route_table",
            reason="Route to 10.0.0.0/16 via local",
        )
        assert result.resource_type == "route_table"

    def test_return_direction(self) -> None:
        """Can specify return direction for reverse path checks."""
        result = RuleEvalResult(
            allowed=False,
            resource_id="rtb-12345",
            resource_type="route_table",
            direction="return",
            reason="No route back to source IP",
        )
        assert result.direction == "return"

    def test_prefix_list_resolution(self) -> None:
        """Can include resolved prefix list ID."""
        result = RuleEvalResult(
            allowed=True,
            matched_rule_id="rule-pl",
            resource_id="sg-12345",
            resource_type="security_group",
            direction="inbound",
            reason="Allowed via prefix list pl-12345",
            resolved_prefix_list="pl-12345",
        )
        assert result.resolved_prefix_list == "pl-12345"


class TestHopResult:
    """Tests for HopResult model."""

    def test_minimal_hop(self) -> None:
        """Can create hop with required fields only."""
        hop = HopResult(
            hop_number=1,
            node_id="subnet-12345",
            node_type=NodeType.SUBNET,
        )
        assert hop.hop_number == 1
        assert hop.status == PathStatus.REACHABLE

    def test_hop_with_sg_eval(self) -> None:
        """Hop can have security group evaluation."""
        hop = HopResult(
            hop_number=0,
            node_id="i-12345",
            node_type=NodeType.INSTANCE,
            sg_eval=RuleEvalResult(
                allowed=True,
                resource_id="sg-12345",
                resource_type="security_group",
                direction="outbound",
                reason="Allowed",
            ),
        )
        assert hop.sg_eval is not None
        assert hop.sg_eval.allowed is True

    def test_hop_with_nacl_eval(self) -> None:
        """Hop can have NACL evaluation."""
        hop = HopResult(
            hop_number=1,
            node_id="subnet-12345",
            node_type=NodeType.SUBNET,
            nacl_eval=RuleEvalResult(
                allowed=True,
                resource_id="acl-12345",
                resource_type="nacl",
                direction="inbound",
                reason="Allowed",
            ),
        )
        assert hop.nacl_eval is not None

    def test_hop_with_route_eval(self) -> None:
        """Hop can have route evaluation."""
        hop = HopResult(
            hop_number=1,
            node_id="subnet-12345",
            node_type=NodeType.SUBNET,
            route_eval=RuleEvalResult(
                allowed=True,
                resource_id="rtb-12345",
                resource_type="route_table",
                reason="Route via NAT",
            ),
        )
        assert hop.route_eval is not None

    def test_blocking_reason_reachable(self) -> None:
        """blocking_reason is None for reachable hop."""
        hop = HopResult(
            hop_number=1,
            node_id="subnet-12345",
            node_type=NodeType.SUBNET,
            status=PathStatus.REACHABLE,
        )
        assert hop.blocking_reason is None

    def test_blocking_reason_sg_blocked(self) -> None:
        """blocking_reason returns SG reason when blocked."""
        hop = HopResult(
            hop_number=0,
            node_id="i-12345",
            node_type=NodeType.INSTANCE,
            status=PathStatus.BLOCKED,
            sg_eval=RuleEvalResult(
                allowed=False,
                resource_id="sg-12345",
                resource_type="security_group",
                direction="outbound",
                reason="No rule allows TCP/443 to 8.8.8.8",
            ),
        )
        assert hop.blocking_reason == "No rule allows TCP/443 to 8.8.8.8"

    def test_blocking_reason_nacl_blocked(self) -> None:
        """blocking_reason returns NACL reason when blocked."""
        hop = HopResult(
            hop_number=1,
            node_id="subnet-12345",
            node_type=NodeType.SUBNET,
            status=PathStatus.BLOCKED,
            nacl_eval=RuleEvalResult(
                allowed=False,
                matched_rule_id="rule-*",
                resource_id="acl-12345",
                resource_type="nacl",
                direction="inbound",
                reason="NACL implicit deny",
            ),
        )
        assert hop.blocking_reason == "NACL implicit deny"

    def test_blocking_reason_route_blocked(self) -> None:
        """blocking_reason returns route reason when blocked."""
        hop = HopResult(
            hop_number=1,
            node_id="subnet-12345",
            node_type=NodeType.SUBNET,
            status=PathStatus.BLOCKED,
            route_eval=RuleEvalResult(
                allowed=False,
                resource_id="rtb-12345",
                resource_type="route_table",
                reason="No route to 10.0.2.0/24",
            ),
        )
        assert hop.blocking_reason == "No route to 10.0.2.0/24"

    def test_blocking_reason_unknown(self) -> None:
        """blocking_reason returns default when no eval set."""
        hop = HopResult(
            hop_number=1,
            node_id="subnet-12345",
            node_type=NodeType.SUBNET,
            status=PathStatus.BLOCKED,
        )
        assert hop.blocking_reason == "Unknown blocking reason"


class TestPathAnalysisResult:
    """Tests for PathAnalysisResult model."""

    def test_minimal_result(self) -> None:
        """Can create result with required fields only."""
        result = PathAnalysisResult(
            status=PathStatus.REACHABLE,
            source_id="i-12345",
            destination_ip="10.0.2.50",
            port=443,
            protocol="tcp",
        )
        assert result.status == PathStatus.REACHABLE
        assert result.hops == []

    def test_result_with_hops(self) -> None:
        """Result can have hop details."""
        result = PathAnalysisResult(
            status=PathStatus.REACHABLE,
            source_id="i-12345",
            destination_ip="10.0.2.50",
            port=443,
            protocol="tcp",
            hops=[
                HopResult(hop_number=1, node_id="eni-1", node_type=NodeType.ENI),
                HopResult(hop_number=2, node_id="pcx-1", node_type=NodeType.VPC_PEERING),
                HopResult(hop_number=3, node_id="i-dest", node_type=NodeType.INSTANCE),
            ],
        )
        assert len(result.hops) == 3

    def test_blocked_result(self) -> None:
        """Blocked result with blocked_at hop."""
        result = PathAnalysisResult(
            status=PathStatus.BLOCKED,
            source_id="i-12345",
            destination_ip="10.0.2.50",
            port=443,
            protocol="tcp",
            blocked_at=HopResult(
                hop_number=0,
                node_id="sg-12345",
                node_type=NodeType.INSTANCE,
                status=PathStatus.BLOCKED,
                sg_eval=RuleEvalResult(
                    allowed=False,
                    resource_id="sg-12345",
                    resource_type="security_group",
                    direction="outbound",
                    reason="No rule allows TCP/443",
                ),
            ),
        )
        assert result.blocked_at is not None
        assert result.blocked_at.node_id == "sg-12345"

    def test_unknown_result(self) -> None:
        """Unknown result with reason."""
        result = PathAnalysisResult(
            status=PathStatus.UNKNOWN,
            source_id="i-12345",
            destination_ip="10.0.2.50",
            port=443,
            protocol="tcp",
            unknown_reason="Access denied to subnet-xyz in account 123456789012",
        )
        assert result.status == PathStatus.UNKNOWN
        assert "Access denied" in result.unknown_reason

    def test_return_route_verification(self) -> None:
        """Result includes return route verification."""
        result = PathAnalysisResult(
            status=PathStatus.REACHABLE,
            source_id="i-12345",
            destination_ip="10.0.2.50",
            port=443,
            protocol="tcp",
            return_route_verified=True,
            return_route_table_id="rtb-dest",
        )
        assert result.return_route_verified is True
        assert result.return_route_table_id == "rtb-dest"


class TestGenerateHumanSummary:
    """Tests for generate_human_summary() method."""

    def test_reachable_path_summary(self) -> None:
        """REACHABLE paths generate concise hop summary."""
        result = PathAnalysisResult(
            status=PathStatus.REACHABLE,
            source_id="i-source",
            destination_ip="10.0.2.50",
            port=443,
            protocol="tcp",
            hops=[
                HopResult(hop_number=1, node_id="eni-1", node_type=NodeType.ENI),
                HopResult(hop_number=2, node_id="pcx-1", node_type=NodeType.VPC_PEERING),
                HopResult(hop_number=3, node_id="i-dest", node_type=NodeType.INSTANCE),
            ],
            return_route_verified=True,
            return_route_table_id="rtb-12345",
        )
        summary = result.generate_human_summary()
        assert "Traffic Allowed" in summary
        assert "3 hops" in summary
        assert "Eni -> Peering -> Instance" in summary
        assert "rtb-12345" in summary

    def test_reachable_direct_path(self) -> None:
        """REACHABLE direct path (no hops)."""
        result = PathAnalysisResult(
            status=PathStatus.REACHABLE,
            source_id="i-source",
            destination_ip="10.0.1.50",
            port=443,
            protocol="tcp",
            hops=[],
        )
        summary = result.generate_human_summary()
        assert "Traffic Allowed" in summary
        assert "0 hops" in summary
        assert "Direct" in summary

    def test_reachable_without_return_route_info(self) -> None:
        """REACHABLE path without return route info."""
        result = PathAnalysisResult(
            status=PathStatus.REACHABLE,
            source_id="i-source",
            destination_ip="10.0.2.50",
            port=443,
            protocol="tcp",
            hops=[HopResult(hop_number=1, node_id="subnet-1", node_type=NodeType.SUBNET)],
            return_route_verified=False,
        )
        summary = result.generate_human_summary()
        assert "Traffic Allowed" in summary
        assert "Return traffic" not in summary

    def test_blocked_sg_summary(self) -> None:
        """BLOCKED paths identify blocking resource and reason."""
        result = PathAnalysisResult(
            status=PathStatus.BLOCKED,
            source_id="i-source",
            destination_ip="10.0.2.50",
            port=22,
            protocol="tcp",
            blocked_at=HopResult(
                hop_number=0,
                node_id="sg-abc123",
                node_type=NodeType.INSTANCE,
                status=PathStatus.BLOCKED,
                sg_eval=RuleEvalResult(
                    allowed=False,
                    resource_id="sg-abc123",
                    resource_type="security_group",
                    direction="outbound",
                    reason="No rule allows TCP/22 to 10.0.2.50",
                ),
            ),
        )
        summary = result.generate_human_summary()
        assert "Traffic Blocked" in summary
        assert "instance" in summary
        assert "sg-abc123" in summary
        assert "No rule allows TCP/22" in summary

    def test_blocked_nacl_summary(self) -> None:
        """BLOCKED by NACL."""
        result = PathAnalysisResult(
            status=PathStatus.BLOCKED,
            source_id="i-source",
            destination_ip="10.0.2.50",
            port=443,
            protocol="tcp",
            blocked_at=HopResult(
                hop_number=1,
                node_id="subnet-12345",
                node_type=NodeType.SUBNET,
                status=PathStatus.BLOCKED,
                nacl_eval=RuleEvalResult(
                    allowed=False,
                    matched_rule_id="rule-200",
                    resource_id="acl-12345",
                    resource_type="nacl",
                    direction="inbound",
                    reason="NACL acl-12345 rule 200 denies TCP/443",
                ),
            ),
        )
        summary = result.generate_human_summary()
        assert "Traffic Blocked" in summary
        assert "subnet" in summary
        assert "NACL acl-12345 rule 200 denies" in summary

    def test_blocked_without_blocked_at(self) -> None:
        """BLOCKED without blocked_at uses summary field."""
        result = PathAnalysisResult(
            status=PathStatus.BLOCKED,
            source_id="i-source",
            destination_ip="10.0.2.50",
            port=443,
            protocol="tcp",
            summary="Routing loop detected at subnet-12345",
        )
        summary = result.generate_human_summary()
        assert "Traffic Blocked" in summary
        assert "Routing loop" in summary

    def test_unknown_summary(self) -> None:
        """UNKNOWN paths explain why determination failed."""
        result = PathAnalysisResult(
            status=PathStatus.UNKNOWN,
            source_id="i-source",
            destination_ip="10.0.2.50",
            port=443,
            protocol="tcp",
            unknown_reason="Access denied to subnet-xyz in account 123456789012",
        )
        summary = result.generate_human_summary()
        assert "Cannot determine reachability" in summary
        assert "Access denied" in summary
        assert "subnet-xyz" in summary

    def test_unknown_tgw_summary(self) -> None:
        """UNKNOWN due to Transit Gateway."""
        result = PathAnalysisResult(
            status=PathStatus.UNKNOWN,
            source_id="i-source",
            destination_ip="10.1.0.50",
            port=443,
            protocol="tcp",
            unknown_reason="Transit Gateway traversal not yet supported. "
            "Cannot determine reachability through tgw-12345.",
        )
        summary = result.generate_human_summary()
        assert "Cannot determine reachability" in summary
        assert "Transit Gateway" in summary

    def test_unknown_without_reason_uses_summary(self) -> None:
        """UNKNOWN without unknown_reason uses summary field."""
        result = PathAnalysisResult(
            status=PathStatus.UNKNOWN,
            source_id="i-source",
            destination_ip="10.0.2.50",
            port=443,
            protocol="tcp",
            summary="Permission error at cross-account boundary",
        )
        summary = result.generate_human_summary()
        assert "Cannot determine reachability" in summary
        assert "Permission error" in summary


class TestDiscoveredResource:
    """Tests for DiscoveredResource model."""

    def test_minimal_resource(self) -> None:
        """Can create resource with required fields."""
        resource = DiscoveredResource(
            id="i-12345",
            resource_type=NodeType.INSTANCE,
            resource_arn="arn:aws:ec2:us-east-1:123456789012:instance/i-12345",
        )
        assert resource.id == "i-12345"
        assert resource.name is None

    def test_resource_with_all_fields(self) -> None:
        """Resource with all optional fields."""
        resource = DiscoveredResource(
            id="i-12345",
            resource_type=NodeType.INSTANCE,
            resource_arn="arn:aws:ec2:us-east-1:123456789012:instance/i-12345",
            name="web-server-1",
            tags={"Environment": "prod", "Team": "backend"},
            vpc_id="vpc-12345",
            subnet_id="subnet-12345",
            availability_zone="us-east-1a",
            private_ip="10.0.1.50",
            public_ip="54.123.45.67",
        )
        assert resource.name == "web-server-1"
        assert resource.tags["Environment"] == "prod"
        assert resource.availability_zone == "us-east-1a"


class TestResourceDiscoveryResult:
    """Tests for ResourceDiscoveryResult model."""

    def test_empty_result(self) -> None:
        """Can create empty discovery result."""
        result = ResourceDiscoveryResult(
            vpc_id="vpc-12345",
            filters_applied={"name_pattern": "nonexistent-*"},
            total_found=0,
            resources=[],
        )
        assert result.total_found == 0
        assert result.truncated is False
        assert result.vpc_id == "vpc-12345"

    def test_result_with_resources(self) -> None:
        """Result with discovered resources."""
        result = ResourceDiscoveryResult(
            vpc_id="vpc-12345",
            filters_applied={"name_pattern": "web-*", "resource_types": ["instance"]},
            total_found=2,
            resources=[
                DiscoveredResource(
                    id="i-web1",
                    resource_type=NodeType.INSTANCE,
                    resource_arn="arn:...",
                    name="web-prod-1",
                ),
                DiscoveredResource(
                    id="i-web2",
                    resource_type=NodeType.INSTANCE,
                    resource_arn="arn:...",
                    name="web-prod-2",
                ),
            ],
        )
        assert result.total_found == 2

    def test_truncated_result(self) -> None:
        """Result can be truncated."""
        result = ResourceDiscoveryResult(
            vpc_id="vpc-12345",
            filters_applied={"tags": "Environment=prod"},
            total_found=100,
            resources=[],  # Would have 20 in real use
            truncated=True,
        )
        assert result.truncated is True


class TestExposedResource:
    """Tests for ExposedResource model."""

    def test_direct_exposure(self) -> None:
        """Direct internet exposure."""
        resource = ExposedResource(
            resource_id="i-12345",
            resource_type=NodeType.INSTANCE,
            resource_arn="arn:...",
            exposure_type="direct",
            exposure_path=["i-12345", "igw-12345"],
            open_port=22,
            protocol="tcp",
            allowing_sg_rule_id="rule-123",
            severity="critical",
            remediation="Remove 0.0.0.0/0 from inbound SSH rule",
        )
        assert resource.exposure_type == "direct"
        assert resource.severity == "critical"

    def test_indirect_exposure(self) -> None:
        """Indirect exposure through NAT."""
        resource = ExposedResource(
            resource_id="i-12345",
            resource_type=NodeType.INSTANCE,
            resource_arn="arn:...",
            exposure_type="indirect",
            exposure_path=["i-12345", "nat-12345", "igw-12345"],
            open_port=443,
            protocol="tcp",
            allowing_sg_rule_id="rule-456",
            severity="low",
            remediation="Review if outbound HTTPS is necessary",
        )
        assert resource.exposure_type == "indirect"


class TestPublicExposureResult:
    """Tests for PublicExposureResult model."""

    def test_exposure_scan_result(self) -> None:
        """Public exposure scan result."""
        result = PublicExposureResult(
            vpc_id="vpc-12345",
            port=22,
            protocol="tcp",
            total_exposed=3,
            exposed_resources=[],
            total_resources_scanned=100,
            scan_duration_seconds=1.5,
            summary="Found 3 resources with SSH exposed to internet",
            high_severity_count=1,
            critical_severity_count=2,
        )
        assert result.vpc_id == "vpc-12345"
        assert result.total_exposed == 3
        assert result.critical_severity_count == 2
        assert result.total_resources_scanned == 100
        assert result.scan_duration_seconds == 1.5


class TestTopologyRefreshResult:
    """Tests for TopologyRefreshResult model."""

    def test_successful_refresh(self) -> None:
        """Successful topology refresh."""
        result = TopologyRefreshResult(
            success=True,
            vpc_ids_processed=["vpc-12345", "vpc-67890"],
            node_count=150,
            edge_count=200,
            resources_by_type={"instances": 50, "enis": 75, "subnets": 10, "igws": 2},
            duration_seconds=5.5,
        )
        assert result.success is True
        assert result.node_count == 150

    def test_partial_failure(self) -> None:
        """Refresh with some VPCs failing."""
        result = TopologyRefreshResult(
            success=False,
            vpc_ids_processed=["vpc-12345"],
            vpc_ids_failed=["vpc-67890"],
            node_count=50,
            edge_count=75,
            duration_seconds=3.0,
            warnings=["Access denied to vpc-67890"],
        )
        assert result.success is False
        assert "vpc-67890" in result.vpc_ids_failed


class TestCacheStats:
    """Tests for CacheStats model."""

    def test_cache_stats(self) -> None:
        """Cache statistics."""
        stats = CacheStats(
            hits=100,
            misses=20,
            expired=5,
            size=115,
            oldest_entry=datetime(2024, 1, 1, 12, 0, 0),
            ttl_seconds=60,
            entries_expiring_soon=10,
        )
        assert stats.hits == 100
        assert stats.ttl_seconds == 60

    def test_empty_cache_stats(self) -> None:
        """Empty cache statistics."""
        stats = CacheStats(
            hits=0,
            misses=0,
            expired=0,
            size=0,
            ttl_seconds=60,
        )
        assert stats.oldest_entry is None
        assert stats.entries_expiring_soon == 0
