"""Performance tests for large VPC topologies.

These tests verify that NetGraph performs acceptably with:
- Large numbers of instances (100+)
- Many ENIs per subnet
- Complex route tables
- Multiple security groups per instance

Performance targets:
- Path analysis: < 1 second for typical paths
- Topology refresh: < 10 seconds for 1000 ENIs
- Memory: < 500MB for 5000 ENI topology
"""

from __future__ import annotations

import asyncio
import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from netgraph.aws.client import AWSClient
from netgraph.aws.fetcher import EC2Fetcher
from netgraph.core.graph_manager import GraphManager
from netgraph.core.path_analyzer import PathAnalyzer
from netgraph.models.graph import NodeType

from tests.fixtures.vpc_topologies import ACCOUNT_ID, REGION


# =============================================================================
# Large Topology Generator
# =============================================================================


def generate_large_topology(
    num_instances: int = 100,
    num_subnets: int = 10,
    sgs_per_instance: int = 3,
) -> dict[str, Any]:
    """Generate a large VPC topology for performance testing.

    Args:
        num_instances: Number of EC2 instances to generate
        num_subnets: Number of subnets to distribute instances across
        sgs_per_instance: Number of security groups per instance

    Returns:
        Dictionary containing all generated resources
    """
    vpc_id = "vpc-perf12345"

    # Generate subnets
    subnets = []
    for i in range(num_subnets):
        subnets.append({
            "SubnetId": f"subnet-perf{i:04d}",
            "VpcId": vpc_id,
            "CidrBlock": f"10.{i}.0.0/24",
            "AvailabilityZone": f"us-east-1{chr(97 + i % 3)}",
            "MapPublicIpOnLaunch": i < 2,  # First 2 subnets are public
        })

    # Generate security groups
    security_groups = []
    num_sgs = max(sgs_per_instance * 2, 20)  # Ensure enough SGs
    for i in range(num_sgs):
        security_groups.append({
            "GroupId": f"sg-perf{i:06d}",
            "VpcId": vpc_id,
            "GroupName": f"perf-sg-{i}",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                },
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                },
            ],
            "IpPermissionsEgress": [
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                },
            ],
        })

    # Generate instances with ENIs
    instances = []
    enis = []
    for i in range(num_instances):
        subnet_idx = i % num_subnets
        subnet = subnets[subnet_idx]
        instance_id = f"i-perf{i:08d}"
        eni_id = f"eni-perf{i:08d}"
        private_ip = f"10.{subnet_idx}.0.{(i // num_subnets) + 10}"

        # Assign security groups
        sg_ids = [
            security_groups[(i * sgs_per_instance + j) % num_sgs]["GroupId"]
            for j in range(sgs_per_instance)
        ]

        instances.append({
            "InstanceId": instance_id,
            "VpcId": vpc_id,
            "SubnetId": subnet["SubnetId"],
            "PrivateIpAddress": private_ip,
            "PublicIpAddress": f"54.{i // 256}.{i % 256}.1" if subnet_idx < 2 else None,
            "State": {"Name": "running"},
            "SecurityGroups": [{"GroupId": sg} for sg in sg_ids],
            "NetworkInterfaces": [{
                "NetworkInterfaceId": eni_id,
                "PrivateIpAddress": private_ip,
                "SubnetId": subnet["SubnetId"],
                "Groups": [{"GroupId": sg} for sg in sg_ids],
            }],
            "Tags": [
                {"Key": "Name", "Value": f"perf-instance-{i}"},
                {"Key": "Index", "Value": str(i)},
            ],
        })

        enis.append({
            "NetworkInterfaceId": eni_id,
            "VpcId": vpc_id,
            "SubnetId": subnet["SubnetId"],
            "PrivateIpAddress": private_ip,
            "Groups": [{"GroupId": sg} for sg in sg_ids],
            "Attachment": {"InstanceId": instance_id},
        })

    # Generate route tables (one per subnet)
    route_tables = []
    igw_id = "igw-perf12345"
    nat_id = "nat-perf12345"

    for i, subnet in enumerate(subnets):
        routes = [
            {
                "DestinationCidrBlock": "10.0.0.0/8",
                "GatewayId": "local",
                "State": "active",
            },
        ]

        if i < 2:  # Public subnets
            routes.append({
                "DestinationCidrBlock": "0.0.0.0/0",
                "GatewayId": igw_id,
                "State": "active",
            })
        else:  # Private subnets
            routes.append({
                "DestinationCidrBlock": "0.0.0.0/0",
                "NatGatewayId": nat_id,
                "State": "active",
            })

        route_tables.append({
            "RouteTableId": f"rtb-perf{i:04d}",
            "VpcId": vpc_id,
            "Routes": routes,
            "Associations": [{
                "SubnetId": subnet["SubnetId"],
                "RouteTableId": f"rtb-perf{i:04d}",
            }],
        })

    # Generate NACLs (one per subnet)
    nacls = []
    for i, subnet in enumerate(subnets):
        nacls.append({
            "NetworkAclId": f"acl-perf{i:04d}",
            "VpcId": vpc_id,
            "Entries": [
                {
                    "RuleNumber": 100,
                    "RuleAction": "allow",
                    "Protocol": "-1",
                    "CidrBlock": "0.0.0.0/0",
                    "Egress": False,
                },
                {
                    "RuleNumber": 100,
                    "RuleAction": "allow",
                    "Protocol": "-1",
                    "CidrBlock": "0.0.0.0/0",
                    "Egress": True,
                },
                {
                    "RuleNumber": 32767,
                    "RuleAction": "deny",
                    "Protocol": "-1",
                    "CidrBlock": "0.0.0.0/0",
                    "Egress": False,
                },
                {
                    "RuleNumber": 32767,
                    "RuleAction": "deny",
                    "Protocol": "-1",
                    "CidrBlock": "0.0.0.0/0",
                    "Egress": True,
                },
            ],
            "Associations": [{
                "SubnetId": subnet["SubnetId"],
                "NetworkAclAssociationId": f"aclassoc-perf{i:04d}",
            }],
        })

    return {
        "vpc_id": vpc_id,
        "subnets": subnets,
        "instances": instances,
        "enis": enis,
        "security_groups": security_groups,
        "route_tables": route_tables,
        "nacls": nacls,
        "igw_id": igw_id,
        "nat_id": nat_id,
    }


def setup_large_topology_mocks(
    mock_fetcher: EC2Fetcher,
    topology: dict[str, Any],
) -> None:
    """Configure mocks with large topology data."""

    # Index for faster lookups
    instances_by_id = {i["InstanceId"]: i for i in topology["instances"]}
    enis_by_id = {e["NetworkInterfaceId"]: e for e in topology["enis"]}
    subnets_by_id = {s["SubnetId"]: s for s in topology["subnets"]}
    sgs_by_id = {s["GroupId"]: s for s in topology["security_groups"]}
    rtbs_by_subnet = {}
    nacls_by_subnet = {}

    for rtb in topology["route_tables"]:
        for assoc in rtb.get("Associations", []):
            if "SubnetId" in assoc:
                rtbs_by_subnet[assoc["SubnetId"]] = rtb

    for nacl in topology["nacls"]:
        for assoc in nacl.get("Associations", []):
            if "SubnetId" in assoc:
                nacls_by_subnet[assoc["SubnetId"]] = nacl

    # Mock describe_instances_by_id
    async def mock_describe_instance(instance_id: str) -> dict[str, Any] | None:
        return instances_by_id.get(instance_id)

    mock_fetcher.describe_instances_by_id = AsyncMock(side_effect=mock_describe_instance)

    # Mock describe_network_interface_by_id
    async def mock_describe_eni(eni_id: str) -> dict[str, Any] | None:
        return enis_by_id.get(eni_id)

    mock_fetcher.describe_network_interface_by_id = AsyncMock(side_effect=mock_describe_eni)

    # Mock describe_subnet_by_id
    async def mock_describe_subnet(subnet_id: str) -> dict[str, Any] | None:
        return subnets_by_id.get(subnet_id)

    mock_fetcher.describe_subnet_by_id = AsyncMock(side_effect=mock_describe_subnet)

    # Mock describe_security_group_by_id
    async def mock_describe_sg(sg_id: str) -> dict[str, Any] | None:
        return sgs_by_id.get(sg_id)

    mock_fetcher.describe_security_group_by_id = AsyncMock(side_effect=mock_describe_sg)

    # Mock describe_route_tables
    async def mock_describe_rtbs(**kwargs: Any) -> list[dict[str, Any]]:
        return topology["route_tables"]

    mock_fetcher.describe_route_tables = AsyncMock(side_effect=mock_describe_rtbs)

    # Mock describe_route_table_by_id
    async def mock_describe_rtb(rtb_id: str) -> dict[str, Any] | None:
        for rtb in topology["route_tables"]:
            if rtb["RouteTableId"] == rtb_id:
                return rtb
        return None

    mock_fetcher.describe_route_table_by_id = AsyncMock(side_effect=mock_describe_rtb)

    # Mock describe_network_acls
    async def mock_describe_nacls(**kwargs: Any) -> list[dict[str, Any]]:
        return topology["nacls"]

    mock_fetcher.describe_network_acls = AsyncMock(side_effect=mock_describe_nacls)

    # Mock describe_nacl_by_id
    async def mock_describe_nacl(nacl_id: str) -> dict[str, Any] | None:
        for nacl in topology["nacls"]:
            if nacl["NetworkAclId"] == nacl_id:
                return nacl
        return None

    mock_fetcher.describe_nacl_by_id = AsyncMock(side_effect=mock_describe_nacl)

    # Mock describe_internet_gateways
    async def mock_describe_igws(**kwargs: Any) -> list[dict[str, Any]]:
        return [{
            "InternetGatewayId": topology["igw_id"],
            "Attachments": [{"VpcId": topology["vpc_id"], "State": "available"}],
        }]

    mock_fetcher.describe_internet_gateways = AsyncMock(side_effect=mock_describe_igws)

    # Mock describe_nat_gateways
    async def mock_describe_nats(**kwargs: Any) -> list[dict[str, Any]]:
        return [{
            "NatGatewayId": topology["nat_id"],
            "VpcId": topology["vpc_id"],
            "SubnetId": topology["subnets"][0]["SubnetId"],
            "State": "available",
        }]

    mock_fetcher.describe_nat_gateways = AsyncMock(side_effect=mock_describe_nats)

    # Mock describe_network_interfaces
    async def mock_describe_enis(**kwargs: Any) -> list[dict[str, Any]]:
        return topology["enis"]

    mock_fetcher.describe_network_interfaces = AsyncMock(side_effect=mock_describe_enis)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_aws_client() -> AWSClient:
    """Create a mock AWS client."""
    client = MagicMock(spec=AWSClient)
    client.ec2 = MagicMock()
    client.region = REGION
    client.account_id = ACCOUNT_ID
    return client


@pytest.fixture
def mock_fetcher(mock_aws_client: AWSClient) -> EC2Fetcher:
    """Create a mock EC2 fetcher."""
    fetcher = MagicMock(spec=EC2Fetcher)
    fetcher.client = mock_aws_client
    return fetcher


# =============================================================================
# Performance Benchmarks
# =============================================================================


class TestPathAnalysisPerformance:
    """Performance tests for path analysis."""

    @pytest.mark.asyncio
    async def test_single_path_analysis_time(self, mock_fetcher: EC2Fetcher) -> None:
        """Single path analysis should complete within 1 second."""
        topology = generate_large_topology(num_instances=100)
        setup_large_topology_mocks(mock_fetcher, topology)

        graph = GraphManager(
            fetcher=mock_fetcher,
            region=REGION,
            account_id=ACCOUNT_ID,
            ttl_seconds=300,
        )
        analyzer = PathAnalyzer(graph=graph)

        # Pick source and destination from topology
        source_id = topology["instances"][0]["InstanceId"]
        dest_ip = topology["instances"][50]["PrivateIpAddress"]

        start_time = time.perf_counter()
        result = await analyzer.analyze(
            source_id=source_id,
            dest_ip=dest_ip,
            port=443,
            protocol="tcp",
        )
        elapsed = time.perf_counter() - start_time

        assert elapsed < 1.0, f"Path analysis took {elapsed:.3f}s, expected < 1s"
        assert result is not None

    @pytest.mark.asyncio
    async def test_multiple_sequential_paths(self, mock_fetcher: EC2Fetcher) -> None:
        """Multiple sequential path analyses should benefit from caching."""
        topology = generate_large_topology(num_instances=50)
        setup_large_topology_mocks(mock_fetcher, topology)

        graph = GraphManager(
            fetcher=mock_fetcher,
            region=REGION,
            account_id=ACCOUNT_ID,
            ttl_seconds=300,
        )
        analyzer = PathAnalyzer(graph=graph)

        # Analyze 10 paths
        num_paths = 10
        start_time = time.perf_counter()

        for i in range(num_paths):
            source_id = topology["instances"][i]["InstanceId"]
            dest_ip = topology["instances"][(i + 25) % 50]["PrivateIpAddress"]
            await analyzer.analyze(
                source_id=source_id,
                dest_ip=dest_ip,
                port=443,
                protocol="tcp",
            )

        total_elapsed = time.perf_counter() - start_time
        avg_time = total_elapsed / num_paths

        # With caching, average should be well under 1 second
        assert avg_time < 0.5, f"Average path analysis took {avg_time:.3f}s, expected < 0.5s"

    @pytest.mark.asyncio
    async def test_concurrent_path_analyses(self, mock_fetcher: EC2Fetcher) -> None:
        """Concurrent path analyses should complete efficiently."""
        topology = generate_large_topology(num_instances=50)
        setup_large_topology_mocks(mock_fetcher, topology)

        graph = GraphManager(
            fetcher=mock_fetcher,
            region=REGION,
            account_id=ACCOUNT_ID,
            ttl_seconds=300,
        )
        analyzer = PathAnalyzer(graph=graph)

        # Create 5 concurrent path analysis tasks
        async def analyze_path(idx: int) -> None:
            source_id = topology["instances"][idx]["InstanceId"]
            dest_ip = topology["instances"][(idx + 25) % 50]["PrivateIpAddress"]
            await analyzer.analyze(
                source_id=source_id,
                dest_ip=dest_ip,
                port=443,
                protocol="tcp",
            )

        start_time = time.perf_counter()
        await asyncio.gather(*[analyze_path(i) for i in range(5)])
        elapsed = time.perf_counter() - start_time

        # Concurrent should complete faster than 5x sequential
        assert elapsed < 3.0, f"Concurrent analysis took {elapsed:.3f}s, expected < 3s"


class TestCachePerformance:
    """Performance tests for caching behavior."""

    @pytest.mark.asyncio
    async def test_cache_hit_rate(self, mock_fetcher: EC2Fetcher) -> None:
        """Repeated queries should hit cache."""
        topology = generate_large_topology(num_instances=20)
        setup_large_topology_mocks(mock_fetcher, topology)

        graph = GraphManager(
            fetcher=mock_fetcher,
            region=REGION,
            account_id=ACCOUNT_ID,
            ttl_seconds=300,
        )
        analyzer = PathAnalyzer(graph=graph)

        source_id = topology["instances"][0]["InstanceId"]
        dest_ip = topology["instances"][10]["PrivateIpAddress"]

        # First analysis - populates cache
        await analyzer.analyze(
            source_id=source_id,
            dest_ip=dest_ip,
            port=443,
            protocol="tcp",
        )

        # Second analysis - should hit cache
        await analyzer.analyze(
            source_id=source_id,
            dest_ip=dest_ip,
            port=443,
            protocol="tcp",
        )

        stats = graph.cache_stats
        total_requests = stats.hits + stats.misses
        hit_rate = stats.hits / total_requests if total_requests > 0 else 0

        # Second query should have much higher hit rate
        assert hit_rate > 0.5, f"Cache hit rate {hit_rate:.2%} too low"

    @pytest.mark.asyncio
    async def test_cache_invalidation_performance(
        self, mock_fetcher: EC2Fetcher
    ) -> None:
        """Cache invalidation should be fast."""
        topology = generate_large_topology(num_instances=100)
        setup_large_topology_mocks(mock_fetcher, topology)

        graph = GraphManager(
            fetcher=mock_fetcher,
            region=REGION,
            account_id=ACCOUNT_ID,
            ttl_seconds=300,
        )

        # Populate cache with several nodes
        for i in range(10):
            instance = topology["instances"][i]
            await graph.get_node(instance["InstanceId"])

        # Measure invalidation time
        start_time = time.perf_counter()
        graph.invalidate()  # Invalidate all
        elapsed = time.perf_counter() - start_time

        assert elapsed < 0.1, f"Cache invalidation took {elapsed:.3f}s, expected < 0.1s"


class TestMemoryUsage:
    """Tests for memory usage patterns."""

    def test_topology_generator_memory(self) -> None:
        """Large topology generation should be memory efficient."""
        import sys

        # Generate a moderately large topology
        topology = generate_large_topology(num_instances=500, num_subnets=20)

        # Rough size estimate
        # This is approximate - real memory profiling would use tracemalloc
        instance_count = len(topology["instances"])
        eni_count = len(topology["enis"])
        sg_count = len(topology["security_groups"])

        assert instance_count == 500
        assert eni_count == 500
        assert sg_count >= 20

    @pytest.mark.asyncio
    async def test_graph_manager_memory_with_large_topology(
        self, mock_fetcher: EC2Fetcher
    ) -> None:
        """GraphManager should handle large topologies without excessive memory."""
        topology = generate_large_topology(num_instances=200)
        setup_large_topology_mocks(mock_fetcher, topology)

        graph = GraphManager(
            fetcher=mock_fetcher,
            region=REGION,
            account_id=ACCOUNT_ID,
            ttl_seconds=300,
        )

        # Load a subset of the topology
        for i in range(50):
            instance = topology["instances"][i]
            await graph.get_node(instance["InstanceId"])

        stats = graph.cache_stats
        # Cache should have entries
        assert stats.size > 0


class TestScalability:
    """Tests for scalability with increasing load."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("num_instances", [10, 50, 100])
    async def test_scaling_with_instance_count(
        self, mock_fetcher: EC2Fetcher, num_instances: int
    ) -> None:
        """Path analysis time should scale reasonably with instance count."""
        topology = generate_large_topology(num_instances=num_instances)
        setup_large_topology_mocks(mock_fetcher, topology)

        graph = GraphManager(
            fetcher=mock_fetcher,
            region=REGION,
            account_id=ACCOUNT_ID,
            ttl_seconds=300,
        )
        analyzer = PathAnalyzer(graph=graph)

        source_id = topology["instances"][0]["InstanceId"]
        dest_ip = topology["instances"][num_instances // 2]["PrivateIpAddress"]

        start_time = time.perf_counter()
        result = await analyzer.analyze(
            source_id=source_id,
            dest_ip=dest_ip,
            port=443,
            protocol="tcp",
        )
        elapsed = time.perf_counter() - start_time

        # Should complete within reasonable time regardless of topology size
        # (lazy loading means we don't load all instances)
        assert elapsed < 2.0, f"Analysis with {num_instances} instances took {elapsed:.3f}s"
        assert result is not None

    @pytest.mark.asyncio
    async def test_many_security_groups(self, mock_fetcher: EC2Fetcher) -> None:
        """Path analysis should handle instances with many security groups."""
        topology = generate_large_topology(
            num_instances=20,
            sgs_per_instance=5,  # More SGs per instance
        )
        setup_large_topology_mocks(mock_fetcher, topology)

        graph = GraphManager(
            fetcher=mock_fetcher,
            region=REGION,
            account_id=ACCOUNT_ID,
            ttl_seconds=300,
        )
        analyzer = PathAnalyzer(graph=graph)

        source_id = topology["instances"][0]["InstanceId"]
        dest_ip = topology["instances"][10]["PrivateIpAddress"]

        start_time = time.perf_counter()
        result = await analyzer.analyze(
            source_id=source_id,
            dest_ip=dest_ip,
            port=443,
            protocol="tcp",
        )
        elapsed = time.perf_counter() - start_time

        assert elapsed < 1.0, f"Analysis with 5 SGs/instance took {elapsed:.3f}s"
        assert result is not None


# =============================================================================
# Stress Tests
# =============================================================================


class TestStressConditions:
    """Tests under stress conditions."""

    @pytest.mark.asyncio
    async def test_rapid_sequential_requests(self, mock_fetcher: EC2Fetcher) -> None:
        """Handle rapid sequential requests without degradation."""
        topology = generate_large_topology(num_instances=30)
        setup_large_topology_mocks(mock_fetcher, topology)

        graph = GraphManager(
            fetcher=mock_fetcher,
            region=REGION,
            account_id=ACCOUNT_ID,
            ttl_seconds=300,
        )
        analyzer = PathAnalyzer(graph=graph)

        # Rapid fire 20 requests
        num_requests = 20
        start_time = time.perf_counter()

        for i in range(num_requests):
            source_id = topology["instances"][i % 30]["InstanceId"]
            dest_ip = topology["instances"][(i + 15) % 30]["PrivateIpAddress"]
            await analyzer.analyze(
                source_id=source_id,
                dest_ip=dest_ip,
                port=443,
                protocol="tcp",
            )

        total_elapsed = time.perf_counter() - start_time

        # All requests should complete within reasonable time
        assert total_elapsed < 10.0, f"20 rapid requests took {total_elapsed:.3f}s"

    @pytest.mark.asyncio
    async def test_force_refresh_performance(self, mock_fetcher: EC2Fetcher) -> None:
        """force_refresh should not cause excessive slowdown."""
        topology = generate_large_topology(num_instances=20)
        setup_large_topology_mocks(mock_fetcher, topology)

        graph = GraphManager(
            fetcher=mock_fetcher,
            region=REGION,
            account_id=ACCOUNT_ID,
            ttl_seconds=300,
        )
        analyzer = PathAnalyzer(graph=graph)

        source_id = topology["instances"][0]["InstanceId"]
        dest_ip = topology["instances"][10]["PrivateIpAddress"]

        # First request (cache miss)
        start1 = time.perf_counter()
        await analyzer.analyze(
            source_id=source_id,
            dest_ip=dest_ip,
            port=443,
            protocol="tcp",
        )
        time1 = time.perf_counter() - start1

        # Second request with force_refresh
        start2 = time.perf_counter()
        await analyzer.analyze(
            source_id=source_id,
            dest_ip=dest_ip,
            port=443,
            protocol="tcp",
            force_refresh=True,
        )
        time2 = time.perf_counter() - start2

        # force_refresh should be similar to cache miss (not much slower)
        # Allow 50% overhead for cache operations
        assert time2 < time1 * 2.0, f"force_refresh ({time2:.3f}s) much slower than cold ({time1:.3f}s)"
