"""MCP Server entry point for NetGraph.

This module implements the MCP server that exposes network path analysis,
topology refresh, public exposure detection, and resource discovery tools.

The server uses FastMCP with lifespan management to initialize and share
AWS clients and GraphManager across all tool handlers.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from mcp.server.fastmcp import Context, FastMCP

from netgraph.aws.client import AWSClientFactory, RetryConfig
from netgraph.aws.fetcher import EC2Fetcher
from netgraph.core.graph_manager import GraphManager
from netgraph.core.path_analyzer import PathAnalyzer
from netgraph.models.errors import NetGraphError, ValidationError
from netgraph.utils.logging import get_logger, setup_logging

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from netgraph.models import (
        CacheStats,
        PathAnalysisResult,
        PublicExposureResult,
        ResourceDiscoveryResult,
        TopologyRefreshResult,
    )

logger = get_logger(__name__)

# Default configuration
DEFAULT_REGION = "us-east-1"
DEFAULT_TTL_SECONDS = 60
DEFAULT_MAX_RESULTS = 50


@dataclass
class AppContext:
    """Application context shared across all tool handlers.

    Attributes:
        graph_manager: GraphManager with read-through cache
        path_analyzer: PathAnalyzer for network path analysis
        fetcher: EC2Fetcher for direct AWS queries
        region: AWS region
        account_id: AWS account ID
    """

    graph_manager: GraphManager
    path_analyzer: PathAnalyzer
    fetcher: EC2Fetcher
    region: str
    account_id: str


@asynccontextmanager
async def app_lifespan(_server: FastMCP) -> AsyncIterator[AppContext]:
    """Initialize and clean up application resources.

    This lifespan manager:
    1. Creates AWS client using environment credentials or profile
    2. Initializes EC2Fetcher with retry configuration
    3. Creates GraphManager with configurable TTL
    4. Creates PathAnalyzer for path analysis

    Environment variables:
        AWS_REGION: AWS region (default: us-east-1)
        AWS_PROFILE: AWS profile name (optional)
        NETGRAPH_TTL: Cache TTL in seconds (default: 60)
        NETGRAPH_ROLE_ARN: Role ARN for cross-account access (optional)

    Args:
        server: FastMCP server instance

    Yields:
        AppContext with initialized resources
    """
    # Get configuration from environment
    region = os.environ.get("AWS_REGION", DEFAULT_REGION)
    profile = os.environ.get("AWS_PROFILE")
    ttl_seconds = int(os.environ.get("NETGRAPH_TTL", str(DEFAULT_TTL_SECONDS)))
    role_arn = os.environ.get("NETGRAPH_ROLE_ARN")

    logger.info(f"Initializing NetGraph MCP server in region {region}")

    # Create AWS client factory with region and profile
    factory = AWSClientFactory(region=region, profile=profile)

    if role_arn:
        logger.info(f"Using cross-account role: {role_arn}")
        aws_client = await factory.create_cross_account_client(
            role_arn=role_arn,
            session_name="netgraph-mcp",
        )
    else:
        if profile:
            logger.info(f"Using AWS profile: {profile}")
        else:
            logger.info("Using default AWS credentials")
        aws_client = factory.create_client()

    # Create EC2Fetcher with retry configuration
    retry_config = RetryConfig(
        initial_delay=0.5,
        multiplier=2.0,
        max_delay=30.0,
        max_retries=5,
        jitter=True,
    )
    fetcher = EC2Fetcher(client=aws_client, retry_config=retry_config)

    # Create GraphManager
    graph_manager = GraphManager(
        fetcher=fetcher,
        region=region,
        account_id=aws_client.account_id or "unknown",
        ttl_seconds=ttl_seconds,
    )

    # Create PathAnalyzer
    path_analyzer = PathAnalyzer(graph=graph_manager)

    logger.info(
        f"NetGraph initialized: region={region}, account={aws_client.account_id}, ttl={ttl_seconds}s"
    )

    try:
        yield AppContext(
            graph_manager=graph_manager,
            path_analyzer=path_analyzer,
            fetcher=fetcher,
            region=region,
            account_id=aws_client.account_id or "unknown",
        )
    finally:
        logger.info("Shutting down NetGraph MCP server")


# Create FastMCP server instance
mcp = FastMCP(
    name="NetGraph",
    lifespan=app_lifespan,
)


def _get_app_context(ctx: Context) -> AppContext:  # type: ignore[type-arg]
    """Extract AppContext from MCP Context.

    Args:
        ctx: MCP Context with request context

    Returns:
        AppContext with shared resources

    Raises:
        RuntimeError: If context is not properly initialized
    """
    app_ctx = ctx.request_context.lifespan_context
    if not isinstance(app_ctx, AppContext):
        raise RuntimeError("Application context not initialized")
    return app_ctx


# =============================================================================
# Tool Handlers
# =============================================================================


@mcp.tool()
async def analyze_path(
    source_id: str,
    destination_ip: str,
    port: int,
    protocol: str = "tcp",
    force_refresh: bool = False,
    ctx: Context = None,  # type: ignore
) -> dict[str, Any]:
    """Analyze network path between a source resource and destination IP.

    Evaluates Security Groups, NACLs, and route tables along the path using
    deterministic LPM (Longest Prefix Match) routing traversal.

    Args:
        source_id: Source resource ID (i-xxx for instance, eni-xxx for ENI)
        destination_ip: Destination IP address (IPv4 or IPv6)
        port: Destination port number (1-65535)
        protocol: Protocol - "tcp", "udp", "icmp", or "-1" for all (default: tcp)
        force_refresh: If True, bypass cache and fetch fresh data from AWS
        ctx: MCP context (injected automatically)

    Returns:
        Dictionary containing:
        - status: "REACHABLE", "BLOCKED", or "UNKNOWN"
        - summary: Human-readable explanation
        - hops: List of network hops with evaluation details
        - blocked_at: Details of blocking point (if BLOCKED)
        - unknown_reason: Explanation (if UNKNOWN)
        - evaluated_security_groups: List of SG IDs evaluated
        - evaluated_nacls: List of NACL IDs evaluated
        - route_path: List of route table IDs traversed

    Examples:
        >>> analyze_path("i-1234567890abcdef0", "10.0.2.50", 443)
        {"status": "REACHABLE", "summary": "Traffic Allowed: ...", ...}

        >>> analyze_path("eni-abcdef123456", "8.8.8.8", 80, protocol="tcp")
        {"status": "BLOCKED", "blocked_at": {"sg_eval": ...}, ...}
    """
    # Validate inputs
    if not source_id:
        raise ValidationError(
            message="source_id is required",
            field="source_id",
            expected="i-xxx or eni-xxx",
        )

    if not source_id.startswith(("i-", "eni-")):
        raise ValidationError(
            message="source_id must be an instance ID (i-xxx) or ENI ID (eni-xxx)",
            field="source_id",
            expected="i-xxx or eni-xxx",
        )

    if not destination_ip:
        raise ValidationError(
            message="destination_ip is required",
            field="destination_ip",
            expected="IPv4 or IPv6 address",
        )

    if not 1 <= port <= 65535:
        raise ValidationError(
            message=f"port must be between 1 and 65535, got {port}",
            field="port",
            expected="1-65535",
        )

    protocol = protocol.lower()
    if protocol not in ("tcp", "udp", "icmp", "-1"):
        raise ValidationError(
            message=f"Invalid protocol: {protocol}",
            field="protocol",
            expected="tcp, udp, icmp, or -1",
        )

    app_ctx = _get_app_context(ctx)

    try:
        result = await app_ctx.path_analyzer.analyze(
            source_id=source_id,
            dest_ip=destination_ip,
            port=port,
            protocol=protocol,
            force_refresh=force_refresh,
        )

        return _path_result_to_dict(result)

    except NetGraphError as e:
        logger.warning(f"Path analysis failed: {e}")
        return e.to_response()


@mcp.tool()
async def refresh_topology(
    vpc_ids: list[str],
    ctx: Context = None,  # type: ignore
) -> dict[str, Any]:
    """Pre-warm the topology cache by fetching all resources in specified VPCs.

    This is an OPTIONAL optimization. The graph manager will fetch resources
    on-demand if this is not called. Pre-warming can improve response times
    for subsequent analyze_path calls.

    Args:
        vpc_ids: List of VPC IDs to pre-warm (e.g., ["vpc-12345678", "vpc-87654321"])
        ctx: MCP context (injected automatically)

    Returns:
        Dictionary containing:
        - success: True if all VPCs processed successfully
        - vpc_ids_processed: List of VPCs that were successfully processed
        - vpc_ids_failed: List of VPCs that failed to process
        - node_count: Total number of nodes in the graph
        - edge_count: Total number of edges in the graph
        - resources_by_type: Count of each resource type fetched
        - duration_seconds: Time taken to build topology
        - warnings: List of non-fatal warnings

    Examples:
        >>> refresh_topology(["vpc-12345678"])
        {"success": True, "node_count": 42, "resources_by_type": {...}, ...}
    """
    if not vpc_ids:
        raise ValidationError(
            message="vpc_ids is required and cannot be empty",
            field="vpc_ids",
            expected="List of VPC IDs (vpc-xxx)",
        )

    for vpc_id in vpc_ids:
        if not vpc_id.startswith("vpc-"):
            raise ValidationError(
                message=f"Invalid VPC ID format: {vpc_id}",
                field="vpc_ids",
                expected="vpc-xxx",
            )

    app_ctx = _get_app_context(ctx)

    try:
        result = await app_ctx.graph_manager.build_topology(vpc_ids=vpc_ids)
        return _topology_result_to_dict(result)

    except NetGraphError as e:
        logger.warning(f"Topology refresh failed: {e}")
        return e.to_response()


@mcp.tool()
async def find_public_exposure(
    vpc_id: str,
    port: int,
    protocol: str = "tcp",
    force_refresh: bool = False,
    ctx: Context = None,  # type: ignore
) -> dict[str, Any]:
    """Find resources in a VPC that are exposed to the public internet on a port.

    Scans all ENIs in the VPC and checks if they have:
    1. A route to an Internet Gateway (IGW)
    2. Security Group rules allowing inbound traffic on the specified port
    3. NACL rules allowing the traffic

    Args:
        vpc_id: VPC ID to scan (vpc-xxx)
        port: Port number to check for exposure (1-65535)
        protocol: Protocol - "tcp", "udp", or "-1" for all (default: tcp)
        force_refresh: If True, bypass cache and fetch fresh data
        ctx: MCP context (injected automatically)

    Returns:
        Dictionary containing:
        - vpc_id: The scanned VPC ID
        - port: The port checked
        - protocol: The protocol checked
        - exposed_resources: List of exposed resources with details
        - total_resources_scanned: Number of ENIs scanned
        - scan_duration_seconds: Time taken for the scan

    Examples:
        >>> find_public_exposure("vpc-12345678", 22)
        {"exposed_resources": [{"resource_id": "i-xxx", "exposure_path": [...]}], ...}
    """
    if not vpc_id:
        raise ValidationError(
            message="vpc_id is required",
            field="vpc_id",
            expected="vpc-xxx",
        )

    if not vpc_id.startswith("vpc-"):
        raise ValidationError(
            message=f"Invalid VPC ID format: {vpc_id}",
            field="vpc_id",
            expected="vpc-xxx",
        )

    if not 1 <= port <= 65535:
        raise ValidationError(
            message=f"port must be between 1 and 65535, got {port}",
            field="port",
            expected="1-65535",
        )

    protocol = protocol.lower()
    if protocol not in ("tcp", "udp", "-1"):
        raise ValidationError(
            message=f"Invalid protocol for exposure check: {protocol}",
            field="protocol",
            expected="tcp, udp, or -1",
        )

    app_ctx = _get_app_context(ctx)

    try:
        # Import here to avoid circular dependency
        from netgraph.core.exposure_detector import ExposureDetector

        detector = ExposureDetector(
            graph=app_ctx.graph_manager,
            fetcher=app_ctx.fetcher,
        )

        result = await detector.find_exposed(
            vpc_id=vpc_id,
            port=port,
            protocol=protocol,
            force_refresh=force_refresh,
        )

        return _exposure_result_to_dict(result)

    except NetGraphError as e:
        logger.warning(f"Exposure detection failed: {e}")
        return e.to_response()


@mcp.tool()
async def find_resources(
    vpc_id: str,
    tags: dict[str, str] | None = None,
    resource_types: list[str] | None = None,
    name_pattern: str | None = None,
    max_results: int = DEFAULT_MAX_RESULTS,
    ctx: Context = None,  # type: ignore
) -> dict[str, Any]:
    """Find AWS resources in a VPC by tags, type, or name pattern.

    This tool enables natural language resource discovery by allowing
    flexible tag-based and pattern-based queries.

    Args:
        vpc_id: VPC ID to search in (vpc-xxx)
        tags: Optional tag filters as key-value pairs (e.g., {"Environment": "prod"})
        resource_types: Optional list of resource types to include
                       ("instance", "eni", "subnet", "igw", "nat")
        name_pattern: Optional pattern to match against Name tag (case-insensitive)
        max_results: Maximum number of results to return (default: 50, max: 50)
        ctx: MCP context (injected automatically)

    Returns:
        Dictionary containing:
        - vpc_id: The searched VPC ID
        - resources: List of matching resources with details
        - total_found: Total number of matches (may exceed max_results)
        - truncated: True if results were capped at max_results
        - filters_applied: Summary of applied filters

    Examples:
        >>> find_resources("vpc-12345678", tags={"Environment": "production"})
        {"resources": [{"id": "i-xxx", "name": "web-server", ...}], ...}

        >>> find_resources("vpc-12345678", name_pattern="web-*", resource_types=["instance"])
        {"resources": [...], "total_found": 5, ...}
    """
    if not vpc_id:
        raise ValidationError(
            message="vpc_id is required",
            field="vpc_id",
            expected="vpc-xxx",
        )

    if not vpc_id.startswith("vpc-"):
        raise ValidationError(
            message=f"Invalid VPC ID format: {vpc_id}",
            field="vpc_id",
            expected="vpc-xxx",
        )

    # Cap max_results to prevent context overflow
    if max_results > DEFAULT_MAX_RESULTS:
        logger.warning(f"max_results {max_results} exceeds limit, capping to {DEFAULT_MAX_RESULTS}")
        max_results = DEFAULT_MAX_RESULTS

    if max_results < 1:
        max_results = 1

    # Validate resource types if provided
    valid_types = {"instance", "eni", "subnet", "igw", "nat", "peering", "tgw"}
    if resource_types:
        for rt in resource_types:
            if rt.lower() not in valid_types:
                raise ValidationError(
                    message=f"Invalid resource type: {rt}",
                    field="resource_types",
                    expected=f"One of: {', '.join(sorted(valid_types))}",
                )

    app_ctx = _get_app_context(ctx)

    try:
        # Import here to avoid circular dependency
        from netgraph.core.resource_discovery import ResourceDiscovery

        discovery = ResourceDiscovery(
            graph=app_ctx.graph_manager,
            fetcher=app_ctx.fetcher,
        )

        result = await discovery.find(
            vpc_id=vpc_id,
            tags=tags,
            resource_types=resource_types,
            name_pattern=name_pattern,
            max_results=max_results,
        )

        return _discovery_result_to_dict(result)

    except NetGraphError as e:
        logger.warning(f"Resource discovery failed: {e}")
        return e.to_response()


@mcp.tool()
async def list_vpcs(
    name_pattern: str | None = None,
    tags: dict[str, str] | None = None,
    cidr: str | None = None,
    ctx: Context = None,  # type: ignore
) -> dict[str, Any]:
    """List VPCs in the account, optionally filtered by name, tags, or CIDR.

    Use this tool to discover VPC IDs when you know the VPC by name or tags
    but need the VPC ID for other tools like find_resources or find_public_exposure.

    Args:
        name_pattern: Optional pattern to match VPC Name tag (case-insensitive,
                     supports wildcards like "prod-*" or "*-web-*")
        tags: Optional tag filters as key-value pairs (e.g., {"Environment": "prod"})
        cidr: Optional CIDR block to filter by (exact match, e.g., "10.0.0.0/16")
        ctx: MCP context (injected automatically)

    Returns:
        Dictionary containing:
        - vpcs: List of matching VPCs with id, name, cidr, state, is_default, tags
        - total_found: Total number of VPCs found
        - filters_applied: Summary of filters used

    Examples:
        >>> list_vpcs()
        {"vpcs": [{"id": "vpc-12345", "name": "production", ...}], ...}

        >>> list_vpcs(name_pattern="prod-*")
        {"vpcs": [{"id": "vpc-12345", "name": "prod-web", ...}], ...}

        >>> list_vpcs(tags={"Environment": "production"})
        {"vpcs": [{"id": "vpc-67890", "name": "main-vpc", ...}], ...}
    """
    import fnmatch

    app_ctx = _get_app_context(ctx)

    try:
        # Build AWS filters if provided
        aws_filters: list[dict[str, Any]] = []

        if cidr:
            aws_filters.append({"Name": "cidr-block-association.cidr-block", "Values": [cidr]})

        # Fetch VPCs from AWS
        vpcs = await app_ctx.fetcher.describe_vpcs(filters=aws_filters if aws_filters else None)

        # Apply additional filtering (name pattern, tags) that AWS doesn't support well
        filtered_vpcs: list[dict[str, Any]] = []

        for vpc in vpcs:
            # Extract name from tags
            vpc_tags = {t["Key"]: t["Value"] for t in vpc.get("Tags", [])}
            vpc_name = vpc_tags.get("Name", "")

            # Filter by name pattern if provided
            if name_pattern and not fnmatch.fnmatch(vpc_name.lower(), name_pattern.lower()):
                continue

            # Filter by tags if provided
            if tags:
                match = True
                for key, value in tags.items():
                    if vpc_tags.get(key) != value:
                        match = False
                        break
                if not match:
                    continue

            filtered_vpcs.append(vpc)

        # Build response
        result_vpcs = []
        for vpc in filtered_vpcs:
            vpc_tags = {t["Key"]: t["Value"] for t in vpc.get("Tags", [])}
            result_vpcs.append(
                {
                    "id": vpc["VpcId"],
                    "name": vpc_tags.get("Name"),
                    "cidr": vpc.get("CidrBlock"),
                    "state": vpc.get("State"),
                    "is_default": vpc.get("IsDefault", False),
                    "tags": vpc_tags if vpc_tags else None,
                }
            )

        # Build filters applied summary
        filters_applied: dict[str, Any] = {}
        if name_pattern:
            filters_applied["name_pattern"] = name_pattern
        if tags:
            filters_applied["tags"] = tags
        if cidr:
            filters_applied["cidr"] = cidr

        return {
            "vpcs": result_vpcs,
            "total_found": len(result_vpcs),
            "filters_applied": filters_applied if filters_applied else None,
        }

    except NetGraphError as e:
        logger.warning(f"VPC listing failed: {e}")
        return e.to_response()


@mcp.tool()
async def get_cache_stats(
    ctx: Context = None,  # type: ignore
) -> dict[str, Any]:
    """Get cache statistics for the graph manager.

    Returns information about cache performance and current state.

    Args:
        ctx: MCP context (injected automatically)

    Returns:
        Dictionary containing:
        - hits: Number of cache hits
        - misses: Number of cache misses
        - expired: Number of expired entries removed
        - size: Current cache size (total entries)
        - ttl_seconds: Configured TTL
        - hit_rate: Cache hit rate as percentage
        - oldest_entry: Timestamp of oldest cache entry (if any)
    """
    app_ctx = _get_app_context(ctx)
    stats = app_ctx.graph_manager.cache_stats
    return _cache_stats_to_dict(stats)


# =============================================================================
# Result Conversion Helpers
# =============================================================================


def _path_result_to_dict(result: PathAnalysisResult) -> dict[str, Any]:
    """Convert PathAnalysisResult to dictionary for MCP response."""
    response: dict[str, Any] = {
        "status": result.status.value,
        "source_id": result.source_id,
        "destination_ip": result.destination_ip,
        "port": result.port,
        "protocol": result.protocol,
        "summary": result.summary or result.generate_human_summary(),
        "evaluated_security_groups": result.evaluated_security_groups,
        "evaluated_nacls": result.evaluated_nacls,
        "route_path": result.route_path,
    }

    # Add hops
    response["hops"] = [
        {
            "hop_number": hop.hop_number,
            "node_id": hop.node_id,
            "node_type": hop.node_type.value,
            "status": hop.status.value,
            "sg_eval": _rule_eval_to_dict(hop.sg_eval) if hop.sg_eval else None,
            "nacl_eval": _rule_eval_to_dict(hop.nacl_eval) if hop.nacl_eval else None,
            "route_eval": (_rule_eval_to_dict(hop.route_eval) if hop.route_eval else None),
        }
        for hop in result.hops
    ]

    # Add blocked_at if present
    if result.blocked_at:
        response["blocked_at"] = {
            "hop_number": result.blocked_at.hop_number,
            "node_id": result.blocked_at.node_id,
            "node_type": result.blocked_at.node_type.value,
            "sg_eval": (
                _rule_eval_to_dict(result.blocked_at.sg_eval) if result.blocked_at.sg_eval else None
            ),
            "nacl_eval": (
                _rule_eval_to_dict(result.blocked_at.nacl_eval)
                if result.blocked_at.nacl_eval
                else None
            ),
            "route_eval": (
                _rule_eval_to_dict(result.blocked_at.route_eval)
                if result.blocked_at.route_eval
                else None
            ),
        }

    # Add unknown_reason if present
    if result.unknown_reason:
        response["unknown_reason"] = result.unknown_reason

    # Add return route verification
    if result.return_route_verified is not None:
        response["return_route_verified"] = result.return_route_verified
    if result.return_route_table_id:
        response["return_route_table_id"] = result.return_route_table_id

    return response


def _rule_eval_to_dict(eval_result: Any) -> dict[str, Any]:
    """Convert RuleEvalResult to dictionary."""
    return {
        "allowed": eval_result.allowed,
        "resource_id": eval_result.resource_id,
        "resource_type": eval_result.resource_type,
        "rule_id": eval_result.matched_rule_id,
        "direction": eval_result.direction,
        "reason": eval_result.reason,
    }


def _topology_result_to_dict(result: TopologyRefreshResult) -> dict[str, Any]:
    """Convert TopologyRefreshResult to dictionary for MCP response."""
    return {
        "success": result.success,
        "vpc_ids_processed": result.vpc_ids_processed,
        "vpc_ids_failed": result.vpc_ids_failed,
        "node_count": result.node_count,
        "edge_count": result.edge_count,
        "resources_by_type": result.resources_by_type,
        "duration_seconds": round(result.duration_seconds, 3),
        "warnings": result.warnings,
    }


def _exposure_result_to_dict(result: PublicExposureResult) -> dict[str, Any]:
    """Convert PublicExposureResult to dictionary for MCP response."""
    return {
        "vpc_id": result.vpc_id,
        "port": result.port,
        "protocol": result.protocol,
        "exposed_resources": [
            {
                "resource_id": r.resource_id,
                "resource_type": (
                    r.resource_type.value if hasattr(r.resource_type, "value") else r.resource_type
                ),
                "name": r.name,
                "private_ip": r.private_ip,
                "public_ip": r.public_ip,
                "exposure_path": r.exposure_path,
                "allowing_rules": r.allowing_rules,
            }
            for r in result.exposed_resources
        ],
        "total_resources_scanned": result.total_resources_scanned,
        "scan_duration_seconds": round(result.scan_duration_seconds, 3),
    }


def _discovery_result_to_dict(result: ResourceDiscoveryResult) -> dict[str, Any]:
    """Convert ResourceDiscoveryResult to dictionary for MCP response."""
    return {
        "vpc_id": result.vpc_id,
        "resources": [
            {
                "id": r.id,
                "resource_type": (
                    r.resource_type.value if hasattr(r.resource_type, "value") else r.resource_type
                ),
                "name": r.name,
                "tags": r.tags,
                "private_ip": r.private_ip,
                "public_ip": r.public_ip,
                "subnet_id": r.subnet_id,
                "availability_zone": r.availability_zone,
            }
            for r in result.resources
        ],
        "total_found": result.total_found,
        "truncated": result.truncated,
        "filters_applied": result.filters_applied,
    }


def _cache_stats_to_dict(stats: CacheStats) -> dict[str, Any]:
    """Convert CacheStats to dictionary for MCP response."""
    total_requests = stats.hits + stats.misses
    hit_rate = (stats.hits / total_requests * 100) if total_requests > 0 else 0.0

    return {
        "hits": stats.hits,
        "misses": stats.misses,
        "expired": stats.expired,
        "size": stats.size,
        "ttl_seconds": stats.ttl_seconds,
        "hit_rate": round(hit_rate, 2),
        "oldest_entry": stats.oldest_entry.isoformat() if stats.oldest_entry else None,
        "entries_expiring_soon": stats.entries_expiring_soon,
    }


# =============================================================================
# Main Entry Point
# =============================================================================


def main() -> None:
    """Main entry point for the MCP server.

    This function initializes logging and starts the FastMCP server.
    The server communicates via stdio with the MCP client.
    """
    # Setup logging
    log_level_str = os.environ.get("NETGRAPH_LOG_LEVEL", "INFO").upper()
    valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
    if log_level_str not in valid_levels:
        log_level_str = "INFO"
    # Cast to the expected Literal type
    from typing import Literal, cast

    log_level = cast("Literal['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']", log_level_str)
    setup_logging(level=log_level)

    logger.info("Starting NetGraph MCP server")

    # Run the server
    mcp.run()


if __name__ == "__main__":
    main()
