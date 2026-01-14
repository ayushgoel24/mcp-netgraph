"""Graph Manager with read-through cache for AWS VPC topology.

This module provides the GraphManager class that manages the NetworkX DiGraph
topology as a read-through cache. Nodes are fetched on-demand from AWS when
not in cache, enabling scalability to accounts with thousands of resources.

Cache entries have a configurable TTL (default 60 seconds) to prevent stale
data from causing false negatives after rule changes in AWS Console.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from ipaddress import IPv4Address, IPv6Address
from typing import TYPE_CHECKING, Any

import networkx as nx

from netgraph.models import (
    CacheStats,
    EdgeType,
    ENIAttributes,
    GatewayAttributes,
    GraphEdge,
    GraphNode,
    InstanceAttributes,
    NACLRule,
    NetworkACL,
    NodeType,
    Route,
    RouteTable,
    SecurityGroup,
    SGRule,
    SubnetAttributes,
    TopologyRefreshResult,
)
from netgraph.utils.logging import get_logger

if TYPE_CHECKING:
    from netgraph.aws.fetcher import EC2Fetcher

logger = get_logger(__name__)

# Type alias for dual-stack support
IPAddress = IPv4Address | IPv6Address

# Default cache TTL in seconds
DEFAULT_TTL_SECONDS = 60


@dataclass
class CacheEntry:
    """A cached entry with TTL tracking.

    Attributes:
        data: The cached data (GraphNode, SecurityGroup, etc.)
        cached_at: Timestamp when the entry was cached (UTC)
    """

    data: Any
    cached_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def is_expired(self, ttl_seconds: int) -> bool:
        """Check if this cache entry has exceeded its TTL.

        Args:
            ttl_seconds: Time-to-live in seconds

        Returns:
            True if the entry is expired, False otherwise
        """
        if ttl_seconds <= 0:
            # TTL of 0 means request-scoped caching (always expired)
            return True
        now = datetime.now(timezone.utc)
        age = (now - self.cached_at).total_seconds()
        return age > ttl_seconds

    @property
    def age_seconds(self) -> float:
        """Get the age of this cache entry in seconds."""
        now = datetime.now(timezone.utc)
        return (now - self.cached_at).total_seconds()


class GraphManager:
    """Manages the NetworkX DiGraph topology as a read-through cache.

    Nodes are fetched on-demand from AWS when not in cache.
    This enables scalability to accounts with thousands of resources.

    Cache entries have a configurable TTL (default 60 seconds) to prevent
    stale data from causing false negatives after rule changes in AWS Console.

    Attributes:
        fetcher: EC2Fetcher for AWS API calls
        region: AWS region
        account_id: AWS account ID
        ttl_seconds: Cache TTL in seconds (default 60)
    """

    def __init__(
        self,
        fetcher: EC2Fetcher,
        region: str | None = None,
        account_id: str | None = None,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
    ) -> None:
        """Initialize the GraphManager.

        Args:
            fetcher: EC2Fetcher for AWS API calls
            region: AWS region (defaults to fetcher's region)
            account_id: AWS account ID (defaults to fetcher's account ID)
            ttl_seconds: Cache TTL in seconds (default 60)
        """
        self.fetcher = fetcher
        self.region = region or fetcher.client.region
        self.account_id = account_id or fetcher.client.account_id or "unknown"
        self._ttl_seconds = ttl_seconds

        # NetworkX directed graph for topology
        self._graph: nx.DiGraph = nx.DiGraph()

        # Caches for various resource types
        self._node_cache: dict[str, CacheEntry] = {}
        self._security_group_cache: dict[str, CacheEntry] = {}
        self._route_table_cache: dict[str, CacheEntry] = {}
        self._nacl_cache: dict[str, CacheEntry] = {}

        # Cache statistics
        self._hits = 0
        self._misses = 0
        self._expired = 0

        # Lock for thread-safe cache updates
        self._lock = asyncio.Lock()

    # =========================================================================
    # Core Node Methods
    # =========================================================================

    async def get_node(
        self,
        node_id: str,
        force_refresh: bool = False,
    ) -> GraphNode | None:
        """Retrieve a node by ID (instance, ENI, subnet, or gateway).

        If not in cache (or force_refresh=True or TTL expired),
        fetches from AWS and caches the result.

        Args:
            node_id: AWS resource ID (i-xxx, eni-xxx, subnet-xxx, etc.)
            force_refresh: If True, bypass cache and fetch fresh data

        Returns:
            GraphNode if found, None if resource doesn't exist in AWS
        """
        # Check cache first (unless force_refresh)
        if not force_refresh:
            cached = self._get_from_cache(self._node_cache, node_id)
            if cached is not None:
                return cached  # type: ignore

        # Determine resource type and fetch
        node: GraphNode | None = None

        if node_id.startswith("i-"):
            node = await self._fetch_instance(node_id)
        elif node_id.startswith("eni-"):
            node = await self._fetch_eni(node_id)
        elif node_id.startswith("subnet-"):
            node = await self._fetch_subnet_node(node_id)
        elif node_id.startswith("igw-"):
            node = await self._fetch_igw(node_id)
        elif node_id.startswith("nat-"):
            node = await self._fetch_nat_gateway(node_id)
        elif node_id.startswith("pcx-"):
            node = await self._fetch_peering(node_id)
        elif node_id.startswith("tgw-"):
            node = await self._fetch_tgw(node_id)
        else:
            logger.warning(f"Unknown resource type for ID: {node_id}")
            return None

        # Cache the result (even None for negative caching)
        if node is not None:
            await self._put_in_cache(self._node_cache, node_id, node)
            # Add to NetworkX graph
            self._graph.add_node(node_id, data=node)

        return node

    async def get_subnet(
        self,
        subnet_id: str,
        force_refresh: bool = False,
    ) -> GraphNode | None:
        """Get subnet with its route table and NACL associations.

        This is a convenience method that ensures the subnet node has
        proper route_table_id and nacl_id populated in subnet_attrs.

        Args:
            subnet_id: Subnet ID (subnet-xxx)
            force_refresh: If True, bypass cache and fetch fresh data

        Returns:
            GraphNode with SubnetAttributes if found, None otherwise
        """
        node = await self.get_node(subnet_id, force_refresh=force_refresh)
        if node is None or node.subnet_attrs is None:
            return None
        return node

    # =========================================================================
    # Security Group Methods
    # =========================================================================

    async def get_security_group(
        self,
        sg_id: str,
        force_refresh: bool = False,
    ) -> SecurityGroup | None:
        """Get security group with all rules.

        Args:
            sg_id: Security group ID (sg-xxx)
            force_refresh: If True, bypass cache and fetch fresh data

        Returns:
            SecurityGroup if found, None otherwise
        """
        # Check cache first
        if not force_refresh:
            cached = self._get_from_cache(self._security_group_cache, sg_id)
            if cached is not None:
                return cached  # type: ignore

        # Fetch from AWS
        sg_data = await self.fetcher.describe_security_group_by_id(sg_id)
        if sg_data is None:
            return None

        # Parse rules
        inbound_rules = self._parse_sg_rules(
            sg_data.get("IpPermissions", []),
            "inbound",
            sg_id,
        )
        outbound_rules = self._parse_sg_rules(
            sg_data.get("IpPermissionsEgress", []),
            "outbound",
            sg_id,
        )

        sg = SecurityGroup(
            sg_id=sg_id,
            vpc_id=sg_data.get("VpcId", ""),
            name=sg_data.get("GroupName", ""),
            description=sg_data.get("Description", ""),
            inbound_rules=inbound_rules,
            outbound_rules=outbound_rules,
        )

        # Cache and return
        await self._put_in_cache(self._security_group_cache, sg_id, sg)
        return sg

    # =========================================================================
    # Route Table Methods
    # =========================================================================

    async def get_route_table(
        self,
        rt_id: str,
        force_refresh: bool = False,
    ) -> RouteTable | None:
        """Get route table with all routes.

        Args:
            rt_id: Route table ID (rtb-xxx)
            force_refresh: If True, bypass cache and fetch fresh data

        Returns:
            RouteTable if found, None otherwise
        """
        # Check cache first
        if not force_refresh:
            cached = self._get_from_cache(self._route_table_cache, rt_id)
            if cached is not None:
                return cached  # type: ignore

        # Fetch from AWS
        rt_data = await self.fetcher.describe_route_table_by_id(rt_id)
        if rt_data is None:
            return None

        # Parse routes
        routes = self._parse_routes(rt_data.get("Routes", []))

        # Get subnet associations
        associations = rt_data.get("Associations", [])
        subnet_associations = [
            assoc.get("SubnetId")
            for assoc in associations
            if assoc.get("SubnetId") is not None
        ]

        rt = RouteTable(
            route_table_id=rt_id,
            vpc_id=rt_data.get("VpcId", ""),
            routes=routes,
            subnet_associations=subnet_associations,
        )

        # Cache and return
        await self._put_in_cache(self._route_table_cache, rt_id, rt)
        return rt

    # =========================================================================
    # NACL Methods
    # =========================================================================

    async def get_nacl(
        self,
        nacl_id: str,
        force_refresh: bool = False,
    ) -> NetworkACL | None:
        """Get network ACL with all rules.

        Args:
            nacl_id: Network ACL ID (acl-xxx)
            force_refresh: If True, bypass cache and fetch fresh data

        Returns:
            NetworkACL if found, None otherwise
        """
        # Check cache first
        if not force_refresh:
            cached = self._get_from_cache(self._nacl_cache, nacl_id)
            if cached is not None:
                return cached  # type: ignore

        # Fetch from AWS
        nacl_data = await self.fetcher.describe_nacl_by_id(nacl_id)
        if nacl_data is None:
            return None

        # Parse rules
        entries = nacl_data.get("Entries", [])
        inbound_rules = self._parse_nacl_rules(entries, "inbound")
        outbound_rules = self._parse_nacl_rules(entries, "outbound")

        # Get subnet associations
        associations = nacl_data.get("Associations", [])
        subnet_associations = [
            assoc.get("SubnetId")
            for assoc in associations
            if assoc.get("SubnetId") is not None
        ]

        nacl = NetworkACL(
            nacl_id=nacl_id,
            vpc_id=nacl_data.get("VpcId", ""),
            is_default=nacl_data.get("IsDefault", False),
            inbound_rules=inbound_rules,
            outbound_rules=outbound_rules,
            subnet_associations=subnet_associations,
        )

        # Cache and return
        await self._put_in_cache(self._nacl_cache, nacl_id, nacl)
        return nacl

    # =========================================================================
    # Edge Methods
    # =========================================================================

    def get_outbound_edges(self, node_id: str) -> list[GraphEdge]:
        """Get all edges originating from a node.

        This method only returns edges from the cache; it does not
        trigger any AWS API calls.

        Args:
            node_id: Source node ID

        Returns:
            List of GraphEdge objects originating from the node
        """
        edges: list[GraphEdge] = []

        if node_id not in self._graph:
            return edges

        for _, target_id, edge_data in self._graph.out_edges(node_id, data=True):
            edge = edge_data.get("data")
            if isinstance(edge, GraphEdge):
                edges.append(edge)
            else:
                # Construct edge from graph data
                edges.append(
                    GraphEdge(
                        source_id=node_id,
                        target_id=target_id,
                        edge_type=edge_data.get("edge_type", EdgeType.ROUTE),
                        route_table_id=edge_data.get("route_table_id"),
                        destination_cidr=edge_data.get("destination_cidr"),
                        prefix_length=edge_data.get("prefix_length", 0),
                    )
                )

        return edges

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        edge_type: EdgeType,
        route_table_id: str | None = None,
        destination_cidr: str | None = None,
        prefix_length: int = 0,
    ) -> None:
        """Add an edge to the graph.

        Args:
            source_id: Source node ID
            target_id: Target node ID
            edge_type: Type of edge (ROUTE, ATTACHMENT, ASSOCIATION)
            route_table_id: Associated route table ID (for ROUTE edges)
            destination_cidr: Destination CIDR for route matching
            prefix_length: CIDR prefix length for LPM sorting
        """
        edge = GraphEdge(
            source_id=source_id,
            target_id=target_id,
            edge_type=edge_type,
            route_table_id=route_table_id,
            destination_cidr=destination_cidr,
            prefix_length=prefix_length,
        )
        self._graph.add_edge(
            source_id,
            target_id,
            data=edge,
            edge_type=edge_type,
            route_table_id=route_table_id,
            destination_cidr=destination_cidr,
            prefix_length=prefix_length,
        )

    # =========================================================================
    # Cache Management Methods
    # =========================================================================

    def invalidate(self, node_id: str | None = None) -> None:
        """Invalidate cache entry or entire cache.

        Args:
            node_id: Specific resource ID to invalidate.
                    If None, invalidates the entire cache.
        """
        if node_id is None:
            # Clear all caches
            self._node_cache.clear()
            self._security_group_cache.clear()
            self._route_table_cache.clear()
            self._nacl_cache.clear()
            self._graph.clear()
            logger.info("Invalidated entire cache")
        else:
            # Clear specific entry from all caches
            self._node_cache.pop(node_id, None)
            self._security_group_cache.pop(node_id, None)
            self._route_table_cache.pop(node_id, None)
            self._nacl_cache.pop(node_id, None)
            if node_id in self._graph:
                self._graph.remove_node(node_id)
            logger.debug(f"Invalidated cache entry: {node_id}")

    def invalidate_expired(self) -> int:
        """Remove all cache entries that have exceeded TTL.

        Returns:
            Count of removed entries
        """
        removed = 0

        for cache in [
            self._node_cache,
            self._security_group_cache,
            self._route_table_cache,
            self._nacl_cache,
        ]:
            expired_keys = [
                key
                for key, entry in cache.items()
                if entry.is_expired(self._ttl_seconds)
            ]
            for key in expired_keys:
                del cache[key]
                removed += 1

        if removed > 0:
            logger.debug(f"Invalidated {removed} expired cache entries")
            self._expired += removed

        return removed

    def set_ttl(self, ttl_seconds: int) -> None:
        """Configure cache TTL.

        Args:
            ttl_seconds: TTL in seconds. Set to 0 for request-scoped caching.
        """
        self._ttl_seconds = ttl_seconds
        logger.info(f"Cache TTL set to {ttl_seconds} seconds")

    @property
    def cache_stats(self) -> CacheStats:
        """Return cache hit/miss/expired statistics."""
        # Calculate cache size
        size = (
            len(self._node_cache)
            + len(self._security_group_cache)
            + len(self._route_table_cache)
            + len(self._nacl_cache)
        )

        # Find oldest entry
        oldest: datetime | None = None
        all_entries: list[CacheEntry] = []
        for cache in [
            self._node_cache,
            self._security_group_cache,
            self._route_table_cache,
            self._nacl_cache,
        ]:
            all_entries.extend(cache.values())

        if all_entries:
            oldest_entry = min(all_entries, key=lambda e: e.cached_at)
            oldest = oldest_entry.cached_at

        # Count entries expiring soon (within 10 seconds)
        expiring_soon = sum(
            1
            for entry in all_entries
            if entry.age_seconds > (self._ttl_seconds - 10)
            and not entry.is_expired(self._ttl_seconds)
        )

        return CacheStats(
            hits=self._hits,
            misses=self._misses,
            expired=self._expired,
            size=size,
            oldest_entry=oldest,
            ttl_seconds=self._ttl_seconds,
            entries_expiring_soon=expiring_soon,
        )

    # =========================================================================
    # Topology Building
    # =========================================================================

    async def build_topology(
        self,
        vpc_ids: list[str],
    ) -> TopologyRefreshResult:
        """Pre-warm cache by fetching entire VPC topology.

        This is an OPTIONAL optimization. The graph manager will
        fetch resources on-demand if this is not called.

        Args:
            vpc_ids: List of VPC IDs to pre-warm

        Returns:
            TopologyRefreshResult with counts and statistics
        """
        import time

        start_time = time.time()

        vpc_ids_processed: list[str] = []
        vpc_ids_failed: list[str] = []
        warnings: list[str] = []
        resources_by_type: dict[str, int] = {
            "instances": 0,
            "enis": 0,
            "subnets": 0,
            "igws": 0,
            "nat_gateways": 0,
            "peerings": 0,
            "security_groups": 0,
            "route_tables": 0,
            "nacls": 0,
        }

        for vpc_id in vpc_ids:
            try:
                await self._build_vpc_topology(vpc_id, resources_by_type, warnings)
                vpc_ids_processed.append(vpc_id)
            except Exception as e:
                logger.error(f"Failed to build topology for VPC {vpc_id}: {e}")
                vpc_ids_failed.append(vpc_id)
                warnings.append(f"VPC {vpc_id}: {e}")

        duration = time.time() - start_time

        return TopologyRefreshResult(
            success=len(vpc_ids_failed) == 0,
            vpc_ids_processed=vpc_ids_processed,
            vpc_ids_failed=vpc_ids_failed,
            node_count=self._graph.number_of_nodes(),
            edge_count=self._graph.number_of_edges(),
            resources_by_type=resources_by_type,
            duration_seconds=duration,
            warnings=warnings,
        )

    async def _build_vpc_topology(
        self,
        vpc_id: str,
        resources_by_type: dict[str, int],
        warnings: list[str],
    ) -> None:
        """Build topology for a single VPC."""
        # Fetch all resources in parallel
        instances_task = self.fetcher.describe_instances(
            filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )
        subnets_task = self.fetcher.describe_subnets(vpc_id=vpc_id)
        sgs_task = self.fetcher.describe_security_groups(vpc_id=vpc_id)
        nacls_task = self.fetcher.describe_network_acls(vpc_id=vpc_id)
        route_tables_task = self.fetcher.describe_route_tables(vpc_id=vpc_id)
        igws_task = self.fetcher.describe_internet_gateways(vpc_id=vpc_id)
        nat_gws_task = self.fetcher.describe_nat_gateways(vpc_id=vpc_id)
        enis_task = self.fetcher.describe_network_interfaces(
            filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )

        results = await asyncio.gather(
            instances_task,
            subnets_task,
            sgs_task,
            nacls_task,
            route_tables_task,
            igws_task,
            nat_gws_task,
            enis_task,
            return_exceptions=True,
        )

        instances, subnets, sgs, nacls, route_tables, igws, nat_gws, enis = results

        # Process instances
        if isinstance(instances, list):
            for inst in instances:
                node = self._instance_to_node(inst, vpc_id)
                if node:
                    await self._put_in_cache(self._node_cache, node.id, node)
                    self._graph.add_node(node.id, data=node)
                    resources_by_type["instances"] += 1
        elif isinstance(instances, Exception):
            warnings.append(f"Failed to fetch instances: {instances}")

        # Process subnets
        if isinstance(subnets, list):
            # Build subnet -> route table and subnet -> NACL mappings
            rt_associations = await self._build_subnet_rt_map(route_tables, vpc_id)
            nacl_associations = self._build_subnet_nacl_map(nacls)

            for subnet_data in subnets:
                subnet_id = subnet_data.get("SubnetId", "")
                node = self._subnet_to_node(
                    subnet_data,
                    vpc_id,
                    rt_associations.get(subnet_id),
                    nacl_associations.get(subnet_id),
                )
                if node:
                    await self._put_in_cache(self._node_cache, node.id, node)
                    self._graph.add_node(node.id, data=node)
                    resources_by_type["subnets"] += 1
        elif isinstance(subnets, Exception):
            warnings.append(f"Failed to fetch subnets: {subnets}")

        # Process security groups
        if isinstance(sgs, list):
            for sg_data in sgs:
                sg = self._sg_data_to_model(sg_data)
                if sg:
                    await self._put_in_cache(self._security_group_cache, sg.sg_id, sg)
                    resources_by_type["security_groups"] += 1
        elif isinstance(sgs, Exception):
            warnings.append(f"Failed to fetch security groups: {sgs}")

        # Process NACLs
        if isinstance(nacls, list):
            for nacl_data in nacls:
                nacl = self._nacl_data_to_model(nacl_data)
                if nacl:
                    await self._put_in_cache(self._nacl_cache, nacl.nacl_id, nacl)
                    resources_by_type["nacls"] += 1
        elif isinstance(nacls, Exception):
            warnings.append(f"Failed to fetch NACLs: {nacls}")

        # Process route tables
        if isinstance(route_tables, list):
            for rt_data in route_tables:
                rt = self._rt_data_to_model(rt_data)
                if rt:
                    await self._put_in_cache(
                        self._route_table_cache, rt.route_table_id, rt
                    )
                    resources_by_type["route_tables"] += 1
        elif isinstance(route_tables, Exception):
            warnings.append(f"Failed to fetch route tables: {route_tables}")

        # Process IGWs
        if isinstance(igws, list):
            for igw_data in igws:
                node = self._igw_to_node(igw_data, vpc_id)
                if node:
                    await self._put_in_cache(self._node_cache, node.id, node)
                    self._graph.add_node(node.id, data=node)
                    resources_by_type["igws"] += 1
        elif isinstance(igws, Exception):
            warnings.append(f"Failed to fetch internet gateways: {igws}")

        # Process NAT gateways
        if isinstance(nat_gws, list):
            for nat_data in nat_gws:
                node = self._nat_to_node(nat_data, vpc_id)
                if node:
                    await self._put_in_cache(self._node_cache, node.id, node)
                    self._graph.add_node(node.id, data=node)
                    resources_by_type["nat_gateways"] += 1
        elif isinstance(nat_gws, Exception):
            warnings.append(f"Failed to fetch NAT gateways: {nat_gws}")

        # Process ENIs
        if isinstance(enis, list):
            for eni_data in enis:
                node = self._eni_to_node(eni_data, vpc_id)
                if node:
                    await self._put_in_cache(self._node_cache, node.id, node)
                    self._graph.add_node(node.id, data=node)
                    resources_by_type["enis"] += 1
        elif isinstance(enis, Exception):
            warnings.append(f"Failed to fetch ENIs: {enis}")

    # =========================================================================
    # Helper Methods
    # =========================================================================

    async def resolve_to_eni(
        self,
        resource_id: str,
        force_refresh: bool = False,
    ) -> GraphNode | None:
        """Resolve a resource ID to its primary ENI.

        For instances, returns the primary ENI.
        For ENI IDs, returns the ENI directly.

        Args:
            resource_id: Instance ID (i-xxx) or ENI ID (eni-xxx)
            force_refresh: If True, bypass cache

        Returns:
            GraphNode for the ENI, or None if not found
        """
        if resource_id.startswith("eni-"):
            return await self.get_node(resource_id, force_refresh=force_refresh)

        if resource_id.startswith("i-"):
            node = await self.get_node(resource_id, force_refresh=force_refresh)
            if node is None or node.instance_attrs is None:
                return None

            # Get the first ENI (primary)
            eni_ids = node.instance_attrs.eni_ids
            if not eni_ids:
                logger.warning(f"Instance {resource_id} has no ENIs")
                return None

            return await self.get_node(eni_ids[0], force_refresh=force_refresh)

        logger.warning(f"Cannot resolve {resource_id} to ENI - unknown resource type")
        return None

    async def find_eni_by_ip(
        self,
        ip: IPAddress | str,
        force_refresh: bool = False,
    ) -> GraphNode | None:
        """Find the ENI that has the given IP address.

        This searches through cached ENIs and instances to find
        the network interface with the matching IP.

        Args:
            ip: IP address to find (IPv4 or IPv6)
            force_refresh: If True, bypass cache (requires VPC context)

        Returns:
            GraphNode for the ENI, or None if not found
        """
        if isinstance(ip, str):
            from ipaddress import ip_address

            ip = ip_address(ip)

        # Search through node cache for ENIs and instances
        for entry in self._node_cache.values():
            node = entry.data
            if not isinstance(node, GraphNode):
                continue

            # Check ENI attributes
            if node.eni_attrs is not None:
                if node.eni_attrs.private_ip == ip:
                    return node
                if node.eni_attrs.public_ip == ip:
                    return node
                if node.eni_attrs.private_ipv6 == ip:
                    return node

            # Check instance attributes
            if node.instance_attrs is not None:
                if node.instance_attrs.private_ip == ip:
                    # Return the primary ENI for this instance
                    return await self.resolve_to_eni(
                        node.id, force_refresh=force_refresh
                    )
                if node.instance_attrs.public_ip == ip:
                    return await self.resolve_to_eni(
                        node.id, force_refresh=force_refresh
                    )
                if node.instance_attrs.private_ipv6 == ip:
                    return await self.resolve_to_eni(
                        node.id, force_refresh=force_refresh
                    )
                if node.instance_attrs.public_ipv6 == ip:
                    return await self.resolve_to_eni(
                        node.id, force_refresh=force_refresh
                    )

        # If not found in cache and force_refresh is True,
        # we could query AWS, but that would require VPC context
        # For now, return None
        return None

    # =========================================================================
    # Private Cache Helpers
    # =========================================================================

    def _get_from_cache(
        self,
        cache: dict[str, CacheEntry],
        key: str,
    ) -> Any | None:
        """Get a value from cache, respecting TTL."""
        entry = cache.get(key)
        if entry is None:
            self._misses += 1
            return None

        if entry.is_expired(self._ttl_seconds):
            self._expired += 1
            self._misses += 1
            del cache[key]
            return None

        self._hits += 1
        return entry.data

    async def _put_in_cache(
        self,
        cache: dict[str, CacheEntry],
        key: str,
        value: Any,
    ) -> None:
        """Put a value in cache."""
        async with self._lock:
            cache[key] = CacheEntry(data=value)

    # =========================================================================
    # Private Fetch Methods
    # =========================================================================

    async def _fetch_instance(self, instance_id: str) -> GraphNode | None:
        """Fetch an EC2 instance and convert to GraphNode."""
        data = await self.fetcher.describe_instances_by_id(instance_id)
        if data is None:
            return None

        vpc_id = data.get("VpcId", "")
        return self._instance_to_node(data, vpc_id)

    async def _fetch_eni(self, eni_id: str) -> GraphNode | None:
        """Fetch an ENI and convert to GraphNode."""
        data = await self.fetcher.describe_network_interface_by_id(eni_id)
        if data is None:
            return None

        vpc_id = data.get("VpcId", "")
        return self._eni_to_node(data, vpc_id)

    async def _fetch_subnet_node(self, subnet_id: str) -> GraphNode | None:
        """Fetch a subnet and convert to GraphNode."""
        subnet_data = await self.fetcher.describe_subnet_by_id(subnet_id)
        if subnet_data is None:
            return None

        vpc_id = subnet_data.get("VpcId", "")

        # Get route table for this subnet
        rt_id = await self._get_route_table_for_subnet(subnet_id, vpc_id)

        # Get NACL for this subnet
        nacl_id = await self._get_nacl_for_subnet(subnet_id, vpc_id)

        return self._subnet_to_node(subnet_data, vpc_id, rt_id, nacl_id)

    async def _fetch_igw(self, igw_id: str) -> GraphNode | None:
        """Fetch an Internet Gateway and convert to GraphNode."""
        igws = await self.fetcher.describe_internet_gateways(
            internet_gateway_ids=[igw_id]
        )
        if not igws:
            return None

        data = igws[0]
        # Get VPC from attachments
        attachments = data.get("Attachments", [])
        vpc_id = attachments[0].get("VpcId", "") if attachments else ""

        return self._igw_to_node(data, vpc_id)

    async def _fetch_nat_gateway(self, nat_id: str) -> GraphNode | None:
        """Fetch a NAT Gateway and convert to GraphNode."""
        nat_gws = await self.fetcher.describe_nat_gateways(nat_gateway_ids=[nat_id])
        if not nat_gws:
            return None

        data = nat_gws[0]
        vpc_id = data.get("VpcId", "")
        return self._nat_to_node(data, vpc_id)

    async def _fetch_peering(self, pcx_id: str) -> GraphNode | None:
        """Fetch a VPC Peering Connection and convert to GraphNode."""
        peerings = await self.fetcher.describe_vpc_peering_connections(
            vpc_peering_connection_ids=[pcx_id]
        )
        if not peerings:
            return None

        data = peerings[0]
        # Use accepter VPC as primary (arbitrary choice)
        accepter = data.get("AccepterVpcInfo", {})
        requester = data.get("RequesterVpcInfo", {})

        vpc_id = accepter.get("VpcId", "")
        peer_vpc_id = requester.get("VpcId", "")
        peer_account_id = requester.get("OwnerId", "")
        peer_region = requester.get("Region", "")

        return GraphNode(
            id=pcx_id,
            node_type=NodeType.VPC_PEERING,
            vpc_id=vpc_id,
            account_id=self.account_id,
            region=self.region,
            gateway_attrs=GatewayAttributes(
                gateway_type="peering",
                peer_vpc_id=peer_vpc_id,
                peer_account_id=peer_account_id,
                peer_region=peer_region,
            ),
        )

    async def _fetch_tgw(self, tgw_id: str) -> GraphNode | None:
        """Fetch a Transit Gateway and convert to GraphNode."""
        tgws = await self.fetcher.describe_transit_gateways(
            transit_gateway_ids=[tgw_id]
        )
        if not tgws:
            return None

        data = tgws[0]
        return GraphNode(
            id=tgw_id,
            node_type=NodeType.TRANSIT_GATEWAY,
            vpc_id="",  # TGW is not in a specific VPC
            account_id=data.get("OwnerId", self.account_id),
            region=self.region,
            gateway_attrs=GatewayAttributes(gateway_type="tgw"),
        )

    # =========================================================================
    # Private Conversion Helpers
    # =========================================================================

    def _instance_to_node(self, data: dict[str, Any], vpc_id: str) -> GraphNode | None:
        """Convert AWS instance data to GraphNode."""
        instance_id = data.get("InstanceId", "")
        if not instance_id:
            return None

        # Get private IP
        private_ip_str = data.get("PrivateIpAddress")
        if not private_ip_str:
            return None
        private_ip = IPv4Address(private_ip_str)

        # Get public IP (optional)
        public_ip: IPv4Address | None = None
        public_ip_str = data.get("PublicIpAddress")
        if public_ip_str:
            public_ip = IPv4Address(public_ip_str)

        # Get IPv6 addresses
        private_ipv6: IPv6Address | None = None
        public_ipv6: IPv6Address | None = None
        for interface in data.get("NetworkInterfaces", []):
            for ipv6_entry in interface.get("Ipv6Addresses", []):
                ipv6_str = ipv6_entry.get("Ipv6Address")
                if ipv6_str:
                    private_ipv6 = IPv6Address(ipv6_str)
                    break

        # Get security groups
        sg_ids = [sg.get("GroupId", "") for sg in data.get("SecurityGroups", [])]
        sg_ids = [sg_id for sg_id in sg_ids if sg_id]

        # Get ENIs
        eni_ids = [
            eni.get("NetworkInterfaceId", "")
            for eni in data.get("NetworkInterfaces", [])
        ]
        eni_ids = [eni_id for eni_id in eni_ids if eni_id]

        # Get tags
        tags = {tag["Key"]: tag["Value"] for tag in data.get("Tags", [])}

        return GraphNode(
            id=instance_id,
            node_type=NodeType.INSTANCE,
            vpc_id=vpc_id,
            account_id=self.account_id,
            region=self.region,
            arn=f"arn:aws:ec2:{self.region}:{self.account_id}:instance/{instance_id}",
            instance_attrs=InstanceAttributes(
                private_ip=private_ip,
                private_ipv6=private_ipv6,
                public_ip=public_ip,
                public_ipv6=public_ipv6,
                security_group_ids=sg_ids,
                subnet_id=data.get("SubnetId", ""),
                eni_ids=eni_ids,
                tags=tags,
            ),
        )

    def _eni_to_node(self, data: dict[str, Any], vpc_id: str) -> GraphNode | None:
        """Convert AWS ENI data to GraphNode."""
        eni_id = data.get("NetworkInterfaceId", "")
        if not eni_id:
            return None

        # Get private IP
        private_ip_str = data.get("PrivateIpAddress")
        if not private_ip_str:
            return None
        private_ip = IPv4Address(private_ip_str)

        # Get public IP from association
        public_ip: IPv4Address | None = None
        association = data.get("Association", {})
        public_ip_str = association.get("PublicIp")
        if public_ip_str:
            public_ip = IPv4Address(public_ip_str)

        # Get IPv6
        private_ipv6: IPv6Address | None = None
        for ipv6_entry in data.get("Ipv6Addresses", []):
            ipv6_str = ipv6_entry.get("Ipv6Address")
            if ipv6_str:
                private_ipv6 = IPv6Address(ipv6_str)
                break

        # Get security groups
        sg_ids = [sg.get("GroupId", "") for sg in data.get("Groups", [])]
        sg_ids = [sg_id for sg_id in sg_ids if sg_id]

        # Get attachment
        attachment = data.get("Attachment", {})
        attachment_id = attachment.get("AttachmentId")

        return GraphNode(
            id=eni_id,
            node_type=NodeType.ENI,
            vpc_id=vpc_id,
            account_id=self.account_id,
            region=self.region,
            arn=f"arn:aws:ec2:{self.region}:{self.account_id}:network-interface/{eni_id}",
            eni_attrs=ENIAttributes(
                private_ip=private_ip,
                private_ipv6=private_ipv6,
                public_ip=public_ip,
                security_group_ids=sg_ids,
                subnet_id=data.get("SubnetId", ""),
                attachment_id=attachment_id,
            ),
        )

    def _subnet_to_node(
        self,
        data: dict[str, Any],
        vpc_id: str,
        route_table_id: str | None,
        nacl_id: str | None,
    ) -> GraphNode | None:
        """Convert AWS subnet data to GraphNode."""
        subnet_id = data.get("SubnetId", "")
        if not subnet_id:
            return None

        cidr_block = data.get("CidrBlock", "")
        ipv6_cidr_block: str | None = None
        for assoc in data.get("Ipv6CidrBlockAssociationSet", []):
            if assoc.get("Ipv6CidrBlockState", {}).get("State") == "associated":
                ipv6_cidr_block = assoc.get("Ipv6CidrBlock")
                break

        return GraphNode(
            id=subnet_id,
            node_type=NodeType.SUBNET,
            vpc_id=vpc_id,
            account_id=self.account_id,
            region=self.region,
            arn=f"arn:aws:ec2:{self.region}:{self.account_id}:subnet/{subnet_id}",
            subnet_attrs=SubnetAttributes(
                cidr_block=cidr_block,
                ipv6_cidr_block=ipv6_cidr_block,
                availability_zone=data.get("AvailabilityZone", ""),
                route_table_id=route_table_id or "",
                nacl_id=nacl_id or "",
                is_public=False,  # Updated when route table is analyzed
            ),
        )

    def _igw_to_node(self, data: dict[str, Any], vpc_id: str) -> GraphNode | None:
        """Convert AWS IGW data to GraphNode."""
        igw_id = data.get("InternetGatewayId", "")
        if not igw_id:
            return None

        return GraphNode(
            id=igw_id,
            node_type=NodeType.INTERNET_GATEWAY,
            vpc_id=vpc_id,
            account_id=self.account_id,
            region=self.region,
            gateway_attrs=GatewayAttributes(gateway_type="igw"),
        )

    def _nat_to_node(self, data: dict[str, Any], vpc_id: str) -> GraphNode | None:
        """Convert AWS NAT Gateway data to GraphNode."""
        nat_id = data.get("NatGatewayId", "")
        if not nat_id:
            return None

        # Get elastic IP
        elastic_ip: IPv4Address | None = None
        for addr in data.get("NatGatewayAddresses", []):
            public_ip_str = addr.get("PublicIp")
            if public_ip_str:
                elastic_ip = IPv4Address(public_ip_str)
                break

        return GraphNode(
            id=nat_id,
            node_type=NodeType.NAT_GATEWAY,
            vpc_id=vpc_id,
            account_id=self.account_id,
            region=self.region,
            gateway_attrs=GatewayAttributes(
                gateway_type="nat",
                elastic_ip=elastic_ip,
            ),
        )

    def _sg_data_to_model(self, data: dict[str, Any]) -> SecurityGroup | None:
        """Convert AWS SG data to SecurityGroup model."""
        sg_id = data.get("GroupId", "")
        if not sg_id:
            return None

        inbound_rules = self._parse_sg_rules(
            data.get("IpPermissions", []),
            "inbound",
            sg_id,
        )
        outbound_rules = self._parse_sg_rules(
            data.get("IpPermissionsEgress", []),
            "outbound",
            sg_id,
        )

        return SecurityGroup(
            sg_id=sg_id,
            vpc_id=data.get("VpcId", ""),
            name=data.get("GroupName", ""),
            description=data.get("Description", ""),
            inbound_rules=inbound_rules,
            outbound_rules=outbound_rules,
        )

    def _nacl_data_to_model(self, data: dict[str, Any]) -> NetworkACL | None:
        """Convert AWS NACL data to NetworkACL model."""
        nacl_id = data.get("NetworkAclId", "")
        if not nacl_id:
            return None

        entries = data.get("Entries", [])
        inbound_rules = self._parse_nacl_rules(entries, "inbound")
        outbound_rules = self._parse_nacl_rules(entries, "outbound")

        associations = data.get("Associations", [])
        subnet_associations = [
            assoc.get("SubnetId")
            for assoc in associations
            if assoc.get("SubnetId") is not None
        ]

        return NetworkACL(
            nacl_id=nacl_id,
            vpc_id=data.get("VpcId", ""),
            is_default=data.get("IsDefault", False),
            inbound_rules=inbound_rules,
            outbound_rules=outbound_rules,
            subnet_associations=subnet_associations,
        )

    def _rt_data_to_model(self, data: dict[str, Any]) -> RouteTable | None:
        """Convert AWS route table data to RouteTable model."""
        rt_id = data.get("RouteTableId", "")
        if not rt_id:
            return None

        routes = self._parse_routes(data.get("Routes", []))

        associations = data.get("Associations", [])
        subnet_associations = [
            assoc.get("SubnetId")
            for assoc in associations
            if assoc.get("SubnetId") is not None
        ]

        return RouteTable(
            route_table_id=rt_id,
            vpc_id=data.get("VpcId", ""),
            routes=routes,
            subnet_associations=subnet_associations,
        )

    # =========================================================================
    # Private Parsing Helpers
    # =========================================================================

    def _parse_sg_rules(
        self,
        permissions: list[dict[str, Any]],
        direction: str,
        sg_id: str,
    ) -> list[SGRule]:
        """Parse AWS SG permissions into SGRule list."""
        rules: list[SGRule] = []
        rule_counter = 0

        for perm in permissions:
            ip_protocol = perm.get("IpProtocol", "-1")
            from_port = perm.get("FromPort", 0) or 0
            to_port = perm.get("ToPort", 65535) or 65535

            # Handle "all traffic" rule
            if ip_protocol == "-1":
                from_port = 0
                to_port = 65535

            # IPv4 ranges
            for ip_range in perm.get("IpRanges", []):
                rule_counter += 1
                rules.append(
                    SGRule(
                        rule_id=f"{sg_id}-{direction}-{rule_counter}",
                        direction=direction,
                        ip_protocol=ip_protocol,
                        from_port=from_port,
                        to_port=to_port,
                        cidr_ipv4=ip_range.get("CidrIp"),
                        description=ip_range.get("Description"),
                    )
                )

            # IPv6 ranges
            for ipv6_range in perm.get("Ipv6Ranges", []):
                rule_counter += 1
                rules.append(
                    SGRule(
                        rule_id=f"{sg_id}-{direction}-{rule_counter}",
                        direction=direction,
                        ip_protocol=ip_protocol,
                        from_port=from_port,
                        to_port=to_port,
                        cidr_ipv6=ipv6_range.get("CidrIpv6"),
                        description=ipv6_range.get("Description"),
                    )
                )

            # Prefix lists
            for pl in perm.get("PrefixListIds", []):
                rule_counter += 1
                rules.append(
                    SGRule(
                        rule_id=f"{sg_id}-{direction}-{rule_counter}",
                        direction=direction,
                        ip_protocol=ip_protocol,
                        from_port=from_port,
                        to_port=to_port,
                        prefix_list_id=pl.get("PrefixListId"),
                        description=pl.get("Description"),
                    )
                )

            # Security group references
            for sg_ref in perm.get("UserIdGroupPairs", []):
                rule_counter += 1
                rules.append(
                    SGRule(
                        rule_id=f"{sg_id}-{direction}-{rule_counter}",
                        direction=direction,
                        ip_protocol=ip_protocol,
                        from_port=from_port,
                        to_port=to_port,
                        referenced_sg_id=sg_ref.get("GroupId"),
                        description=sg_ref.get("Description"),
                    )
                )

        return rules

    def _parse_nacl_rules(
        self,
        entries: list[dict[str, Any]],
        direction: str,
    ) -> list[NACLRule]:
        """Parse AWS NACL entries into NACLRule list."""
        rules: list[NACLRule] = []

        for entry in entries:
            # Filter by direction
            is_egress = entry.get("Egress", False)
            if (direction == "inbound" and is_egress) or (
                direction == "outbound" and not is_egress
            ):
                continue

            rule_number = entry.get("RuleNumber", 32767)

            # Skip the default deny rule (*)
            if rule_number == 32767:
                continue

            rule_action = "allow" if entry.get("RuleAction") == "allow" else "deny"
            protocol = entry.get("Protocol", "-1")

            # Get port range
            port_range = entry.get("PortRange", {})
            from_port = port_range.get("From")
            to_port = port_range.get("To")

            rules.append(
                NACLRule(
                    rule_number=rule_number,
                    rule_action=rule_action,
                    direction=direction,
                    protocol=protocol,
                    cidr_block=entry.get("CidrBlock"),
                    ipv6_cidr_block=entry.get("Ipv6CidrBlock"),
                    from_port=from_port,
                    to_port=to_port,
                )
            )

        return rules

    def _parse_routes(self, routes_data: list[dict[str, Any]]) -> list[Route]:
        """Parse AWS routes into Route list."""
        routes: list[Route] = []

        for route_data in routes_data:
            # Get destination CIDR (IPv4 or IPv6)
            dest_cidr = route_data.get("DestinationCidrBlock") or route_data.get(
                "DestinationIpv6CidrBlock"
            )
            if not dest_cidr:
                continue

            # Determine target and type
            target_id, target_type = self._get_route_target(route_data)
            if not target_id:
                continue

            state = route_data.get("State", "active")
            if state not in ["active", "blackhole"]:
                state = "active"

            routes.append(
                Route(
                    destination_cidr=dest_cidr,
                    target_id=target_id,
                    target_type=target_type,
                    state=state,
                )
            )

        return routes

    def _get_route_target(
        self, route_data: dict[str, Any]
    ) -> tuple[str | None, str | None]:
        """Extract route target ID and type from AWS route data."""
        # Check various target types in order of precedence
        if route_data.get("GatewayId"):
            gw_id = route_data["GatewayId"]
            if gw_id == "local":
                return "local", "local"
            if gw_id.startswith("igw-"):
                return gw_id, "igw"
            if gw_id.startswith("vgw-"):
                return gw_id, "igw"  # Virtual gateway treated as IGW

        if route_data.get("NatGatewayId"):
            return route_data["NatGatewayId"], "nat"

        if route_data.get("VpcPeeringConnectionId"):
            return route_data["VpcPeeringConnectionId"], "peering"

        if route_data.get("TransitGatewayId"):
            return route_data["TransitGatewayId"], "tgw"

        if route_data.get("NetworkInterfaceId"):
            return route_data["NetworkInterfaceId"], "eni"

        if route_data.get("InstanceId"):
            return route_data["InstanceId"], "instance"

        return None, None

    async def _get_route_table_for_subnet(
        self, subnet_id: str, vpc_id: str
    ) -> str | None:
        """Get the route table ID associated with a subnet."""
        # First check for explicit association
        route_tables = await self.fetcher.describe_route_tables(vpc_id=vpc_id)

        for rt in route_tables:
            for assoc in rt.get("Associations", []):
                if assoc.get("SubnetId") == subnet_id:
                    return rt.get("RouteTableId")

        # If no explicit association, use main route table
        for rt in route_tables:
            for assoc in rt.get("Associations", []):
                if assoc.get("Main", False):
                    return rt.get("RouteTableId")

        return None

    async def _get_nacl_for_subnet(self, subnet_id: str, vpc_id: str) -> str | None:
        """Get the NACL ID associated with a subnet."""
        nacls = await self.fetcher.describe_network_acls(vpc_id=vpc_id)

        for nacl in nacls:
            for assoc in nacl.get("Associations", []):
                if assoc.get("SubnetId") == subnet_id:
                    return nacl.get("NetworkAclId")

        # If no explicit association, use default NACL
        for nacl in nacls:
            if nacl.get("IsDefault", False):
                return nacl.get("NetworkAclId")

        return None

    async def _build_subnet_rt_map(
        self, route_tables: list[dict[str, Any]] | BaseException, _vpc_id: str
    ) -> dict[str, str]:
        """Build a mapping of subnet ID to route table ID."""
        mapping: dict[str, str] = {}
        main_rt_id: str | None = None

        if isinstance(route_tables, BaseException):
            return mapping

        for rt in route_tables:
            rt_id = rt.get("RouteTableId", "")
            for assoc in rt.get("Associations", []):
                if assoc.get("Main", False):
                    main_rt_id = rt_id
                subnet_id = assoc.get("SubnetId")
                if subnet_id:
                    mapping[subnet_id] = rt_id

        # For subnets without explicit association, use main RT
        if main_rt_id:
            # This will be applied later when processing subnets
            mapping["__main__"] = main_rt_id

        return mapping

    def _build_subnet_nacl_map(
        self, nacls: list[dict[str, Any]] | BaseException
    ) -> dict[str, str]:
        """Build a mapping of subnet ID to NACL ID."""
        mapping: dict[str, str] = {}
        default_nacl_id: str | None = None

        if isinstance(nacls, BaseException):
            return mapping

        for nacl in nacls:
            nacl_id = nacl.get("NetworkAclId", "")
            if nacl.get("IsDefault", False):
                default_nacl_id = nacl_id
            for assoc in nacl.get("Associations", []):
                subnet_id = assoc.get("SubnetId")
                if subnet_id:
                    mapping[subnet_id] = nacl_id

        if default_nacl_id:
            mapping["__default__"] = default_nacl_id

        return mapping
