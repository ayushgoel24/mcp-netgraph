"""Path Analyzer for deterministic network connectivity analysis.

This module implements the core path analysis algorithm that traverses
the VPC topology graph using Longest Prefix Match (LPM) routing.

Key design decisions:
- Deterministic traversal: Uses LPM routing, not BFS/DFS graph search
- Loop detection: Tracks visited nodes to detect routing cycles
- NACL return path: Verifies ephemeral port rules for stateless NACLs
- Reverse path routing: Verifies destination can route back to source
- Permission errors -> UNKNOWN: Never report BLOCKED on access denied
"""

from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import TYPE_CHECKING

from netgraph.evaluators.cidr import CIDRMatcher
from netgraph.evaluators.nacl import NACLEvaluator, evaluate_nacl_return_path
from netgraph.evaluators.route import RouteEvaluator, find_longest_prefix_match
from netgraph.evaluators.security_group import SecurityGroupEvaluator
from netgraph.models import (
    GraphNode,
    HopResult,
    NodeType,
    PathAnalysisResult,
    PathStatus,
    RuleEvalResult,
    SecurityGroup,
)
from netgraph.models.errors import (
    CrossAccountSGResolutionError,
    PermissionDeniedError,
    ResourceNotFoundError,
)
from netgraph.utils.logging import get_logger

if TYPE_CHECKING:
    from netgraph.core.graph_manager import GraphManager

logger = get_logger(__name__)

# Type alias for IP addresses
IPAddress = IPv4Address | IPv6Address


@dataclass
class TraversalContext:
    """Context maintained during path traversal.

    Tracks visited nodes, hop history, and accumulated evaluations.
    """

    source_ip: str
    dest_ip: str
    port: int
    protocol: str
    force_refresh: bool = False

    # Traversal state
    visited_nodes: set[str] = field(default_factory=set)
    hops: list[HopResult] = field(default_factory=list)
    hop_counter: int = 0

    # Evaluation tracking
    evaluated_sgs: list[str] = field(default_factory=list)
    evaluated_nacls: list[str] = field(default_factory=list)
    route_path: list[str] = field(default_factory=list)

    # Current position
    current_node: GraphNode | None = None
    current_subnet_id: str | None = None


class PathAnalyzer:
    """Analyzes network paths between AWS resources.

    Uses deterministic LPM-based routing traversal (not graph search).
    Each hop evaluates Security Groups, NACLs, and route tables.

    Attributes:
        graph: GraphManager for topology and resource access
        max_hops: Maximum hops before terminating (default 50)
    """

    # Maximum hops to prevent infinite loops in edge cases
    MAX_HOPS = 50

    def __init__(
        self,
        graph: GraphManager,
        max_hops: int = MAX_HOPS,
    ) -> None:
        """Initialize the PathAnalyzer.

        Args:
            graph: GraphManager for topology access
            max_hops: Maximum hops before terminating (default 50)
        """
        self.graph = graph
        self.max_hops = max_hops

    async def analyze(
        self,
        source_id: str,
        dest_ip: str,
        port: int,
        protocol: str = "tcp",
        force_refresh: bool = False,
    ) -> PathAnalysisResult:
        """Analyze network path from source to destination.

        Args:
            source_id: Source resource ID (i-xxx or eni-xxx)
            dest_ip: Destination IP address
            port: Destination port number
            protocol: Protocol ("tcp", "udp", "icmp", or "-1")
            force_refresh: If True, bypass cache

        Returns:
            PathAnalysisResult with status, hops, and verification info.
        """
        # Initialize traversal context
        ctx = TraversalContext(
            source_ip="",  # Will be set after resolving source
            dest_ip=dest_ip,
            port=port,
            protocol=protocol.lower(),
            force_refresh=force_refresh,
        )

        try:
            # Step 1: Resolve source to ENI
            source_eni = await self._resolve_source(source_id, ctx)
            if source_eni is None:
                return self._unknown_result(
                    ctx,
                    source_id,
                    f"Could not resolve source {source_id} to ENI",
                )

            # Get source IP from ENI
            if source_eni.eni_attrs is None:
                return self._unknown_result(
                    ctx,
                    source_id,
                    f"Source ENI {source_eni.id} has no attributes",
                )

            ctx.source_ip = str(source_eni.eni_attrs.private_ip)
            ctx.current_node = source_eni
            ctx.current_subnet_id = source_eni.eni_attrs.subnet_id

            # Step 2: Check if destination is in same subnet (local)
            if await self._is_local_destination(ctx):
                return await self._handle_local_destination(ctx, source_id)

            # Step 3: Evaluate egress from source
            egress_result = await self._evaluate_egress(ctx, source_eni)
            if egress_result.status != PathStatus.REACHABLE:
                return egress_result

            # Step 4: Traverse to destination via routing
            traversal_result = await self._traverse_to_destination(ctx)
            if traversal_result.status != PathStatus.REACHABLE:
                return traversal_result

            # Check if traffic exited VPC (peering, TGW) - no further evaluation needed
            if self._traffic_exited_vpc(ctx):
                return traversal_result

            # Step 5: Evaluate ingress at destination
            ingress_result = await self._evaluate_destination_ingress(ctx)
            if ingress_result.status != PathStatus.REACHABLE:
                return ingress_result

            # Step 6: Verify NACL return path
            return_path_result = await self._verify_nacl_return_path(ctx)
            if return_path_result.status != PathStatus.REACHABLE:
                return return_path_result

            # Step 7: Verify reverse route exists
            return await self._verify_reverse_route(ctx, source_id)

        except PermissionDeniedError as e:
            logger.warning(f"Permission denied during path analysis: {e}")
            return self._unknown_result(
                ctx,
                source_id,
                f"Access denied: {e.message}. Cannot determine reachability.",
            )
        except CrossAccountSGResolutionError as e:
            logger.warning(f"Cross-account SG resolution failed: {e}")
            return self._unknown_result(
                ctx,
                source_id,
                f"Cannot verify cross-account SG reference: {e.message}",
            )
        except ResourceNotFoundError as e:
            logger.warning(f"Resource not found during path analysis: {e}")
            return self._unknown_result(
                ctx,
                source_id,
                f"Resource not found: {e.message}",
            )
        except Exception as e:
            logger.error(f"Unexpected error during path analysis: {e}", exc_info=True)
            return self._unknown_result(
                ctx,
                source_id,
                f"Analysis failed: {e!s}",
            )

    # =========================================================================
    # Source Resolution
    # =========================================================================

    async def _resolve_source(
        self,
        source_id: str,
        ctx: TraversalContext,
    ) -> GraphNode | None:
        """Resolve source ID to ENI GraphNode.

        Args:
            source_id: Instance or ENI ID
            ctx: Traversal context

        Returns:
            GraphNode for the source ENI, or None if not found.
        """
        return await self.graph.resolve_to_eni(
            source_id,
            force_refresh=ctx.force_refresh,
        )

    async def _is_local_destination(self, ctx: TraversalContext) -> bool:
        """Check if destination IP is in same subnet as source.

        Local traffic doesn't leave the subnet - no routing required.
        """
        if ctx.current_subnet_id is None:
            return False

        subnet = await self.graph.get_subnet(
            ctx.current_subnet_id,
            force_refresh=ctx.force_refresh,
        )
        if subnet is None or subnet.subnet_attrs is None:
            return False

        # Check if dest_ip is in subnet CIDR
        cidr = subnet.subnet_attrs.cidr_block
        if cidr and CIDRMatcher.matches(ctx.dest_ip, cidr):
            return True

        # Check IPv6 if available
        ipv6_cidr = subnet.subnet_attrs.ipv6_cidr_block
        if ipv6_cidr and CIDRMatcher.matches(ctx.dest_ip, ipv6_cidr):
            return True

        return False

    async def _handle_local_destination(
        self,
        ctx: TraversalContext,
        source_id: str,
    ) -> PathAnalysisResult:
        """Handle traffic to destination in same subnet.

        Local traffic still goes through SG evaluation but not routing.
        """
        if ctx.current_node is None or ctx.current_node.eni_attrs is None:
            return self._unknown_result(ctx, source_id, "Source ENI not available")

        # Evaluate egress SG at source
        sg_ids = ctx.current_node.eni_attrs.security_group_ids
        sgs = await self._get_security_groups(sg_ids, ctx)
        ctx.evaluated_sgs.extend(sg_ids)

        egress_eval = await SecurityGroupEvaluator.evaluate_egress(
            security_groups=sgs,
            dest_ip=ctx.dest_ip,
            port=ctx.port,
            protocol=ctx.protocol,
            prefix_resolver=self.graph.fetcher,
        )

        if not egress_eval.allowed:
            return self._blocked_result(
                ctx,
                source_id,
                blocked_at=HopResult(
                    hop_number=1,
                    node_id=ctx.current_node.id,
                    node_type=NodeType.ENI,
                    sg_eval=egress_eval,
                    status=PathStatus.BLOCKED,
                ),
            )

        # Find destination ENI in same subnet
        dest_eni = await self.graph.find_eni_by_ip(ctx.dest_ip, ctx.force_refresh)
        if dest_eni is None:
            return self._unknown_result(
                ctx,
                source_id,
                f"Cannot find ENI with IP {ctx.dest_ip} in local subnet",
            )

        # Evaluate ingress SG at destination
        if dest_eni.eni_attrs is None:
            return self._unknown_result(
                ctx,
                source_id,
                f"Destination ENI {dest_eni.id} has no attributes",
            )

        dest_sg_ids = dest_eni.eni_attrs.security_group_ids
        dest_sgs = await self._get_security_groups(dest_sg_ids, ctx)
        ctx.evaluated_sgs.extend(dest_sg_ids)

        ingress_eval = await SecurityGroupEvaluator.evaluate_ingress(
            security_groups=dest_sgs,
            source_ip=ctx.source_ip,
            port=ctx.port,
            protocol=ctx.protocol,
            prefix_resolver=self.graph.fetcher,
        )

        if not ingress_eval.allowed:
            return self._blocked_result(
                ctx,
                source_id,
                blocked_at=HopResult(
                    hop_number=2,
                    node_id=dest_eni.id,
                    node_type=NodeType.ENI,
                    sg_eval=ingress_eval,
                    status=PathStatus.BLOCKED,
                ),
            )

        # Local traffic is reachable
        ctx.hops.append(
            HopResult(
                hop_number=1,
                node_id=ctx.current_node.id,
                node_type=NodeType.ENI,
                sg_eval=egress_eval,
                status=PathStatus.REACHABLE,
            )
        )
        ctx.hops.append(
            HopResult(
                hop_number=2,
                node_id=dest_eni.id,
                node_type=NodeType.ENI,
                sg_eval=ingress_eval,
                status=PathStatus.REACHABLE,
            )
        )

        return self._reachable_result(
            ctx,
            source_id,
            return_route_verified=True,  # Local traffic doesn't need routing
            return_route_table_id=None,
        )

    # =========================================================================
    # Egress Evaluation
    # =========================================================================

    async def _evaluate_egress(
        self,
        ctx: TraversalContext,
        source_eni: GraphNode,
    ) -> PathAnalysisResult:
        """Evaluate egress from source (SG, NACL, Route).

        Returns REACHABLE if all checks pass, BLOCKED otherwise.
        """
        if source_eni.eni_attrs is None:
            return self._unknown_result(
                ctx,
                source_eni.id,
                "Source ENI has no attributes",
            )

        ctx.hop_counter += 1
        hop_number = ctx.hop_counter

        # 1. Security Group egress check
        sg_ids = source_eni.eni_attrs.security_group_ids
        sgs = await self._get_security_groups(sg_ids, ctx)
        ctx.evaluated_sgs.extend(sg_ids)

        sg_eval = await SecurityGroupEvaluator.evaluate_egress(
            security_groups=sgs,
            dest_ip=ctx.dest_ip,
            port=ctx.port,
            protocol=ctx.protocol,
            prefix_resolver=self.graph.fetcher,
        )

        if not sg_eval.allowed:
            return self._blocked_result(
                ctx,
                source_eni.id,
                blocked_at=HopResult(
                    hop_number=hop_number,
                    node_id=source_eni.id,
                    node_type=NodeType.ENI,
                    sg_eval=sg_eval,
                    status=PathStatus.BLOCKED,
                ),
            )

        # 2. NACL outbound check
        subnet = await self.graph.get_subnet(
            source_eni.eni_attrs.subnet_id,
            force_refresh=ctx.force_refresh,
        )
        if subnet is None or subnet.subnet_attrs is None:
            return self._unknown_result(
                ctx,
                source_eni.id,
                f"Cannot fetch subnet {source_eni.eni_attrs.subnet_id}",
            )

        nacl_id = subnet.subnet_attrs.nacl_id
        nacl = await self.graph.get_nacl(nacl_id, force_refresh=ctx.force_refresh)
        if nacl is None:
            return self._unknown_result(
                ctx,
                source_eni.id,
                f"Cannot fetch NACL {nacl_id}",
            )

        ctx.evaluated_nacls.append(nacl_id)

        nacl_eval = NACLEvaluator.evaluate(
            rules=nacl.outbound_rules,
            direction="outbound",
            source_ip=ctx.source_ip,
            dest_ip=ctx.dest_ip,
            port=ctx.port,
            protocol=ctx.protocol,
            nacl_id=nacl_id,
        )

        if not nacl_eval.allowed:
            return self._blocked_result(
                ctx,
                source_eni.id,
                blocked_at=HopResult(
                    hop_number=hop_number,
                    node_id=source_eni.id,
                    node_type=NodeType.ENI,
                    sg_eval=sg_eval,
                    nacl_eval=nacl_eval,
                    status=PathStatus.BLOCKED,
                ),
            )

        # 3. Route table lookup
        rt_id = subnet.subnet_attrs.route_table_id
        route_table = await self.graph.get_route_table(
            rt_id,
            force_refresh=ctx.force_refresh,
        )
        if route_table is None:
            return self._unknown_result(
                ctx,
                source_eni.id,
                f"Cannot fetch route table {rt_id}",
            )

        ctx.route_path.append(rt_id)

        route_eval = RouteEvaluator.find_route(
            dest_ip=ctx.dest_ip,
            routes=route_table.routes,
            route_table_id=rt_id,
        )

        if not route_eval.allowed:
            return self._blocked_result(
                ctx,
                source_eni.id,
                blocked_at=HopResult(
                    hop_number=hop_number,
                    node_id=source_eni.id,
                    node_type=NodeType.ENI,
                    sg_eval=sg_eval,
                    nacl_eval=nacl_eval,
                    route_eval=route_eval,
                    status=PathStatus.BLOCKED,
                ),
            )

        # Egress passed - record hop
        hop = HopResult(
            hop_number=hop_number,
            node_id=source_eni.id,
            node_type=NodeType.ENI,
            sg_eval=sg_eval,
            nacl_eval=nacl_eval,
            route_eval=route_eval,
            status=PathStatus.REACHABLE,
        )
        ctx.hops.append(hop)
        ctx.visited_nodes.add(source_eni.id)

        # Store route info for traversal
        ctx.current_node = source_eni

        return PathAnalysisResult(
            status=PathStatus.REACHABLE,
            source_id=source_eni.id,
            destination_ip=ctx.dest_ip,
            port=ctx.port,
            protocol=ctx.protocol,
            hops=ctx.hops,
        )

    # =========================================================================
    # Traversal to Destination
    # =========================================================================

    async def _traverse_to_destination(
        self,
        ctx: TraversalContext,
    ) -> PathAnalysisResult:
        """Traverse from source subnet to destination via routing.

        Uses LPM to determine next hop at each step.
        Handles IGW, NAT, VPC Peering, and TGW.
        """
        while ctx.hop_counter < self.max_hops:
            # Get current subnet's route table
            if ctx.current_subnet_id is None:
                return self._unknown_result(
                    ctx,
                    ctx.hops[-1].node_id if ctx.hops else "unknown",
                    "Lost subnet context during traversal",
                )

            subnet = await self.graph.get_subnet(
                ctx.current_subnet_id,
                force_refresh=ctx.force_refresh,
            )
            if subnet is None or subnet.subnet_attrs is None:
                return self._unknown_result(
                    ctx,
                    ctx.current_subnet_id,
                    f"Cannot fetch subnet {ctx.current_subnet_id}",
                )

            rt_id = subnet.subnet_attrs.route_table_id
            route_table = await self.graph.get_route_table(
                rt_id,
                force_refresh=ctx.force_refresh,
            )
            if route_table is None:
                return self._unknown_result(
                    ctx,
                    ctx.current_subnet_id,
                    f"Cannot fetch route table {rt_id}",
                )

            # Find next hop via LPM
            next_hop = RouteEvaluator.get_next_hop(ctx.dest_ip, route_table.routes)
            if next_hop is None:
                return self._blocked_result(
                    ctx,
                    ctx.current_subnet_id,
                    blocked_at=HopResult(
                        hop_number=ctx.hop_counter + 1,
                        node_id=ctx.current_subnet_id,
                        node_type=NodeType.SUBNET,
                        route_eval=RuleEvalResult(
                            allowed=False,
                            resource_id=rt_id,
                            resource_type="route_table",
                            reason=f"No route to {ctx.dest_ip}",
                        ),
                        status=PathStatus.BLOCKED,
                    ),
                )

            target_id, target_type = next_hop

            # Check for local route - destination reached
            if target_type == "local":
                # Traffic stays in VPC - destination should be reachable
                return PathAnalysisResult(
                    status=PathStatus.REACHABLE,
                    source_id=ctx.hops[0].node_id if ctx.hops else "unknown",
                    destination_ip=ctx.dest_ip,
                    port=ctx.port,
                    protocol=ctx.protocol,
                    hops=ctx.hops,
                    evaluated_security_groups=ctx.evaluated_sgs,
                    evaluated_nacls=ctx.evaluated_nacls,
                    route_path=ctx.route_path,
                )

            # Loop detection
            if target_id in ctx.visited_nodes:
                return self._blocked_result(
                    ctx,
                    target_id,
                    blocked_at=HopResult(
                        hop_number=ctx.hop_counter + 1,
                        node_id=target_id,
                        node_type=self._target_type_to_node_type(target_type),
                        route_eval=RuleEvalResult(
                            allowed=False,
                            resource_id=rt_id,
                            resource_type="route_table",
                            reason=f"Routing loop detected: {target_id} visited twice",
                        ),
                        status=PathStatus.BLOCKED,
                    ),
                )

            # Handle different target types
            result = await self._handle_next_hop(
                ctx,
                target_id,
                target_type,
                rt_id,
            )

            if result is not None:
                return result

            # Continue traversal
            ctx.visited_nodes.add(target_id)

        # Max hops exceeded
        return self._unknown_result(
            ctx,
            ctx.hops[-1].node_id if ctx.hops else "unknown",
            f"Max hops ({self.max_hops}) exceeded - possible routing issue",
        )

    async def _handle_next_hop(
        self,
        ctx: TraversalContext,
        target_id: str,
        target_type: str,
        route_table_id: str,
    ) -> PathAnalysisResult | None:
        """Handle traversal through different hop types.

        Returns PathAnalysisResult if traversal completes or fails.
        Returns None if traversal should continue.
        """
        ctx.hop_counter += 1
        hop_number = ctx.hop_counter
        ctx.route_path.append(route_table_id)

        # Handle Internet Gateway
        if target_type == "igw":
            return await self._handle_igw(ctx, target_id, hop_number)

        # Handle NAT Gateway
        if target_type == "nat":
            return await self._handle_nat(ctx, target_id, hop_number)

        # Handle VPC Peering
        if target_type == "peering":
            return await self._handle_peering(ctx, target_id, hop_number)

        # Handle Transit Gateway - not supported
        if target_type == "tgw":
            return self._handle_tgw(ctx, target_id, hop_number)

        # Handle ENI or Instance target
        if target_type in ("eni", "instance"):
            return await self._handle_eni_target(ctx, target_id, hop_number)

        # Unknown target type
        return self._unknown_result(
            ctx,
            target_id,
            f"Unknown route target type: {target_type}",
        )

    async def _handle_igw(
        self,
        ctx: TraversalContext,
        igw_id: str,
        hop_number: int,
    ) -> PathAnalysisResult | None:
        """Handle Internet Gateway traversal.

        IGW allows traffic to/from the internet.
        For outbound: traffic leaves VPC to internet destination.
        """
        igw = await self.graph.get_node(igw_id, force_refresh=ctx.force_refresh)
        if igw is None:
            return self._unknown_result(
                ctx,
                igw_id,
                f"Cannot fetch Internet Gateway {igw_id}",
            )

        hop = HopResult(
            hop_number=hop_number,
            node_id=igw_id,
            node_type=NodeType.INTERNET_GATEWAY,
            route_eval=RuleEvalResult(
                allowed=True,
                resource_id=igw_id,
                resource_type="route_table",
                reason=f"Traffic routed to Internet Gateway {igw_id}",
            ),
            status=PathStatus.REACHABLE,
        )
        ctx.hops.append(hop)

        # Check if destination is a public IP (outside VPC)
        if self._is_public_ip(ctx.dest_ip):
            # Traffic leaves VPC - path complete (no further VPC evaluation needed)
            return PathAnalysisResult(
                status=PathStatus.REACHABLE,
                source_id=ctx.hops[0].node_id if ctx.hops else "unknown",
                destination_ip=ctx.dest_ip,
                port=ctx.port,
                protocol=ctx.protocol,
                hops=ctx.hops,
                evaluated_security_groups=ctx.evaluated_sgs,
                evaluated_nacls=ctx.evaluated_nacls,
                route_path=ctx.route_path,
                return_route_verified=True,  # Internet doesn't need reverse verification
                summary="Traffic exits VPC via Internet Gateway to public destination",
            )

        # Destination should be reachable via IGW
        return None  # Continue traversal

    async def _handle_nat(
        self,
        ctx: TraversalContext,
        nat_id: str,
        hop_number: int,
    ) -> PathAnalysisResult | None:
        """Handle NAT Gateway traversal.

        NAT Gateway translates private IPs to public for internet egress.
        """
        nat = await self.graph.get_node(nat_id, force_refresh=ctx.force_refresh)
        if nat is None:
            return self._unknown_result(
                ctx,
                nat_id,
                f"Cannot fetch NAT Gateway {nat_id}",
            )

        hop = HopResult(
            hop_number=hop_number,
            node_id=nat_id,
            node_type=NodeType.NAT_GATEWAY,
            route_eval=RuleEvalResult(
                allowed=True,
                resource_id=nat_id,
                resource_type="route_table",
                reason=f"Traffic routed to NAT Gateway {nat_id}",
            ),
            status=PathStatus.REACHABLE,
        )
        ctx.hops.append(hop)

        # NAT Gateway routes to internet - path complete for internet destinations
        if self._is_public_ip(ctx.dest_ip):
            return PathAnalysisResult(
                status=PathStatus.REACHABLE,
                source_id=ctx.hops[0].node_id if ctx.hops else "unknown",
                destination_ip=ctx.dest_ip,
                port=ctx.port,
                protocol=ctx.protocol,
                hops=ctx.hops,
                evaluated_security_groups=ctx.evaluated_sgs,
                evaluated_nacls=ctx.evaluated_nacls,
                route_path=ctx.route_path,
                return_route_verified=True,
                summary="Traffic exits VPC via NAT Gateway to public destination",
            )

        return None  # Continue traversal

    async def _handle_peering(
        self,
        ctx: TraversalContext,
        pcx_id: str,
        hop_number: int,
    ) -> PathAnalysisResult | None:
        """Handle VPC Peering connection traversal.

        Traffic crosses to peer VPC. Need to continue evaluation
        in the peer VPC context.
        """
        pcx = await self.graph.get_node(pcx_id, force_refresh=ctx.force_refresh)
        if pcx is None:
            return self._unknown_result(
                ctx,
                pcx_id,
                f"Cannot fetch VPC Peering connection {pcx_id}",
            )

        hop = HopResult(
            hop_number=hop_number,
            node_id=pcx_id,
            node_type=NodeType.VPC_PEERING,
            route_eval=RuleEvalResult(
                allowed=True,
                resource_id=pcx_id,
                resource_type="route_table",
                reason=f"Traffic routed via VPC Peering {pcx_id}",
            ),
            status=PathStatus.REACHABLE,
        )
        ctx.hops.append(hop)

        # Get peer VPC info
        if pcx.gateway_attrs is None:
            return self._unknown_result(
                ctx,
                pcx_id,
                f"VPC Peering {pcx_id} has no gateway attributes",
            )

        peer_vpc_id = pcx.gateway_attrs.peer_vpc_id
        peer_account_id = pcx.gateway_attrs.peer_account_id

        # Check for cross-account peering
        if peer_account_id and peer_account_id != self.graph.account_id:
            return self._unknown_result(
                ctx,
                pcx_id,
                f"Cross-account VPC peering to {peer_account_id}/{peer_vpc_id}. "
                f"Cannot verify connectivity in peer account.",
            )

        # TODO: Continue traversal in peer VPC
        # For now, we mark as reachable if we got to the peering connection
        # Full implementation would switch context to peer VPC

        return PathAnalysisResult(
            status=PathStatus.REACHABLE,
            source_id=ctx.hops[0].node_id if ctx.hops else "unknown",
            destination_ip=ctx.dest_ip,
            port=ctx.port,
            protocol=ctx.protocol,
            hops=ctx.hops,
            evaluated_security_groups=ctx.evaluated_sgs,
            evaluated_nacls=ctx.evaluated_nacls,
            route_path=ctx.route_path,
            return_route_verified=False,  # Cannot verify return path in peer VPC
            summary=f"Traffic routed via VPC Peering to {peer_vpc_id}",
        )

    def _handle_tgw(
        self,
        ctx: TraversalContext,
        tgw_id: str,
        hop_number: int,
    ) -> PathAnalysisResult:
        """Handle Transit Gateway - not supported.

        Transit Gateway routing is complex and not yet implemented.
        Return UNKNOWN status with clear message.
        """
        hop = HopResult(
            hop_number=hop_number,
            node_id=tgw_id,
            node_type=NodeType.TRANSIT_GATEWAY,
            route_eval=RuleEvalResult(
                allowed=False,
                resource_id=tgw_id,
                resource_type="route_table",
                reason="Transit Gateway traversal not yet supported",
            ),
            status=PathStatus.UNKNOWN,
        )
        ctx.hops.append(hop)

        return PathAnalysisResult(
            status=PathStatus.UNKNOWN,
            source_id=ctx.hops[0].node_id if ctx.hops else "unknown",
            destination_ip=ctx.dest_ip,
            port=ctx.port,
            protocol=ctx.protocol,
            hops=ctx.hops,
            unknown_reason=f"Transit Gateway traversal not yet supported. "
            f"Cannot determine reachability through {tgw_id}.",
            evaluated_security_groups=ctx.evaluated_sgs,
            evaluated_nacls=ctx.evaluated_nacls,
            route_path=ctx.route_path,
        )

    async def _handle_eni_target(
        self,
        ctx: TraversalContext,
        target_id: str,
        hop_number: int,
    ) -> PathAnalysisResult | None:
        """Handle ENI or Instance as route target.

        This typically indicates a VPC endpoint or appliance.
        """
        node = await self.graph.get_node(target_id, force_refresh=ctx.force_refresh)
        if node is None:
            return self._unknown_result(
                ctx,
                target_id,
                f"Cannot fetch target {target_id}",
            )

        node_type = NodeType.ENI if target_id.startswith("eni-") else NodeType.INSTANCE

        hop = HopResult(
            hop_number=hop_number,
            node_id=target_id,
            node_type=node_type,
            route_eval=RuleEvalResult(
                allowed=True,
                resource_id=target_id,
                resource_type="route_table",
                reason=f"Traffic routed to {node_type.value} {target_id}",
            ),
            status=PathStatus.REACHABLE,
        )
        ctx.hops.append(hop)

        # Update context for potential continued traversal
        if node.eni_attrs is not None:
            ctx.current_subnet_id = node.eni_attrs.subnet_id
        elif node.instance_attrs is not None:
            ctx.current_subnet_id = node.instance_attrs.subnet_id

        return None  # Continue traversal

    # =========================================================================
    # Destination Ingress Evaluation
    # =========================================================================

    async def _evaluate_destination_ingress(
        self,
        ctx: TraversalContext,
    ) -> PathAnalysisResult:
        """Evaluate ingress rules at destination.

        Checks destination's Security Groups and subnet's inbound NACL.
        """
        # Find destination ENI
        dest_eni = await self.graph.find_eni_by_ip(ctx.dest_ip, ctx.force_refresh)
        if dest_eni is None:
            # Destination might be external (internet)
            if self._is_public_ip(ctx.dest_ip):
                return PathAnalysisResult(
                    status=PathStatus.REACHABLE,
                    source_id=ctx.hops[0].node_id if ctx.hops else "unknown",
                    destination_ip=ctx.dest_ip,
                    port=ctx.port,
                    protocol=ctx.protocol,
                    hops=ctx.hops,
                    evaluated_security_groups=ctx.evaluated_sgs,
                    evaluated_nacls=ctx.evaluated_nacls,
                    route_path=ctx.route_path,
                    return_route_verified=True,
                )

            return self._unknown_result(
                ctx,
                "destination",
                f"Cannot find ENI with IP {ctx.dest_ip}",
            )

        if dest_eni.eni_attrs is None:
            return self._unknown_result(
                ctx,
                dest_eni.id,
                f"Destination ENI {dest_eni.id} has no attributes",
            )

        ctx.hop_counter += 1
        hop_number = ctx.hop_counter

        # 1. NACL inbound check
        dest_subnet_id = dest_eni.eni_attrs.subnet_id
        dest_subnet = await self.graph.get_subnet(
            dest_subnet_id,
            force_refresh=ctx.force_refresh,
        )
        if dest_subnet is None or dest_subnet.subnet_attrs is None:
            return self._unknown_result(
                ctx,
                dest_subnet_id,
                f"Cannot fetch destination subnet {dest_subnet_id}",
            )

        nacl_id = dest_subnet.subnet_attrs.nacl_id
        nacl = await self.graph.get_nacl(nacl_id, force_refresh=ctx.force_refresh)
        if nacl is None:
            return self._unknown_result(
                ctx,
                nacl_id,
                f"Cannot fetch destination NACL {nacl_id}",
            )

        ctx.evaluated_nacls.append(nacl_id)

        nacl_eval = NACLEvaluator.evaluate(
            rules=nacl.inbound_rules,
            direction="inbound",
            source_ip=ctx.source_ip,
            dest_ip=ctx.dest_ip,
            port=ctx.port,
            protocol=ctx.protocol,
            nacl_id=nacl_id,
        )

        if not nacl_eval.allowed:
            return self._blocked_result(
                ctx,
                dest_eni.id,
                blocked_at=HopResult(
                    hop_number=hop_number,
                    node_id=dest_eni.id,
                    node_type=NodeType.ENI,
                    nacl_eval=nacl_eval,
                    status=PathStatus.BLOCKED,
                ),
            )

        # 2. Security Group ingress check
        sg_ids = dest_eni.eni_attrs.security_group_ids
        sgs = await self._get_security_groups(sg_ids, ctx)
        ctx.evaluated_sgs.extend(sg_ids)

        sg_eval = await SecurityGroupEvaluator.evaluate_ingress(
            security_groups=sgs,
            source_ip=ctx.source_ip,
            port=ctx.port,
            protocol=ctx.protocol,
            prefix_resolver=self.graph.fetcher,
        )

        if not sg_eval.allowed:
            return self._blocked_result(
                ctx,
                dest_eni.id,
                blocked_at=HopResult(
                    hop_number=hop_number,
                    node_id=dest_eni.id,
                    node_type=NodeType.ENI,
                    nacl_eval=nacl_eval,
                    sg_eval=sg_eval,
                    status=PathStatus.BLOCKED,
                ),
            )

        # Record destination hop
        hop = HopResult(
            hop_number=hop_number,
            node_id=dest_eni.id,
            node_type=NodeType.ENI,
            nacl_eval=nacl_eval,
            sg_eval=sg_eval,
            status=PathStatus.REACHABLE,
        )
        ctx.hops.append(hop)

        # Store for return path verification
        ctx.current_node = dest_eni
        ctx.current_subnet_id = dest_subnet_id

        return PathAnalysisResult(
            status=PathStatus.REACHABLE,
            source_id=ctx.hops[0].node_id if ctx.hops else "unknown",
            destination_ip=ctx.dest_ip,
            port=ctx.port,
            protocol=ctx.protocol,
            hops=ctx.hops,
            evaluated_security_groups=ctx.evaluated_sgs,
            evaluated_nacls=ctx.evaluated_nacls,
            route_path=ctx.route_path,
        )

    # =========================================================================
    # Return Path Verification
    # =========================================================================

    async def _verify_nacl_return_path(
        self,
        ctx: TraversalContext,
    ) -> PathAnalysisResult:
        """Verify NACL allows return traffic on ephemeral ports.

        NACLs are stateless - return traffic needs explicit rules.
        This catches connection hangs caused by blocked return traffic.
        """
        if ctx.current_subnet_id is None:
            return PathAnalysisResult(
                status=PathStatus.REACHABLE,
                source_id=ctx.hops[0].node_id if ctx.hops else "unknown",
                destination_ip=ctx.dest_ip,
                port=ctx.port,
                protocol=ctx.protocol,
                hops=ctx.hops,
                evaluated_security_groups=ctx.evaluated_sgs,
                evaluated_nacls=ctx.evaluated_nacls,
                route_path=ctx.route_path,
            )

        dest_subnet = await self.graph.get_subnet(
            ctx.current_subnet_id,
            force_refresh=ctx.force_refresh,
        )
        if dest_subnet is None or dest_subnet.subnet_attrs is None:
            return PathAnalysisResult(
                status=PathStatus.REACHABLE,
                source_id=ctx.hops[0].node_id if ctx.hops else "unknown",
                destination_ip=ctx.dest_ip,
                port=ctx.port,
                protocol=ctx.protocol,
                hops=ctx.hops,
            )

        nacl_id = dest_subnet.subnet_attrs.nacl_id
        nacl = await self.graph.get_nacl(nacl_id, force_refresh=ctx.force_refresh)
        if nacl is None:
            return PathAnalysisResult(
                status=PathStatus.REACHABLE,
                source_id=ctx.hops[0].node_id if ctx.hops else "unknown",
                destination_ip=ctx.dest_ip,
                port=ctx.port,
                protocol=ctx.protocol,
                hops=ctx.hops,
            )

        # Verify return path allows ephemeral ports
        return_eval = evaluate_nacl_return_path(
            rules=nacl.outbound_rules,
            source_ip=ctx.source_ip,
            dest_ip=ctx.dest_ip,
            protocol=ctx.protocol,
            nacl_id=nacl_id,
        )

        if not return_eval.allowed:
            return self._blocked_result(
                ctx,
                ctx.current_subnet_id,
                blocked_at=HopResult(
                    hop_number=ctx.hop_counter + 1,
                    node_id=nacl_id,
                    node_type=NodeType.SUBNET,  # NACL is at subnet level
                    nacl_eval=return_eval,
                    status=PathStatus.BLOCKED,
                ),
            )

        return PathAnalysisResult(
            status=PathStatus.REACHABLE,
            source_id=ctx.hops[0].node_id if ctx.hops else "unknown",
            destination_ip=ctx.dest_ip,
            port=ctx.port,
            protocol=ctx.protocol,
            hops=ctx.hops,
            evaluated_security_groups=ctx.evaluated_sgs,
            evaluated_nacls=ctx.evaluated_nacls,
            route_path=ctx.route_path,
        )

    async def _verify_reverse_route(
        self,
        ctx: TraversalContext,
        source_id: str,
    ) -> PathAnalysisResult:
        """Verify destination can route back to source.

        Catches asymmetric routing failures where forward path works
        but return traffic has no route.
        """
        if ctx.current_subnet_id is None:
            return self._reachable_result(ctx, source_id, False, None)

        dest_subnet = await self.graph.get_subnet(
            ctx.current_subnet_id,
            force_refresh=ctx.force_refresh,
        )
        if dest_subnet is None or dest_subnet.subnet_attrs is None:
            return self._reachable_result(ctx, source_id, False, None)

        rt_id = dest_subnet.subnet_attrs.route_table_id
        route_table = await self.graph.get_route_table(
            rt_id,
            force_refresh=ctx.force_refresh,
        )
        if route_table is None:
            return self._reachable_result(ctx, source_id, False, None)

        # Check if there's a route back to source IP
        return_route = find_longest_prefix_match(ctx.source_ip, route_table.routes)

        if return_route is None:
            return self._blocked_result(
                ctx,
                source_id,
                blocked_at=HopResult(
                    hop_number=ctx.hop_counter + 1,
                    node_id=ctx.current_subnet_id,
                    node_type=NodeType.SUBNET,
                    route_eval=RuleEvalResult(
                        allowed=False,
                        resource_id=rt_id,
                        resource_type="route_table",
                        direction="return",
                        reason=f"Destination has NO ROUTE back to source IP {ctx.source_ip}. "
                        f"Asymmetric routing failure.",
                    ),
                    status=PathStatus.BLOCKED,
                ),
            )

        return self._reachable_result(ctx, source_id, True, rt_id)

    # =========================================================================
    # Helper Methods
    # =========================================================================

    async def _get_security_groups(
        self,
        sg_ids: list[str],
        ctx: TraversalContext,
    ) -> list[SecurityGroup]:
        """Fetch multiple security groups."""
        sgs: list[SecurityGroup] = []
        for sg_id in sg_ids:
            sg = await self.graph.get_security_group(
                sg_id,
                force_refresh=ctx.force_refresh,
            )
            if sg is not None:
                sgs.append(sg)
        return sgs

    def _is_public_ip(self, ip: str) -> bool:
        """Check if IP is a public (non-RFC1918) address."""
        try:
            addr = ip_address(ip)
            return not (
                addr.is_private
                or addr.is_loopback
                or addr.is_link_local
                or addr.is_reserved
            )
        except ValueError:
            return False

    def _target_type_to_node_type(self, target_type: str) -> NodeType:
        """Convert route target type to NodeType enum."""
        type_map = {
            "igw": NodeType.INTERNET_GATEWAY,
            "nat": NodeType.NAT_GATEWAY,
            "peering": NodeType.VPC_PEERING,
            "tgw": NodeType.TRANSIT_GATEWAY,
            "eni": NodeType.ENI,
            "instance": NodeType.INSTANCE,
            "local": NodeType.SUBNET,
        }
        return type_map.get(target_type, NodeType.SUBNET)

    def _traffic_exited_vpc(self, ctx: TraversalContext) -> bool:
        """Check if traffic has exited the current VPC via peering or TGW.

        When traffic routes through VPC Peering or Transit Gateway,
        we can't evaluate destination ingress in the peer VPC.
        """
        if not ctx.hops:
            return False

        last_hop = ctx.hops[-1]
        # VPC Peering and TGW traffic exits the current VPC
        return last_hop.node_type in (
            NodeType.VPC_PEERING,
            NodeType.TRANSIT_GATEWAY,
        )

    # =========================================================================
    # Result Builders
    # =========================================================================

    def _reachable_result(
        self,
        ctx: TraversalContext,
        source_id: str,
        return_route_verified: bool,
        return_route_table_id: str | None,
    ) -> PathAnalysisResult:
        """Build a REACHABLE result."""
        result = PathAnalysisResult(
            status=PathStatus.REACHABLE,
            source_id=source_id,
            destination_ip=ctx.dest_ip,
            port=ctx.port,
            protocol=ctx.protocol,
            hops=ctx.hops,
            evaluated_security_groups=ctx.evaluated_sgs,
            evaluated_nacls=ctx.evaluated_nacls,
            route_path=ctx.route_path,
            return_route_verified=return_route_verified,
            return_route_table_id=return_route_table_id,
        )
        result.summary = result.generate_human_summary()
        return result

    def _blocked_result(
        self,
        ctx: TraversalContext,
        source_id: str,
        blocked_at: HopResult,
    ) -> PathAnalysisResult:
        """Build a BLOCKED result."""
        result = PathAnalysisResult(
            status=PathStatus.BLOCKED,
            source_id=source_id,
            destination_ip=ctx.dest_ip,
            port=ctx.port,
            protocol=ctx.protocol,
            hops=ctx.hops,
            blocked_at=blocked_at,
            evaluated_security_groups=ctx.evaluated_sgs,
            evaluated_nacls=ctx.evaluated_nacls,
            route_path=ctx.route_path,
        )
        result.summary = result.generate_human_summary()
        return result

    def _unknown_result(
        self,
        ctx: TraversalContext,
        source_id: str,
        reason: str,
    ) -> PathAnalysisResult:
        """Build an UNKNOWN result."""
        result = PathAnalysisResult(
            status=PathStatus.UNKNOWN,
            source_id=source_id,
            destination_ip=ctx.dest_ip,
            port=ctx.port,
            protocol=ctx.protocol,
            hops=ctx.hops,
            unknown_reason=reason,
            evaluated_security_groups=ctx.evaluated_sgs,
            evaluated_nacls=ctx.evaluated_nacls,
            route_path=ctx.route_path,
        )
        result.summary = result.generate_human_summary()
        return result
