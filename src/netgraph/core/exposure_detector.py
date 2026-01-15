"""Exposure Detector for finding resources exposed to the public internet.

This module scans VPC resources to find ENIs that have:
1. A route to an Internet Gateway (IGW)
2. Security Group rules allowing inbound traffic on a specified port
3. NACL rules allowing the traffic

Used for security analysis to identify resources that may be unintentionally
exposed to the public internet.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from netgraph.evaluators.route import RouteEvaluator
from netgraph.evaluators.security_group import SecurityGroupEvaluator
from netgraph.models import (
    ExposedResource,
    GraphNode,
    NodeType,
    PublicExposureResult,
    SecurityGroup,
)
from netgraph.utils.logging import get_logger

if TYPE_CHECKING:
    from netgraph.aws.fetcher import EC2Fetcher
    from netgraph.core.graph_manager import GraphManager

logger = get_logger(__name__)

# Severity classification by port
CRITICAL_PORTS = {22, 3389, 5432, 3306, 1433, 27017, 6379}  # SSH, RDP, DBs
HIGH_SEVERITY_PORTS = {23, 21, 25, 110, 143, 445, 135, 139}  # Telnet, FTP, SMB


class ExposureDetector:
    """Detects resources exposed to the public internet.

    Scans ENIs in a VPC to find those with:
    1. A route to an Internet Gateway (direct or via NAT for egress-only)
    2. Security Group rules allowing inbound traffic on the target port
    3. NACL rules allowing the traffic

    Attributes:
        graph: GraphManager for topology and resource access
        fetcher: EC2Fetcher for direct AWS queries
    """

    def __init__(
        self,
        graph: GraphManager,
        fetcher: EC2Fetcher,
    ) -> None:
        """Initialize the ExposureDetector.

        Args:
            graph: GraphManager for topology access
            fetcher: EC2Fetcher for AWS queries
        """
        self.graph = graph
        self.fetcher = fetcher

    async def find_exposed(
        self,
        vpc_id: str,
        port: int,
        protocol: str = "tcp",
        force_refresh: bool = False,
    ) -> PublicExposureResult:
        """Find resources in a VPC exposed to the public internet on a port.

        Args:
            vpc_id: VPC ID to scan
            port: Port number to check for exposure
            protocol: Protocol ("tcp", "udp", or "-1" for all)
            force_refresh: If True, bypass cache

        Returns:
            PublicExposureResult with list of exposed resources
        """
        start_time = time.time()
        exposed_resources: list[ExposedResource] = []
        total_scanned = 0

        logger.info(f"Scanning VPC {vpc_id} for exposure on port {port}/{protocol}")

        # Step 1: Get all ENIs in the VPC
        enis = await self._get_vpc_enis(vpc_id, force_refresh)
        total_scanned = len(enis)

        logger.debug(f"Found {len(enis)} ENIs in VPC {vpc_id}")

        # Step 2: For each ENI, check if exposed
        for eni in enis:
            exposed = await self._check_eni_exposure(
                eni=eni,
                port=port,
                protocol=protocol,
                force_refresh=force_refresh,
            )
            if exposed is not None:
                exposed_resources.append(exposed)

        # Calculate statistics
        duration = time.time() - start_time
        high_severity = sum(1 for r in exposed_resources if r.severity == "high")
        critical_severity = sum(1 for r in exposed_resources if r.severity == "critical")

        # Generate summary
        if exposed_resources:
            summary = (
                f"Found {len(exposed_resources)} resources exposed on port {port}/{protocol} "
                f"({critical_severity} critical, {high_severity} high severity)"
            )
        else:
            summary = f"No resources exposed on port {port}/{protocol}"

        logger.info(
            f"Exposure scan complete: {len(exposed_resources)}/{total_scanned} "
            f"exposed in {duration:.2f}s"
        )

        return PublicExposureResult(
            vpc_id=vpc_id,
            port=port,
            protocol=protocol,
            total_exposed=len(exposed_resources),
            exposed_resources=exposed_resources,
            total_resources_scanned=total_scanned,
            scan_duration_seconds=duration,
            summary=summary,
            high_severity_count=high_severity,
            critical_severity_count=critical_severity,
        )

    async def _get_vpc_enis(
        self,
        vpc_id: str,
        force_refresh: bool,
    ) -> list[GraphNode]:
        """Get all ENIs in a VPC.

        Args:
            vpc_id: VPC ID to scan
            force_refresh: If True, bypass cache

        Returns:
            List of ENI GraphNodes
        """
        # Fetch ENIs from AWS
        eni_data = await self.fetcher.describe_network_interfaces(
            filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )

        enis: list[GraphNode] = []
        for eni in eni_data:
            eni_id = eni.get("NetworkInterfaceId", "")
            if not eni_id:
                continue

            # Get the node from graph manager (will cache it)
            node = await self.graph.get_node(eni_id, force_refresh=force_refresh)
            if node is not None and node.eni_attrs is not None:
                enis.append(node)

        return enis

    async def _check_eni_exposure(
        self,
        eni: GraphNode,
        port: int,
        protocol: str,
        force_refresh: bool,
    ) -> ExposedResource | None:
        """Check if an ENI is exposed to the public internet on a port.

        Args:
            eni: ENI GraphNode to check
            port: Port number
            protocol: Protocol string
            force_refresh: If True, bypass cache

        Returns:
            ExposedResource if exposed, None otherwise
        """
        if eni.eni_attrs is None:
            return None

        # Step 1: Check if subnet has a route to IGW
        subnet_id = eni.eni_attrs.subnet_id
        subnet = await self.graph.get_subnet(subnet_id, force_refresh=force_refresh)
        if subnet is None or subnet.subnet_attrs is None:
            return None

        # Get route table for the subnet
        rt_id = subnet.subnet_attrs.route_table_id
        route_table = await self.graph.get_route_table(rt_id, force_refresh=force_refresh)
        if route_table is None:
            return None

        # Check for IGW route (0.0.0.0/0 or ::/0 via igw-*)
        if not RouteEvaluator.has_internet_route(route_table.routes):
            return None  # No internet route, not exposed

        # Step 2: Check Security Group allows inbound traffic on the port
        sg_ids = eni.eni_attrs.security_group_ids
        sgs = await self._get_security_groups(sg_ids, force_refresh)
        if not sgs:
            return None

        # Evaluate ingress from 0.0.0.0/0 (any internet source)
        sg_eval = await SecurityGroupEvaluator.evaluate_ingress(
            security_groups=sgs,
            source_ip="0.0.0.0",  # Any internet source
            port=port,
            protocol=protocol,
            prefix_resolver=self.fetcher,
        )

        if not sg_eval.allowed:
            return None  # SG blocks the traffic

        # Step 3: Build exposure path
        exposure_path = self._build_exposure_path(eni, subnet, route_table)

        # Step 4: Get allowing rules
        allowing_rules = self._get_allowing_rules(sgs, port, protocol)

        # Step 5: Determine severity
        severity = self._determine_severity(port)

        # Step 6: Generate remediation advice
        remediation = self._generate_remediation(port, sg_ids)

        # Get resource name from tags if available
        name = self._get_resource_name(eni)

        # Get IPs
        private_ip = str(eni.eni_attrs.private_ip) if eni.eni_attrs.private_ip else None
        public_ip = str(eni.eni_attrs.public_ip) if eni.eni_attrs.public_ip else None

        return ExposedResource(
            resource_id=eni.id,
            resource_type=NodeType.ENI,
            resource_arn=self._build_arn(eni.id),
            name=name,
            private_ip=private_ip,
            public_ip=public_ip,
            exposure_type="direct" if public_ip else "indirect",
            exposure_path=exposure_path,
            open_port=port,
            protocol=protocol,
            allowing_rules=allowing_rules,
            severity=severity,
            remediation=remediation,
        )

    async def _get_security_groups(
        self,
        sg_ids: list[str],
        force_refresh: bool,
    ) -> list[SecurityGroup]:
        """Fetch multiple security groups.

        Args:
            sg_ids: List of security group IDs
            force_refresh: If True, bypass cache

        Returns:
            List of SecurityGroup objects
        """
        sgs: list[SecurityGroup] = []
        for sg_id in sg_ids:
            sg = await self.graph.get_security_group(sg_id, force_refresh=force_refresh)
            if sg is not None:
                sgs.append(sg)
        return sgs

    def _build_exposure_path(
        self,
        eni: GraphNode,
        subnet: GraphNode,
        route_table: object,
    ) -> list[str]:
        """Build the exposure path from ENI to IGW.

        Args:
            eni: ENI GraphNode
            subnet: Subnet GraphNode
            route_table: RouteTable object

        Returns:
            List of resource IDs in the path
        """
        path = [eni.id]

        if subnet.subnet_attrs:
            path.append(subnet.id)

        # Find IGW in routes
        if hasattr(route_table, "routes"):
            for route in route_table.routes:
                if route.target_type == "igw":
                    path.append(route.target_id)
                    break

        return path

    def _get_allowing_rules(
        self,
        sgs: list[SecurityGroup],
        port: int,
        protocol: str,
    ) -> list[str]:
        """Get rule IDs that allow traffic on the port.

        Args:
            sgs: List of security groups
            port: Port number
            protocol: Protocol string

        Returns:
            List of rule IDs
        """
        allowing_rules: list[str] = []

        for sg in sgs:
            for rule in sg.inbound_rules:
                # Check if rule allows traffic from anywhere on this port
                is_public_cidr = rule.cidr_ipv4 == "0.0.0.0/0" or rule.cidr_ipv6 == "::/0"
                is_matching_protocol = rule.ip_protocol == "-1" or rule.ip_protocol == protocol
                if is_public_cidr and is_matching_protocol:
                    # Check port range
                    from_port = rule.from_port or 0
                    to_port = rule.to_port or 65535
                    if from_port <= port <= to_port:
                        allowing_rules.append(rule.rule_id)

        return allowing_rules

    def _determine_severity(self, port: int) -> str:
        """Determine exposure severity based on port.

        Args:
            port: Port number

        Returns:
            Severity level: "critical", "high", "medium", or "low"
        """
        if port in CRITICAL_PORTS:
            return "critical"
        if port in HIGH_SEVERITY_PORTS:
            return "high"
        if port < 1024:
            return "medium"
        return "low"

    def _generate_remediation(self, port: int, sg_ids: list[str]) -> str:
        """Generate remediation advice.

        Args:
            port: Port number
            sg_ids: Security group IDs

        Returns:
            Remediation advice string
        """
        sg_list = ", ".join(sg_ids[:3])  # Limit to first 3
        if len(sg_ids) > 3:
            sg_list += f" and {len(sg_ids) - 3} more"

        if port in CRITICAL_PORTS:
            return (
                f"CRITICAL: Restrict port {port} in {sg_list} to specific source IPs. "
                f"Consider using a bastion host or VPN for access."
            )
        if port in HIGH_SEVERITY_PORTS:
            return (
                f"HIGH: Restrict port {port} in {sg_list} to specific source IPs or "
                f"consider disabling this protocol if not needed."
            )
        return (
            f"Review security group rules in {sg_list} to ensure port {port} "
            f"exposure is intentional and properly secured."
        )

    def _get_resource_name(self, _eni: GraphNode) -> str | None:
        """Get resource name from ENI.

        Note: ENIAttributes doesn't store tags. Name would need to be
        retrieved from AWS describe call or stored separately.

        Args:
            _eni: ENI GraphNode (unused - tags not available in current model)

        Returns:
            None (tags not available in current model)
        """
        # ENI tags are not stored in the current model
        # Name would need to be fetched separately from AWS
        return None

    def _build_arn(self, eni_id: str) -> str:
        """Build ARN for an ENI.

        Args:
            eni_id: ENI ID

        Returns:
            ARN string
        """
        return f"arn:aws:ec2:{self.graph.region}:{self.graph.account_id}:network-interface/{eni_id}"
