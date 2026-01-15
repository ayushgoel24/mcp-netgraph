"""Resource Discovery for tag-based and pattern-based resource lookup.

This module enables natural language resource discovery by allowing
flexible tag-based and name pattern-based queries against VPC resources.

Used by LLM-powered tools to find resources based on user descriptions
like "find all production web servers" or "database instances in us-east-1a".
"""

from __future__ import annotations

import fnmatch
from typing import TYPE_CHECKING

from netgraph.models import (
    DiscoveredResource,
    NodeType,
    ResourceDiscoveryResult,
)
from netgraph.utils.logging import get_logger

if TYPE_CHECKING:
    from netgraph.aws.fetcher import EC2Fetcher
    from netgraph.core.graph_manager import GraphManager

logger = get_logger(__name__)

# Map of resource type strings to NodeType
RESOURCE_TYPE_MAP = {
    "instance": NodeType.INSTANCE,
    "eni": NodeType.ENI,
    "subnet": NodeType.SUBNET,
    "igw": NodeType.INTERNET_GATEWAY,
    "nat": NodeType.NAT_GATEWAY,
    "peering": NodeType.VPC_PEERING,
    "tgw": NodeType.TRANSIT_GATEWAY,
}


class ResourceDiscovery:
    """Discovers AWS resources in a VPC by tags, type, or name pattern.

    Provides flexible resource lookup for LLM-powered natural language queries.

    Attributes:
        graph: GraphManager for topology and resource access
        fetcher: EC2Fetcher for direct AWS queries
    """

    def __init__(
        self,
        graph: GraphManager,
        fetcher: EC2Fetcher,
    ) -> None:
        """Initialize ResourceDiscovery.

        Args:
            graph: GraphManager for topology access
            fetcher: EC2Fetcher for AWS queries
        """
        self.graph = graph
        self.fetcher = fetcher

    async def find(
        self,
        vpc_id: str,
        tags: dict[str, str] | None = None,
        resource_types: list[str] | None = None,
        name_pattern: str | None = None,
        max_results: int = 50,
    ) -> ResourceDiscoveryResult:
        """Find resources in a VPC matching the specified criteria.

        Args:
            vpc_id: VPC ID to search in
            tags: Tag filters as key-value pairs (e.g., {"Environment": "prod"})
            resource_types: List of resource types to include
                           ("instance", "eni", "subnet", "igw", "nat", "peering", "tgw")
            name_pattern: Pattern to match against Name tag (case-insensitive, supports wildcards)
            max_results: Maximum number of results to return (default: 50)

        Returns:
            ResourceDiscoveryResult with matching resources
        """
        logger.info(
            f"Searching VPC {vpc_id}: types={resource_types}, "
            f"tags={tags}, name_pattern={name_pattern}"
        )

        # Normalize resource types
        target_types = self._normalize_resource_types(resource_types)

        # Collect all matching resources
        all_resources: list[DiscoveredResource] = []

        # Search each resource type
        if NodeType.INSTANCE in target_types:
            instances = await self._find_instances(vpc_id, tags, name_pattern)
            all_resources.extend(instances)

        if NodeType.ENI in target_types:
            enis = await self._find_enis(vpc_id, tags, name_pattern)
            all_resources.extend(enis)

        if NodeType.SUBNET in target_types:
            subnets = await self._find_subnets(vpc_id, tags, name_pattern)
            all_resources.extend(subnets)

        if NodeType.INTERNET_GATEWAY in target_types:
            igws = await self._find_igws(vpc_id, tags, name_pattern)
            all_resources.extend(igws)

        if NodeType.NAT_GATEWAY in target_types:
            nats = await self._find_nat_gateways(vpc_id, tags, name_pattern)
            all_resources.extend(nats)

        if NodeType.VPC_PEERING in target_types:
            peerings = await self._find_peering_connections(vpc_id, tags, name_pattern)
            all_resources.extend(peerings)

        if NodeType.TRANSIT_GATEWAY in target_types:
            tgws = await self._find_transit_gateways(vpc_id, tags, name_pattern)
            all_resources.extend(tgws)

        # Track total before truncation
        total_found = len(all_resources)
        truncated = total_found > max_results

        # Truncate to max_results
        if truncated:
            all_resources = all_resources[:max_results]

        # Build filters applied summary
        filters_applied: dict[str, str | list[str] | None] = {
            "vpc_id": vpc_id,
        }
        if tags:
            filters_applied["tags"] = str(tags)
        if resource_types:
            filters_applied["resource_types"] = resource_types
        if name_pattern:
            filters_applied["name_pattern"] = name_pattern

        logger.info(
            f"Found {total_found} resources, returning {len(all_resources)} (truncated={truncated})"
        )

        return ResourceDiscoveryResult(
            vpc_id=vpc_id,
            resources=all_resources,
            total_found=total_found,
            truncated=truncated,
            filters_applied=filters_applied,
        )

    def _normalize_resource_types(
        self,
        resource_types: list[str] | None,
    ) -> set[NodeType]:
        """Normalize resource type strings to NodeType enum.

        Args:
            resource_types: List of resource type strings

        Returns:
            Set of NodeType values
        """
        if not resource_types:
            # Default to all searchable types
            return {
                NodeType.INSTANCE,
                NodeType.ENI,
                NodeType.SUBNET,
                NodeType.INTERNET_GATEWAY,
                NodeType.NAT_GATEWAY,
                NodeType.VPC_PEERING,
                NodeType.TRANSIT_GATEWAY,
            }

        types: set[NodeType] = set()
        for rt in resource_types:
            rt_lower = rt.lower()
            if rt_lower in RESOURCE_TYPE_MAP:
                types.add(RESOURCE_TYPE_MAP[rt_lower])

        return types

    def _matches_tags(
        self,
        resource_tags: dict[str, str],
        filter_tags: dict[str, str] | None,
    ) -> bool:
        """Check if resource tags match all filter tags.

        Args:
            resource_tags: Tags on the resource
            filter_tags: Tags to filter by

        Returns:
            True if all filter tags match
        """
        if not filter_tags:
            return True

        return all(resource_tags.get(key) == value for key, value in filter_tags.items())

    def _matches_name_pattern(
        self,
        name: str | None,
        pattern: str | None,
    ) -> bool:
        """Check if name matches the pattern (case-insensitive).

        Args:
            name: Resource name
            pattern: Pattern to match (supports wildcards)

        Returns:
            True if name matches pattern
        """
        if not pattern:
            return True

        if not name:
            return False

        # Case-insensitive fnmatch
        return fnmatch.fnmatch(name.lower(), pattern.lower())

    def _extract_tags(self, tags_list: list[dict[str, str]] | None) -> dict[str, str]:
        """Extract tags from AWS response format to dict.

        Args:
            tags_list: List of {"Key": k, "Value": v} dicts

        Returns:
            Dict of tag key to value
        """
        if not tags_list:
            return {}

        return {tag.get("Key", ""): tag.get("Value", "") for tag in tags_list if tag.get("Key")}

    async def _find_instances(
        self,
        vpc_id: str,
        tags: dict[str, str] | None,
        name_pattern: str | None,
    ) -> list[DiscoveredResource]:
        """Find EC2 instances matching criteria.

        Args:
            vpc_id: VPC ID
            tags: Tag filters
            name_pattern: Name pattern

        Returns:
            List of matching DiscoveredResource
        """
        resources: list[DiscoveredResource] = []

        # Fetch instances in VPC
        instances = await self.fetcher.describe_instances(
            filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )

        for instance in instances:
            instance_id = instance.get("InstanceId", "")
            if not instance_id:
                continue

            instance_tags = self._extract_tags(instance.get("Tags"))
            name = instance_tags.get("Name")

            # Apply filters
            if not self._matches_tags(instance_tags, tags):
                continue
            if not self._matches_name_pattern(name, name_pattern):
                continue

            # Get IPs
            private_ip = instance.get("PrivateIpAddress")
            public_ip = instance.get("PublicIpAddress")

            # Get placement info
            placement = instance.get("Placement", {})
            az = placement.get("AvailabilityZone")
            subnet_id = instance.get("SubnetId")

            resources.append(
                DiscoveredResource(
                    id=instance_id,
                    resource_type=NodeType.INSTANCE,
                    resource_arn=f"arn:aws:ec2:{self.graph.region}:{self.graph.account_id}:instance/{instance_id}",
                    name=name,
                    tags=instance_tags,
                    vpc_id=vpc_id,
                    subnet_id=subnet_id,
                    availability_zone=az,
                    private_ip=private_ip,
                    public_ip=public_ip,
                )
            )

        return resources

    async def _find_enis(
        self,
        vpc_id: str,
        tags: dict[str, str] | None,
        name_pattern: str | None,
    ) -> list[DiscoveredResource]:
        """Find ENIs matching criteria.

        Args:
            vpc_id: VPC ID
            tags: Tag filters
            name_pattern: Name pattern

        Returns:
            List of matching DiscoveredResource
        """
        resources: list[DiscoveredResource] = []

        # Fetch ENIs in VPC
        enis = await self.fetcher.describe_network_interfaces(
            filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )

        for eni in enis:
            eni_id = eni.get("NetworkInterfaceId", "")
            if not eni_id:
                continue

            eni_tags = self._extract_tags(eni.get("TagSet"))
            name = eni_tags.get("Name")

            # Apply filters
            if not self._matches_tags(eni_tags, tags):
                continue
            if not self._matches_name_pattern(name, name_pattern):
                continue

            # Get IPs
            private_ip = eni.get("PrivateIpAddress")
            public_ip = None
            association = eni.get("Association")
            if association:
                public_ip = association.get("PublicIp")

            # Get placement info
            az = eni.get("AvailabilityZone")
            subnet_id = eni.get("SubnetId")

            resources.append(
                DiscoveredResource(
                    id=eni_id,
                    resource_type=NodeType.ENI,
                    resource_arn=f"arn:aws:ec2:{self.graph.region}:{self.graph.account_id}:network-interface/{eni_id}",
                    name=name,
                    tags=eni_tags,
                    vpc_id=vpc_id,
                    subnet_id=subnet_id,
                    availability_zone=az,
                    private_ip=private_ip,
                    public_ip=public_ip,
                )
            )

        return resources

    async def _find_subnets(
        self,
        vpc_id: str,
        tags: dict[str, str] | None,
        name_pattern: str | None,
    ) -> list[DiscoveredResource]:
        """Find subnets matching criteria.

        Args:
            vpc_id: VPC ID
            tags: Tag filters
            name_pattern: Name pattern

        Returns:
            List of matching DiscoveredResource
        """
        resources: list[DiscoveredResource] = []

        # Fetch subnets in VPC
        subnets = await self.fetcher.describe_subnets(
            filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )

        for subnet in subnets:
            subnet_id = subnet.get("SubnetId", "")
            if not subnet_id:
                continue

            subnet_tags = self._extract_tags(subnet.get("Tags"))
            name = subnet_tags.get("Name")

            # Apply filters
            if not self._matches_tags(subnet_tags, tags):
                continue
            if not self._matches_name_pattern(name, name_pattern):
                continue

            az = subnet.get("AvailabilityZone")

            resources.append(
                DiscoveredResource(
                    id=subnet_id,
                    resource_type=NodeType.SUBNET,
                    resource_arn=f"arn:aws:ec2:{self.graph.region}:{self.graph.account_id}:subnet/{subnet_id}",
                    name=name,
                    tags=subnet_tags,
                    vpc_id=vpc_id,
                    subnet_id=subnet_id,
                    availability_zone=az,
                )
            )

        return resources

    async def _find_igws(
        self,
        vpc_id: str,
        tags: dict[str, str] | None,
        name_pattern: str | None,
    ) -> list[DiscoveredResource]:
        """Find Internet Gateways matching criteria.

        Args:
            vpc_id: VPC ID
            tags: Tag filters
            name_pattern: Name pattern

        Returns:
            List of matching DiscoveredResource
        """
        resources: list[DiscoveredResource] = []

        # Fetch IGWs attached to VPC
        igws = await self.fetcher.describe_internet_gateways(
            filters=[{"Name": "attachment.vpc-id", "Values": [vpc_id]}]
        )

        for igw in igws:
            igw_id = igw.get("InternetGatewayId", "")
            if not igw_id:
                continue

            igw_tags = self._extract_tags(igw.get("Tags"))
            name = igw_tags.get("Name")

            # Apply filters
            if not self._matches_tags(igw_tags, tags):
                continue
            if not self._matches_name_pattern(name, name_pattern):
                continue

            resources.append(
                DiscoveredResource(
                    id=igw_id,
                    resource_type=NodeType.INTERNET_GATEWAY,
                    resource_arn=f"arn:aws:ec2:{self.graph.region}:{self.graph.account_id}:internet-gateway/{igw_id}",
                    name=name,
                    tags=igw_tags,
                    vpc_id=vpc_id,
                )
            )

        return resources

    async def _find_nat_gateways(
        self,
        vpc_id: str,
        tags: dict[str, str] | None,
        name_pattern: str | None,
    ) -> list[DiscoveredResource]:
        """Find NAT Gateways matching criteria.

        Args:
            vpc_id: VPC ID
            tags: Tag filters
            name_pattern: Name pattern

        Returns:
            List of matching DiscoveredResource
        """
        resources: list[DiscoveredResource] = []

        # Fetch NAT Gateways in VPC
        nats = await self.fetcher.describe_nat_gateways(
            filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )

        for nat in nats:
            nat_id = nat.get("NatGatewayId", "")
            if not nat_id:
                continue

            nat_tags = self._extract_tags(nat.get("Tags"))
            name = nat_tags.get("Name")

            # Apply filters
            if not self._matches_tags(nat_tags, tags):
                continue
            if not self._matches_name_pattern(name, name_pattern):
                continue

            # Get subnet and public IP
            subnet_id = nat.get("SubnetId")
            public_ip = None
            addresses = nat.get("NatGatewayAddresses", [])
            if addresses:
                public_ip = addresses[0].get("PublicIp")

            resources.append(
                DiscoveredResource(
                    id=nat_id,
                    resource_type=NodeType.NAT_GATEWAY,
                    resource_arn=f"arn:aws:ec2:{self.graph.region}:{self.graph.account_id}:natgateway/{nat_id}",
                    name=name,
                    tags=nat_tags,
                    vpc_id=vpc_id,
                    subnet_id=subnet_id,
                    public_ip=public_ip,
                )
            )

        return resources

    async def _find_peering_connections(
        self,
        vpc_id: str,
        tags: dict[str, str] | None,
        name_pattern: str | None,
    ) -> list[DiscoveredResource]:
        """Find VPC Peering Connections matching criteria.

        Args:
            vpc_id: VPC ID
            tags: Tag filters
            name_pattern: Name pattern

        Returns:
            List of matching DiscoveredResource
        """
        resources: list[DiscoveredResource] = []

        # Fetch peering connections involving this VPC (as requester or accepter)
        peerings = await self.fetcher.describe_vpc_peering_connections(
            filters=[
                {
                    "Name": "status-code",
                    "Values": ["active", "pending-acceptance"],
                }
            ]
        )

        for pcx in peerings:
            pcx_id = pcx.get("VpcPeeringConnectionId", "")
            if not pcx_id:
                continue

            # Check if this VPC is involved
            requester_vpc = pcx.get("RequesterVpcInfo", {}).get("VpcId")
            accepter_vpc = pcx.get("AccepterVpcInfo", {}).get("VpcId")

            if vpc_id not in (requester_vpc, accepter_vpc):
                continue

            pcx_tags = self._extract_tags(pcx.get("Tags"))
            name = pcx_tags.get("Name")

            # Apply filters
            if not self._matches_tags(pcx_tags, tags):
                continue
            if not self._matches_name_pattern(name, name_pattern):
                continue

            resources.append(
                DiscoveredResource(
                    id=pcx_id,
                    resource_type=NodeType.VPC_PEERING,
                    resource_arn=f"arn:aws:ec2:{self.graph.region}:{self.graph.account_id}:vpc-peering-connection/{pcx_id}",
                    name=name,
                    tags=pcx_tags,
                    vpc_id=vpc_id,
                )
            )

        return resources

    async def _find_transit_gateways(
        self,
        vpc_id: str,
        tags: dict[str, str] | None,
        name_pattern: str | None,
    ) -> list[DiscoveredResource]:
        """Find Transit Gateways attached to the VPC.

        Args:
            vpc_id: VPC ID
            tags: Tag filters
            name_pattern: Name pattern

        Returns:
            List of matching DiscoveredResource
        """
        resources: list[DiscoveredResource] = []

        # First get TGW attachments for this VPC
        attachments = await self.fetcher.describe_transit_gateway_attachments(
            filters=[
                {"Name": "resource-type", "Values": ["vpc"]},
                {"Name": "resource-id", "Values": [vpc_id]},
            ]
        )

        # Get unique TGW IDs
        tgw_ids: list[str] = [
            tgw_id for att in attachments if (tgw_id := att.get("TransitGatewayId")) is not None
        ]

        if not tgw_ids:
            return resources

        # Deduplicate
        unique_tgw_ids = list(set(tgw_ids))

        # Fetch TGW details
        tgws = await self.fetcher.describe_transit_gateways(transit_gateway_ids=unique_tgw_ids)

        for tgw in tgws:
            tgw_id = tgw.get("TransitGatewayId", "")
            if not tgw_id:
                continue

            tgw_tags = self._extract_tags(tgw.get("Tags"))
            name = tgw_tags.get("Name")

            # Apply filters
            if not self._matches_tags(tgw_tags, tags):
                continue
            if not self._matches_name_pattern(name, name_pattern):
                continue

            resources.append(
                DiscoveredResource(
                    id=tgw_id,
                    resource_type=NodeType.TRANSIT_GATEWAY,
                    resource_arn=tgw.get("TransitGatewayArn", ""),
                    name=name,
                    tags=tgw_tags,
                    vpc_id=vpc_id,
                )
            )

        return resources
