"""EC2 resource fetcher with auto-pagination.

This module provides the EC2Fetcher class that wraps all EC2 describe_*
operations with automatic pagination to ensure complete data retrieval.

CRITICAL: Without pagination, a subnet with 200 ENIs will silently miss 50%
of data since AWS defaults to 50-100 items per page.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, TypeVar, cast

if TYPE_CHECKING:
    from collections.abc import Callable

from botocore.exceptions import ClientError

from netgraph.aws.client import (
    AWSClient,
    RetryConfig,
    detect_error_type,
    is_retryable_error,
)
from netgraph.models.errors import (
    PermissionDeniedError,
    PrefixListResolutionError,
    ResourceNotFoundError,
)
from netgraph.utils.logging import get_logger

logger = get_logger(__name__)

T = TypeVar("T")


class EC2Fetcher:
    """Fetches EC2 resources with automatic pagination.

    All methods use boto3 paginators to ensure complete data retrieval.
    Methods are async to support concurrent fetching.
    """

    def __init__(
        self,
        client: AWSClient,
        retry_config: RetryConfig | None = None,
    ) -> None:
        """Initialize the fetcher.

        Args:
            client: AWSClient to use for API calls
            retry_config: Retry configuration for rate limiting
        """
        self.client = client
        self.retry_config = retry_config or RetryConfig()

    async def _execute_with_retry(
        self,
        sync_operation: Callable[[], T],
        operation_name: str,
    ) -> T:
        """Execute a synchronous operation with async retry.

        Args:
            sync_operation: Synchronous callable to execute
            operation_name: Name for logging

        Returns:
            Result of the operation
        """
        config = self.retry_config
        delay = config.initial_delay
        last_error: ClientError | None = None

        for attempt in range(config.max_retries + 1):
            try:
                # Run synchronous boto3 call in thread pool
                return await asyncio.to_thread(sync_operation)
            except ClientError as e:
                last_error = e
                if not is_retryable_error(e):
                    raise detect_error_type(e) from e

                if attempt == config.max_retries:
                    logger.error(f"{operation_name} failed after {config.max_retries + 1} attempts")
                    raise detect_error_type(e) from e

                # Calculate delay with jitter
                import random

                if config.jitter:
                    jitter = random.uniform(0, delay * 0.5)
                    actual_delay = delay + jitter
                else:
                    actual_delay = delay

                logger.warning(
                    f"{operation_name} failed (attempt {attempt + 1}/{config.max_retries + 1}), "
                    f"retrying in {actual_delay:.2f}s: {e}"
                )

                await asyncio.sleep(actual_delay)
                delay = min(delay * config.multiplier, config.max_delay)

        # Should never reach here
        if last_error:
            raise detect_error_type(last_error)
        raise RuntimeError("Unexpected state in _execute_with_retry")

    def _paginate_instances(
        self,
        instance_ids: list[str] | None = None,
        filters: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Synchronous helper to paginate through instances."""
        params: dict[str, Any] = {}
        if instance_ids:
            params["InstanceIds"] = instance_ids
        if filters:
            params["Filters"] = filters

        paginator = self.client.ec2.get_paginator("describe_instances")
        instances: list[dict[str, Any]] = []

        for page in paginator.paginate(**params):
            for reservation in page.get("Reservations", []):
                instances.extend(cast("list[dict[str, Any]]", reservation.get("Instances", [])))

        logger.debug(f"Fetched {len(instances)} instances")
        return instances

    async def describe_instances(
        self,
        instance_ids: list[str] | None = None,
        filters: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch all EC2 instances with pagination.

        Args:
            instance_ids: Optional list of instance IDs to filter
            filters: Optional AWS filters

        Returns:
            List of instance dictionaries from AWS API

        Raises:
            ResourceNotFoundError: If an instance ID doesn't exist
            PermissionDeniedError: If access is denied
        """
        return await self._execute_with_retry(
            lambda: self._paginate_instances(instance_ids, filters),
            "describe_instances",
        )

    def _paginate_subnets(
        self,
        subnet_ids: list[str] | None = None,
        vpc_id: str | None = None,
        filters: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Synchronous helper to paginate through subnets."""
        params: dict[str, Any] = {}
        if subnet_ids:
            params["SubnetIds"] = subnet_ids

        all_filters = list(filters or [])
        if vpc_id:
            all_filters.append({"Name": "vpc-id", "Values": [vpc_id]})
        if all_filters:
            params["Filters"] = all_filters

        paginator = self.client.ec2.get_paginator("describe_subnets")
        subnets: list[dict[str, Any]] = []

        for page in paginator.paginate(**params):
            subnets.extend(cast("list[dict[str, Any]]", page.get("Subnets", [])))

        logger.debug(f"Fetched {len(subnets)} subnets")
        return subnets

    async def describe_subnets(
        self,
        subnet_ids: list[str] | None = None,
        vpc_id: str | None = None,
        filters: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch all subnets with pagination.

        Args:
            subnet_ids: Optional list of subnet IDs to filter
            vpc_id: Optional VPC ID to filter by
            filters: Optional AWS filters

        Returns:
            List of subnet dictionaries from AWS API
        """
        return await self._execute_with_retry(
            lambda: self._paginate_subnets(subnet_ids, vpc_id, filters),
            "describe_subnets",
        )

    def _paginate_security_groups(
        self,
        group_ids: list[str] | None = None,
        vpc_id: str | None = None,
        filters: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Synchronous helper to paginate through security groups."""
        params: dict[str, Any] = {}
        if group_ids:
            params["GroupIds"] = group_ids

        all_filters = list(filters or [])
        if vpc_id:
            all_filters.append({"Name": "vpc-id", "Values": [vpc_id]})
        if all_filters:
            params["Filters"] = all_filters

        paginator = self.client.ec2.get_paginator("describe_security_groups")
        security_groups: list[dict[str, Any]] = []

        for page in paginator.paginate(**params):
            security_groups.extend(cast("list[dict[str, Any]]", page.get("SecurityGroups", [])))

        logger.debug(f"Fetched {len(security_groups)} security groups")
        return security_groups

    async def describe_security_groups(
        self,
        group_ids: list[str] | None = None,
        vpc_id: str | None = None,
        filters: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch all security groups with pagination.

        Args:
            group_ids: Optional list of security group IDs
            vpc_id: Optional VPC ID to filter by
            filters: Optional AWS filters

        Returns:
            List of security group dictionaries from AWS API
        """
        return await self._execute_with_retry(
            lambda: self._paginate_security_groups(group_ids, vpc_id, filters),
            "describe_security_groups",
        )

    def _paginate_network_acls(
        self,
        network_acl_ids: list[str] | None = None,
        vpc_id: str | None = None,
        filters: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Synchronous helper to paginate through network ACLs."""
        params: dict[str, Any] = {}
        if network_acl_ids:
            params["NetworkAclIds"] = network_acl_ids

        all_filters = list(filters or [])
        if vpc_id:
            all_filters.append({"Name": "vpc-id", "Values": [vpc_id]})
        if all_filters:
            params["Filters"] = all_filters

        paginator = self.client.ec2.get_paginator("describe_network_acls")
        nacls: list[dict[str, Any]] = []

        for page in paginator.paginate(**params):
            nacls.extend(cast("list[dict[str, Any]]", page.get("NetworkAcls", [])))

        logger.debug(f"Fetched {len(nacls)} network ACLs")
        return nacls

    async def describe_network_acls(
        self,
        network_acl_ids: list[str] | None = None,
        vpc_id: str | None = None,
        filters: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch all network ACLs with pagination.

        Args:
            network_acl_ids: Optional list of NACL IDs
            vpc_id: Optional VPC ID to filter by
            filters: Optional AWS filters

        Returns:
            List of NACL dictionaries from AWS API
        """
        return await self._execute_with_retry(
            lambda: self._paginate_network_acls(network_acl_ids, vpc_id, filters),
            "describe_network_acls",
        )

    def _paginate_route_tables(
        self,
        route_table_ids: list[str] | None = None,
        vpc_id: str | None = None,
        filters: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Synchronous helper to paginate through route tables."""
        params: dict[str, Any] = {}
        if route_table_ids:
            params["RouteTableIds"] = route_table_ids

        all_filters = list(filters or [])
        if vpc_id:
            all_filters.append({"Name": "vpc-id", "Values": [vpc_id]})
        if all_filters:
            params["Filters"] = all_filters

        paginator = self.client.ec2.get_paginator("describe_route_tables")
        route_tables: list[dict[str, Any]] = []

        for page in paginator.paginate(**params):
            route_tables.extend(cast("list[dict[str, Any]]", page.get("RouteTables", [])))

        logger.debug(f"Fetched {len(route_tables)} route tables")
        return route_tables

    async def describe_route_tables(
        self,
        route_table_ids: list[str] | None = None,
        vpc_id: str | None = None,
        filters: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch all route tables with pagination.

        Args:
            route_table_ids: Optional list of route table IDs
            vpc_id: Optional VPC ID to filter by
            filters: Optional AWS filters

        Returns:
            List of route table dictionaries from AWS API
        """
        return await self._execute_with_retry(
            lambda: self._paginate_route_tables(route_table_ids, vpc_id, filters),
            "describe_route_tables",
        )

    def _paginate_internet_gateways(
        self,
        internet_gateway_ids: list[str] | None = None,
        vpc_id: str | None = None,
        filters: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Synchronous helper to paginate through internet gateways."""
        params: dict[str, Any] = {}
        if internet_gateway_ids:
            params["InternetGatewayIds"] = internet_gateway_ids

        all_filters = list(filters or [])
        if vpc_id:
            all_filters.append({"Name": "attachment.vpc-id", "Values": [vpc_id]})
        if all_filters:
            params["Filters"] = all_filters

        paginator = self.client.ec2.get_paginator("describe_internet_gateways")
        igws: list[dict[str, Any]] = []

        for page in paginator.paginate(**params):
            igws.extend(cast("list[dict[str, Any]]", page.get("InternetGateways", [])))

        logger.debug(f"Fetched {len(igws)} internet gateways")
        return igws

    async def describe_internet_gateways(
        self,
        internet_gateway_ids: list[str] | None = None,
        vpc_id: str | None = None,
        filters: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch all internet gateways with pagination.

        Args:
            internet_gateway_ids: Optional list of IGW IDs
            vpc_id: Optional VPC ID to filter by (via attachment)
            filters: Optional AWS filters

        Returns:
            List of internet gateway dictionaries from AWS API
        """
        return await self._execute_with_retry(
            lambda: self._paginate_internet_gateways(internet_gateway_ids, vpc_id, filters),
            "describe_internet_gateways",
        )

    def _paginate_nat_gateways(
        self,
        nat_gateway_ids: list[str] | None = None,
        vpc_id: str | None = None,
        filters: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Synchronous helper to paginate through NAT gateways."""
        params: dict[str, Any] = {}
        if nat_gateway_ids:
            params["NatGatewayIds"] = nat_gateway_ids

        all_filters = list(filters or [])
        if vpc_id:
            all_filters.append({"Name": "vpc-id", "Values": [vpc_id]})
        if all_filters:
            params["Filter"] = all_filters  # Note: 'Filter' not 'Filters'

        paginator = self.client.ec2.get_paginator("describe_nat_gateways")
        nat_gws: list[dict[str, Any]] = []

        for page in paginator.paginate(**params):
            nat_gws.extend(cast("list[dict[str, Any]]", page.get("NatGateways", [])))

        logger.debug(f"Fetched {len(nat_gws)} NAT gateways")
        return nat_gws

    async def describe_nat_gateways(
        self,
        nat_gateway_ids: list[str] | None = None,
        vpc_id: str | None = None,
        filters: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch all NAT gateways with pagination.

        Args:
            nat_gateway_ids: Optional list of NAT gateway IDs
            vpc_id: Optional VPC ID to filter by
            filters: Optional AWS filters

        Returns:
            List of NAT gateway dictionaries from AWS API
        """
        return await self._execute_with_retry(
            lambda: self._paginate_nat_gateways(nat_gateway_ids, vpc_id, filters),
            "describe_nat_gateways",
        )

    def _paginate_vpc_peering_connections(
        self,
        vpc_peering_connection_ids: list[str] | None = None,
        filters: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Synchronous helper to paginate through VPC peering connections."""
        params: dict[str, Any] = {}
        if vpc_peering_connection_ids:
            params["VpcPeeringConnectionIds"] = vpc_peering_connection_ids
        if filters:
            params["Filters"] = filters

        paginator = self.client.ec2.get_paginator("describe_vpc_peering_connections")
        peerings: list[dict[str, Any]] = []

        for page in paginator.paginate(**params):
            peerings.extend(cast("list[dict[str, Any]]", page.get("VpcPeeringConnections", [])))

        logger.debug(f"Fetched {len(peerings)} VPC peering connections")
        return peerings

    async def describe_vpc_peering_connections(
        self,
        vpc_peering_connection_ids: list[str] | None = None,
        filters: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch all VPC peering connections with pagination.

        Args:
            vpc_peering_connection_ids: Optional list of peering connection IDs
            filters: Optional AWS filters

        Returns:
            List of VPC peering connection dictionaries from AWS API
        """
        return await self._execute_with_retry(
            lambda: self._paginate_vpc_peering_connections(vpc_peering_connection_ids, filters),
            "describe_vpc_peering_connections",
        )

    def _paginate_network_interfaces(
        self,
        network_interface_ids: list[str] | None = None,
        filters: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Synchronous helper to paginate through network interfaces."""
        params: dict[str, Any] = {}
        if network_interface_ids:
            params["NetworkInterfaceIds"] = network_interface_ids
        if filters:
            params["Filters"] = filters

        paginator = self.client.ec2.get_paginator("describe_network_interfaces")
        enis: list[dict[str, Any]] = []

        for page in paginator.paginate(**params):
            enis.extend(cast("list[dict[str, Any]]", page.get("NetworkInterfaces", [])))

        logger.debug(f"Fetched {len(enis)} network interfaces")
        return enis

    async def describe_network_interfaces(
        self,
        network_interface_ids: list[str] | None = None,
        filters: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch all network interfaces with pagination.

        Args:
            network_interface_ids: Optional list of ENI IDs
            filters: Optional AWS filters

        Returns:
            List of network interface dictionaries from AWS API
        """
        return await self._execute_with_retry(
            lambda: self._paginate_network_interfaces(network_interface_ids, filters),
            "describe_network_interfaces",
        )

    def _paginate_vpcs(
        self,
        vpc_ids: list[str] | None = None,
        filters: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Synchronous helper to paginate through VPCs."""
        params: dict[str, Any] = {}
        if vpc_ids:
            params["VpcIds"] = vpc_ids
        if filters:
            params["Filters"] = filters

        paginator = self.client.ec2.get_paginator("describe_vpcs")
        vpcs: list[dict[str, Any]] = []

        for page in paginator.paginate(**params):
            vpcs.extend(cast("list[dict[str, Any]]", page.get("Vpcs", [])))

        logger.debug(f"Fetched {len(vpcs)} VPCs")
        return vpcs

    async def describe_vpcs(
        self,
        vpc_ids: list[str] | None = None,
        filters: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch all VPCs with pagination.

        Args:
            vpc_ids: Optional list of VPC IDs
            filters: Optional AWS filters

        Returns:
            List of VPC dictionaries from AWS API
        """
        return await self._execute_with_retry(
            lambda: self._paginate_vpcs(vpc_ids, filters),
            "describe_vpcs",
        )

    def _paginate_prefix_list_entries(
        self,
        prefix_list_id: str,
    ) -> list[str]:
        """Synchronous helper to paginate through prefix list entries."""
        paginator = self.client.ec2.get_paginator("get_managed_prefix_list_entries")
        cidrs: list[str] = []

        for page in paginator.paginate(PrefixListId=prefix_list_id):
            for entry in page.get("Entries", []):
                cidr = entry.get("Cidr")
                if cidr:
                    cidrs.append(cidr)

        logger.debug(f"Fetched {len(cidrs)} entries from prefix list {prefix_list_id}")
        return cidrs

    async def get_managed_prefix_list_entries(
        self,
        prefix_list_id: str,
    ) -> list[str]:
        """Fetch all CIDR entries from a managed prefix list.

        This implements the PrefixListResolver protocol for SecurityGroupEvaluator.

        Args:
            prefix_list_id: The prefix list ID (e.g., pl-abc123)

        Returns:
            List of CIDR strings from the prefix list

        Raises:
            PrefixListResolutionError: If the prefix list cannot be resolved
        """
        try:
            return await self._execute_with_retry(
                lambda: self._paginate_prefix_list_entries(prefix_list_id),
                f"get_managed_prefix_list_entries({prefix_list_id})",
            )
        except ResourceNotFoundError as e:
            # _execute_with_retry transforms InvalidPrefixListId to ResourceNotFoundError
            raise PrefixListResolutionError(
                prefix_list_id=prefix_list_id,
                reason=f"Prefix list not found: {e}",
            ) from e
        except PermissionDeniedError as e:
            # _execute_with_retry transforms AccessDenied to PermissionDeniedError
            raise PrefixListResolutionError(
                prefix_list_id=prefix_list_id,
                reason=f"Access denied: {e}. Verify ec2:GetManagedPrefixListEntries permission.",
            ) from e
        except ClientError as e:
            # Fallback for any errors not transformed by _execute_with_retry
            error_code = e.response.get("Error", {}).get("Code", "")
            error_message = e.response.get("Error", {}).get("Message", str(e))

            if error_code.startswith("InvalidPrefixListId"):
                raise PrefixListResolutionError(
                    prefix_list_id=prefix_list_id,
                    reason=f"Prefix list not found: {error_message}",
                ) from e

            if error_code in {"AccessDenied", "UnauthorizedOperation"}:
                raise PrefixListResolutionError(
                    prefix_list_id=prefix_list_id,
                    reason=f"Access denied: {error_message}. "
                    "Verify ec2:GetManagedPrefixListEntries permission.",
                ) from e

            raise PrefixListResolutionError(
                prefix_list_id=prefix_list_id,
                reason=str(e),
            ) from e

    def _paginate_transit_gateways(
        self,
        transit_gateway_ids: list[str] | None = None,
        filters: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Synchronous helper to paginate through transit gateways."""
        params: dict[str, Any] = {}
        if transit_gateway_ids:
            params["TransitGatewayIds"] = transit_gateway_ids
        if filters:
            params["Filters"] = filters

        paginator = self.client.ec2.get_paginator("describe_transit_gateways")
        tgws: list[dict[str, Any]] = []

        for page in paginator.paginate(**params):
            tgws.extend(cast("list[dict[str, Any]]", page.get("TransitGateways", [])))

        logger.debug(f"Fetched {len(tgws)} transit gateways")
        return tgws

    async def describe_transit_gateways(
        self,
        transit_gateway_ids: list[str] | None = None,
        filters: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch all transit gateways with pagination.

        Args:
            transit_gateway_ids: Optional list of TGW IDs
            filters: Optional AWS filters

        Returns:
            List of transit gateway dictionaries from AWS API
        """
        return await self._execute_with_retry(
            lambda: self._paginate_transit_gateways(transit_gateway_ids, filters),
            "describe_transit_gateways",
        )

    def _paginate_transit_gateway_attachments(
        self,
        transit_gateway_attachment_ids: list[str] | None = None,
        transit_gateway_id: str | None = None,
        filters: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Synchronous helper to paginate through TGW attachments."""
        params: dict[str, Any] = {}
        if transit_gateway_attachment_ids:
            params["TransitGatewayAttachmentIds"] = transit_gateway_attachment_ids

        all_filters = list(filters or [])
        if transit_gateway_id:
            all_filters.append({"Name": "transit-gateway-id", "Values": [transit_gateway_id]})
        if all_filters:
            params["Filters"] = all_filters

        paginator = self.client.ec2.get_paginator("describe_transit_gateway_attachments")
        attachments: list[dict[str, Any]] = []

        for page in paginator.paginate(**params):
            attachments.extend(
                cast("list[dict[str, Any]]", page.get("TransitGatewayAttachments", []))
            )

        logger.debug(f"Fetched {len(attachments)} TGW attachments")
        return attachments

    async def describe_transit_gateway_attachments(
        self,
        transit_gateway_attachment_ids: list[str] | None = None,
        transit_gateway_id: str | None = None,
        filters: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch all transit gateway attachments with pagination.

        Args:
            transit_gateway_attachment_ids: Optional list of attachment IDs
            transit_gateway_id: Optional TGW ID to filter by
            filters: Optional AWS filters

        Returns:
            List of TGW attachment dictionaries from AWS API
        """
        return await self._execute_with_retry(
            lambda: self._paginate_transit_gateway_attachments(
                transit_gateway_attachment_ids, transit_gateway_id, filters
            ),
            "describe_transit_gateway_attachments",
        )

    # Alias for PrefixListResolver protocol compatibility
    async def get_prefix_list_cidrs(self, prefix_list_id: str) -> list[str]:
        """Alias for get_managed_prefix_list_entries.

        This method provides compatibility with the PrefixListResolver protocol
        used by SecurityGroupEvaluator.
        """
        return await self.get_managed_prefix_list_entries(prefix_list_id)

    async def describe_instances_by_id(
        self,
        instance_id: str,
    ) -> dict[str, Any] | None:
        """Fetch a single instance by ID.

        Args:
            instance_id: The instance ID

        Returns:
            Instance dictionary or None if not found
        """
        try:
            instances = await self.describe_instances(instance_ids=[instance_id])
            return instances[0] if instances else None
        except ResourceNotFoundError:
            return None

    async def describe_subnet_by_id(
        self,
        subnet_id: str,
    ) -> dict[str, Any] | None:
        """Fetch a single subnet by ID.

        Args:
            subnet_id: The subnet ID

        Returns:
            Subnet dictionary or None if not found
        """
        try:
            subnets = await self.describe_subnets(subnet_ids=[subnet_id])
            return subnets[0] if subnets else None
        except ResourceNotFoundError:
            return None

    async def describe_security_group_by_id(
        self,
        group_id: str,
    ) -> dict[str, Any] | None:
        """Fetch a single security group by ID.

        Args:
            group_id: The security group ID

        Returns:
            Security group dictionary or None if not found
        """
        try:
            groups = await self.describe_security_groups(group_ids=[group_id])
            return groups[0] if groups else None
        except ResourceNotFoundError:
            return None

    async def describe_network_interface_by_id(
        self,
        eni_id: str,
    ) -> dict[str, Any] | None:
        """Fetch a single network interface by ID.

        Args:
            eni_id: The network interface ID

        Returns:
            ENI dictionary or None if not found
        """
        try:
            enis = await self.describe_network_interfaces(network_interface_ids=[eni_id])
            return enis[0] if enis else None
        except ResourceNotFoundError:
            return None

    async def describe_route_table_by_id(
        self,
        route_table_id: str,
    ) -> dict[str, Any] | None:
        """Fetch a single route table by ID.

        Args:
            route_table_id: The route table ID

        Returns:
            Route table dictionary or None if not found
        """
        try:
            route_tables = await self.describe_route_tables(route_table_ids=[route_table_id])
            return route_tables[0] if route_tables else None
        except ResourceNotFoundError:
            return None

    async def describe_nacl_by_id(
        self,
        nacl_id: str,
    ) -> dict[str, Any] | None:
        """Fetch a single network ACL by ID.

        Args:
            nacl_id: The NACL ID

        Returns:
            NACL dictionary or None if not found
        """
        try:
            nacls = await self.describe_network_acls(network_acl_ids=[nacl_id])
            return nacls[0] if nacls else None
        except ResourceNotFoundError:
            return None

    async def describe_vpc_by_id(
        self,
        vpc_id: str,
    ) -> dict[str, Any] | None:
        """Fetch a single VPC by ID.

        Args:
            vpc_id: The VPC ID

        Returns:
            VPC dictionary or None if not found
        """
        try:
            vpcs = await self.describe_vpcs(vpc_ids=[vpc_id])
            return vpcs[0] if vpcs else None
        except ResourceNotFoundError:
            return None
