"""Tests for EC2Fetcher with auto-pagination and retry logic."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from netgraph.aws.client import AWSClient, RetryConfig
from netgraph.aws.fetcher import EC2Fetcher
from netgraph.models.errors import (
    PermissionDeniedError,
    PrefixListResolutionError,
    ResourceNotFoundError,
)


@pytest.fixture
def mock_ec2_client() -> MagicMock:
    """Create a mock EC2 client."""
    return MagicMock()


@pytest.fixture
def mock_aws_client(mock_ec2_client: MagicMock) -> AWSClient:
    """Create a mock AWSClient."""
    return AWSClient(
        ec2=mock_ec2_client,
        region="us-east-1",
        account_id="123456789012",
    )


@pytest.fixture
def fetcher(mock_aws_client: AWSClient) -> EC2Fetcher:
    """Create an EC2Fetcher with fast retry config for testing."""
    return EC2Fetcher(
        client=mock_aws_client,
        retry_config=RetryConfig(
            initial_delay=0.01,  # Very fast for testing
            max_retries=2,
            jitter=False,
        ),
    )


def create_paginator_mock(pages: list[dict[str, Any]]) -> MagicMock:
    """Create a mock paginator that returns the given pages."""
    paginator = MagicMock()
    paginator.paginate.return_value = iter(pages)
    return paginator


class TestEC2FetcherInit:
    """Tests for EC2Fetcher initialization."""

    def test_init_with_defaults(self, mock_aws_client: AWSClient) -> None:
        """EC2Fetcher initializes with default retry config."""
        fetcher = EC2Fetcher(client=mock_aws_client)
        assert fetcher.client is mock_aws_client
        assert fetcher.retry_config.max_retries == 5

    def test_init_with_custom_retry(self, mock_aws_client: AWSClient) -> None:
        """EC2Fetcher accepts custom retry config."""
        config = RetryConfig(max_retries=3)
        fetcher = EC2Fetcher(client=mock_aws_client, retry_config=config)
        assert fetcher.retry_config.max_retries == 3


class TestDescribeInstances:
    """Tests for describe_instances with pagination."""

    @pytest.mark.asyncio
    async def test_single_page(self, fetcher: EC2Fetcher, mock_ec2_client: MagicMock) -> None:
        """Fetches instances from single page."""
        mock_ec2_client.get_paginator.return_value = create_paginator_mock(
            [
                {
                    "Reservations": [
                        {
                            "Instances": [
                                {"InstanceId": "i-1", "State": {"Name": "running"}},
                                {"InstanceId": "i-2", "State": {"Name": "running"}},
                            ]
                        }
                    ]
                }
            ]
        )

        result = await fetcher.describe_instances()

        assert len(result) == 2
        assert result[0]["InstanceId"] == "i-1"
        assert result[1]["InstanceId"] == "i-2"

    @pytest.mark.asyncio
    async def test_multiple_pages(self, fetcher: EC2Fetcher, mock_ec2_client: MagicMock) -> None:
        """Fetches instances across multiple pages."""
        mock_ec2_client.get_paginator.return_value = create_paginator_mock(
            [
                {"Reservations": [{"Instances": [{"InstanceId": "i-1"}]}]},
                {"Reservations": [{"Instances": [{"InstanceId": "i-2"}]}]},
                {"Reservations": [{"Instances": [{"InstanceId": "i-3"}]}]},
            ]
        )

        result = await fetcher.describe_instances()

        assert len(result) == 3
        ids = [r["InstanceId"] for r in result]
        assert ids == ["i-1", "i-2", "i-3"]

    @pytest.mark.asyncio
    async def test_multiple_reservations(
        self, fetcher: EC2Fetcher, mock_ec2_client: MagicMock
    ) -> None:
        """Fetches instances from multiple reservations."""
        mock_ec2_client.get_paginator.return_value = create_paginator_mock(
            [
                {
                    "Reservations": [
                        {"Instances": [{"InstanceId": "i-1"}]},
                        {"Instances": [{"InstanceId": "i-2"}, {"InstanceId": "i-3"}]},
                    ]
                }
            ]
        )

        result = await fetcher.describe_instances()

        assert len(result) == 3

    @pytest.mark.asyncio
    async def test_with_instance_ids_filter(
        self, fetcher: EC2Fetcher, mock_ec2_client: MagicMock
    ) -> None:
        """Passes instance IDs filter to paginator."""
        paginator = create_paginator_mock([{"Reservations": []}])
        mock_ec2_client.get_paginator.return_value = paginator

        await fetcher.describe_instances(instance_ids=["i-1", "i-2"])

        paginator.paginate.assert_called_once_with(InstanceIds=["i-1", "i-2"])

    @pytest.mark.asyncio
    async def test_with_aws_filters(self, fetcher: EC2Fetcher, mock_ec2_client: MagicMock) -> None:
        """Passes AWS filters to paginator."""
        paginator = create_paginator_mock([{"Reservations": []}])
        mock_ec2_client.get_paginator.return_value = paginator

        filters = [{"Name": "instance-state-name", "Values": ["running"]}]
        await fetcher.describe_instances(filters=filters)

        paginator.paginate.assert_called_once_with(Filters=filters)

    @pytest.mark.asyncio
    async def test_empty_result(self, fetcher: EC2Fetcher, mock_ec2_client: MagicMock) -> None:
        """Returns empty list when no instances found."""
        mock_ec2_client.get_paginator.return_value = create_paginator_mock([{"Reservations": []}])

        result = await fetcher.describe_instances()

        assert result == []


class TestDescribeSubnets:
    """Tests for describe_subnets with pagination."""

    @pytest.mark.asyncio
    async def test_fetches_subnets(self, fetcher: EC2Fetcher, mock_ec2_client: MagicMock) -> None:
        """Fetches subnets with pagination."""
        mock_ec2_client.get_paginator.return_value = create_paginator_mock(
            [{"Subnets": [{"SubnetId": "subnet-1"}, {"SubnetId": "subnet-2"}]}]
        )

        result = await fetcher.describe_subnets()

        assert len(result) == 2

    @pytest.mark.asyncio
    async def test_with_vpc_filter(self, fetcher: EC2Fetcher, mock_ec2_client: MagicMock) -> None:
        """Adds VPC filter to request."""
        paginator = create_paginator_mock([{"Subnets": []}])
        mock_ec2_client.get_paginator.return_value = paginator

        await fetcher.describe_subnets(vpc_id="vpc-12345")

        paginator.paginate.assert_called_once()
        call_args = paginator.paginate.call_args
        filters = call_args[1]["Filters"]
        assert {"Name": "vpc-id", "Values": ["vpc-12345"]} in filters


class TestDescribeSecurityGroups:
    """Tests for describe_security_groups with pagination."""

    @pytest.mark.asyncio
    async def test_fetches_security_groups(
        self, fetcher: EC2Fetcher, mock_ec2_client: MagicMock
    ) -> None:
        """Fetches security groups with pagination."""
        mock_ec2_client.get_paginator.return_value = create_paginator_mock(
            [{"SecurityGroups": [{"GroupId": "sg-1"}, {"GroupId": "sg-2"}]}]
        )

        result = await fetcher.describe_security_groups()

        assert len(result) == 2

    @pytest.mark.asyncio
    async def test_with_group_ids(self, fetcher: EC2Fetcher, mock_ec2_client: MagicMock) -> None:
        """Passes group IDs to paginator."""
        paginator = create_paginator_mock([{"SecurityGroups": []}])
        mock_ec2_client.get_paginator.return_value = paginator

        await fetcher.describe_security_groups(group_ids=["sg-1", "sg-2"])

        paginator.paginate.assert_called_once_with(GroupIds=["sg-1", "sg-2"])


class TestDescribeNetworkInterfaces:
    """Tests for describe_network_interfaces with pagination."""

    @pytest.mark.asyncio
    async def test_fetches_enis(self, fetcher: EC2Fetcher, mock_ec2_client: MagicMock) -> None:
        """Fetches ENIs with pagination."""
        mock_ec2_client.get_paginator.return_value = create_paginator_mock(
            [
                {
                    "NetworkInterfaces": [
                        {"NetworkInterfaceId": "eni-1"},
                        {"NetworkInterfaceId": "eni-2"},
                    ]
                }
            ]
        )

        result = await fetcher.describe_network_interfaces()

        assert len(result) == 2


class TestDescribeRouteTables:
    """Tests for describe_route_tables with pagination."""

    @pytest.mark.asyncio
    async def test_fetches_route_tables(
        self, fetcher: EC2Fetcher, mock_ec2_client: MagicMock
    ) -> None:
        """Fetches route tables with pagination."""
        mock_ec2_client.get_paginator.return_value = create_paginator_mock(
            [{"RouteTables": [{"RouteTableId": "rtb-1"}]}]
        )

        result = await fetcher.describe_route_tables()

        assert len(result) == 1


class TestDescribeNatGateways:
    """Tests for describe_nat_gateways with pagination."""

    @pytest.mark.asyncio
    async def test_uses_filter_not_filters(
        self, fetcher: EC2Fetcher, mock_ec2_client: MagicMock
    ) -> None:
        """NAT gateways use 'Filter' not 'Filters' parameter."""
        paginator = create_paginator_mock([{"NatGateways": []}])
        mock_ec2_client.get_paginator.return_value = paginator

        await fetcher.describe_nat_gateways(vpc_id="vpc-12345")

        call_args = paginator.paginate.call_args
        # NAT gateway API uses "Filter" not "Filters"
        assert "Filter" in call_args[1]
        assert "Filters" not in call_args[1]


class TestDescribeVPCs:
    """Tests for describe_vpcs with pagination."""

    @pytest.mark.asyncio
    async def test_fetches_vpcs(self, fetcher: EC2Fetcher, mock_ec2_client: MagicMock) -> None:
        """Fetches VPCs with pagination."""
        mock_ec2_client.get_paginator.return_value = create_paginator_mock(
            [{"Vpcs": [{"VpcId": "vpc-1"}, {"VpcId": "vpc-2"}]}]
        )

        result = await fetcher.describe_vpcs()

        assert len(result) == 2


class TestGetManagedPrefixListEntries:
    """Tests for prefix list resolution."""

    @pytest.mark.asyncio
    async def test_fetches_prefix_list_cidrs(
        self, fetcher: EC2Fetcher, mock_ec2_client: MagicMock
    ) -> None:
        """Fetches CIDRs from prefix list."""
        mock_ec2_client.get_paginator.return_value = create_paginator_mock(
            [
                {
                    "Entries": [
                        {"Cidr": "10.0.0.0/8"},
                        {"Cidr": "192.168.0.0/16"},
                    ]
                }
            ]
        )

        result = await fetcher.get_managed_prefix_list_entries("pl-12345")

        assert result == ["10.0.0.0/8", "192.168.0.0/16"]

    @pytest.mark.asyncio
    async def test_prefix_list_not_found(
        self, fetcher: EC2Fetcher, mock_ec2_client: MagicMock
    ) -> None:
        """Raises PrefixListResolutionError when not found."""
        paginator = MagicMock()
        paginator.paginate.side_effect = ClientError(
            {"Error": {"Code": "InvalidPrefixListId.NotFound", "Message": "Not found"}},
            "GetManagedPrefixListEntries",
        )
        mock_ec2_client.get_paginator.return_value = paginator

        with pytest.raises(PrefixListResolutionError) as exc_info:
            await fetcher.get_managed_prefix_list_entries("pl-invalid")

        assert exc_info.value.prefix_list_id == "pl-invalid"
        assert "not found" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_prefix_list_access_denied(
        self, fetcher: EC2Fetcher, mock_ec2_client: MagicMock
    ) -> None:
        """Raises PrefixListResolutionError on access denied."""
        paginator = MagicMock()
        paginator.paginate.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
            "GetManagedPrefixListEntries",
        )
        mock_ec2_client.get_paginator.return_value = paginator

        with pytest.raises(PrefixListResolutionError) as exc_info:
            await fetcher.get_managed_prefix_list_entries("pl-secret")

        assert "access denied" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_get_prefix_list_cidrs_alias(
        self, fetcher: EC2Fetcher, mock_ec2_client: MagicMock
    ) -> None:
        """get_prefix_list_cidrs is alias for get_managed_prefix_list_entries."""
        mock_ec2_client.get_paginator.return_value = create_paginator_mock(
            [{"Entries": [{"Cidr": "10.0.0.0/8"}]}]
        )

        result = await fetcher.get_prefix_list_cidrs("pl-12345")

        assert result == ["10.0.0.0/8"]


class TestSingleResourceFetchers:
    """Tests for single resource fetch by ID."""

    @pytest.mark.asyncio
    async def test_describe_instances_by_id(
        self, fetcher: EC2Fetcher, mock_ec2_client: MagicMock
    ) -> None:
        """Fetches single instance by ID."""
        mock_ec2_client.get_paginator.return_value = create_paginator_mock(
            [{"Reservations": [{"Instances": [{"InstanceId": "i-12345"}]}]}]
        )

        result = await fetcher.describe_instances_by_id("i-12345")

        assert result is not None
        assert result["InstanceId"] == "i-12345"

    @pytest.mark.asyncio
    async def test_describe_instances_by_id_not_found(
        self, fetcher: EC2Fetcher, mock_ec2_client: MagicMock
    ) -> None:
        """Returns None when instance not found."""
        mock_ec2_client.get_paginator.return_value = create_paginator_mock([{"Reservations": []}])

        result = await fetcher.describe_instances_by_id("i-invalid")

        assert result is None

    @pytest.mark.asyncio
    async def test_describe_subnet_by_id(
        self, fetcher: EC2Fetcher, mock_ec2_client: MagicMock
    ) -> None:
        """Fetches single subnet by ID."""
        mock_ec2_client.get_paginator.return_value = create_paginator_mock(
            [{"Subnets": [{"SubnetId": "subnet-12345"}]}]
        )

        result = await fetcher.describe_subnet_by_id("subnet-12345")

        assert result is not None
        assert result["SubnetId"] == "subnet-12345"

    @pytest.mark.asyncio
    async def test_describe_security_group_by_id(
        self, fetcher: EC2Fetcher, mock_ec2_client: MagicMock
    ) -> None:
        """Fetches single security group by ID."""
        mock_ec2_client.get_paginator.return_value = create_paginator_mock(
            [{"SecurityGroups": [{"GroupId": "sg-12345"}]}]
        )

        result = await fetcher.describe_security_group_by_id("sg-12345")

        assert result is not None
        assert result["GroupId"] == "sg-12345"

    @pytest.mark.asyncio
    async def test_describe_vpc_by_id(
        self, fetcher: EC2Fetcher, mock_ec2_client: MagicMock
    ) -> None:
        """Fetches single VPC by ID."""
        mock_ec2_client.get_paginator.return_value = create_paginator_mock(
            [{"Vpcs": [{"VpcId": "vpc-12345"}]}]
        )

        result = await fetcher.describe_vpc_by_id("vpc-12345")

        assert result is not None
        assert result["VpcId"] == "vpc-12345"


class TestRetryLogic:
    """Tests for retry logic with exponential backoff."""

    @pytest.mark.asyncio
    async def test_retries_on_throttling(
        self, mock_aws_client: AWSClient, mock_ec2_client: MagicMock
    ) -> None:
        """Retries when throttled."""
        # Use very fast retry config for testing
        fetcher = EC2Fetcher(
            client=mock_aws_client,
            retry_config=RetryConfig(initial_delay=0.001, max_retries=2, jitter=False),
        )

        paginator = MagicMock()
        call_count = 0

        def paginate_side_effect(**_kwargs: Any) -> Any:
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise ClientError(
                    {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                    "DescribeInstances",
                )
            return iter([{"Reservations": [{"Instances": [{"InstanceId": "i-1"}]}]}])

        paginator.paginate = paginate_side_effect
        mock_ec2_client.get_paginator.return_value = paginator

        result = await fetcher.describe_instances()

        assert len(result) == 1
        assert call_count == 2  # First failed, second succeeded

    @pytest.mark.asyncio
    async def test_fails_after_max_retries(
        self, mock_aws_client: AWSClient, mock_ec2_client: MagicMock
    ) -> None:
        """Raises error after exhausting retries."""
        fetcher = EC2Fetcher(
            client=mock_aws_client,
            retry_config=RetryConfig(initial_delay=0.001, max_retries=2, jitter=False),
        )

        paginator = MagicMock()
        paginator.paginate.side_effect = ClientError(
            {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
            "DescribeInstances",
        )
        mock_ec2_client.get_paginator.return_value = paginator

        with pytest.raises(ClientError):
            await fetcher.describe_instances()

        # Should have tried max_retries + 1 times (initial + retries)
        assert paginator.paginate.call_count == 3

    @pytest.mark.asyncio
    async def test_no_retry_on_permission_denied(
        self, mock_aws_client: AWSClient, mock_ec2_client: MagicMock
    ) -> None:
        """Does not retry on permission denied errors."""
        fetcher = EC2Fetcher(
            client=mock_aws_client,
            retry_config=RetryConfig(initial_delay=0.001, max_retries=2, jitter=False),
        )

        paginator = MagicMock()
        paginator.paginate.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Not authorized"}},
            "DescribeInstances",
        )
        mock_ec2_client.get_paginator.return_value = paginator

        with pytest.raises(PermissionDeniedError):
            await fetcher.describe_instances()

        # Should only try once (no retries for access denied)
        assert paginator.paginate.call_count == 1

    @pytest.mark.asyncio
    async def test_no_retry_on_not_found(
        self, mock_aws_client: AWSClient, mock_ec2_client: MagicMock
    ) -> None:
        """Does not retry on not found errors."""
        fetcher = EC2Fetcher(
            client=mock_aws_client,
            retry_config=RetryConfig(initial_delay=0.001, max_retries=2, jitter=False),
        )

        paginator = MagicMock()
        paginator.paginate.side_effect = ClientError(
            {"Error": {"Code": "InvalidInstanceID.NotFound", "Message": "Not found"}},
            "DescribeInstances",
        )
        mock_ec2_client.get_paginator.return_value = paginator

        with pytest.raises(ResourceNotFoundError):
            await fetcher.describe_instances()

        # Should only try once
        assert paginator.paginate.call_count == 1


class TestTransitGatewayResources:
    """Tests for Transit Gateway resource fetching."""

    @pytest.mark.asyncio
    async def test_describe_transit_gateways(
        self, fetcher: EC2Fetcher, mock_ec2_client: MagicMock
    ) -> None:
        """Fetches transit gateways with pagination."""
        mock_ec2_client.get_paginator.return_value = create_paginator_mock(
            [{"TransitGateways": [{"TransitGatewayId": "tgw-1"}]}]
        )

        result = await fetcher.describe_transit_gateways()

        assert len(result) == 1
        assert result[0]["TransitGatewayId"] == "tgw-1"

    @pytest.mark.asyncio
    async def test_describe_transit_gateway_attachments(
        self, fetcher: EC2Fetcher, mock_ec2_client: MagicMock
    ) -> None:
        """Fetches TGW attachments with pagination."""
        mock_ec2_client.get_paginator.return_value = create_paginator_mock(
            [{"TransitGatewayAttachments": [{"TransitGatewayAttachmentId": "tgw-attach-1"}]}]
        )

        result = await fetcher.describe_transit_gateway_attachments()

        assert len(result) == 1
        assert result[0]["TransitGatewayAttachmentId"] == "tgw-attach-1"


class TestVPCPeeringConnections:
    """Tests for VPC peering connection fetching."""

    @pytest.mark.asyncio
    async def test_describe_vpc_peering_connections(
        self, fetcher: EC2Fetcher, mock_ec2_client: MagicMock
    ) -> None:
        """Fetches VPC peering connections with pagination."""
        mock_ec2_client.get_paginator.return_value = create_paginator_mock(
            [{"VpcPeeringConnections": [{"VpcPeeringConnectionId": "pcx-1"}]}]
        )

        result = await fetcher.describe_vpc_peering_connections()

        assert len(result) == 1


class TestInternetGateways:
    """Tests for Internet Gateway fetching."""

    @pytest.mark.asyncio
    async def test_describe_internet_gateways(
        self, fetcher: EC2Fetcher, mock_ec2_client: MagicMock
    ) -> None:
        """Fetches internet gateways with pagination."""
        mock_ec2_client.get_paginator.return_value = create_paginator_mock(
            [{"InternetGateways": [{"InternetGatewayId": "igw-1"}]}]
        )

        result = await fetcher.describe_internet_gateways()

        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_igw_vpc_filter_uses_attachment(
        self, fetcher: EC2Fetcher, mock_ec2_client: MagicMock
    ) -> None:
        """IGW VPC filter uses attachment.vpc-id."""
        paginator = create_paginator_mock([{"InternetGateways": []}])
        mock_ec2_client.get_paginator.return_value = paginator

        await fetcher.describe_internet_gateways(vpc_id="vpc-12345")

        call_args = paginator.paginate.call_args
        filters = call_args[1]["Filters"]
        # IGW uses "attachment.vpc-id" not "vpc-id"
        assert {"Name": "attachment.vpc-id", "Values": ["vpc-12345"]} in filters


class TestNetworkACLs:
    """Tests for Network ACL fetching."""

    @pytest.mark.asyncio
    async def test_describe_network_acls(
        self, fetcher: EC2Fetcher, mock_ec2_client: MagicMock
    ) -> None:
        """Fetches network ACLs with pagination."""
        mock_ec2_client.get_paginator.return_value = create_paginator_mock(
            [{"NetworkAcls": [{"NetworkAclId": "acl-1"}]}]
        )

        result = await fetcher.describe_network_acls()

        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_describe_nacl_by_id(
        self, fetcher: EC2Fetcher, mock_ec2_client: MagicMock
    ) -> None:
        """Fetches single NACL by ID."""
        mock_ec2_client.get_paginator.return_value = create_paginator_mock(
            [{"NetworkAcls": [{"NetworkAclId": "acl-12345"}]}]
        )

        result = await fetcher.describe_nacl_by_id("acl-12345")

        assert result is not None
        assert result["NetworkAclId"] == "acl-12345"

    @pytest.mark.asyncio
    async def test_describe_route_table_by_id(
        self, fetcher: EC2Fetcher, mock_ec2_client: MagicMock
    ) -> None:
        """Fetches single route table by ID."""
        mock_ec2_client.get_paginator.return_value = create_paginator_mock(
            [{"RouteTables": [{"RouteTableId": "rtb-12345"}]}]
        )

        result = await fetcher.describe_route_table_by_id("rtb-12345")

        assert result is not None
        assert result["RouteTableId"] == "rtb-12345"

    @pytest.mark.asyncio
    async def test_describe_network_interface_by_id(
        self, fetcher: EC2Fetcher, mock_ec2_client: MagicMock
    ) -> None:
        """Fetches single ENI by ID."""
        mock_ec2_client.get_paginator.return_value = create_paginator_mock(
            [{"NetworkInterfaces": [{"NetworkInterfaceId": "eni-12345"}]}]
        )

        result = await fetcher.describe_network_interface_by_id("eni-12345")

        assert result is not None
        assert result["NetworkInterfaceId"] == "eni-12345"
