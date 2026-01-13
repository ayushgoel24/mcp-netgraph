"""Tests for AWS client, error detection, and retry logic."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from netgraph.aws.client import (
    ACCESS_DENIED_CODES,
    NOT_FOUND_CODES,
    RETRYABLE_CODES,
    AWSClient,
    AWSClientFactory,
    RetryConfig,
    _extract_operation,
    _extract_resource_id,
    _extract_resource_type,
    detect_error_type,
    is_retryable_error,
)
from netgraph.models.errors import (
    AWSAuthError,
    CrossAccountAccessError,
    PermissionDeniedError,
    ResourceNotFoundError,
)


class TestRetryConfig:
    """Tests for RetryConfig dataclass."""

    def test_default_values(self) -> None:
        """RetryConfig has sensible defaults."""
        config = RetryConfig()
        assert config.initial_delay == 1.0
        assert config.multiplier == 2.0
        assert config.max_delay == 30.0
        assert config.max_retries == 5
        assert config.jitter is True

    def test_custom_values(self) -> None:
        """RetryConfig accepts custom values."""
        config = RetryConfig(
            initial_delay=0.5,
            multiplier=1.5,
            max_delay=10.0,
            max_retries=3,
            jitter=False,
        )
        assert config.initial_delay == 0.5
        assert config.multiplier == 1.5
        assert config.max_delay == 10.0
        assert config.max_retries == 3
        assert config.jitter is False


class TestAWSClient:
    """Tests for AWSClient dataclass."""

    def test_init_with_account_id(self) -> None:
        """AWSClient can be initialized with explicit account ID."""
        mock_ec2 = MagicMock()
        client = AWSClient(ec2=mock_ec2, region="us-east-1", account_id="123456789012")

        assert client.ec2 is mock_ec2
        assert client.region == "us-east-1"
        assert client.account_id == "123456789012"

    def test_post_init_resolves_account_id(self) -> None:
        """AWSClient resolves account ID via STS if not provided."""
        mock_ec2 = MagicMock()
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}

        client = AWSClient(ec2=mock_ec2, region="us-east-1", _sts=mock_sts)

        assert client.account_id == "123456789012"
        mock_sts.get_caller_identity.assert_called_once()

    def test_post_init_handles_sts_error(self) -> None:
        """AWSClient sets 'unknown' if STS call fails."""
        mock_ec2 = MagicMock()
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "test"}},
            "GetCallerIdentity",
        )

        client = AWSClient(ec2=mock_ec2, region="us-east-1", _sts=mock_sts)

        assert client.account_id == "unknown"


class TestAWSClientFactory:
    """Tests for AWSClientFactory."""

    def test_init_defaults(self) -> None:
        """Factory has default region and retry config."""
        factory = AWSClientFactory()
        assert factory.region == "us-east-1"
        assert factory.profile is None
        assert factory.retry_config.max_retries == 5

    def test_init_custom_values(self) -> None:
        """Factory accepts custom region, profile, and retry config."""
        config = RetryConfig(max_retries=3)
        factory = AWSClientFactory(region="eu-west-1", profile="dev", retry_config=config)

        assert factory.region == "eu-west-1"
        assert factory.profile == "dev"
        assert factory.retry_config.max_retries == 3

    @patch("netgraph.aws.client.boto3.Session")
    def test_create_client_success(self, mock_session_class: MagicMock) -> None:
        """Factory creates client with proper configuration."""
        mock_session = MagicMock()
        mock_ec2 = MagicMock()
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}

        mock_session.client.side_effect = [mock_ec2, mock_sts]
        mock_session_class.return_value = mock_session

        factory = AWSClientFactory(region="us-west-2")
        client = factory.create_client()

        assert client.region == "us-west-2"
        assert client.account_id == "123456789012"
        mock_session_class.assert_called_once_with(region_name="us-west-2")

    @patch("netgraph.aws.client.boto3.Session")
    def test_create_client_with_profile(self, mock_session_class: MagicMock) -> None:
        """Factory creates session with profile."""
        mock_session = MagicMock()
        mock_ec2 = MagicMock()
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}

        mock_session.client.side_effect = [mock_ec2, mock_sts]
        mock_session_class.return_value = mock_session

        factory = AWSClientFactory(profile="production")
        factory.create_client()

        mock_session_class.assert_called_once_with(
            profile_name="production",
            region_name="us-east-1",
        )

    @patch("netgraph.aws.client.boto3.Session")
    def test_create_client_auth_error(self, mock_session_class: MagicMock) -> None:
        """Factory raises AWSAuthError on authentication failure."""
        mock_session = MagicMock()
        mock_session.client.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
            "CreateClient",
        )
        mock_session_class.return_value = mock_session

        factory = AWSClientFactory()

        with pytest.raises(AWSAuthError) as exc_info:
            factory.create_client()

        assert "authentication failed" in str(exc_info.value).lower()

    def test_clear_assumed_role_cache(self) -> None:
        """Factory can clear assumed role cache."""
        factory = AWSClientFactory()
        factory._assumed_role_clients["test-key"] = MagicMock()

        factory.clear_assumed_role_cache()

        assert len(factory._assumed_role_clients) == 0


class TestAWSClientFactoryCrossAccount:
    """Tests for cross-account role assumption."""

    @pytest.mark.asyncio
    @patch("netgraph.aws.client.asyncio.to_thread")
    @patch("netgraph.aws.client.boto3.client")
    @patch("netgraph.aws.client.boto3.Session")
    async def test_assume_role_success(
        self,
        mock_session_class: MagicMock,
        mock_boto3_client: MagicMock,
        mock_to_thread: MagicMock,
    ) -> None:
        """Factory can assume cross-account role."""
        mock_session = MagicMock()
        mock_sts = MagicMock()
        mock_session.client.return_value = mock_sts
        mock_session_class.return_value = mock_session

        mock_to_thread.return_value = {
            "Credentials": {
                "AccessKeyId": "AKIATEST",
                "SecretAccessKey": "secret",
                "SessionToken": "token",
            }
        }

        mock_ec2 = MagicMock()
        mock_boto3_client.return_value = mock_ec2

        factory = AWSClientFactory(region="us-east-1")
        client = await factory.create_cross_account_client(
            role_arn="arn:aws:iam::987654321098:role/NetGraphRole",
            external_id="ext-123",
        )

        assert client.region == "us-east-1"
        assert client.account_id == "987654321098"

    @pytest.mark.asyncio
    @patch("netgraph.aws.client.asyncio.to_thread")
    @patch("netgraph.aws.client.boto3.Session")
    async def test_assume_role_cached(
        self,
        mock_session_class: MagicMock,
        mock_to_thread: MagicMock,
    ) -> None:
        """Cross-account clients are cached."""
        mock_session = MagicMock()
        mock_sts = MagicMock()
        mock_session.client.return_value = mock_sts
        mock_session_class.return_value = mock_session

        mock_to_thread.return_value = {
            "Credentials": {
                "AccessKeyId": "AKIATEST",
                "SecretAccessKey": "secret",
                "SessionToken": "token",
            }
        }

        factory = AWSClientFactory()
        role_arn = "arn:aws:iam::987654321098:role/NetGraphRole"

        with patch("netgraph.aws.client.boto3.client"):
            client1 = await factory.create_cross_account_client(role_arn=role_arn)
            client2 = await factory.create_cross_account_client(role_arn=role_arn)

        assert client1 is client2
        assert mock_to_thread.call_count == 1  # Only called once

    @pytest.mark.asyncio
    @patch("netgraph.aws.client.asyncio.to_thread")
    @patch("netgraph.aws.client.boto3.Session")
    async def test_assume_role_access_denied(
        self,
        mock_session_class: MagicMock,
        mock_to_thread: MagicMock,
    ) -> None:
        """Factory raises CrossAccountAccessError on access denied."""
        mock_session = MagicMock()
        mock_sts = MagicMock()
        mock_session.client.return_value = mock_sts
        mock_session_class.return_value = mock_session

        mock_to_thread.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Cannot assume role"}},
            "AssumeRole",
        )

        factory = AWSClientFactory()

        with pytest.raises(CrossAccountAccessError) as exc_info:
            await factory.create_cross_account_client(
                role_arn="arn:aws:iam::987654321098:role/BadRole"
            )

        assert "987654321098" in str(exc_info.value)


class TestErrorDetection:
    """Tests for error detection functions."""

    def test_detect_access_denied(self) -> None:
        """detect_error_type returns PermissionDeniedError for access denied."""
        for code in ACCESS_DENIED_CODES:
            error = ClientError(
                {"Error": {"Code": code, "Message": "Not authorized for sg-12345"}},
                "DescribeSecurityGroups",
            )
            result = detect_error_type(error)
            assert isinstance(result, PermissionDeniedError)

    def test_detect_not_found(self) -> None:
        """detect_error_type returns ResourceNotFoundError for not found errors."""
        for code in NOT_FOUND_CODES:
            error = ClientError(
                {"Error": {"Code": code, "Message": "Resource not found"}},
                "DescribeInstances",
            )
            result = detect_error_type(error)
            assert isinstance(result, ResourceNotFoundError)

    def test_detect_unknown_error(self) -> None:
        """detect_error_type returns original error for unknown codes."""
        error = ClientError(
            {"Error": {"Code": "UnknownError", "Message": "Something went wrong"}},
            "SomeOperation",
        )
        result = detect_error_type(error)
        assert result is error

    def test_is_retryable_error(self) -> None:
        """is_retryable_error returns True for retryable error codes."""
        for code in RETRYABLE_CODES:
            error = ClientError(
                {"Error": {"Code": code, "Message": "Rate exceeded"}},
                "DescribeInstances",
            )
            assert is_retryable_error(error) is True

    def test_is_not_retryable_error(self) -> None:
        """is_retryable_error returns False for non-retryable errors."""
        error = ClientError(
            {"Error": {"Code": "InvalidParameterValue", "Message": "Invalid param"}},
            "DescribeInstances",
        )
        assert is_retryable_error(error) is False


class TestResourceIdExtraction:
    """Tests for resource ID extraction from error messages."""

    def test_extract_instance_id(self) -> None:
        """Extracts EC2 instance ID from message."""
        msg = "The instance ID 'i-1234567890abcdef0' does not exist"
        assert _extract_resource_id(msg) == "i-1234567890abcdef0"

    def test_extract_subnet_id(self) -> None:
        """Extracts subnet ID from message."""
        msg = "The subnet 'subnet-abc12345' does not exist"
        assert _extract_resource_id(msg) == "subnet-abc12345"

    def test_extract_sg_id(self) -> None:
        """Extracts security group ID from message."""
        msg = "Security group sg-12345678 not found"
        assert _extract_resource_id(msg) == "sg-12345678"

    def test_extract_eni_id(self) -> None:
        """Extracts ENI ID from message."""
        msg = "Network interface eni-abcdef12 not found"
        assert _extract_resource_id(msg) == "eni-abcdef12"

    def test_extract_vpc_id(self) -> None:
        """Extracts VPC ID from message."""
        msg = "VPC vpc-12345678 does not exist"
        assert _extract_resource_id(msg) == "vpc-12345678"

    def test_extract_nacl_id(self) -> None:
        """Extracts NACL ID from message."""
        msg = "Network ACL acl-12345678 not found"
        assert _extract_resource_id(msg) == "acl-12345678"

    def test_extract_route_table_id(self) -> None:
        """Extracts route table ID from message."""
        msg = "Route table rtb-12345678 does not exist"
        assert _extract_resource_id(msg) == "rtb-12345678"

    def test_extract_prefix_list_id(self) -> None:
        """Extracts prefix list ID from message."""
        msg = "Prefix list pl-12345678 not found"
        assert _extract_resource_id(msg) == "pl-12345678"

    def test_no_resource_id_found(self) -> None:
        """Returns None when no resource ID in message."""
        msg = "An unknown error occurred"
        assert _extract_resource_id(msg) is None


class TestOperationExtraction:
    """Tests for operation name extraction from error messages."""

    def test_extract_operation_with_keyword(self) -> None:
        """Extracts operation name with 'operation:' prefix."""
        msg = "User is not authorized. operation: DescribeInstances"
        assert _extract_operation(msg) == "DescribeInstances"

    def test_extract_action_with_keyword(self) -> None:
        """Extracts action name with 'action:' prefix."""
        msg = "Not authorized for action: ec2:DescribeSecurityGroups"
        assert _extract_operation(msg) == "ec2"  # First word match

    def test_no_operation_found(self) -> None:
        """Returns None when no operation in message."""
        msg = "Access denied"
        assert _extract_operation(msg) is None


class TestResourceTypeExtraction:
    """Tests for resource type extraction from error codes."""

    def test_extract_instance_type(self) -> None:
        """Extracts 'instance' from InvalidInstanceID error."""
        assert _extract_resource_type("InvalidInstanceID.NotFound") == "instance"

    def test_extract_subnet_type(self) -> None:
        """Extracts 'subnet' from InvalidSubnetID error."""
        assert _extract_resource_type("InvalidSubnetID.NotFound") == "subnet"

    def test_extract_security_group_type(self) -> None:
        """Extracts 'security_group' from InvalidSecurityGroupID error."""
        assert _extract_resource_type("InvalidSecurityGroupID.NotFound") == "security_group"

    def test_extract_nacl_type(self) -> None:
        """Extracts 'nacl' from InvalidNetworkAclID error."""
        assert _extract_resource_type("InvalidNetworkAclID.NotFound") == "nacl"

    def test_extract_vpc_type(self) -> None:
        """Extracts 'vpc' from InvalidVpcID error."""
        assert _extract_resource_type("InvalidVpcID.NotFound") == "vpc"

    def test_extract_eni_type(self) -> None:
        """Extracts 'network_interface' from InvalidNetworkInterfaceID error."""
        assert _extract_resource_type("InvalidNetworkInterfaceID.NotFound") == "network_interface"

    def test_extract_prefix_list_type(self) -> None:
        """Extracts 'prefix_list' from InvalidPrefixListId error."""
        assert _extract_resource_type("InvalidPrefixListId.NotFound") == "prefix_list"

    def test_unknown_type_returns_resource(self) -> None:
        """Returns 'resource' for unknown error codes."""
        assert _extract_resource_type("SomeOtherError") == "resource"


class TestErrorCodeSets:
    """Tests that error code sets are properly defined."""

    def test_access_denied_codes_not_empty(self) -> None:
        """ACCESS_DENIED_CODES contains codes."""
        assert len(ACCESS_DENIED_CODES) > 0
        assert "AccessDenied" in ACCESS_DENIED_CODES
        assert "UnauthorizedOperation" in ACCESS_DENIED_CODES

    def test_not_found_codes_not_empty(self) -> None:
        """NOT_FOUND_CODES contains codes."""
        assert len(NOT_FOUND_CODES) > 0
        assert "InvalidInstanceID.NotFound" in NOT_FOUND_CODES
        assert "InvalidSubnetID.NotFound" in NOT_FOUND_CODES

    def test_retryable_codes_not_empty(self) -> None:
        """RETRYABLE_CODES contains codes."""
        assert len(RETRYABLE_CODES) > 0
        assert "Throttling" in RETRYABLE_CODES
        assert "RequestLimitExceeded" in RETRYABLE_CODES

    def test_code_sets_are_disjoint(self) -> None:
        """Error code sets don't overlap."""
        assert ACCESS_DENIED_CODES.isdisjoint(NOT_FOUND_CODES)
        assert ACCESS_DENIED_CODES.isdisjoint(RETRYABLE_CODES)
        assert NOT_FOUND_CODES.isdisjoint(RETRYABLE_CODES)
