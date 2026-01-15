"""AWS client with credential handling and retry logic.

This module provides:
- AWSClient: Wrapper around boto3 EC2 client with error handling
- AWSClientFactory: Creates clients with proper credential chain
- Exponential backoff retry for rate limiting
"""

from __future__ import annotations

import asyncio
import random
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from netgraph.models.errors import (
    AWSAuthError,
    CrossAccountAccessError,
    PermissionDeniedError,
    ResourceNotFoundError,
)
from netgraph.utils.logging import get_logger

if TYPE_CHECKING:
    from mypy_boto3_ec2 import EC2Client
    from mypy_boto3_sts import STSClient

logger = get_logger(__name__)

# Error codes that indicate permission issues
ACCESS_DENIED_CODES = frozenset(
    {
        "AccessDenied",
        "UnauthorizedOperation",
        "AccessDeniedException",
        "AuthorizationError",
    }
)

# Error codes that indicate resource doesn't exist
NOT_FOUND_CODES = frozenset(
    {
        "InvalidInstanceID.NotFound",
        "InvalidSubnetID.NotFound",
        "InvalidSecurityGroupID.NotFound",
        "InvalidNetworkAclID.NotFound",
        "InvalidRouteTableID.NotFound",
        "InvalidInternetGatewayID.NotFound",
        "InvalidNatGatewayID.NotFound",
        "InvalidVpcPeeringConnectionID.NotFound",
        "InvalidPrefixListId.NotFound",
        "InvalidNetworkInterfaceID.NotFound",
        "InvalidVpcID.NotFound",
    }
)

# Error codes that should trigger retry
RETRYABLE_CODES = frozenset(
    {
        "Throttling",
        "ThrottlingException",
        "RequestLimitExceeded",
        "ServiceUnavailable",
        "ServiceUnavailableException",
        "InternalError",
        "InternalServiceError",
    }
)


@dataclass
class RetryConfig:
    """Configuration for exponential backoff retry."""

    initial_delay: float = 1.0
    multiplier: float = 2.0
    max_delay: float = 30.0
    max_retries: int = 5
    jitter: bool = True


@dataclass
class AWSClient:
    """AWS client wrapper with error handling.

    This class wraps a boto3 EC2 client and provides:
    - Error code translation to NetGraph exceptions
    - Region and account tracking
    """

    ec2: EC2Client
    region: str
    account_id: str | None = None
    _sts: STSClient | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        """Resolve account ID if not provided."""
        if self.account_id is None:
            try:
                if self._sts is None:
                    self._sts = boto3.client("sts", region_name=self.region)
                identity = self._sts.get_caller_identity()
                self.account_id = identity["Account"]
            except ClientError as e:
                logger.warning(f"Could not determine account ID: {e}")
                self.account_id = "unknown"


class AWSClientFactory:
    """Factory for creating AWS clients with credential chain support.

    Supports:
    - Default credential chain (env vars, ~/.aws/credentials, instance role)
    - Explicit profile selection
    - Cross-account role assumption
    """

    def __init__(
        self,
        region: str | None = None,
        profile: str | None = None,
        retry_config: RetryConfig | None = None,
    ) -> None:
        """Initialize the factory.

        Args:
            region: AWS region (default: from env or 'us-east-1')
            profile: AWS profile name (default: use credential chain)
            retry_config: Retry configuration (default: use defaults)
        """
        self.region = region or "us-east-1"
        self.profile = profile
        self.retry_config = retry_config or RetryConfig()
        self._session: boto3.Session | None = None
        self._assumed_role_clients: dict[str, AWSClient] = {}

    def _get_session(self) -> boto3.Session:
        """Get or create boto3 session."""
        if self._session is None:
            if self.profile:
                self._session = boto3.Session(
                    profile_name=self.profile,
                    region_name=self.region,
                )
            else:
                self._session = boto3.Session(region_name=self.region)
        return self._session

    def _create_boto_config(self) -> Config:
        """Create boto3 config with retry settings."""
        return Config(
            retries={
                "max_attempts": self.retry_config.max_retries,
                "mode": "adaptive",
            }
        )

    def create_client(self) -> AWSClient:
        """Create an AWS client using the default credential chain.

        Returns:
            AWSClient configured for the current credentials.

        Raises:
            AWSAuthError: If authentication fails.
        """
        try:
            session = self._get_session()
            ec2 = session.client("ec2", config=self._create_boto_config())
            sts = session.client("sts")

            return AWSClient(
                ec2=ec2,
                region=self.region,
                _sts=sts,
            )
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in ACCESS_DENIED_CODES:
                raise AWSAuthError(
                    f"AWS authentication failed: {e}",
                    missing_permission="sts:GetCallerIdentity",
                ) from e
            raise

    async def create_cross_account_client(
        self,
        role_arn: str,
        external_id: str | None = None,
        session_name: str = "NetGraphCrossAccount",
    ) -> AWSClient:
        """Create an AWS client by assuming a cross-account role.

        Args:
            role_arn: ARN of the role to assume (e.g., arn:aws:iam::123456789012:role/NetGraphRole)
            external_id: Optional external ID for additional security
            session_name: Name for the assumed role session

        Returns:
            AWSClient configured with assumed role credentials.

        Raises:
            CrossAccountAccessError: If role assumption fails.
        """
        # Check cache first
        cache_key = f"{role_arn}:{external_id or ''}"
        if cache_key in self._assumed_role_clients:
            return self._assumed_role_clients[cache_key]

        try:
            session = self._get_session()
            sts = session.client("sts")

            # Build assume role request
            assume_params: dict[str, Any] = {
                "RoleArn": role_arn,
                "RoleSessionName": session_name,
                "DurationSeconds": 3600,  # 1 hour
            }
            if external_id:
                assume_params["ExternalId"] = external_id

            # Assume the role
            response = await asyncio.to_thread(
                sts.assume_role,
                **assume_params,
            )

            credentials = response["Credentials"]

            # Create EC2 client with assumed role credentials
            ec2 = boto3.client(
                "ec2",
                region_name=self.region,
                aws_access_key_id=credentials["AccessKeyId"],
                aws_secret_access_key=credentials["SecretAccessKey"],
                aws_session_token=credentials["SessionToken"],
                config=self._create_boto_config(),
            )

            # Extract account ID from role ARN
            # Format: arn:aws:iam::123456789012:role/RoleName
            account_id = role_arn.split(":")[4]

            client = AWSClient(
                ec2=ec2,
                region=self.region,
                account_id=account_id,
            )

            # Cache the client
            self._assumed_role_clients[cache_key] = client

            logger.info(f"Assumed role {role_arn} for account {account_id}")
            return client

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            account_id = role_arn.split(":")[4] if ":" in role_arn else "unknown"

            if error_code in ACCESS_DENIED_CODES:
                raise CrossAccountAccessError(
                    f"Cannot assume role {role_arn}: {e}",
                    account_id=account_id,
                ) from e

            raise CrossAccountAccessError(
                f"Failed to assume role {role_arn}: {e}",
                account_id=account_id,
            ) from e

    def clear_assumed_role_cache(self) -> None:
        """Clear the assumed role client cache."""
        self._assumed_role_clients.clear()


def detect_error_type(error: ClientError) -> Exception:
    """Convert boto3 ClientError to appropriate NetGraph exception.

    Args:
        error: The boto3 ClientError to analyze

    Returns:
        Appropriate NetGraph exception based on error code

    Raises:
        The original error if it doesn't match known patterns
    """
    response = error.response
    error_code = response.get("Error", {}).get("Code", "")
    error_message = response.get("Error", {}).get("Message", str(error))

    if error_code in ACCESS_DENIED_CODES:
        # Extract resource ID from message if possible
        resource_id = _extract_resource_id(error_message)
        operation = _extract_operation(error_message)
        return PermissionDeniedError(
            f"Access denied: {error_message}",
            resource_id=resource_id or "unknown",
            operation=operation or "unknown",
        )

    if error_code in NOT_FOUND_CODES:
        resource_id = _extract_resource_id(error_message)
        resource_type = _extract_resource_type(error_code)
        return ResourceNotFoundError(
            resource_id=resource_id or "unknown",
            resource_type=resource_type,
        )

    # Return original error if not a known type
    return error


def is_retryable_error(error: ClientError) -> bool:
    """Check if an error should trigger a retry.

    Args:
        error: The boto3 ClientError to check

    Returns:
        True if the error is retryable
    """
    error_code = error.response.get("Error", {}).get("Code", "")
    return error_code in RETRYABLE_CODES


async def retry_with_backoff(
    operation: Any,
    config: RetryConfig | None = None,
    operation_name: str = "AWS operation",
) -> Any:
    """Execute an operation with exponential backoff retry.

    Args:
        operation: Async callable to execute
        config: Retry configuration
        operation_name: Name for logging

    Returns:
        Result of the operation

    Raises:
        ClientError: If all retries are exhausted
    """
    if config is None:
        config = RetryConfig()

    delay = config.initial_delay
    last_error: ClientError | None = None

    for attempt in range(config.max_retries + 1):
        try:
            return await operation()
        except ClientError as e:
            last_error = e
            if not is_retryable_error(e):
                raise

            if attempt == config.max_retries:
                logger.error(f"{operation_name} failed after {config.max_retries + 1} attempts")
                raise

            # Calculate delay with optional jitter
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

            # Increase delay for next attempt
            delay = min(delay * config.multiplier, config.max_delay)

    # Should never reach here, but type checker needs it
    if last_error:
        raise last_error
    raise RuntimeError("Unexpected state in retry_with_backoff")


def _extract_resource_id(message: str) -> str | None:
    """Extract resource ID from error message."""
    import re

    # Common patterns for AWS resource IDs
    # Order matters: longer prefixes first to avoid partial matches
    # (e.g., 'eni-' must come before 'i-' to avoid 'eni-xxx' matching as 'i-xxx')
    patterns = [
        r"(eni-[a-f0-9]+)",  # Network Interface (before 'i-')
        r"(subnet-[a-f0-9]+)",  # Subnet
        r"(sg-[a-f0-9]+)",  # Security Group
        r"(acl-[a-f0-9]+)",  # NACL
        r"(rtb-[a-f0-9]+)",  # Route Table
        r"(igw-[a-f0-9]+)",  # Internet Gateway
        r"(nat-[a-f0-9]+)",  # NAT Gateway
        r"(pcx-[a-f0-9]+)",  # VPC Peering
        r"(pl-[a-f0-9]+)",  # Prefix List
        r"(vpc-[a-f0-9]+)",  # VPC
        r"(i-[a-f0-9]+)",  # Instance (last, to avoid matching 'eni-')
    ]

    for pattern in patterns:
        match = re.search(pattern, message)
        if match:
            return match.group(1)

    return None


def _extract_operation(message: str) -> str | None:
    """Extract operation name from error message."""
    import re

    # Look for operation name patterns
    match = re.search(r"operation: (\w+)", message, re.IGNORECASE)
    if match:
        return match.group(1)

    # Look for API action patterns
    match = re.search(r"action: (\w+)", message, re.IGNORECASE)
    if match:
        return match.group(1)

    return None


def _extract_resource_type(error_code: str) -> str:
    """Extract resource type from error code."""
    mappings = {
        "InvalidInstanceID": "instance",
        "InvalidSubnetID": "subnet",
        "InvalidSecurityGroupID": "security_group",
        "InvalidNetworkAclID": "nacl",
        "InvalidRouteTableID": "route_table",
        "InvalidInternetGatewayID": "internet_gateway",
        "InvalidNatGatewayID": "nat_gateway",
        "InvalidVpcPeeringConnectionID": "vpc_peering",
        "InvalidPrefixListId": "prefix_list",
        "InvalidNetworkInterfaceID": "network_interface",
        "InvalidVpcID": "vpc",
    }

    for prefix, resource_type in mappings.items():
        if error_code.startswith(prefix):
            return resource_type

    return "resource"
