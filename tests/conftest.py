"""Pytest configuration and shared fixtures for NetGraph tests."""

from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network

import pytest

from netgraph.utils.logging import setup_logging


def pytest_configure(config: pytest.Config) -> None:  # noqa: ARG001
    """Configure pytest environment."""
    # Set up logging for tests
    setup_logging(level="DEBUG")


# =============================================================================
# IP Address Fixtures
# =============================================================================


@pytest.fixture
def ipv4_address() -> IPv4Address:
    """Sample IPv4 address."""
    return IPv4Address("10.0.1.50")


@pytest.fixture
def ipv4_public() -> IPv4Address:
    """Sample public IPv4 address."""
    return IPv4Address("8.8.8.8")


@pytest.fixture
def ipv6_address() -> IPv6Address:
    """Sample IPv6 address."""
    return IPv6Address("2001:db8::1")


@pytest.fixture
def ipv4_network() -> IPv4Network:
    """Sample IPv4 network."""
    return IPv4Network("10.0.0.0/16")


@pytest.fixture
def ipv6_network() -> IPv6Network:
    """Sample IPv6 network."""
    return IPv6Network("2001:db8::/32")


# =============================================================================
# AWS Resource ID Fixtures
# =============================================================================


@pytest.fixture
def vpc_id() -> str:
    """Sample VPC ID."""
    return "vpc-12345678"


@pytest.fixture
def subnet_id() -> str:
    """Sample subnet ID."""
    return "subnet-12345678"


@pytest.fixture
def instance_id() -> str:
    """Sample EC2 instance ID."""
    return "i-1234567890abcdef0"


@pytest.fixture
def eni_id() -> str:
    """Sample ENI ID."""
    return "eni-12345678"


@pytest.fixture
def security_group_id() -> str:
    """Sample Security Group ID."""
    return "sg-12345678"


@pytest.fixture
def nacl_id() -> str:
    """Sample Network ACL ID."""
    return "acl-12345678"


@pytest.fixture
def route_table_id() -> str:
    """Sample Route Table ID."""
    return "rtb-12345678"


@pytest.fixture
def igw_id() -> str:
    """Sample Internet Gateway ID."""
    return "igw-12345678"


@pytest.fixture
def nat_id() -> str:
    """Sample NAT Gateway ID."""
    return "nat-12345678"


@pytest.fixture
def peering_id() -> str:
    """Sample VPC Peering Connection ID."""
    return "pcx-12345678"


@pytest.fixture
def prefix_list_id() -> str:
    """Sample Managed Prefix List ID."""
    return "pl-12345678"


# =============================================================================
# AWS Account Fixtures
# =============================================================================


@pytest.fixture
def aws_account_id() -> str:
    """Sample AWS account ID."""
    return "123456789012"


@pytest.fixture
def aws_region() -> str:
    """Sample AWS region."""
    return "us-east-1"
