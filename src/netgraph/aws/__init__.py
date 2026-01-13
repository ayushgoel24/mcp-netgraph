"""AWS client abstractions for NetGraph.

This module provides the AWS client layer with:
- AWSClientProtocol: Interface for EC2 operations
- AWSClientFactory: Creates clients with credential chain
- Exponential backoff retry for rate limiting
- Auto-pagination on all describe_* operations
"""

from netgraph.aws.client import AWSClient, AWSClientFactory
from netgraph.aws.fetcher import EC2Fetcher

__all__ = [
    "AWSClient",
    "AWSClientFactory",
    "EC2Fetcher",
]
