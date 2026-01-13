"""Data models for NetGraph."""

from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network

from netgraph.models.aws_resources import (
    ManagedPrefixList,
    NACLRule,
    NetworkACL,
    NetworkConstants,
    Route,
    RouteTable,
    SecurityGroup,
    SGRule,
)
from netgraph.models.graph import (
    EdgeType,
    ENIAttributes,
    GatewayAttributes,
    GraphEdge,
    GraphNode,
    InstanceAttributes,
    NodeType,
    SubnetAttributes,
)
from netgraph.models.results import (
    CacheStats,
    DiscoveredResource,
    ExposedResource,
    HopResult,
    PathAnalysisResult,
    PathStatus,
    PublicExposureResult,
    ResourceDiscoveryResult,
    RuleEvalResult,
    TopologyRefreshResult,
)

# Type aliases for dual-stack support
IPAddress = IPv4Address | IPv6Address
IPNetwork = IPv4Network | IPv6Network

__all__ = [
    # Stdlib re-exports
    "IPv4Address",
    "IPv4Network",
    "IPv6Address",
    "IPv6Network",
    # Type aliases
    "IPAddress",
    "IPNetwork",
    # Graph models
    "EdgeType",
    "ENIAttributes",
    "GatewayAttributes",
    "GraphEdge",
    "GraphNode",
    "InstanceAttributes",
    "NodeType",
    "SubnetAttributes",
    # AWS resource models
    "ManagedPrefixList",
    "NACLRule",
    "NetworkACL",
    "NetworkConstants",
    "Route",
    "RouteTable",
    "SGRule",
    "SecurityGroup",
    # Result models
    "CacheStats",
    "DiscoveredResource",
    "ExposedResource",
    "HopResult",
    "PathAnalysisResult",
    "PathStatus",
    "PublicExposureResult",
    "ResourceDiscoveryResult",
    "RuleEvalResult",
    "TopologyRefreshResult",
]
