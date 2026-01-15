"""Result models for path analysis, discovery, and exposure detection."""

from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field

from netgraph.models.graph import NodeType


class PathStatus(str, Enum):
    """Result status for path analysis.

    UNKNOWN is used when we cannot determine reachability due to
    permission failures, cross-account access issues, etc.
    """

    REACHABLE = "reachable"
    BLOCKED = "blocked"
    UNKNOWN = "unknown"


class RuleEvalResult(BaseModel):
    """Result of evaluating a single rule set."""

    allowed: bool
    matched_rule_id: str | None = None
    resource_id: str  # SG or NACL ID
    resource_type: Literal["security_group", "nacl", "route_table"]
    direction: Literal["inbound", "outbound", "return"] | None = None
    reason: str  # Human-readable explanation

    # For prefix list rules, include resolved CIDRs
    resolved_prefix_list: str | None = None


class HopResult(BaseModel):
    """Result of traversing a single hop in the path."""

    hop_number: int
    node_id: str
    node_type: NodeType
    sg_eval: RuleEvalResult | None = None
    nacl_eval: RuleEvalResult | None = None
    route_eval: RuleEvalResult | None = None
    status: PathStatus = PathStatus.REACHABLE

    @property
    def blocking_reason(self) -> str | None:
        """Get the reason if this hop blocked traffic."""
        if self.status == PathStatus.REACHABLE:
            return None
        for eval_result in [self.sg_eval, self.nacl_eval, self.route_eval]:
            if eval_result and not eval_result.allowed:
                return eval_result.reason
        return "Unknown blocking reason"


class PathAnalysisResult(BaseModel):
    """Complete result of path analysis."""

    status: PathStatus  # REACHABLE, BLOCKED, or UNKNOWN
    source_id: str
    destination_ip: str
    port: int
    protocol: str

    hops: list[HopResult] = Field(default_factory=list)
    blocked_at: HopResult | None = None

    # For UNKNOWN status
    unknown_reason: str | None = Field(
        None,
        description="Explanation when status is UNKNOWN (e.g., permission denied)",
    )

    # Reverse path verification (Principal Engineer Fix)
    return_route_verified: bool = Field(
        False,
        description="True if destination subnet has valid route back to source IP. "
        "False indicates asymmetric routing risk.",
    )
    return_route_table_id: str | None = Field(
        None, description="Route table ID used for return path verification"
    )

    # Human-readable summary
    summary: str = ""
    technical_details: str = ""

    # For debugging
    evaluated_security_groups: list[str] = Field(default_factory=list)
    evaluated_nacls: list[str] = Field(default_factory=list)
    route_path: list[str] = Field(default_factory=list)  # List of route table IDs

    def generate_human_summary(self) -> str:
        """Generate an LLM-friendly summary of the path analysis.

        Returns a concise human-readable string suitable for summarizing
        complex multi-hop paths without hallucination risk.

        Example outputs:
        - "Traffic Allowed. Path follows 3 hops: Eni -> Peering -> Instance.
           Note: Return traffic relies on Route Table rtb-12345."
        - "Traffic Blocked at Security Group sg-abc123. Reason..."
        - "Cannot determine reachability. Access denied to subnet-xyz."
        """
        if self.status == PathStatus.REACHABLE:
            hop_summary = (
                " -> ".join(hop.node_type.value.title() for hop in self.hops)
                if self.hops
                else "Direct"
            )

            base = f"Traffic Allowed. Path follows {len(self.hops)} hops: {hop_summary}."

            if self.return_route_verified and self.return_route_table_id:
                base += f" Note: Return traffic relies on Route Table {self.return_route_table_id}."

            return base

        elif self.status == PathStatus.BLOCKED:
            if self.blocked_at:
                blocking_resource = self.blocked_at.node_id
                blocking_type = self.blocked_at.node_type.value
                reason = self.blocked_at.blocking_reason or "Unknown reason"
                return f"Traffic Blocked at {blocking_type} {blocking_resource}. {reason}"
            return f"Traffic Blocked. {self.summary}"

        else:  # UNKNOWN
            return f"Cannot determine reachability. {self.unknown_reason or self.summary}"


class DiscoveredResource(BaseModel):
    """A resource found via discovery search."""

    id: str  # Resource ID
    resource_type: NodeType
    resource_arn: str = ""
    name: str | None = None
    tags: dict[str, str] = Field(default_factory=dict)
    vpc_id: str | None = None
    subnet_id: str | None = None
    availability_zone: str | None = None
    private_ip: str | None = None
    public_ip: str | None = None


class ResourceDiscoveryResult(BaseModel):
    """Result of resource discovery search."""

    vpc_id: str
    resources: list[DiscoveredResource]
    total_found: int
    truncated: bool = Field(False, description="True if more results exist beyond the limit")
    filters_applied: dict[str, str | list[str] | None] = Field(
        default_factory=dict, description="The search filters that were applied"
    )


class ExposedResource(BaseModel):
    """A resource exposed to the public internet."""

    resource_id: str
    resource_type: NodeType
    resource_arn: str = ""

    # Resource identification
    name: str | None = None
    private_ip: str | None = None
    public_ip: str | None = None

    exposure_type: Literal["direct", "indirect"]
    exposure_path: list[str]  # Node IDs from resource to IGW

    open_port: int
    protocol: str

    # Rules that allow the traffic
    allowing_sg_rule_id: str | None = None  # Deprecated, use allowing_rules
    allowing_rules: list[str] = Field(default_factory=list)

    severity: Literal["critical", "high", "medium", "low"]
    remediation: str


class PublicExposureResult(BaseModel):
    """Result of public exposure scan."""

    vpc_id: str
    port: int
    protocol: str
    total_exposed: int

    exposed_resources: list[ExposedResource]

    # Scan metrics
    total_resources_scanned: int = 0
    scan_duration_seconds: float = 0.0

    summary: str = ""
    high_severity_count: int = 0
    critical_severity_count: int = 0


class TopologyRefreshResult(BaseModel):
    """Result of topology refresh operation."""

    success: bool
    vpc_ids_processed: list[str]
    vpc_ids_failed: list[str] = Field(default_factory=list)

    node_count: int
    edge_count: int

    resources_by_type: dict[str, int] = Field(default_factory=dict)
    # e.g., {"instances": 50, "enis": 75, "subnets": 10, "igws": 1}

    duration_seconds: float
    warnings: list[str] = Field(default_factory=list)


class CacheStats(BaseModel):
    """Statistics for the graph cache."""

    hits: int
    misses: int
    expired: int  # Count of entries that were stale (TTL exceeded)
    size: int
    oldest_entry: datetime | None = None
    ttl_seconds: int  # Current TTL configuration
    entries_expiring_soon: int = Field(0, description="Entries expiring within 10 seconds")
