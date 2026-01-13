"""Security Group evaluation with prefix list support.

IMPORTANT: Security Groups are STATEFUL. Unlike NACLs, you only need to
check the initiated traffic direction:
- For outbound traffic: check egress rules at source
- For inbound traffic: check ingress rules at destination

Return traffic is automatically allowed by AWS.
"""

from typing import Literal, Protocol, runtime_checkable

from netgraph.evaluators.cidr import CIDRMatcher
from netgraph.models.aws_resources import SecurityGroup, SGRule
from netgraph.models.errors import PrefixListResolutionError
from netgraph.models.results import RuleEvalResult


@runtime_checkable
class PrefixListResolver(Protocol):
    """Protocol for resolving prefix list CIDRs."""

    async def get_prefix_list_cidrs(self, prefix_list_id: str) -> list[str]:
        """Resolve a prefix list ID to its CIDR entries."""
        ...


@runtime_checkable
class SGReferenceResolver(Protocol):
    """Protocol for resolving security group references."""

    async def get_eni_security_groups(self, eni_id: str) -> list[str]:
        """Get security group IDs attached to an ENI."""
        ...


class SecurityGroupEvaluator:
    """Evaluates Security Group rules.

    Security Groups are stateful - only check the initiated direction.
    Multiple SGs can be attached - any allow = allowed (OR logic).
    """

    @staticmethod
    async def evaluate_egress(
        security_groups: list[SecurityGroup],
        dest_ip: str,
        port: int,
        protocol: str,
        prefix_resolver: PrefixListResolver | None = None,
    ) -> RuleEvalResult:
        """Evaluate outbound traffic against Security Group egress rules.

        Args:
            security_groups: List of Security Groups attached to the source
            dest_ip: Destination IP address
            port: Destination port number
            protocol: Protocol ("tcp", "udp", "icmp", or "-1" for all)
            prefix_resolver: Optional resolver for prefix lists

        Returns:
            RuleEvalResult indicating if traffic is allowed.
        """
        return await SecurityGroupEvaluator._evaluate(
            security_groups=security_groups,
            ip=dest_ip,
            port=port,
            protocol=protocol,
            direction="outbound",
            prefix_resolver=prefix_resolver,
        )

    @staticmethod
    async def evaluate_ingress(
        security_groups: list[SecurityGroup],
        source_ip: str,
        port: int,
        protocol: str,
        prefix_resolver: PrefixListResolver | None = None,
    ) -> RuleEvalResult:
        """Evaluate inbound traffic against Security Group ingress rules.

        Args:
            security_groups: List of Security Groups attached to the destination
            source_ip: Source IP address
            port: Destination port number
            protocol: Protocol ("tcp", "udp", "icmp", or "-1" for all)
            prefix_resolver: Optional resolver for prefix lists

        Returns:
            RuleEvalResult indicating if traffic is allowed.
        """
        return await SecurityGroupEvaluator._evaluate(
            security_groups=security_groups,
            ip=source_ip,
            port=port,
            protocol=protocol,
            direction="inbound",
            prefix_resolver=prefix_resolver,
        )

    @staticmethod
    async def _evaluate(
        security_groups: list[SecurityGroup],
        ip: str,
        port: int,
        protocol: str,
        direction: Literal["inbound", "outbound"],
        prefix_resolver: PrefixListResolver | None = None,
    ) -> RuleEvalResult:
        """Core evaluation logic for Security Groups.

        Multiple Security Groups use OR logic - if any SG allows,
        traffic is allowed.
        """
        if not security_groups:
            return RuleEvalResult(
                allowed=False,
                resource_id="none",
                resource_type="security_group",
                direction=direction,
                reason="No security groups attached",
            )

        # Normalize protocol
        protocol = SecurityGroupEvaluator._normalize_protocol(protocol)

        # Track all SG IDs for error reporting
        sg_ids = [sg.sg_id for sg in security_groups]

        # Check each security group - any allow = allowed
        for sg in security_groups:
            rules = sg.outbound_rules if direction == "outbound" else sg.inbound_rules

            for rule in rules:
                match_result = await SecurityGroupEvaluator._rule_matches(
                    rule=rule,
                    ip=ip,
                    port=port,
                    protocol=protocol,
                    prefix_resolver=prefix_resolver,
                )

                if match_result.matches:
                    direction_text = "to" if direction == "outbound" else "from"
                    return RuleEvalResult(
                        allowed=True,
                        matched_rule_id=rule.rule_id,
                        resource_id=sg.sg_id,
                        resource_type="security_group",
                        direction=direction,
                        reason=f"Security Group {sg.sg_id} allows "
                        f"{protocol.upper()}/{port} {direction_text} {ip}",
                        resolved_prefix_list=match_result.resolved_prefix_list,
                    )

        # No rule in any SG allowed - implicit deny
        direction_text = "to" if direction == "outbound" else "from"
        return RuleEvalResult(
            allowed=False,
            resource_id=",".join(sg_ids),
            resource_type="security_group",
            direction=direction,
            reason=f"No rule allows {protocol.upper()}/{port} {direction_text} {ip} "
            f"in security groups: {', '.join(sg_ids)}",
        )

    @staticmethod
    async def _rule_matches(
        rule: SGRule,
        ip: str,
        port: int,
        protocol: str,
        prefix_resolver: PrefixListResolver | None = None,
    ) -> "MatchResult":
        """Check if a Security Group rule matches the traffic.

        Returns a MatchResult with match status and any resolved prefix list.
        """
        # Check protocol match
        if not SecurityGroupEvaluator._protocol_matches(rule.ip_protocol, protocol):
            return MatchResult(matches=False)

        # Check port match
        if not rule.matches_port(port):
            return MatchResult(matches=False)

        # Check IP match - this is where prefix lists come in
        ip_match_result = await SecurityGroupEvaluator._ip_matches(
            rule=rule,
            ip=ip,
            prefix_resolver=prefix_resolver,
        )

        return ip_match_result

    @staticmethod
    async def _ip_matches(
        rule: SGRule,
        ip: str,
        prefix_resolver: PrefixListResolver | None = None,
    ) -> "MatchResult":
        """Check if IP matches the rule's source/destination.

        Handles:
        - Direct IPv4 CIDR
        - Direct IPv6 CIDR
        - Managed Prefix Lists (pl-xxx)
        - Security Group references (sg-xxx) - not IP-based, skip
        """
        # Direct IPv4 CIDR match
        if rule.cidr_ipv4:
            if CIDRMatcher.matches(ip, rule.cidr_ipv4):
                return MatchResult(matches=True)
            return MatchResult(matches=False)

        # Direct IPv6 CIDR match
        if rule.cidr_ipv6:
            if CIDRMatcher.matches(ip, rule.cidr_ipv6):
                return MatchResult(matches=True)
            return MatchResult(matches=False)

        # Prefix list resolution
        if rule.prefix_list_id:
            if prefix_resolver is None:
                # Can't resolve without a resolver - treat as no match
                # In production, this should probably raise or return UNKNOWN
                return MatchResult(matches=False)

            try:
                cidrs = await prefix_resolver.get_prefix_list_cidrs(rule.prefix_list_id)
                if CIDRMatcher.matches_any(ip, cidrs):
                    return MatchResult(
                        matches=True,
                        resolved_prefix_list=rule.prefix_list_id,
                    )
                return MatchResult(matches=False)
            except PrefixListResolutionError:
                # Can't resolve prefix list - treat as no match
                return MatchResult(matches=False)

        # SG-to-SG reference - these don't match by IP
        # The actual instances behind the referenced SG need different handling
        if rule.referenced_sg_id:
            # SG references don't match by IP address
            # This requires checking if source/dest ENI has the referenced SG attached
            return MatchResult(matches=False)

        return MatchResult(matches=False)

    @staticmethod
    def _protocol_matches(rule_protocol: str, traffic_protocol: str) -> bool:
        """Check if Security Group rule protocol matches traffic protocol."""
        rule_protocol = rule_protocol.lower()
        traffic_protocol = traffic_protocol.lower()

        # "-1" matches all protocols
        if rule_protocol == "-1":
            return True
        if traffic_protocol == "-1":
            return True

        return rule_protocol == traffic_protocol

    @staticmethod
    def _normalize_protocol(protocol: str) -> str:
        """Normalize protocol to lowercase string."""
        return protocol.lower()


class MatchResult:
    """Result of a rule match check."""

    def __init__(
        self,
        matches: bool,
        resolved_prefix_list: str | None = None,
    ) -> None:
        self.matches = matches
        self.resolved_prefix_list = resolved_prefix_list


async def evaluate_sg_reference(
    rule: SGRule,
    source_sg_ids: list[str],
    sg_resolver: SGReferenceResolver | None = None,
) -> RuleEvalResult | None:
    """Evaluate Security Group-to-Security Group reference rules.

    SG-to-SG rules allow traffic from/to instances that have the
    referenced security group attached.

    Args:
        rule: SGRule with referenced_sg_id
        source_sg_ids: Security groups attached to the source/destination
        sg_resolver: Optional resolver for cross-account SG references

    Returns:
        RuleEvalResult if the rule applies, None otherwise.

    Raises:
        CrossAccountSGResolutionError: If cross-account resolution fails.
    """
    if not rule.referenced_sg_id:
        return None

    # Check if source has the referenced SG attached
    if rule.referenced_sg_id in source_sg_ids:
        return RuleEvalResult(
            allowed=True,
            matched_rule_id=rule.rule_id,
            resource_id=rule.referenced_sg_id,
            resource_type="security_group",
            reason=f"Traffic allowed via SG reference to {rule.referenced_sg_id}",
        )

    # Cross-account SG reference - would need resolution
    # For now, return None (no match) if we can't resolve
    if sg_resolver is not None:
        # Future: implement cross-account resolution
        # If resolution fails, should raise CrossAccountSGResolutionError
        # which caller converts to PathStatus.UNKNOWN
        pass

    return None
