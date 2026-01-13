"""Network ACL evaluation with stateless rule processing.

CRITICAL: NACLs are STATELESS. Unlike Security Groups, NACLs require
explicit rules for both inbound AND outbound traffic. This means:

1. Forward path: Check inbound rule at destination
2. Return path: Check outbound rule at destination for ephemeral ports

The return path verification catches scenarios where forward traffic
is allowed but return traffic is blocked, causing connection hangs.
"""

from typing import Literal

from netgraph.evaluators.cidr import CIDRMatcher
from netgraph.models.aws_resources import NACLRule, NetworkConstants
from netgraph.models.results import RuleEvalResult


class NACLEvaluator:
    """Evaluates Network ACL rules.

    NACL rules are processed in order by rule number (lowest first).
    The first matching rule wins, whether allow or deny.
    Rule number 32767 (*) is the implicit deny-all rule.
    """

    @staticmethod
    def evaluate(
        rules: list[NACLRule],
        direction: Literal["inbound", "outbound"],
        source_ip: str,
        dest_ip: str,
        port: int,
        protocol: str,
        nacl_id: str,
    ) -> RuleEvalResult:
        """Evaluate NACL rules for a specific traffic flow.

        Args:
            rules: List of NACL rules (will be sorted by rule number)
            direction: "inbound" or "outbound"
            source_ip: Source IP address
            dest_ip: Destination IP address
            port: Destination port number
            protocol: Protocol ("tcp", "udp", "icmp", or "-1" for all)
            nacl_id: NACL ID for result reporting

        Returns:
            RuleEvalResult indicating if traffic is allowed or denied.
        """
        # Filter rules by direction
        direction_rules = [r for r in rules if r.direction == direction]

        # Sort by rule number ascending (lowest first)
        direction_rules.sort(key=lambda r: r.rule_number)

        # Determine which IP to match based on direction
        # Inbound: match against source IP
        # Outbound: match against destination IP
        match_ip = source_ip if direction == "inbound" else dest_ip

        # Convert protocol string to NACL protocol number
        nacl_protocol = NACLEvaluator._normalize_protocol(protocol)

        for rule in direction_rules:
            if NACLEvaluator._rule_matches(rule, match_ip, port, nacl_protocol):
                if rule.rule_action == "allow":
                    return RuleEvalResult(
                        allowed=True,
                        matched_rule_id=f"rule-{rule.rule_number}",
                        resource_id=nacl_id,
                        resource_type="nacl",
                        direction=direction,
                        reason=f"NACL {nacl_id} rule {rule.rule_number} allows "
                        f"{protocol.upper()}/{port} from {source_ip}",
                    )
                else:  # deny
                    return RuleEvalResult(
                        allowed=False,
                        matched_rule_id=f"rule-{rule.rule_number}",
                        resource_id=nacl_id,
                        resource_type="nacl",
                        direction=direction,
                        reason=f"NACL {nacl_id} rule {rule.rule_number} denies "
                        f"{protocol.upper()}/{port} from {source_ip}",
                    )

        # No rule matched - implicit deny (rule *)
        return RuleEvalResult(
            allowed=False,
            matched_rule_id="rule-*",
            resource_id=nacl_id,
            resource_type="nacl",
            direction=direction,
            reason=f"NACL {nacl_id} implicit deny (no rule matches "
            f"{protocol.upper()}/{port} from {source_ip})",
        )

    @staticmethod
    def _rule_matches(
        rule: NACLRule,
        ip: str,
        port: int,
        protocol: str,
    ) -> bool:
        """Check if a NACL rule matches the given traffic parameters.

        Args:
            rule: NACL rule to check
            ip: IP address to match against rule's CIDR
            port: Port number to check
            protocol: Protocol number string ("-1", "6", "17", etc.)

        Returns:
            True if rule matches all parameters, False otherwise.
        """
        # Check protocol match
        if not NACLEvaluator._protocol_matches(rule.protocol, protocol):
            return False

        # Check CIDR match
        cidr = rule.effective_cidr
        if cidr is None:
            return False

        if not CIDRMatcher.matches(ip, cidr):
            return False

        # Check port match (if applicable)
        return NACLEvaluator._port_matches(rule, port, protocol)

    @staticmethod
    def _protocol_matches(rule_protocol: str, traffic_protocol: str) -> bool:
        """Check if NACL rule protocol matches traffic protocol.

        Args:
            rule_protocol: Protocol from NACL rule ("-1" for all, "6" for TCP, etc.)
            traffic_protocol: Protocol of the traffic

        Returns:
            True if protocols match, False otherwise.
        """
        # "-1" matches all protocols
        if rule_protocol == NetworkConstants.PROTO_ALL:
            return True
        if traffic_protocol == NetworkConstants.PROTO_ALL:
            return True

        return rule_protocol == traffic_protocol

    @staticmethod
    def _port_matches(rule: NACLRule, port: int, protocol: str) -> bool:
        """Check if port matches NACL rule's port range.

        Args:
            rule: NACL rule with from_port/to_port
            port: Port to check
            protocol: Protocol string

        Returns:
            True if port matches, False otherwise.
        """
        # All traffic rule (-1) matches any port
        if rule.protocol == NetworkConstants.PROTO_ALL:
            return True

        # ICMP doesn't use ports in the traditional sense
        if protocol in (NetworkConstants.PROTO_ICMP, NetworkConstants.PROTO_ICMPV6):
            return True

        # No port range specified = all ports
        if rule.from_port is None or rule.to_port is None:
            return True

        return rule.from_port <= port <= rule.to_port

    @staticmethod
    def _normalize_protocol(protocol: str) -> str:
        """Convert protocol name to NACL protocol number.

        Args:
            protocol: Protocol name or number ("tcp", "udp", "icmp", "-1", "6", etc.)

        Returns:
            Protocol number string as used in NACL rules.
        """
        protocol = protocol.lower()
        protocol_map = {
            "tcp": NetworkConstants.PROTO_TCP,
            "udp": NetworkConstants.PROTO_UDP,
            "icmp": NetworkConstants.PROTO_ICMP,
            "icmpv6": NetworkConstants.PROTO_ICMPV6,
            "all": NetworkConstants.PROTO_ALL,
            "-1": NetworkConstants.PROTO_ALL,
        }
        return protocol_map.get(protocol, protocol)


def evaluate_nacl_return_path(
    rules: list[NACLRule],
    source_ip: str,
    dest_ip: str,
    protocol: str,
    nacl_id: str,
) -> RuleEvalResult:
    """Evaluate NACL for return traffic on ephemeral ports.

    CRITICAL: This catches the "stateless return" bug where:
    - Forward traffic is allowed (e.g., inbound TCP/443)
    - Return traffic is blocked because outbound NACL doesn't allow
      ephemeral ports (1024-65535) back to the source

    This causes TCP connections to hang because SYN-ACK can't return.

    Args:
        rules: List of NACL rules
        source_ip: Original source IP (return traffic destination)
        dest_ip: Original destination IP (return traffic source)
        protocol: Protocol ("tcp" or "udp")
        nacl_id: NACL ID for result reporting

    Returns:
        RuleEvalResult indicating if return traffic is allowed.
    """
    # For TCP/UDP, return traffic uses ephemeral ports
    normalized_protocol = NACLEvaluator._normalize_protocol(protocol)

    if normalized_protocol not in (
        NetworkConstants.PROTO_TCP,
        NetworkConstants.PROTO_UDP,
    ):
        # ICMP and other protocols don't need ephemeral port check
        return RuleEvalResult(
            allowed=True,
            resource_id=nacl_id,
            resource_type="nacl",
            direction="return",
            reason=f"Protocol {protocol} does not require ephemeral port verification",
        )

    # Check if outbound NACL allows traffic to source on ephemeral port range
    # We check both ends of the ephemeral range to ensure coverage
    ephemeral_min = NetworkConstants.EPHEMERAL_PORT_MIN
    ephemeral_max = NetworkConstants.EPHEMERAL_PORT_MAX

    # Check if the NACL allows ANY ephemeral port (check representative ports)
    # We check min, max, and a mid-point to catch partial ranges
    test_ports = [ephemeral_min, (ephemeral_min + ephemeral_max) // 2, ephemeral_max]

    for test_port in test_ports:
        result = NACLEvaluator.evaluate(
            rules=rules,
            direction="outbound",
            source_ip=dest_ip,  # Return traffic originates from original dest
            dest_ip=source_ip,  # Return traffic goes to original source
            port=test_port,
            protocol=protocol,
            nacl_id=nacl_id,
        )

        if result.allowed:
            return RuleEvalResult(
                allowed=True,
                matched_rule_id=result.matched_rule_id,
                resource_id=nacl_id,
                resource_type="nacl",
                direction="return",
                reason=f"NACL {nacl_id} allows return traffic on ephemeral ports "
                f"({ephemeral_min}-{ephemeral_max}) to {source_ip}",
            )

    # No rule allows ephemeral port return traffic
    return RuleEvalResult(
        allowed=False,
        resource_id=nacl_id,
        resource_type="nacl",
        direction="return",
        reason=f"NACL {nacl_id} blocks return traffic on ephemeral ports "
        f"({ephemeral_min}-{ephemeral_max}) to {source_ip}. "
        f"TCP/UDP connections will hang.",
    )
