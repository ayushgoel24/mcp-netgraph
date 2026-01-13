"""Tests for NACLEvaluator and return path verification."""

from netgraph.evaluators.nacl import NACLEvaluator, evaluate_nacl_return_path
from netgraph.models.aws_resources import NACLRule


class TestNACLEvaluatorRuleOrdering:
    """Tests for NACL rule ordering - lowest rule number wins."""

    def test_lowest_rule_number_wins(self) -> None:
        """Rule with lowest number is evaluated first."""
        rules = [
            NACLRule(
                rule_number=200,
                protocol="6",  # TCP
                rule_action="deny",
                direction="inbound",
                cidr_block="10.0.0.0/8",
                from_port=443,
                to_port=443,
            ),
            NACLRule(
                rule_number=100,
                protocol="6",
                rule_action="allow",
                direction="inbound",
                cidr_block="10.0.0.0/8",
                from_port=443,
                to_port=443,
            ),
        ]

        result = NACLEvaluator.evaluate(
            rules=rules,
            direction="inbound",
            source_ip="10.0.1.50",
            dest_ip="10.0.2.100",
            port=443,
            protocol="tcp",
            nacl_id="acl-12345",
        )

        assert result.allowed is True
        assert result.matched_rule_id == "rule-100"

    def test_deny_before_allow(self) -> None:
        """Deny rule with lower number blocks before allow can match."""
        rules = [
            NACLRule(
                rule_number=50,
                protocol="6",
                rule_action="deny",
                direction="inbound",
                cidr_block="10.0.1.0/24",
                from_port=443,
                to_port=443,
            ),
            NACLRule(
                rule_number=100,
                protocol="6",
                rule_action="allow",
                direction="inbound",
                cidr_block="10.0.0.0/8",
                from_port=443,
                to_port=443,
            ),
        ]

        result = NACLEvaluator.evaluate(
            rules=rules,
            direction="inbound",
            source_ip="10.0.1.50",
            dest_ip="10.0.2.100",
            port=443,
            protocol="tcp",
            nacl_id="acl-12345",
        )

        assert result.allowed is False
        assert result.matched_rule_id == "rule-50"
        assert "denies" in result.reason

    def test_unsorted_rules_still_match_correctly(self) -> None:
        """Rules provided out of order still evaluate in correct order."""
        rules = [
            NACLRule(
                rule_number=300,
                protocol="6",
                rule_action="allow",
                direction="inbound",
                cidr_block="0.0.0.0/0",
                from_port=443,
                to_port=443,
            ),
            NACLRule(
                rule_number=100,
                protocol="6",
                rule_action="deny",
                direction="inbound",
                cidr_block="10.0.0.0/8",
                from_port=443,
                to_port=443,
            ),
            NACLRule(
                rule_number=200,
                protocol="6",
                rule_action="allow",
                direction="inbound",
                cidr_block="192.168.0.0/16",
                from_port=443,
                to_port=443,
            ),
        ]

        # IP in 10.0.0.0/8 should hit rule 100 (deny) first
        result = NACLEvaluator.evaluate(
            rules=rules,
            direction="inbound",
            source_ip="10.0.1.50",
            dest_ip="10.0.2.100",
            port=443,
            protocol="tcp",
            nacl_id="acl-12345",
        )

        assert result.allowed is False
        assert result.matched_rule_id == "rule-100"


class TestNACLEvaluatorImplicitDeny:
    """Tests for implicit deny when no rule matches."""

    def test_implicit_deny_no_matching_rules(self) -> None:
        """Implicit deny (*) when no rules match."""
        rules = [
            NACLRule(
                rule_number=100,
                protocol="6",
                rule_action="allow",
                direction="inbound",
                cidr_block="10.0.0.0/8",
                from_port=80,
                to_port=80,
            ),
        ]

        # Different port - no match
        result = NACLEvaluator.evaluate(
            rules=rules,
            direction="inbound",
            source_ip="10.0.1.50",
            dest_ip="10.0.2.100",
            port=443,
            protocol="tcp",
            nacl_id="acl-12345",
        )

        assert result.allowed is False
        assert result.matched_rule_id == "rule-*"
        assert "implicit deny" in result.reason

    def test_implicit_deny_wrong_protocol(self) -> None:
        """Implicit deny when protocol doesn't match."""
        rules = [
            NACLRule(
                rule_number=100,
                protocol="6",  # TCP only
                rule_action="allow",
                direction="inbound",
                cidr_block="0.0.0.0/0",
                from_port=443,
                to_port=443,
            ),
        ]

        result = NACLEvaluator.evaluate(
            rules=rules,
            direction="inbound",
            source_ip="10.0.1.50",
            dest_ip="10.0.2.100",
            port=443,
            protocol="udp",
            nacl_id="acl-12345",
        )

        assert result.allowed is False
        assert result.matched_rule_id == "rule-*"

    def test_implicit_deny_wrong_direction(self) -> None:
        """Implicit deny when only opposite direction rules exist."""
        rules = [
            NACLRule(
                rule_number=100,
                protocol="6",
                rule_action="allow",
                direction="outbound",
                cidr_block="0.0.0.0/0",
                from_port=443,
                to_port=443,
            ),
        ]

        result = NACLEvaluator.evaluate(
            rules=rules,
            direction="inbound",
            source_ip="10.0.1.50",
            dest_ip="10.0.2.100",
            port=443,
            protocol="tcp",
            nacl_id="acl-12345",
        )

        assert result.allowed is False
        assert result.matched_rule_id == "rule-*"

    def test_implicit_deny_cidr_mismatch(self) -> None:
        """Implicit deny when source IP not in any CIDR."""
        rules = [
            NACLRule(
                rule_number=100,
                protocol="6",
                rule_action="allow",
                direction="inbound",
                cidr_block="192.168.0.0/16",
                from_port=443,
                to_port=443,
            ),
        ]

        result = NACLEvaluator.evaluate(
            rules=rules,
            direction="inbound",
            source_ip="10.0.1.50",  # Not in 192.168.0.0/16
            dest_ip="192.168.1.100",
            port=443,
            protocol="tcp",
            nacl_id="acl-12345",
        )

        assert result.allowed is False


class TestNACLEvaluatorIPv6:
    """Tests for IPv6 rule evaluation."""

    def test_ipv6_rule_matches(self) -> None:
        """IPv6 CIDR rule matches IPv6 address."""
        rules = [
            NACLRule(
                rule_number=100,
                protocol="6",
                rule_action="allow",
                direction="inbound",
                ipv6_cidr_block="2001:db8::/32",
                from_port=443,
                to_port=443,
            ),
        ]

        result = NACLEvaluator.evaluate(
            rules=rules,
            direction="inbound",
            source_ip="2001:db8::1",
            dest_ip="2001:db8::2",
            port=443,
            protocol="tcp",
            nacl_id="acl-12345",
        )

        assert result.allowed is True
        assert result.matched_rule_id == "rule-100"

    def test_ipv6_default_route(self) -> None:
        """IPv6 default route ::/0 matches any IPv6."""
        rules = [
            NACLRule(
                rule_number=100,
                protocol="6",
                rule_action="allow",
                direction="inbound",
                ipv6_cidr_block="::/0",
                from_port=443,
                to_port=443,
            ),
        ]

        result = NACLEvaluator.evaluate(
            rules=rules,
            direction="inbound",
            source_ip="2001:db8:abcd::1",
            dest_ip="2001:db8::2",
            port=443,
            protocol="tcp",
            nacl_id="acl-12345",
        )

        assert result.allowed is True

    def test_ipv4_does_not_match_ipv6_rule(self) -> None:
        """IPv4 address should not match IPv6 rule."""
        rules = [
            NACLRule(
                rule_number=100,
                protocol="6",
                rule_action="allow",
                direction="inbound",
                ipv6_cidr_block="2001:db8::/32",
                from_port=443,
                to_port=443,
            ),
        ]

        result = NACLEvaluator.evaluate(
            rules=rules,
            direction="inbound",
            source_ip="10.0.1.50",
            dest_ip="10.0.2.100",
            port=443,
            protocol="tcp",
            nacl_id="acl-12345",
        )

        assert result.allowed is False


class TestNACLEvaluatorPortRanges:
    """Tests for port range matching."""

    def test_port_in_range(self) -> None:
        """Port within range is matched."""
        rules = [
            NACLRule(
                rule_number=100,
                protocol="6",
                rule_action="allow",
                direction="inbound",
                cidr_block="0.0.0.0/0",
                from_port=1024,
                to_port=65535,
            ),
        ]

        result = NACLEvaluator.evaluate(
            rules=rules,
            direction="inbound",
            source_ip="10.0.1.50",
            dest_ip="10.0.2.100",
            port=8080,
            protocol="tcp",
            nacl_id="acl-12345",
        )

        assert result.allowed is True

    def test_port_below_range(self) -> None:
        """Port below range is not matched."""
        rules = [
            NACLRule(
                rule_number=100,
                protocol="6",
                rule_action="allow",
                direction="inbound",
                cidr_block="0.0.0.0/0",
                from_port=1024,
                to_port=65535,
            ),
        ]

        result = NACLEvaluator.evaluate(
            rules=rules,
            direction="inbound",
            source_ip="10.0.1.50",
            dest_ip="10.0.2.100",
            port=443,  # Below ephemeral range
            protocol="tcp",
            nacl_id="acl-12345",
        )

        assert result.allowed is False

    def test_all_traffic_rule_matches_any_port(self) -> None:
        """Protocol -1 (all) matches any port."""
        rules = [
            NACLRule(
                rule_number=100,
                protocol="-1",
                rule_action="allow",
                direction="inbound",
                cidr_block="0.0.0.0/0",
            ),
        ]

        result = NACLEvaluator.evaluate(
            rules=rules,
            direction="inbound",
            source_ip="10.0.1.50",
            dest_ip="10.0.2.100",
            port=443,
            protocol="tcp",
            nacl_id="acl-12345",
        )

        assert result.allowed is True


class TestNACLEvaluatorProtocols:
    """Tests for protocol matching."""

    def test_tcp_protocol_number(self) -> None:
        """TCP (protocol 6) matches tcp string."""
        rules = [
            NACLRule(
                rule_number=100,
                protocol="6",
                rule_action="allow",
                direction="inbound",
                cidr_block="0.0.0.0/0",
                from_port=443,
                to_port=443,
            ),
        ]

        result = NACLEvaluator.evaluate(
            rules=rules,
            direction="inbound",
            source_ip="10.0.1.50",
            dest_ip="10.0.2.100",
            port=443,
            protocol="tcp",
            nacl_id="acl-12345",
        )

        assert result.allowed is True

    def test_udp_protocol_number(self) -> None:
        """UDP (protocol 17) matches udp string."""
        rules = [
            NACLRule(
                rule_number=100,
                protocol="17",
                rule_action="allow",
                direction="inbound",
                cidr_block="0.0.0.0/0",
                from_port=53,
                to_port=53,
            ),
        ]

        result = NACLEvaluator.evaluate(
            rules=rules,
            direction="inbound",
            source_ip="10.0.1.50",
            dest_ip="10.0.2.100",
            port=53,
            protocol="udp",
            nacl_id="acl-12345",
        )

        assert result.allowed is True

    def test_icmp_no_port_check(self) -> None:
        """ICMP doesn't check port numbers."""
        rules = [
            NACLRule(
                rule_number=100,
                protocol="1",  # ICMP
                rule_action="allow",
                direction="inbound",
                cidr_block="0.0.0.0/0",
            ),
        ]

        result = NACLEvaluator.evaluate(
            rules=rules,
            direction="inbound",
            source_ip="10.0.1.50",
            dest_ip="10.0.2.100",
            port=0,
            protocol="icmp",
            nacl_id="acl-12345",
        )

        assert result.allowed is True


class TestNACLReturnPath:
    """Tests for evaluate_nacl_return_path() - ephemeral port verification.

    CRITICAL: This tests the stateless return path bug where forward traffic
    is allowed but return traffic is blocked.
    """

    def test_return_path_allowed_with_ephemeral_ports(self) -> None:
        """Return path allowed when outbound rule covers ephemeral ports."""
        rules = [
            NACLRule(
                rule_number=100,
                protocol="6",
                rule_action="allow",
                direction="inbound",
                cidr_block="0.0.0.0/0",
                from_port=443,
                to_port=443,
            ),
            NACLRule(
                rule_number=100,
                protocol="6",
                rule_action="allow",
                direction="outbound",
                cidr_block="0.0.0.0/0",
                from_port=1024,
                to_port=65535,
            ),
        ]

        result = evaluate_nacl_return_path(
            rules=rules,
            source_ip="8.8.8.8",  # Original source
            dest_ip="10.0.1.50",  # Original destination
            protocol="tcp",
            nacl_id="acl-12345",
        )

        assert result.allowed is True
        assert "ephemeral ports" in result.reason
        assert result.direction == "return"

    def test_return_path_blocked_no_ephemeral_rule(self) -> None:
        """Return path blocked when no outbound ephemeral port rule.

        This is the critical stateless bug scenario:
        - Inbound 443 allowed
        - Outbound ephemeral ports NOT allowed
        - TCP SYN-ACK can't return → connection hangs
        """
        rules = [
            NACLRule(
                rule_number=100,
                protocol="6",
                rule_action="allow",
                direction="inbound",
                cidr_block="0.0.0.0/0",
                from_port=443,
                to_port=443,
            ),
            NACLRule(
                rule_number=100,
                protocol="6",
                rule_action="allow",
                direction="outbound",
                cidr_block="0.0.0.0/0",
                from_port=443,
                to_port=443,  # Only 443, not ephemeral
            ),
        ]

        result = evaluate_nacl_return_path(
            rules=rules,
            source_ip="8.8.8.8",
            dest_ip="10.0.1.50",
            protocol="tcp",
            nacl_id="acl-12345",
        )

        assert result.allowed is False
        assert "blocks return traffic" in result.reason
        assert "will hang" in result.reason

    def test_return_path_icmp_no_check_needed(self) -> None:
        """ICMP doesn't need ephemeral port verification."""
        rules = [
            NACLRule(
                rule_number=100,
                protocol="1",  # ICMP
                rule_action="allow",
                direction="inbound",
                cidr_block="0.0.0.0/0",
            ),
        ]

        result = evaluate_nacl_return_path(
            rules=rules,
            source_ip="8.8.8.8",
            dest_ip="10.0.1.50",
            protocol="icmp",
            nacl_id="acl-12345",
        )

        assert result.allowed is True
        assert "does not require ephemeral port verification" in result.reason

    def test_return_path_udp_checks_ephemeral(self) -> None:
        """UDP also needs ephemeral port verification."""
        rules = [
            NACLRule(
                rule_number=100,
                protocol="17",  # UDP
                rule_action="allow",
                direction="inbound",
                cidr_block="0.0.0.0/0",
                from_port=53,
                to_port=53,
            ),
            NACLRule(
                rule_number=100,
                protocol="17",
                rule_action="allow",
                direction="outbound",
                cidr_block="0.0.0.0/0",
                from_port=1024,
                to_port=65535,
            ),
        ]

        result = evaluate_nacl_return_path(
            rules=rules,
            source_ip="8.8.8.8",
            dest_ip="10.0.1.50",
            protocol="udp",
            nacl_id="acl-12345",
        )

        assert result.allowed is True

    def test_return_path_all_traffic_rule_allows(self) -> None:
        """Protocol -1 (all traffic) covers ephemeral ports."""
        rules = [
            NACLRule(
                rule_number=100,
                protocol="-1",
                rule_action="allow",
                direction="outbound",
                cidr_block="0.0.0.0/0",
            ),
        ]

        result = evaluate_nacl_return_path(
            rules=rules,
            source_ip="8.8.8.8",
            dest_ip="10.0.1.50",
            protocol="tcp",
            nacl_id="acl-12345",
        )

        assert result.allowed is True


class TestNACLEvaluatorDirection:
    """Tests for inbound vs outbound direction handling."""

    def test_inbound_matches_source_ip(self) -> None:
        """Inbound rules match against source IP."""
        rules = [
            NACLRule(
                rule_number=100,
                protocol="6",
                rule_action="allow",
                direction="inbound",
                cidr_block="10.0.0.0/8",  # Only source IPs from 10.x.x.x
                from_port=443,
                to_port=443,
            ),
        ]

        # Source in range - should match
        result = NACLEvaluator.evaluate(
            rules=rules,
            direction="inbound",
            source_ip="10.0.1.50",
            dest_ip="192.168.1.100",
            port=443,
            protocol="tcp",
            nacl_id="acl-12345",
        )
        assert result.allowed is True

        # Source NOT in range - should not match
        result = NACLEvaluator.evaluate(
            rules=rules,
            direction="inbound",
            source_ip="192.168.1.50",
            dest_ip="192.168.1.100",
            port=443,
            protocol="tcp",
            nacl_id="acl-12345",
        )
        assert result.allowed is False

    def test_outbound_matches_dest_ip(self) -> None:
        """Outbound rules match against destination IP."""
        rules = [
            NACLRule(
                rule_number=100,
                protocol="6",
                rule_action="allow",
                direction="outbound",
                cidr_block="8.8.8.0/24",  # Only dest IPs to 8.8.8.x
                from_port=443,
                to_port=443,
            ),
        ]

        # Dest in range - should match
        result = NACLEvaluator.evaluate(
            rules=rules,
            direction="outbound",
            source_ip="10.0.1.50",
            dest_ip="8.8.8.8",
            port=443,
            protocol="tcp",
            nacl_id="acl-12345",
        )
        assert result.allowed is True

        # Dest NOT in range - should not match
        result = NACLEvaluator.evaluate(
            rules=rules,
            direction="outbound",
            source_ip="10.0.1.50",
            dest_ip="1.1.1.1",
            port=443,
            protocol="tcp",
            nacl_id="acl-12345",
        )
        assert result.allowed is False


class TestNACLEvaluatorResultDetails:
    """Tests for result object details."""

    def test_result_includes_nacl_id(self) -> None:
        """Result includes correct NACL ID."""
        rules = [
            NACLRule(
                rule_number=100,
                protocol="-1",
                rule_action="allow",
                direction="inbound",
                cidr_block="0.0.0.0/0",
            ),
        ]

        result = NACLEvaluator.evaluate(
            rules=rules,
            direction="inbound",
            source_ip="10.0.1.50",
            dest_ip="10.0.2.100",
            port=443,
            protocol="tcp",
            nacl_id="acl-custom-id",
        )

        assert result.resource_id == "acl-custom-id"
        assert result.resource_type == "nacl"

    def test_result_includes_direction(self) -> None:
        """Result includes correct direction."""
        rules = [
            NACLRule(
                rule_number=100,
                protocol="-1",
                rule_action="allow",
                direction="outbound",
                cidr_block="0.0.0.0/0",
            ),
        ]

        result = NACLEvaluator.evaluate(
            rules=rules,
            direction="outbound",
            source_ip="10.0.1.50",
            dest_ip="10.0.2.100",
            port=443,
            protocol="tcp",
            nacl_id="acl-12345",
        )

        assert result.direction == "outbound"

    def test_result_reason_contains_details(self) -> None:
        """Result reason includes protocol, port, and IP."""
        rules = [
            NACLRule(
                rule_number=100,
                protocol="6",
                rule_action="allow",
                direction="inbound",
                cidr_block="0.0.0.0/0",
                from_port=443,
                to_port=443,
            ),
        ]

        result = NACLEvaluator.evaluate(
            rules=rules,
            direction="inbound",
            source_ip="10.0.1.50",
            dest_ip="10.0.2.100",
            port=443,
            protocol="tcp",
            nacl_id="acl-12345",
        )

        assert "TCP" in result.reason
        assert "443" in result.reason
        assert "10.0.1.50" in result.reason
