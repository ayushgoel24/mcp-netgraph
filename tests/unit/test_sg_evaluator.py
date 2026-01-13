"""Tests for SecurityGroupEvaluator with prefix list support."""

import pytest

from netgraph.evaluators.security_group import (
    MatchResult,
    SecurityGroupEvaluator,
    evaluate_sg_reference,
)
from netgraph.models.aws_resources import SecurityGroup, SGRule
from netgraph.models.errors import PrefixListResolutionError


class MockPrefixListResolver:
    """Mock resolver for testing prefix list resolution."""

    def __init__(self, prefix_lists: dict[str, list[str]]) -> None:
        self.prefix_lists = prefix_lists
        self.call_count = 0

    async def get_prefix_list_cidrs(self, prefix_list_id: str) -> list[str]:
        self.call_count += 1
        if prefix_list_id not in self.prefix_lists:
            raise PrefixListResolutionError(
                prefix_list_id=prefix_list_id,
                reason="Prefix list not found in mock",
            )
        return self.prefix_lists[prefix_list_id]


class TestSecurityGroupEvaluatorEgress:
    """Tests for evaluate_egress() - outbound traffic."""

    @pytest.mark.asyncio
    async def test_egress_allowed_cidr_match(self) -> None:
        """Egress allowed when CIDR matches destination."""
        sg = SecurityGroup(
            sg_id="sg-12345",
            vpc_id="vpc-12345",
            name="test-sg",
            description="Test security group",
            inbound_rules=[],
            outbound_rules=[
                SGRule(
                    rule_id="sgr-out-1",
                    direction="outbound",
                    ip_protocol="tcp",
                    from_port=443,
                    to_port=443,
                    cidr_ipv4="0.0.0.0/0",
                ),
            ],
        )

        result = await SecurityGroupEvaluator.evaluate_egress(
            security_groups=[sg],
            dest_ip="8.8.8.8",
            port=443,
            protocol="tcp",
        )

        assert result.allowed is True
        assert result.resource_id == "sg-12345"
        assert result.direction == "outbound"
        assert "allows" in result.reason

    @pytest.mark.asyncio
    async def test_egress_denied_no_matching_rule(self) -> None:
        """Egress denied when no rule matches."""
        sg = SecurityGroup(
            sg_id="sg-12345",
            vpc_id="vpc-12345",
            name="test-sg",
            description="Test security group",
            inbound_rules=[],
            outbound_rules=[
                SGRule(
                    rule_id="sgr-out-1",
                    direction="outbound",
                    ip_protocol="tcp",
                    from_port=80,
                    to_port=80,
                    cidr_ipv4="0.0.0.0/0",
                ),
            ],
        )

        result = await SecurityGroupEvaluator.evaluate_egress(
            security_groups=[sg],
            dest_ip="8.8.8.8",
            port=443,  # Wrong port
            protocol="tcp",
        )

        assert result.allowed is False
        assert "No rule allows" in result.reason

    @pytest.mark.asyncio
    async def test_egress_no_security_groups(self) -> None:
        """Returns blocked when no security groups attached."""
        result = await SecurityGroupEvaluator.evaluate_egress(
            security_groups=[],
            dest_ip="8.8.8.8",
            port=443,
            protocol="tcp",
        )

        assert result.allowed is False
        assert "No security groups attached" in result.reason


class TestSecurityGroupEvaluatorIngress:
    """Tests for evaluate_ingress() - inbound traffic."""

    @pytest.mark.asyncio
    async def test_ingress_allowed_cidr_match(self) -> None:
        """Ingress allowed when source IP matches CIDR."""
        sg = SecurityGroup(
            sg_id="sg-12345",
            vpc_id="vpc-12345",
            name="test-sg",
            description="Test security group",
            inbound_rules=[
                SGRule(
                    rule_id="sgr-in-1",
                    direction="inbound",
                    ip_protocol="tcp",
                    from_port=443,
                    to_port=443,
                    cidr_ipv4="10.0.0.0/8",
                ),
            ],
            outbound_rules=[],
        )

        result = await SecurityGroupEvaluator.evaluate_ingress(
            security_groups=[sg],
            source_ip="10.0.1.50",
            port=443,
            protocol="tcp",
        )

        assert result.allowed is True
        assert result.direction == "inbound"
        assert "from 10.0.1.50" in result.reason

    @pytest.mark.asyncio
    async def test_ingress_denied_source_not_in_cidr(self) -> None:
        """Ingress denied when source IP not in CIDR."""
        sg = SecurityGroup(
            sg_id="sg-12345",
            vpc_id="vpc-12345",
            name="test-sg",
            description="Test security group",
            inbound_rules=[
                SGRule(
                    rule_id="sgr-in-1",
                    direction="inbound",
                    ip_protocol="tcp",
                    from_port=443,
                    to_port=443,
                    cidr_ipv4="192.168.0.0/16",
                ),
            ],
            outbound_rules=[],
        )

        result = await SecurityGroupEvaluator.evaluate_ingress(
            security_groups=[sg],
            source_ip="10.0.1.50",  # Not in 192.168.0.0/16
            port=443,
            protocol="tcp",
        )

        assert result.allowed is False


class TestSecurityGroupEvaluatorMultipleSGs:
    """Tests for multiple Security Groups - OR logic."""

    @pytest.mark.asyncio
    async def test_any_sg_allows_traffic_passes(self) -> None:
        """Traffic allowed if ANY attached SG allows it."""
        sg1 = SecurityGroup(
            sg_id="sg-deny",
            vpc_id="vpc-12345",
            name="deny-sg",
            description="Security group with no rules",
            inbound_rules=[],  # No rules = deny all
            outbound_rules=[],
        )
        sg2 = SecurityGroup(
            sg_id="sg-allow",
            vpc_id="vpc-12345",
            name="allow-sg",
            description="Security group with allow rule",
            inbound_rules=[
                SGRule(
                    rule_id="sgr-in-1",
                    direction="inbound",
                    ip_protocol="tcp",
                    from_port=443,
                    to_port=443,
                    cidr_ipv4="0.0.0.0/0",
                ),
            ],
            outbound_rules=[],
        )

        result = await SecurityGroupEvaluator.evaluate_ingress(
            security_groups=[sg1, sg2],  # Both attached
            source_ip="10.0.1.50",
            port=443,
            protocol="tcp",
        )

        assert result.allowed is True
        assert result.resource_id == "sg-allow"

    @pytest.mark.asyncio
    async def test_all_sgs_deny_traffic_blocked(self) -> None:
        """Traffic blocked only if ALL attached SGs deny."""
        sg1 = SecurityGroup(
            sg_id="sg-1",
            vpc_id="vpc-12345",
            name="sg-one",
            description="Security group one",
            inbound_rules=[
                SGRule(
                    rule_id="sgr-in-1",
                    direction="inbound",
                    ip_protocol="tcp",
                    from_port=80,
                    to_port=80,  # Wrong port
                    cidr_ipv4="0.0.0.0/0",
                ),
            ],
            outbound_rules=[],
        )
        sg2 = SecurityGroup(
            sg_id="sg-2",
            vpc_id="vpc-12345",
            name="sg-two",
            description="Security group two",
            inbound_rules=[
                SGRule(
                    rule_id="sgr-in-2",
                    direction="inbound",
                    ip_protocol="udp",  # Wrong protocol
                    from_port=443,
                    to_port=443,
                    cidr_ipv4="0.0.0.0/0",
                ),
            ],
            outbound_rules=[],
        )

        result = await SecurityGroupEvaluator.evaluate_ingress(
            security_groups=[sg1, sg2],
            source_ip="10.0.1.50",
            port=443,
            protocol="tcp",
        )

        assert result.allowed is False
        assert "sg-1,sg-2" in result.resource_id


class TestSecurityGroupEvaluatorPrefixLists:
    """Tests for prefix list (pl-xxx) resolution."""

    @pytest.mark.asyncio
    async def test_prefix_list_allows_when_ip_matches(self) -> None:
        """Traffic allowed when IP matches resolved prefix list CIDRs."""
        sg = SecurityGroup(
            sg_id="sg-12345",
            vpc_id="vpc-12345",
            name="test-sg",
            description="Test security group",
            inbound_rules=[
                SGRule(
                    rule_id="sgr-in-1",
                    direction="inbound",
                    ip_protocol="tcp",
                    from_port=443,
                    to_port=443,
                    prefix_list_id="pl-office-ips",
                ),
            ],
            outbound_rules=[],
        )

        resolver = MockPrefixListResolver(
            {"pl-office-ips": ["10.0.0.0/8", "192.168.0.0/16"]}
        )

        result = await SecurityGroupEvaluator.evaluate_ingress(
            security_groups=[sg],
            source_ip="10.0.1.50",
            port=443,
            protocol="tcp",
            prefix_resolver=resolver,
        )

        assert result.allowed is True
        assert result.resolved_prefix_list == "pl-office-ips"
        assert resolver.call_count == 1

    @pytest.mark.asyncio
    async def test_prefix_list_denies_when_ip_not_in_cidrs(self) -> None:
        """Traffic denied when IP not in resolved prefix list CIDRs."""
        sg = SecurityGroup(
            sg_id="sg-12345",
            vpc_id="vpc-12345",
            name="test-sg",
            description="Test security group",
            inbound_rules=[
                SGRule(
                    rule_id="sgr-in-1",
                    direction="inbound",
                    ip_protocol="tcp",
                    from_port=443,
                    to_port=443,
                    prefix_list_id="pl-office-ips",
                ),
            ],
            outbound_rules=[],
        )

        resolver = MockPrefixListResolver(
            {"pl-office-ips": ["192.168.0.0/16"]}  # 10.x not included
        )

        result = await SecurityGroupEvaluator.evaluate_ingress(
            security_groups=[sg],
            source_ip="10.0.1.50",
            port=443,
            protocol="tcp",
            prefix_resolver=resolver,
        )

        assert result.allowed is False

    @pytest.mark.asyncio
    async def test_prefix_list_no_resolver_denies(self) -> None:
        """Traffic denied when no resolver provided for prefix list."""
        sg = SecurityGroup(
            sg_id="sg-12345",
            vpc_id="vpc-12345",
            name="test-sg",
            description="Test security group",
            inbound_rules=[
                SGRule(
                    rule_id="sgr-in-1",
                    direction="inbound",
                    ip_protocol="tcp",
                    from_port=443,
                    to_port=443,
                    prefix_list_id="pl-office-ips",
                ),
            ],
            outbound_rules=[],
        )

        result = await SecurityGroupEvaluator.evaluate_ingress(
            security_groups=[sg],
            source_ip="10.0.1.50",
            port=443,
            protocol="tcp",
            prefix_resolver=None,  # No resolver
        )

        assert result.allowed is False

    @pytest.mark.asyncio
    async def test_prefix_list_resolution_error_denies(self) -> None:
        """Traffic denied when prefix list resolution fails."""
        sg = SecurityGroup(
            sg_id="sg-12345",
            vpc_id="vpc-12345",
            name="test-sg",
            description="Test security group",
            inbound_rules=[
                SGRule(
                    rule_id="sgr-in-1",
                    direction="inbound",
                    ip_protocol="tcp",
                    from_port=443,
                    to_port=443,
                    prefix_list_id="pl-unknown",
                ),
            ],
            outbound_rules=[],
        )

        resolver = MockPrefixListResolver({})  # Empty - will raise

        result = await SecurityGroupEvaluator.evaluate_ingress(
            security_groups=[sg],
            source_ip="10.0.1.50",
            port=443,
            protocol="tcp",
            prefix_resolver=resolver,
        )

        assert result.allowed is False


class TestSecurityGroupEvaluatorIPv6:
    """Tests for IPv6 CIDR rules."""

    @pytest.mark.asyncio
    async def test_ipv6_cidr_matches(self) -> None:
        """IPv6 CIDR rule matches IPv6 address."""
        sg = SecurityGroup(
            sg_id="sg-12345",
            vpc_id="vpc-12345",
            name="test-sg",
            description="Test security group",
            inbound_rules=[
                SGRule(
                    rule_id="sgr-in-1",
                    direction="inbound",
                    ip_protocol="tcp",
                    from_port=443,
                    to_port=443,
                    cidr_ipv6="2001:db8::/32",
                ),
            ],
            outbound_rules=[],
        )

        result = await SecurityGroupEvaluator.evaluate_ingress(
            security_groups=[sg],
            source_ip="2001:db8::1",
            port=443,
            protocol="tcp",
        )

        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_ipv6_default_route(self) -> None:
        """IPv6 ::/0 matches all IPv6 addresses."""
        sg = SecurityGroup(
            sg_id="sg-12345",
            vpc_id="vpc-12345",
            name="test-sg",
            description="Test security group",
            inbound_rules=[
                SGRule(
                    rule_id="sgr-in-1",
                    direction="inbound",
                    ip_protocol="tcp",
                    from_port=443,
                    to_port=443,
                    cidr_ipv6="::/0",
                ),
            ],
            outbound_rules=[],
        )

        result = await SecurityGroupEvaluator.evaluate_ingress(
            security_groups=[sg],
            source_ip="2001:db8:abcd::1",
            port=443,
            protocol="tcp",
        )

        assert result.allowed is True


class TestSecurityGroupEvaluatorProtocols:
    """Tests for protocol matching."""

    @pytest.mark.asyncio
    async def test_all_protocols_rule(self) -> None:
        """Protocol -1 matches all traffic."""
        sg = SecurityGroup(
            sg_id="sg-12345",
            vpc_id="vpc-12345",
            name="test-sg",
            description="Test security group",
            inbound_rules=[
                SGRule(
                    rule_id="sgr-in-1",
                    direction="inbound",
                    ip_protocol="-1",
                    from_port=0,
                    to_port=65535,
                    cidr_ipv4="0.0.0.0/0",
                ),
            ],
            outbound_rules=[],
        )

        result = await SecurityGroupEvaluator.evaluate_ingress(
            security_groups=[sg],
            source_ip="10.0.1.50",
            port=443,
            protocol="tcp",
        )

        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_protocol_case_insensitive(self) -> None:
        """Protocol matching is case insensitive."""
        sg = SecurityGroup(
            sg_id="sg-12345",
            vpc_id="vpc-12345",
            name="test-sg",
            description="Test security group",
            inbound_rules=[
                SGRule(
                    rule_id="sgr-in-1",
                    direction="inbound",
                    ip_protocol="TCP",  # Uppercase
                    from_port=443,
                    to_port=443,
                    cidr_ipv4="0.0.0.0/0",
                ),
            ],
            outbound_rules=[],
        )

        result = await SecurityGroupEvaluator.evaluate_ingress(
            security_groups=[sg],
            source_ip="10.0.1.50",
            port=443,
            protocol="tcp",  # Lowercase
        )

        assert result.allowed is True


class TestSecurityGroupEvaluatorPortRanges:
    """Tests for port range matching."""

    @pytest.mark.asyncio
    async def test_port_in_range(self) -> None:
        """Port within range matches."""
        sg = SecurityGroup(
            sg_id="sg-12345",
            vpc_id="vpc-12345",
            name="test-sg",
            description="Test security group",
            inbound_rules=[
                SGRule(
                    rule_id="sgr-in-1",
                    direction="inbound",
                    ip_protocol="tcp",
                    from_port=1024,
                    to_port=65535,
                    cidr_ipv4="0.0.0.0/0",
                ),
            ],
            outbound_rules=[],
        )

        result = await SecurityGroupEvaluator.evaluate_ingress(
            security_groups=[sg],
            source_ip="10.0.1.50",
            port=8080,
            protocol="tcp",
        )

        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_port_outside_range(self) -> None:
        """Port outside range doesn't match."""
        sg = SecurityGroup(
            sg_id="sg-12345",
            vpc_id="vpc-12345",
            name="test-sg",
            description="Test security group",
            inbound_rules=[
                SGRule(
                    rule_id="sgr-in-1",
                    direction="inbound",
                    ip_protocol="tcp",
                    from_port=1024,
                    to_port=65535,
                    cidr_ipv4="0.0.0.0/0",
                ),
            ],
            outbound_rules=[],
        )

        result = await SecurityGroupEvaluator.evaluate_ingress(
            security_groups=[sg],
            source_ip="10.0.1.50",
            port=443,  # Below range
            protocol="tcp",
        )

        assert result.allowed is False


class TestSGReferenceEvaluation:
    """Tests for SG-to-SG reference rules."""

    @pytest.mark.asyncio
    async def test_sg_reference_matches_attached_sg(self) -> None:
        """SG reference rule matches when source has referenced SG."""
        rule = SGRule(
            rule_id="sgr-in-1",
            direction="inbound",
            ip_protocol="tcp",
            from_port=443,
            to_port=443,
            referenced_sg_id="sg-source-sg",
        )

        result = await evaluate_sg_reference(
            rule=rule,
            source_sg_ids=["sg-source-sg", "sg-other"],
        )

        assert result is not None
        assert result.allowed is True
        assert "SG reference" in result.reason

    @pytest.mark.asyncio
    async def test_sg_reference_no_match_different_sg(self) -> None:
        """SG reference rule doesn't match when source lacks referenced SG."""
        rule = SGRule(
            rule_id="sgr-in-1",
            direction="inbound",
            ip_protocol="tcp",
            from_port=443,
            to_port=443,
            referenced_sg_id="sg-required",
        )

        result = await evaluate_sg_reference(
            rule=rule,
            source_sg_ids=["sg-other-1", "sg-other-2"],
        )

        assert result is None  # No match

    @pytest.mark.asyncio
    async def test_sg_reference_returns_none_for_cidr_rule(self) -> None:
        """SG reference evaluation returns None for CIDR rules."""
        rule = SGRule(
            rule_id="sgr-in-1",
            direction="inbound",
            ip_protocol="tcp",
            from_port=443,
            to_port=443,
            cidr_ipv4="0.0.0.0/0",  # CIDR, not SG reference
        )

        result = await evaluate_sg_reference(
            rule=rule,
            source_sg_ids=["sg-source"],
        )

        assert result is None


class TestSecurityGroupEvaluatorSGReferences:
    """Tests for SG reference rules in evaluator (IP-based check returns no match)."""

    @pytest.mark.asyncio
    async def test_sg_reference_rule_no_ip_match(self) -> None:
        """SG reference rule doesn't match by IP - requires SG check."""
        sg = SecurityGroup(
            sg_id="sg-12345",
            vpc_id="vpc-12345",
            name="test-sg",
            description="Test security group",
            inbound_rules=[
                SGRule(
                    rule_id="sgr-in-1",
                    direction="inbound",
                    ip_protocol="tcp",
                    from_port=443,
                    to_port=443,
                    referenced_sg_id="sg-web-tier",  # SG reference, not CIDR
                ),
            ],
            outbound_rules=[],
        )

        # IP-based evaluation won't match SG references
        result = await SecurityGroupEvaluator.evaluate_ingress(
            security_groups=[sg],
            source_ip="10.0.1.50",
            port=443,
            protocol="tcp",
        )

        # Should be denied because SG references need separate check
        assert result.allowed is False


class TestMatchResult:
    """Tests for MatchResult helper class."""

    def test_match_result_matches_true(self) -> None:
        """MatchResult with matches=True."""
        result = MatchResult(matches=True)
        assert result.matches is True
        assert result.resolved_prefix_list is None

    def test_match_result_with_prefix_list(self) -> None:
        """MatchResult includes resolved prefix list."""
        result = MatchResult(matches=True, resolved_prefix_list="pl-12345")
        assert result.matches is True
        assert result.resolved_prefix_list == "pl-12345"

    def test_match_result_matches_false(self) -> None:
        """MatchResult with matches=False."""
        result = MatchResult(matches=False)
        assert result.matches is False


class TestSecurityGroupEvaluatorResultDetails:
    """Tests for result object details."""

    @pytest.mark.asyncio
    async def test_result_includes_rule_id(self) -> None:
        """Result includes matched rule ID."""
        sg = SecurityGroup(
            sg_id="sg-12345",
            vpc_id="vpc-12345",
            name="test-sg",
            description="Test security group",
            inbound_rules=[
                SGRule(
                    rule_id="sgr-custom-rule-id",
                    direction="inbound",
                    ip_protocol="tcp",
                    from_port=443,
                    to_port=443,
                    cidr_ipv4="0.0.0.0/0",
                ),
            ],
            outbound_rules=[],
        )

        result = await SecurityGroupEvaluator.evaluate_ingress(
            security_groups=[sg],
            source_ip="10.0.1.50",
            port=443,
            protocol="tcp",
        )

        assert result.matched_rule_id == "sgr-custom-rule-id"

    @pytest.mark.asyncio
    async def test_result_resource_type_is_security_group(self) -> None:
        """Result resource_type is 'security_group'."""
        sg = SecurityGroup(
            sg_id="sg-12345",
            vpc_id="vpc-12345",
            name="test-sg",
            description="Test security group",
            inbound_rules=[
                SGRule(
                    rule_id="sgr-in-1",
                    direction="inbound",
                    ip_protocol="-1",
                    from_port=0,
                    to_port=65535,
                    cidr_ipv4="0.0.0.0/0",
                ),
            ],
            outbound_rules=[],
        )

        result = await SecurityGroupEvaluator.evaluate_ingress(
            security_groups=[sg],
            source_ip="10.0.1.50",
            port=443,
            protocol="tcp",
        )

        assert result.resource_type == "security_group"
