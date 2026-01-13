"""Tests for CIDRMatcher utilities."""

from netgraph.evaluators.cidr import CIDRMatcher


class TestCIDRMatcherMatches:
    """Tests for CIDRMatcher.matches()."""

    def test_ipv4_in_cidr(self) -> None:
        """IPv4 address within CIDR returns True."""
        assert CIDRMatcher.matches("10.0.1.50", "10.0.0.0/16") is True
        assert CIDRMatcher.matches("10.0.255.255", "10.0.0.0/16") is True
        assert CIDRMatcher.matches("10.0.0.0", "10.0.0.0/16") is True

    def test_ipv4_not_in_cidr(self) -> None:
        """IPv4 address outside CIDR returns False."""
        assert CIDRMatcher.matches("192.168.1.1", "10.0.0.0/16") is False
        assert CIDRMatcher.matches("10.1.0.0", "10.0.0.0/16") is False

    def test_ipv4_exact_match(self) -> None:
        """IPv4 address matches /32 CIDR."""
        assert CIDRMatcher.matches("10.0.1.50", "10.0.1.50/32") is True
        assert CIDRMatcher.matches("10.0.1.51", "10.0.1.50/32") is False

    def test_ipv4_default_route(self) -> None:
        """Any IPv4 matches 0.0.0.0/0."""
        assert CIDRMatcher.matches("10.0.1.50", "0.0.0.0/0") is True
        assert CIDRMatcher.matches("192.168.1.1", "0.0.0.0/0") is True
        assert CIDRMatcher.matches("8.8.8.8", "0.0.0.0/0") is True

    def test_ipv6_in_cidr(self) -> None:
        """IPv6 address within CIDR returns True."""
        assert CIDRMatcher.matches("2001:db8::1", "2001:db8::/32") is True
        assert CIDRMatcher.matches("2001:db8:ffff::1", "2001:db8::/32") is True

    def test_ipv6_not_in_cidr(self) -> None:
        """IPv6 address outside CIDR returns False."""
        assert CIDRMatcher.matches("2001:db9::1", "2001:db8::/32") is False

    def test_ipv6_default_route(self) -> None:
        """Any IPv6 matches ::/0."""
        assert CIDRMatcher.matches("2001:db8::1", "::/0") is True
        assert CIDRMatcher.matches("fe80::1", "::/0") is True

    def test_address_family_mismatch_returns_false(self) -> None:
        """IPv4 address vs IPv6 CIDR returns False (not error)."""
        assert CIDRMatcher.matches("10.0.1.50", "2001:db8::/32") is False
        assert CIDRMatcher.matches("2001:db8::1", "10.0.0.0/16") is False

    def test_invalid_ip_returns_false(self) -> None:
        """Invalid IP address returns False."""
        assert CIDRMatcher.matches("not-an-ip", "10.0.0.0/16") is False
        assert CIDRMatcher.matches("256.0.0.1", "10.0.0.0/16") is False

    def test_invalid_cidr_returns_false(self) -> None:
        """Invalid CIDR returns False."""
        assert CIDRMatcher.matches("10.0.1.50", "not-a-cidr") is False
        assert CIDRMatcher.matches("10.0.1.50", "10.0.0.0/33") is False


class TestCIDRMatcherMatchesAny:
    """Tests for CIDRMatcher.matches_any()."""

    def test_matches_first_cidr(self) -> None:
        """Returns True if IP matches first CIDR."""
        cidrs = ["10.0.0.0/16", "192.168.0.0/16"]
        assert CIDRMatcher.matches_any("10.0.1.50", cidrs) is True

    def test_matches_second_cidr(self) -> None:
        """Returns True if IP matches second CIDR."""
        cidrs = ["10.0.0.0/16", "192.168.0.0/16"]
        assert CIDRMatcher.matches_any("192.168.1.1", cidrs) is True

    def test_matches_none(self) -> None:
        """Returns False if IP matches no CIDR."""
        cidrs = ["10.0.0.0/16", "192.168.0.0/16"]
        assert CIDRMatcher.matches_any("172.16.0.1", cidrs) is False

    def test_empty_list(self) -> None:
        """Empty CIDR list returns False."""
        assert CIDRMatcher.matches_any("10.0.1.50", []) is False


class TestCIDRMatcherMostSpecificMatch:
    """Tests for CIDRMatcher.most_specific_match() - LPM algorithm."""

    def test_returns_longest_prefix(self) -> None:
        """Returns CIDR with longest prefix length."""
        cidrs = ["10.0.0.0/8", "10.0.0.0/16", "10.0.1.0/24"]
        result = CIDRMatcher.most_specific_match("10.0.1.50", cidrs)
        assert result == "10.0.1.0/24"

    def test_single_match(self) -> None:
        """Returns single matching CIDR."""
        cidrs = ["10.0.0.0/8", "192.168.0.0/16"]
        result = CIDRMatcher.most_specific_match("10.0.1.50", cidrs)
        assert result == "10.0.0.0/8"

    def test_no_match(self) -> None:
        """Returns None if no CIDR matches."""
        cidrs = ["192.168.0.0/16", "172.16.0.0/12"]
        result = CIDRMatcher.most_specific_match("10.0.1.50", cidrs)
        assert result is None

    def test_exact_match_wins(self) -> None:
        """/32 CIDR wins over broader ranges."""
        cidrs = ["10.0.0.0/8", "10.0.1.50/32"]
        result = CIDRMatcher.most_specific_match("10.0.1.50", cidrs)
        assert result == "10.0.1.50/32"

    def test_ipv6_longest_prefix(self) -> None:
        """LPM works with IPv6 addresses."""
        cidrs = ["2001:db8::/32", "2001:db8:abcd::/48", "2001:db8:abcd:0001::/64"]
        result = CIDRMatcher.most_specific_match("2001:db8:abcd:0001::1", cidrs)
        assert result == "2001:db8:abcd:0001::/64"

    def test_address_family_filtering(self) -> None:
        """Filters out wrong address family CIDRs."""
        cidrs = ["10.0.0.0/8", "2001:db8::/32"]
        result = CIDRMatcher.most_specific_match("10.0.1.50", cidrs)
        assert result == "10.0.0.0/8"

    def test_empty_list(self) -> None:
        """Empty CIDR list returns None."""
        result = CIDRMatcher.most_specific_match("10.0.1.50", [])
        assert result is None

    def test_invalid_ip(self) -> None:
        """Invalid IP returns None."""
        cidrs = ["10.0.0.0/8"]
        result = CIDRMatcher.most_specific_match("not-an-ip", cidrs)
        assert result is None


class TestCIDRMatcherValidation:
    """Tests for validation helper methods."""

    def test_validate_cidr_valid_ipv4(self) -> None:
        """Valid IPv4 CIDR returns True."""
        assert CIDRMatcher.validate_cidr("10.0.0.0/16") is True
        assert CIDRMatcher.validate_cidr("0.0.0.0/0") is True
        assert CIDRMatcher.validate_cidr("192.168.1.0/24") is True

    def test_validate_cidr_valid_ipv6(self) -> None:
        """Valid IPv6 CIDR returns True."""
        assert CIDRMatcher.validate_cidr("2001:db8::/32") is True
        assert CIDRMatcher.validate_cidr("::/0") is True

    def test_validate_cidr_invalid(self) -> None:
        """Invalid CIDR returns False."""
        assert CIDRMatcher.validate_cidr("not-a-cidr") is False
        assert CIDRMatcher.validate_cidr("10.0.0.0/33") is False
        assert CIDRMatcher.validate_cidr("10.0.0.0") is False  # Missing prefix

    def test_validate_ip_valid_ipv4(self) -> None:
        """Valid IPv4 address returns True."""
        assert CIDRMatcher.validate_ip("10.0.1.50") is True
        assert CIDRMatcher.validate_ip("0.0.0.0") is True
        assert CIDRMatcher.validate_ip("255.255.255.255") is True

    def test_validate_ip_valid_ipv6(self) -> None:
        """Valid IPv6 address returns True."""
        assert CIDRMatcher.validate_ip("2001:db8::1") is True
        assert CIDRMatcher.validate_ip("::1") is True
        assert CIDRMatcher.validate_ip("fe80::1") is True

    def test_validate_ip_invalid(self) -> None:
        """Invalid IP returns False."""
        assert CIDRMatcher.validate_ip("not-an-ip") is False
        assert CIDRMatcher.validate_ip("256.0.0.1") is False
        assert CIDRMatcher.validate_ip("10.0.0.0/16") is False  # CIDR not IP


class TestCIDRMatcherAddressFamily:
    """Tests for address family detection."""

    def test_get_address_family_ipv4_address(self) -> None:
        """IPv4 address returns 'IPv4'."""
        assert CIDRMatcher.get_address_family("10.0.1.50") == "IPv4"

    def test_get_address_family_ipv6_address(self) -> None:
        """IPv6 address returns 'IPv6'."""
        assert CIDRMatcher.get_address_family("2001:db8::1") == "IPv6"

    def test_get_address_family_ipv4_cidr(self) -> None:
        """IPv4 CIDR returns 'IPv4'."""
        assert CIDRMatcher.get_address_family("10.0.0.0/16") == "IPv4"

    def test_get_address_family_ipv6_cidr(self) -> None:
        """IPv6 CIDR returns 'IPv6'."""
        assert CIDRMatcher.get_address_family("2001:db8::/32") == "IPv6"

    def test_get_address_family_invalid(self) -> None:
        """Invalid input returns None."""
        assert CIDRMatcher.get_address_family("not-valid") is None

    def test_is_same_family_both_ipv4(self) -> None:
        """Both IPv4 returns True."""
        assert CIDRMatcher.is_same_family("10.0.1.50", "10.0.0.0/16") is True

    def test_is_same_family_both_ipv6(self) -> None:
        """Both IPv6 returns True."""
        assert CIDRMatcher.is_same_family("2001:db8::1", "2001:db8::/32") is True

    def test_is_same_family_mixed(self) -> None:
        """Mixed families returns False."""
        assert CIDRMatcher.is_same_family("10.0.1.50", "2001:db8::/32") is False
        assert CIDRMatcher.is_same_family("2001:db8::1", "10.0.0.0/16") is False


class TestCIDRMatcherPrefixLength:
    """Tests for prefix length extraction."""

    def test_get_prefix_length_ipv4(self) -> None:
        """Returns correct prefix length for IPv4."""
        assert CIDRMatcher.get_prefix_length("10.0.0.0/8") == 8
        assert CIDRMatcher.get_prefix_length("10.0.0.0/16") == 16
        assert CIDRMatcher.get_prefix_length("10.0.1.0/24") == 24
        assert CIDRMatcher.get_prefix_length("10.0.1.50/32") == 32

    def test_get_prefix_length_ipv6(self) -> None:
        """Returns correct prefix length for IPv6."""
        assert CIDRMatcher.get_prefix_length("2001:db8::/32") == 32
        assert CIDRMatcher.get_prefix_length("::/0") == 0
        assert CIDRMatcher.get_prefix_length("2001:db8::1/128") == 128

    def test_get_prefix_length_invalid(self) -> None:
        """Returns None for invalid CIDR."""
        assert CIDRMatcher.get_prefix_length("not-valid") is None


class TestCIDRMatcherCache:
    """Tests for LRU cache behavior."""

    def test_clear_cache(self) -> None:
        """Cache can be cleared."""
        # Run some matches to populate cache
        CIDRMatcher.matches("10.0.1.50", "10.0.0.0/16")
        CIDRMatcher.matches("10.0.1.51", "10.0.0.0/16")

        # Clear cache - should not raise
        CIDRMatcher.clear_cache()

        # Cache should still work after clearing
        assert CIDRMatcher.matches("10.0.1.50", "10.0.0.0/16") is True
