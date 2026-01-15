"""Tests for RouteEvaluator and Longest Prefix Match algorithm."""

from netgraph.evaluators.route import RouteEvaluator, find_longest_prefix_match
from netgraph.models.aws_resources import Route


class TestFindLongestPrefixMatch:
    """Tests for find_longest_prefix_match() function."""

    def test_single_matching_route(self) -> None:
        """Returns the only matching route."""
        routes = [
            Route(destination_cidr="10.0.0.0/16", target_id="local", target_type="local"),
        ]
        result = find_longest_prefix_match("10.0.1.50", routes)
        assert result is not None
        assert result.destination_cidr == "10.0.0.0/16"

    def test_longest_prefix_wins(self) -> None:
        """Most specific route (longest prefix) wins."""
        routes = [
            Route(destination_cidr="10.0.0.0/8", target_id="igw-1", target_type="igw"),
            Route(destination_cidr="10.0.0.0/16", target_id="nat-1", target_type="nat"),
            Route(destination_cidr="10.0.1.0/24", target_id="pcx-1", target_type="peering"),
        ]
        result = find_longest_prefix_match("10.0.1.50", routes)
        assert result is not None
        assert result.destination_cidr == "10.0.1.0/24"
        assert result.target_id == "pcx-1"

    def test_default_route_fallback(self) -> None:
        """Default route (0.0.0.0/0) matches when no specific route."""
        routes = [
            Route(destination_cidr="10.0.0.0/16", target_id="local", target_type="local"),
            Route(destination_cidr="0.0.0.0/0", target_id="igw-1", target_type="igw"),
        ]
        # IP in local range - matches local route
        result = find_longest_prefix_match("10.0.1.50", routes)
        assert result is not None
        assert result.destination_cidr == "10.0.0.0/16"

        # IP outside local range - matches default route
        result = find_longest_prefix_match("8.8.8.8", routes)
        assert result is not None
        assert result.destination_cidr == "0.0.0.0/0"

    def test_no_matching_route(self) -> None:
        """Returns None when no route matches."""
        routes = [
            Route(destination_cidr="10.0.0.0/16", target_id="local", target_type="local"),
        ]
        result = find_longest_prefix_match("192.168.1.1", routes)
        assert result is None

    def test_skips_blackhole_routes(self) -> None:
        """Blackhole routes are not matched."""
        routes = [
            Route(
                destination_cidr="10.0.1.0/24",
                target_id="pcx-dead",
                target_type="peering",
                state="blackhole",
            ),
            Route(destination_cidr="10.0.0.0/16", target_id="local", target_type="local"),
        ]
        # Would match /24 but it's blackhole, so matches /16
        result = find_longest_prefix_match("10.0.1.50", routes)
        assert result is not None
        assert result.destination_cidr == "10.0.0.0/16"

    def test_ipv6_routes(self) -> None:
        """LPM works with IPv6 routes."""
        routes = [
            Route(destination_cidr="2001:db8::/32", target_id="local", target_type="local"),
            Route(destination_cidr="2001:db8:abcd::/48", target_id="pcx-1", target_type="peering"),
            Route(destination_cidr="::/0", target_id="igw-1", target_type="igw"),
        ]
        result = find_longest_prefix_match("2001:db8:abcd::1", routes)
        assert result is not None
        assert result.destination_cidr == "2001:db8:abcd::/48"

    def test_address_family_filtering(self) -> None:
        """Filters out wrong address family routes."""
        routes = [
            Route(destination_cidr="10.0.0.0/16", target_id="local", target_type="local"),
            Route(destination_cidr="2001:db8::/32", target_id="local-v6", target_type="local"),
        ]
        # IPv4 address should only match IPv4 route
        result = find_longest_prefix_match("10.0.1.50", routes)
        assert result is not None
        assert result.destination_cidr == "10.0.0.0/16"

    def test_invalid_destination_ip(self) -> None:
        """Invalid IP returns None."""
        routes = [
            Route(destination_cidr="10.0.0.0/16", target_id="local", target_type="local"),
        ]
        result = find_longest_prefix_match("not-an-ip", routes)
        assert result is None

    def test_empty_routes_list(self) -> None:
        """Empty routes list returns None."""
        result = find_longest_prefix_match("10.0.1.50", [])
        assert result is None


class TestRouteEvaluatorFindRoute:
    """Tests for RouteEvaluator.find_route()."""

    def test_route_found(self) -> None:
        """Returns allowed result when route exists."""
        routes = [
            Route(destination_cidr="10.0.0.0/16", target_id="local", target_type="local"),
            Route(destination_cidr="0.0.0.0/0", target_id="igw-1", target_type="igw"),
        ]
        result = RouteEvaluator.find_route("10.0.1.50", routes, "rtb-12345")

        assert result.allowed is True
        assert result.resource_type == "route_table"
        assert result.resource_id == "rtb-12345"
        assert "local" in result.reason

    def test_no_route_found(self) -> None:
        """Returns blocked result when no route matches."""
        routes = [
            Route(destination_cidr="10.0.0.0/16", target_id="local", target_type="local"),
        ]
        result = RouteEvaluator.find_route("192.168.1.1", routes, "rtb-12345")

        assert result.allowed is False
        assert "No route to 192.168.1.1" in result.reason

    def test_invalid_destination_ip(self) -> None:
        """Returns blocked result for invalid IP."""
        routes = [
            Route(destination_cidr="10.0.0.0/16", target_id="local", target_type="local"),
        ]
        result = RouteEvaluator.find_route("invalid-ip", routes, "rtb-12345")

        assert result.allowed is False
        assert "Invalid destination IP" in result.reason

    def test_igw_route_info(self) -> None:
        """Result includes IGW route information."""
        routes = [
            Route(destination_cidr="0.0.0.0/0", target_id="igw-abc123", target_type="igw"),
        ]
        result = RouteEvaluator.find_route("8.8.8.8", routes, "rtb-12345")

        assert result.allowed is True
        assert "igw" in result.reason
        assert "igw-abc123" in result.reason


class TestRouteEvaluatorGetNextHop:
    """Tests for RouteEvaluator.get_next_hop()."""

    def test_returns_target_tuple(self) -> None:
        """Returns (target_id, target_type) tuple."""
        routes = [
            Route(destination_cidr="0.0.0.0/0", target_id="igw-12345", target_type="igw"),
        ]
        result = RouteEvaluator.get_next_hop("8.8.8.8", routes)

        assert result == ("igw-12345", "igw")

    def test_returns_none_no_route(self) -> None:
        """Returns None when no route matches."""
        routes = [
            Route(destination_cidr="10.0.0.0/16", target_id="local", target_type="local"),
        ]
        result = RouteEvaluator.get_next_hop("192.168.1.1", routes)

        assert result is None


class TestRouteEvaluatorInternetRoute:
    """Tests for RouteEvaluator.has_internet_route()."""

    def test_igw_route_detected(self) -> None:
        """Detects IGW route to 0.0.0.0/0."""
        routes = [
            Route(destination_cidr="10.0.0.0/16", target_id="local", target_type="local"),
            Route(destination_cidr="0.0.0.0/0", target_id="igw-12345", target_type="igw"),
        ]
        assert RouteEvaluator.has_internet_route(routes) is True

    def test_ipv6_igw_route_detected(self) -> None:
        """Detects IGW route to ::/0."""
        routes = [
            Route(destination_cidr="2001:db8::/32", target_id="local", target_type="local"),
            Route(destination_cidr="::/0", target_id="igw-12345", target_type="igw"),
        ]
        assert RouteEvaluator.has_internet_route(routes) is True

    def test_nat_route_not_counted(self) -> None:
        """NAT route doesn't count as direct internet route."""
        routes = [
            Route(destination_cidr="10.0.0.0/16", target_id="local", target_type="local"),
            Route(destination_cidr="0.0.0.0/0", target_id="nat-12345", target_type="nat"),
        ]
        assert RouteEvaluator.has_internet_route(routes) is False

    def test_blackhole_igw_not_counted(self) -> None:
        """Blackhole IGW route doesn't count."""
        routes = [
            Route(
                destination_cidr="0.0.0.0/0",
                target_id="igw-12345",
                target_type="igw",
                state="blackhole",
            ),
        ]
        assert RouteEvaluator.has_internet_route(routes) is False

    def test_no_default_route(self) -> None:
        """Returns False when no default route."""
        routes = [
            Route(destination_cidr="10.0.0.0/16", target_id="local", target_type="local"),
        ]
        assert RouteEvaluator.has_internet_route(routes) is False


class TestRouteEvaluatorNatRoute:
    """Tests for RouteEvaluator.has_nat_route()."""

    def test_nat_route_detected(self) -> None:
        """Detects NAT gateway route."""
        routes = [
            Route(destination_cidr="10.0.0.0/16", target_id="local", target_type="local"),
            Route(destination_cidr="0.0.0.0/0", target_id="nat-12345", target_type="nat"),
        ]
        assert RouteEvaluator.has_nat_route(routes) is True

    def test_igw_not_nat(self) -> None:
        """IGW route is not NAT."""
        routes = [
            Route(destination_cidr="0.0.0.0/0", target_id="igw-12345", target_type="igw"),
        ]
        assert RouteEvaluator.has_nat_route(routes) is False

    def test_blackhole_nat_not_counted(self) -> None:
        """Blackhole NAT route doesn't count."""
        routes = [
            Route(
                destination_cidr="0.0.0.0/0",
                target_id="nat-12345",
                target_type="nat",
                state="blackhole",
            ),
        ]
        assert RouteEvaluator.has_nat_route(routes) is False
