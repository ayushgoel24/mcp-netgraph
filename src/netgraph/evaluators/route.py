"""Route evaluation with Longest Prefix Match (LPM) algorithm."""

from ipaddress import ip_address, ip_network

from netgraph.evaluators.cidr import CIDRMatcher
from netgraph.models.aws_resources import Route
from netgraph.models.results import RuleEvalResult


def find_longest_prefix_match(
    dest_ip: str,
    routes: list[Route],
) -> Route | None:
    """Find the route with the longest matching prefix for a destination IP.

    This implements the Longest Prefix Match (LPM) algorithm used by
    AWS route tables. The most specific route (longest prefix) wins.

    Algorithm:
        1. Filter routes with state="active"
        2. Filter by address family (IPv4 vs IPv6)
        3. Check if dest_ip is in each route's network
        4. Sort matching routes by prefix length DESCENDING
        5. Return route with longest prefix (most specific)

    Args:
        dest_ip: Destination IP address string
        routes: List of Route objects to evaluate

    Returns:
        The Route with the longest matching prefix, or None if no match.

    Examples:
        Given routes for 10.0.0.0/8, 10.0.0.0/16, and 10.0.1.0/24,
        destination 10.0.1.50 matches 10.0.1.0/24 (longest prefix).
    """
    try:
        addr = ip_address(dest_ip)
    except ValueError:
        return None

    matching_routes: list[tuple[Route, int]] = []

    for route in routes:
        # Skip blackhole routes
        if route.state != "active":
            continue

        try:
            network = ip_network(route.destination_cidr, strict=False)
        except ValueError:
            continue

        # Skip address family mismatches
        if addr.version != network.version:
            continue

        # Check if destination IP is in this route's network
        if addr in network:
            matching_routes.append((route, network.prefixlen))

    if not matching_routes:
        return None

    # Sort by prefix length descending (most specific first)
    matching_routes.sort(key=lambda x: x[1], reverse=True)
    return matching_routes[0][0]


class RouteEvaluator:
    """Evaluates route tables to determine next hop for traffic."""

    @staticmethod
    def find_route(
        dest_ip: str,
        routes: list[Route],
        route_table_id: str,
    ) -> RuleEvalResult:
        """Find the route for a destination IP and return evaluation result.

        Args:
            dest_ip: Destination IP address
            routes: List of routes from the route table
            route_table_id: ID of the route table being evaluated

        Returns:
            RuleEvalResult with route information or blocking reason.
        """
        # Validate destination IP
        if not CIDRMatcher.validate_ip(dest_ip):
            return RuleEvalResult(
                allowed=False,
                resource_id=route_table_id,
                resource_type="route_table",
                reason=f"Invalid destination IP: {dest_ip}",
            )

        # Find longest prefix match
        route = find_longest_prefix_match(dest_ip, routes)

        if route is None:
            return RuleEvalResult(
                allowed=False,
                resource_id=route_table_id,
                resource_type="route_table",
                reason=f"No route to {dest_ip} in route table {route_table_id}",
            )

        # Check for blackhole (should be filtered by LPM, but double-check)
        if route.state == "blackhole":
            return RuleEvalResult(
                allowed=False,
                resource_id=route_table_id,
                resource_type="route_table",
                reason=f"Route to {route.destination_cidr} is blackhole "
                f"(target {route.target_id} unavailable)",
            )

        # Route found - traffic is allowed to proceed to next hop
        return RuleEvalResult(
            allowed=True,
            matched_rule_id=route.destination_cidr,  # Use CIDR as rule identifier
            resource_id=route_table_id,
            resource_type="route_table",
            reason=f"Route to {dest_ip} via {route.target_type} "
            f"({route.target_id}) matching {route.destination_cidr}",
        )

    @staticmethod
    def get_next_hop(
        dest_ip: str,
        routes: list[Route],
    ) -> tuple[str, str] | None:
        """Get the next hop target for a destination IP.

        Args:
            dest_ip: Destination IP address
            routes: List of routes from the route table

        Returns:
            Tuple of (target_id, target_type) or None if no route.
        """
        route = find_longest_prefix_match(dest_ip, routes)
        if route is None:
            return None
        return (route.target_id, route.target_type)

    @staticmethod
    def has_internet_route(routes: list[Route]) -> bool:
        """Check if route table has a route to the internet.

        A route table has internet access if it has a route to
        0.0.0.0/0 or ::/0 via an Internet Gateway (igw-*).

        Args:
            routes: List of routes from the route table

        Returns:
            True if there's an active IGW route, False otherwise.
        """
        for route in routes:
            if route.state != "active":
                continue
            if route.target_type != "igw":
                continue
            # Check for default routes
            if route.destination_cidr in ("0.0.0.0/0", "::/0"):
                return True
        return False

    @staticmethod
    def has_nat_route(routes: list[Route]) -> bool:
        """Check if route table has a route via NAT Gateway.

        Args:
            routes: List of routes from the route table

        Returns:
            True if there's an active NAT route for internet traffic.
        """
        for route in routes:
            if route.state != "active":
                continue
            if route.target_type != "nat":
                continue
            # NAT routes are typically for default route
            if route.destination_cidr in ("0.0.0.0/0", "::/0"):
                return True
        return False
