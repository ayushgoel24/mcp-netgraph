"""Exception hierarchy for NetGraph.

All exceptions inherit from NetGraphError and provide:
- Structured error details for debugging
- to_response() method for MCP-compatible error responses
"""

from typing import Any


class NetGraphError(Exception):
    """Base exception for all NetGraph errors."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        self.message = message
        self.details = details or {}
        super().__init__(message)

    def to_response(self) -> dict[str, Any]:
        """Convert to MCP-compatible error response."""
        return {
            "error": self.__class__.__name__,
            "message": self.message,
            "details": self.details,
        }


class ValidationError(NetGraphError):
    """Raised for invalid input parameters."""

    def __init__(
        self,
        message: str,
        field: str | None = None,
        expected: str | None = None,
    ) -> None:
        details: dict[str, Any] = {}
        if field:
            details["field"] = field
        if expected:
            details["expected_format"] = expected
        super().__init__(message, details)
        self.field = field
        self.expected = expected


class AWSAuthError(NetGraphError):
    """Raised for AWS authentication/authorization issues."""

    def __init__(
        self,
        message: str,
        missing_permission: str | None = None,
    ) -> None:
        details: dict[str, Any] = {}
        if missing_permission:
            details["missing_permission"] = missing_permission
            details["suggestion"] = f"Add {missing_permission} to IAM policy"
        super().__init__(message, details)
        self.missing_permission = missing_permission


class PermissionDeniedError(NetGraphError):
    """
    Raised when AWS returns AccessDenied during path traversal.

    This results in PathStatus.UNKNOWN rather than BLOCKED,
    since we cannot determine if the path is actually blocked.
    """

    def __init__(
        self,
        message: str,
        resource_id: str,
        operation: str,
    ) -> None:
        super().__init__(
            message,
            {
                "resource_id": resource_id,
                "operation": operation,
                "result": "PathStatus.UNKNOWN",
                "suggestion": "Grant required permissions or provide cross-account role",
            },
        )
        self.resource_id = resource_id
        self.operation = operation


class CrossAccountAccessError(NetGraphError):
    """Raised when cross-account access fails."""

    def __init__(self, message: str, account_id: str) -> None:
        super().__init__(
            message,
            {
                "account_id": account_id,
                "suggestion": "Configure cross_account_roles parameter with role ARN",
            },
        )
        self.account_id = account_id


class ResourceNotFoundError(NetGraphError):
    """Raised when a referenced resource doesn't exist."""

    def __init__(self, resource_id: str, resource_type: str) -> None:
        super().__init__(
            f"{resource_type} '{resource_id}' not found",
            {
                "resource_id": resource_id,
                "resource_type": resource_type,
                "suggestion": "Verify resource ID exists in AWS",
            },
        )
        self.resource_id = resource_id
        self.resource_type = resource_type


class PrefixListResolutionError(NetGraphError):
    """Raised when a prefix list cannot be resolved."""

    def __init__(self, prefix_list_id: str, reason: str) -> None:
        super().__init__(
            f"Cannot resolve prefix list {prefix_list_id}: {reason}",
            {
                "prefix_list_id": prefix_list_id,
                "suggestion": (
                    "Verify prefix list exists and you have "
                    "ec2:DescribeManagedPrefixLists permission"
                ),
            },
        )
        self.prefix_list_id = prefix_list_id
        self.reason = reason


class CrossAccountSGResolutionError(NetGraphError):
    """
    Raised when a Security Group reference in a peer VPC cannot be resolved
    due to cross-account permission limitations.

    This results in PathStatus.UNKNOWN because we cannot determine if the
    traffic would be allowed by the referenced Security Group.
    """

    def __init__(
        self,
        message: str,
        sg_id: str,
        referencing_sg_id: str,
    ) -> None:
        super().__init__(
            message,
            {
                "referenced_sg_id": sg_id,
                "referencing_sg_id": referencing_sg_id,
                "result": "PathStatus.UNKNOWN",
                "suggestion": (
                    "Configure cross_account_roles parameter with role ARN for the peer "
                    "account, or verify that the role has ec2:DescribeInstances permission "
                    "in the peer VPC"
                ),
            },
        )
        self.sg_id = sg_id
        self.referencing_sg_id = referencing_sg_id


class AsymmetricRoutingError(NetGraphError):
    """
    Raised when forward path succeeds but destination has no route back to source.

    This is a critical false positive scenario: traffic arrives at destination,
    but the response packet cannot return because the destination subnet's
    route table lacks a route to the source IP.
    """

    def __init__(self, dest_route_table_id: str, source_ip: str) -> None:
        super().__init__(
            f"Asymmetric routing: destination route table {dest_route_table_id} "
            f"has no route back to source IP {source_ip}",
            {
                "dest_route_table_id": dest_route_table_id,
                "source_ip": source_ip,
                "result": "PathStatus.BLOCKED",
                "suggestion": (
                    f"Add a route to {source_ip} (or its subnet) in route table "
                    f"{dest_route_table_id}"
                ),
            },
        )
        self.dest_route_table_id = dest_route_table_id
        self.source_ip = source_ip
