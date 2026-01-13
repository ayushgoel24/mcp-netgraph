"""Tests for NetGraph exception hierarchy."""

import pytest

from netgraph.models.errors import (
    AsymmetricRoutingError,
    AWSAuthError,
    CrossAccountAccessError,
    CrossAccountSGResolutionError,
    NetGraphError,
    PermissionDeniedError,
    PrefixListResolutionError,
    ResourceNotFoundError,
    ValidationError,
)


class TestNetGraphError:
    """Tests for base NetGraphError."""

    def test_instantiation_with_message_only(self) -> None:
        """Error can be created with just a message."""
        error = NetGraphError("Something went wrong")
        assert error.message == "Something went wrong"
        assert error.details == {}
        assert str(error) == "Something went wrong"

    def test_instantiation_with_details(self) -> None:
        """Error can be created with message and details."""
        error = NetGraphError("Error", {"key": "value"})
        assert error.message == "Error"
        assert error.details == {"key": "value"}

    def test_to_response(self) -> None:
        """to_response produces valid JSON structure."""
        error = NetGraphError("Test error", {"foo": "bar"})
        response = error.to_response()

        assert response["error"] == "NetGraphError"
        assert response["message"] == "Test error"
        assert response["details"] == {"foo": "bar"}


class TestValidationError:
    """Tests for ValidationError."""

    def test_basic_instantiation(self) -> None:
        """ValidationError can be created with just a message."""
        error = ValidationError("Invalid input")
        assert error.message == "Invalid input"
        assert error.field is None
        assert error.expected is None

    def test_with_field(self) -> None:
        """ValidationError includes field in details."""
        error = ValidationError("Invalid VPC ID", field="vpc_id")
        assert error.field == "vpc_id"
        assert error.details["field"] == "vpc_id"

    def test_with_expected_format(self) -> None:
        """ValidationError includes expected format in details."""
        error = ValidationError(
            "Invalid IP",
            field="dest_ip",
            expected="IPv4 or IPv6 address",
        )
        assert error.details["field"] == "dest_ip"
        assert error.details["expected_format"] == "IPv4 or IPv6 address"

    def test_to_response(self) -> None:
        """to_response produces correct structure."""
        error = ValidationError("Bad input", field="source_id", expected="i-xxx or eni-xxx")
        response = error.to_response()

        assert response["error"] == "ValidationError"
        assert response["details"]["field"] == "source_id"


class TestAWSAuthError:
    """Tests for AWSAuthError."""

    def test_basic_instantiation(self) -> None:
        """AWSAuthError can be created without permission info."""
        error = AWSAuthError("Authentication failed")
        assert error.message == "Authentication failed"
        assert error.missing_permission is None

    def test_with_missing_permission(self) -> None:
        """AWSAuthError includes permission suggestion."""
        error = AWSAuthError(
            "Access denied",
            missing_permission="ec2:DescribeInstances",
        )
        assert error.missing_permission == "ec2:DescribeInstances"
        assert "ec2:DescribeInstances" in error.details["suggestion"]


class TestPermissionDeniedError:
    """Tests for PermissionDeniedError."""

    def test_instantiation(self) -> None:
        """PermissionDeniedError captures resource and operation."""
        error = PermissionDeniedError(
            "Access denied to instance",
            resource_id="i-12345",
            operation="DescribeInstances",
        )
        assert error.resource_id == "i-12345"
        assert error.operation == "DescribeInstances"
        assert error.details["result"] == "PathStatus.UNKNOWN"

    def test_to_response_structure(self) -> None:
        """to_response includes all required fields."""
        error = PermissionDeniedError(
            "Denied",
            resource_id="subnet-abc",
            operation="DescribeSubnets",
        )
        response = error.to_response()

        assert response["details"]["resource_id"] == "subnet-abc"
        assert response["details"]["operation"] == "DescribeSubnets"
        assert "suggestion" in response["details"]


class TestCrossAccountAccessError:
    """Tests for CrossAccountAccessError."""

    def test_instantiation(self) -> None:
        """CrossAccountAccessError captures account ID."""
        error = CrossAccountAccessError(
            "Cannot assume role",
            account_id="123456789012",
        )
        assert error.account_id == "123456789012"
        assert error.details["account_id"] == "123456789012"
        assert "cross_account_roles" in error.details["suggestion"]


class TestResourceNotFoundError:
    """Tests for ResourceNotFoundError."""

    def test_instantiation(self) -> None:
        """ResourceNotFoundError generates appropriate message."""
        error = ResourceNotFoundError(
            resource_id="i-doesnotexist",
            resource_type="instance",
        )
        assert error.resource_id == "i-doesnotexist"
        assert error.resource_type == "instance"
        assert "instance" in error.message
        assert "i-doesnotexist" in error.message

    def test_to_response(self) -> None:
        """to_response includes resource details."""
        error = ResourceNotFoundError("sg-missing", "security_group")
        response = error.to_response()

        assert response["details"]["resource_id"] == "sg-missing"
        assert response["details"]["resource_type"] == "security_group"


class TestPrefixListResolutionError:
    """Tests for PrefixListResolutionError."""

    def test_instantiation(self) -> None:
        """PrefixListResolutionError captures prefix list ID and reason."""
        error = PrefixListResolutionError(
            prefix_list_id="pl-12345",
            reason="Access denied",
        )
        assert error.prefix_list_id == "pl-12345"
        assert error.reason == "Access denied"
        assert "pl-12345" in error.message

    def test_suggestion_includes_permission(self) -> None:
        """Suggestion mentions required permission."""
        error = PrefixListResolutionError("pl-xxx", "Not found")
        assert "DescribeManagedPrefixLists" in error.details["suggestion"]


class TestCrossAccountSGResolutionError:
    """Tests for CrossAccountSGResolutionError."""

    def test_instantiation(self) -> None:
        """CrossAccountSGResolutionError captures SG IDs."""
        error = CrossAccountSGResolutionError(
            message="Cannot verify SG reference",
            sg_id="sg-peer-123",
            referencing_sg_id="sg-local-456",
        )
        assert error.sg_id == "sg-peer-123"
        assert error.referencing_sg_id == "sg-local-456"
        assert error.details["result"] == "PathStatus.UNKNOWN"

    def test_suggestion_mentions_cross_account(self) -> None:
        """Suggestion mentions cross-account configuration."""
        error = CrossAccountSGResolutionError(
            "Cannot verify",
            sg_id="sg-abc",
            referencing_sg_id="sg-def",
        )
        assert "cross_account_roles" in error.details["suggestion"]


class TestAsymmetricRoutingError:
    """Tests for AsymmetricRoutingError."""

    def test_instantiation(self) -> None:
        """AsymmetricRoutingError captures route table and source IP."""
        error = AsymmetricRoutingError(
            dest_route_table_id="rtb-12345",
            source_ip="10.0.1.50",
        )
        assert error.dest_route_table_id == "rtb-12345"
        assert error.source_ip == "10.0.1.50"
        assert "rtb-12345" in error.message
        assert "10.0.1.50" in error.message

    def test_result_is_blocked(self) -> None:
        """Asymmetric routing results in BLOCKED status."""
        error = AsymmetricRoutingError("rtb-xxx", "10.0.0.1")
        assert error.details["result"] == "PathStatus.BLOCKED"

    def test_suggestion_includes_route_fix(self) -> None:
        """Suggestion explains how to fix the routing."""
        error = AsymmetricRoutingError("rtb-abc", "192.168.1.1")
        suggestion = error.details["suggestion"]
        assert "192.168.1.1" in suggestion
        assert "rtb-abc" in suggestion


class TestExceptionInheritance:
    """Tests for exception hierarchy structure."""

    def test_all_exceptions_inherit_from_base(self) -> None:
        """All custom exceptions inherit from NetGraphError."""
        exceptions = [
            ValidationError("test"),
            AWSAuthError("test"),
            PermissionDeniedError("test", "res", "op"),
            CrossAccountAccessError("test", "123"),
            ResourceNotFoundError("res", "type"),
            PrefixListResolutionError("pl-xxx", "reason"),
            CrossAccountSGResolutionError("msg", "sg1", "sg2"),
            AsymmetricRoutingError("rtb", "ip"),
        ]

        for exc in exceptions:
            assert isinstance(exc, NetGraphError)
            assert isinstance(exc, Exception)

    def test_all_exceptions_are_catchable_as_base(self) -> None:
        """All exceptions can be caught as NetGraphError."""
        with pytest.raises(NetGraphError):
            raise ValidationError("test")

        with pytest.raises(NetGraphError):
            raise ResourceNotFoundError("res", "type")

    def test_all_have_to_response(self) -> None:
        """All exceptions implement to_response()."""
        exceptions = [
            ValidationError("test"),
            AWSAuthError("test"),
            PermissionDeniedError("test", "res", "op"),
            CrossAccountAccessError("test", "123"),
            ResourceNotFoundError("res", "type"),
            PrefixListResolutionError("pl-xxx", "reason"),
            CrossAccountSGResolutionError("msg", "sg1", "sg2"),
            AsymmetricRoutingError("rtb", "ip"),
        ]

        for exc in exceptions:
            response = exc.to_response()
            assert "error" in response
            assert "message" in response
            assert "details" in response
            assert isinstance(response["details"], dict)
