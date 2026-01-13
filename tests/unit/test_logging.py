"""Tests for NetGraph logging utilities."""

import logging

from netgraph.utils.logging import get_logger, setup_logging


class TestSetupLogging:
    """Tests for setup_logging function."""

    def test_default_level(self) -> None:
        """Default log level is INFO."""
        setup_logging()
        logger = logging.getLogger("netgraph")
        assert logger.level == logging.INFO

    def test_custom_level(self) -> None:
        """Can set custom log level."""
        setup_logging(level="DEBUG")
        logger = logging.getLogger("netgraph")
        assert logger.level == logging.DEBUG

    def test_logger_has_handler(self) -> None:
        """Logger gets a handler configured."""
        setup_logging()
        logger = logging.getLogger("netgraph")
        assert len(logger.handlers) > 0

    def test_no_propagation(self) -> None:
        """Logger does not propagate to root."""
        setup_logging()
        logger = logging.getLogger("netgraph")
        assert logger.propagate is False


class TestGetLogger:
    """Tests for get_logger function."""

    def test_returns_logger(self) -> None:
        """get_logger returns a Logger instance."""
        logger = get_logger("test_module")
        assert isinstance(logger, logging.Logger)

    def test_logger_name_under_netgraph(self) -> None:
        """Logger name is prefixed with netgraph."""
        logger = get_logger("my_module")
        assert logger.name.startswith("netgraph")

    def test_netgraph_prefix_not_duplicated(self) -> None:
        """If name already starts with netgraph, don't duplicate."""
        logger = get_logger("netgraph.core.path")
        assert logger.name == "netgraph.core.path"
        assert not logger.name.startswith("netgraph.netgraph")

    def test_auto_setup(self) -> None:
        """get_logger auto-configures logging if not done."""
        # This test verifies it doesn't crash when called first
        logger = get_logger("auto_test")
        assert logger is not None
