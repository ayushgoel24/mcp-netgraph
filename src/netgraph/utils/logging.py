"""Logging configuration for NetGraph."""

import logging
import sys
from typing import Literal

LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]

_CONFIGURED = False


def setup_logging(
    level: LogLevel = "INFO",
    format_string: str | None = None,
) -> None:
    """
    Configure logging for NetGraph.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        format_string: Custom format string. If None, uses default format.

    Example:
        setup_logging(level="DEBUG")
    """
    global _CONFIGURED

    if format_string is None:
        format_string = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    # Configure root logger for netgraph
    logger = logging.getLogger("netgraph")
    logger.setLevel(getattr(logging, level))

    # Remove existing handlers to avoid duplicates
    logger.handlers.clear()

    # Create console handler
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(getattr(logging, level))
    handler.setFormatter(logging.Formatter(format_string))
    logger.addHandler(handler)

    # Prevent propagation to root logger
    logger.propagate = False

    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger for a specific module.

    Args:
        name: Module name (typically __name__)

    Returns:
        Logger instance configured for NetGraph

    Example:
        logger = get_logger(__name__)
        logger.info("Processing request")
    """
    if not _CONFIGURED:
        setup_logging()

    # Ensure the logger is under the netgraph namespace
    if not name.startswith("netgraph"):
        name = f"netgraph.{name}"

    return logging.getLogger(name)
