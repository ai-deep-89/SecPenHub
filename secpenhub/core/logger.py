"""
Logging Module
"""

import logging
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional
from enum import Enum


class LogLevel(Enum):
    """Log level enumeration."""
    DEBUG = logging.DEBUG
    INFO = logging.INFO
    WARNING = logging.WARNING
    ERROR = logging.ERROR
    CRITICAL = logging.CRITICAL


class Logger:
    """
    Centralized logging for SecPenHub.

    Features:
    - Multiple output handlers (console, file)
    - Colored output for console
    - Configurable log level
    - Structured logging format
    """

    _instances = {}

    def __init__(
        self,
        name: str,
        level: LogLevel = LogLevel.INFO,
        log_file: Optional[str] = None,
        console: bool = True
    ):
        """
        Initialize logger.

        Args:
            name: Logger name (usually module name)
            level: Minimum log level
            log_file: Path to log file (optional)
            console: Whether to log to console
        """
        self.name = name
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level.value)
        self.logger.handlers = []  # Clear existing handlers

        # Create formatter
        formatter = logging.Formatter(
            fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )

        # Console handler with colors
        if console:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(level.value)
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)

        # File handler
        if log_file:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(log_file, encoding="utf-8")
            file_handler.setLevel(level.value)
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)

        Logger._instances[name] = self

    def debug(self, message: str, **kwargs) -> None:
        """Log debug message."""
        self.logger.debug(message, extra=kwargs)

    def info(self, message: str, **kwargs) -> None:
        """Log info message."""
        self.logger.info(message, extra=kwargs)

    def warning(self, message: str, **kwargs) -> None:
        """Log warning message."""
        self.logger.warning(message, extra=kwargs)

    def error(self, message: str, **kwargs) -> None:
        """Log error message."""
        self.logger.error(message, extra=kwargs)

    def critical(self, message: str, **kwargs) -> None:
        """Log critical message."""
        self.logger.critical(message, extra=kwargs)

    @classmethod
    def get_logger(cls, name: str) -> "Logger":
        """Get or create a logger instance."""
        if name not in cls._instances:
            cls._instances[name] = cls(name)
        return cls._instances[name]

    @staticmethod
    def setup(
        level: LogLevel = LogLevel.INFO,
        log_dir: str = "logs"
    ) -> None:
        """
        Setup default logging configuration.

        Args:
            level: Minimum log level
            log_dir: Directory for log files
        """
        log_path = Path(log_dir)
        log_path.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = log_path / f"secpenhub_{timestamp}.log"

        # Setup root logger
        root_logger = logging.getLogger("secpenhub")
        root_logger.setLevel(level.value)

        formatter = logging.Formatter(
            fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )

        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level.value)
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)

        # File handler
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(level.value)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
