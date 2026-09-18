"""
Configuration Management Module
"""

import os
from pathlib import Path
from typing import Optional, Dict, Any
import json


class Config:
    """
    Centralized configuration management for SecPenHub.

    Supports:
    - Environment variables
    - Config file (JSON/YAML)
    - Default values
    """

    DEFAULT_CONFIG = {
        "database": {
            "type": "sqlite",
            "path": ".secpenhub.db"
        },
        "scanner": {
            "timeout": 30,
            "max_retries": 3,
            "user_agent": "SecPenHub/1.0 (Security Scanner)",
            "concurrent_requests": 10
        },
        "ai": {
            "backend": "openai",
            "model": "gpt-4",
            "api_key": None,
            "temperature": 0.7,
            "max_tokens": 2000
        },
        "recon": {
            "subdomain_wordlist": "wordlists/subdomains.txt",
            "port_range": "1-10000",
            "rate_limit": 50
        },
        "reporting": {
            "output_dir": "reports",
            "format": "html",
            "include_poc": True
        }
    }

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize configuration.

        Args:
            config_path: Path to config file (JSON/YAML). If None, uses defaults.
        """
        self._config = self.DEFAULT_CONFIG.copy()

        if config_path and os.path.exists(config_path):
            self._load_from_file(config_path)

        self._apply_env_overrides()

    def _load_from_file(self, path: str) -> None:
        """Load configuration from file."""
        with open(path, 'r') as f:
            if path.endswith('.json'):
                user_config = json.load(f)
            else:
                # Basic YAML support (simple key-value)
                import yaml
                user_config = yaml.safe_load(f)

        self._deep_merge(self._config, user_config)

    def _apply_env_overrides(self) -> None:
        """Apply environment variable overrides."""
        # AI Configuration
        if os.getenv("OPENAI_API_KEY"):
            self._config["ai"]["api_key"] = os.getenv("OPENAI_API_KEY")
        if os.getenv("AI_MODEL"):
            self._config["ai"]["model"] = os.getenv("AI_MODEL")

        # Scanner Configuration
        if os.getenv("SCANNER_TIMEOUT"):
            self._config["scanner"]["timeout"] = int(os.getenv("SCANNER_TIMEOUT"))

        # Database Configuration
        if os.getenv("DATABASE_PATH"):
            self._config["database"]["path"] = os.getenv("DATABASE_PATH")

    def _deep_merge(self, base: dict, override: dict) -> None:
        """Deep merge override dict into base dict."""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value

    def get(self, path: str, default: Any = None) -> Any:
        """
        Get configuration value using dot notation.

        Args:
            path: Configuration path (e.g., "scanner.timeout")
            default: Default value if path not found

        Returns:
            Configuration value
        """
        keys = path.split(".")
        value = self._config

        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default

        return value

    def set(self, path: str, value: Any) -> None:
        """
        Set configuration value using dot notation.

        Args:
            path: Configuration path (e.g., "scanner.timeout")
            value: Value to set
        """
        keys = path.split(".")
        config = self._config

        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]

        config[keys[-1]] = value

    @property
    def all(self) -> Dict[str, Any]:
        """Get all configuration."""
        return self._config.copy()

    @classmethod
    def from_env(cls) -> "Config":
        """Create configuration from environment variables."""
        return cls()
