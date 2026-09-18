"""
CVSS Calculator - Common Vulnerability Scoring System implementation
"""

import math
from typing import Dict, Optional, Tuple
from dataclasses import dataclass
from enum import Enum


class CVSSSeverity(Enum):
    """CVSS severity levels."""
    NONE = "None"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class CVSSCalculator:
    """
    CVSS 3.1 Calculator.

    Implements the complete CVSS 3.1 formula for calculating base scores.
    Reference: https://www.first.org/cvss/specification-document
    """

    # Metric values
    class AttackVector:
        NETWORK = 0.85
        ADJACENT = 0.62
        LOCAL = 0.55
        PHYSICAL = 0.02

    class AttackComplexity:
        LOW = 0.77
        HIGH = 0.44

    class PrivilegesRequired:
        NONE = 0.85
        LOW = 0.62
        HIGH = 0.27

    class UserInteraction:
        NONE = 0.85
        REQUIRED = 0.62

    class Scope:
        UNCHANGED = 0.0
        CHANGED = 0.0  # Actual value is applied in formula

    class CIA:
        HIGH = 0.56
        LOW = 0.22
        NONE = 0.0

    # Severity thresholds
    SEVERITY_THRESHOLDS = {
        (0.0, 0.1): CVSSSeverity.NONE,
        (0.1, 3.9): CVSSSeverity.LOW,
        (4.0, 6.9): CVSSSeverity.MEDIUM,
        (7.0, 8.9): CVSSSeverity.HIGH,
        (9.0, 10.0): CVSSSeverity.CRITICAL
    }

    def __init__(self):
        """Initialize CVSS calculator."""
        pass

    def calculate(
        self,
        attack_vector: str = "network",
        attack_complexity: str = "low",
        privileges_required: str = "none",
        user_interaction: str = "none",
        scope_changed: bool = False,
        confidentiality_impact: str = "high",
        integrity_impact: str = "high",
        availability_impact: str = "high"
    ) -> Tuple[float, CVSSSeverity]:
        """
        Calculate CVSS base score.

        Args:
            attack_vector: NETWORK, ADJACENT, LOCAL, PHYSICAL
            attack_complexity: LOW, HIGH
            privileges_required: NONE, LOW, HIGH
            user_interaction: NONE, REQUIRED
            scope_changed: True if scope changes, False otherwise
            confidentiality_impact: HIGH, LOW, NONE
            integrity_impact: HIGH, LOW, NONE
            availability_impact: HIGH, LOW, NONE

        Returns:
            Tuple of (CVSS score, severity)
        """
        # Map string values to numeric
        av = getattr(self.AttackVector, attack_vector.upper(), 0.85)
        ac = getattr(self.AttackComplexity, attack_complexity.upper(), 0.77)
        pr = getattr(self.PrivilegesRequired, privileges_required.upper(), 0.85)
        ui = getattr(self.UserInteraction, user_interaction.upper(), 0.85)

        cia_map = {"HIGH": 0.56, "LOW": 0.22, "NONE": 0.0}
        c = cia_map.get(confidentiality_impact.upper(), 0.56)
        i = cia_map.get(integrity_impact.upper(), 0.56)
        a = cia_map.get(availability_impact.upper(), 0.56)

        # Calculate Impact
        if scope_changed:
            iss = 1 - ((1 - c) * (1 - i) * (1 - a))
            impact = 7.52 * (iss - 0.029) - 3.25 * math.pow(iss - 0.02, 15)
        else:
            iss = 1 - ((1 - c) * (1 - i) * (1 - a))
            impact = 6.42 * iss

        # Calculate Exploitability
        exploitability = 8.22 * av * ac * pr * ui

        # Calculate Base Score
        if impact <= 0:
            base_score = 0.0
        elif scope_changed:
            base_score = min(1.08 * (impact + exploitability), 10.0)
        else:
            base_score = min(impact + exploitability, 10.0)

        # Round to one decimal place
        base_score = round(base_score, 1)

        # Determine severity
        severity = self._get_severity(base_score)

        return base_score, severity

    def _get_severity(self, score: float) -> CVSSSeverity:
        """Get severity level from score."""
        for (low, high), severity in self.SEVERITY_THRESHOLDS.items():
            if low <= score < high:
                return severity
        return CVSSSeverity.NONE

    def from_vulnerability_type(self, vuln_type: str, is_remote: bool = True) -> Tuple[float, CVSSSeverity]:
        """
        Estimate CVSS score based on vulnerability type.

        Args:
            vuln_type: Type of vulnerability (e.g., "SQL Injection", "XSS")
            is_remote: Whether the attack can be launched remotely

        Returns:
            Tuple of (estimated CVSS score, severity)
        """
        # Common vulnerability CVSS estimates
        vuln_scores = {
            "sql_injection": (9.1, CVSSSeverity.CRITICAL),
            "remote_code_execution": (9.8, CVSSSeverity.CRITICAL),
            "xss": (6.1, CVSSSeverity.MEDIUM),
            "csrf": (5.3, CVSSSeverity.MEDIUM),
            "ssrf": (8.6, CVSSSeverity.HIGH),
            "idor": (7.5, CVSSSeverity.HIGH),
            "path_traversal": (7.5, CVSSSeverity.HIGH),
            "security_misconfiguration": (3.1, CVSSSeverity.LOW),
            "missing_csrf": (5.3, CVSSSeverity.MEDIUM),
            "information_disclosure": (2.5, CVSSSeverity.LOW),
            "open_redirect": (5.3, CVSSSeverity.MEDIUM),
            "xxe": (9.1, CVSSSeverity.CRITICAL),
        }

        # Normalize vulnerability type
        vuln_lower = vuln_type.lower().replace(" ", "_").replace("-", "_")

        for key, (score, severity) in vuln_scores.items():
            if key in vuln_lower:
                # Adjust for remote vs local
                if not is_remote and score > 7.0:
                    return score - 1.0, self._get_severity(score - 1.0)
                return score, severity

        # Default for unknown vulnerabilities
        return (5.0, CVSSSeverity.MEDIUM)

    def calculate_severity_distribution(self, findings: list) -> Dict[str, int]:
        """
        Calculate severity distribution from findings.

        Args:
            findings: List of finding dictionaries with cvss_score

        Returns:
            Dictionary with severity counts
        """
        distribution = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "none": 0
        }

        for finding in findings:
            score = finding.get("cvss_score", 0)
            severity = self._get_severity(score)
            distribution[severity.value.lower()] += 1

        return distribution

    def vector_to_score(self, vector: str) -> Tuple[float, CVSSSeverity]:
        """
        Calculate score from CVSS vector string.

        Args:
            vector: CVSS vector string (e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

        Returns:
            Tuple of (CVSS score, severity)
        """
        # Parse vector
        metrics = {}
        if vector.startswith("CVSS:3.1/"):
            vector = vector[8:]

        for part in vector.split("/"):
            if ":" in part:
                key, value = part.split(":", 1)
                metrics[key] = value

        return self.calculate(
            attack_vector=metrics.get("AV", "N"),
            attack_complexity=metrics.get("AC", "L"),
            privileges_required=metrics.get("PR", "N"),
            user_interaction=metrics.get("UI", "N"),
            scope_changed=metrics.get("S", "U") == "C",
            confidentiality_impact=metrics.get("C", "H"),
            integrity_impact=metrics.get("I", "H"),
            availability_impact=metrics.get("A", "H")
        )


@dataclass
class CVSSScore:
    """Represents a complete CVSS score with all components."""
    base_score: float
    severity: CVSSSeverity
    vector: str
    impact: float
    exploitability: float

    def to_dict(self) -> Dict:
        return {
            "base_score": self.base_score,
            "severity": self.severity.value,
            "vector": self.vector,
            "impact": self.impact,
            "exploitability": self.exploitability
        }
