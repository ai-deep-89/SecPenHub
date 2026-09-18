"""
Risk Score Calculator - Composite security scoring
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime

from .cvss import CVSSCalculator, CVSSSeverity


@dataclass
class SecurityScore:
    """Complete security assessment score."""
    overall_score: float
    rating: str
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    total_findings: int
    coverage_score: float
    timestamp: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "overall_score": self.overall_score,
            "rating": self.rating,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "total_findings": self.total_findings,
            "coverage_score": self.coverage_score,
            "timestamp": self.timestamp
        }


class RiskCalculator:
    """
    Calculate composite security scores for assessment results.

    Implements a multi-factor scoring model that considers:
    - Vulnerability severity (weighted by CVSS)
    - Asset coverage
    - Remediation urgency
    """

    # Weight factors for severity
    SEVERITY_WEIGHTS = {
        "critical": 10.0,
        "high": 7.5,
        "medium": 5.0,
        "low": 2.5,
        "none": 0.0
    }

    # Exploitability multipliers (simplified)
    EXPLOITABILITY_MULTIPLIERS = {
        "critical": 1.0,
        "high": 0.9,
        "medium": 0.7,
        "low": 0.4,
        "none": 0.0
    }

    def __init__(self):
        """Initialize risk calculator."""
        self.cvss = CVSSCalculator()

    def calculate_security_score(
        self,
        findings: List[Dict],
        total_assets: int = 100,
        scanned_assets: int = 100
    ) -> SecurityScore:
        """
        Calculate overall security score.

        Args:
            findings: List of vulnerability findings
            total_assets: Total expected assets (for coverage calculation)
            scanned_assets: Number of assets actually scanned

        Returns:
            SecurityScore with comprehensive scoring
        """
        # Calculate severity distribution
        severity_dist = self.cvss.calculate_severity_distribution(findings)

        # Calculate weighted risk
        total_risk = 0.0
        for finding in findings:
            severity = finding.get("severity", "low").lower()
            weight = self.SEVERITY_WEIGHTS.get(severity, 2.5)
            exploitability = self.EXPLOITABILITY_MULTIPLIERS.get(severity, 0.5)

            # Risk contribution = weight * exploitability * CVSS score
            cvss_score = finding.get("cvss_score", 5.0)
            risk_contribution = weight * exploitability * (cvss_score / 10.0)
            total_risk += risk_contribution

        # Calculate coverage score
        coverage = (scanned_assets / total_assets * 100) if total_assets > 0 else 100
        coverage_score = min(coverage, 100)

        # Calculate maximum possible risk
        max_findings = 50  # Assume max 50 high-severity findings
        max_risk = max_findings * self.SEVERITY_WEIGHTS["critical"]

        # Calculate normalized score (0-100, higher is better)
        if max_risk > 0:
            normalized_risk = (total_risk / max_risk) * 100
            overall_score = max(0, min(100, 100 - normalized_risk))
        else:
            overall_score = 100

        # Round to one decimal
        overall_score = round(overall_score, 1)

        # Determine rating
        rating = self._get_rating(overall_score)

        return SecurityScore(
            overall_score=overall_score,
            rating=rating,
            critical_count=severity_dist["critical"],
            high_count=severity_dist["high"],
            medium_count=severity_dist["medium"],
            low_count=severity_dist["low"],
            total_findings=len(findings),
            coverage_score=round(coverage_score, 1),
            timestamp=datetime.now().isoformat()
        )

    def _get_rating(self, score: float) -> str:
        """Get rating string from score."""
        if score >= 90:
            return "Excellent"
        elif score >= 70:
            return "Good"
        elif score >= 50:
            return "Fair"
        elif score >= 30:
            return "Poor"
        else:
            return "Critical"

    def calculate_risk_distribution(self, findings: List[Dict]) -> Dict[str, Any]:
        """
        Calculate risk distribution across different categories.

        Args:
            findings: List of vulnerability findings

        Returns:
            Dictionary with risk distribution by category
        """
        distribution = {
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "by_category": {},
            "by_target": {}
        }

        for finding in findings:
            severity = finding.get("severity", "low").lower()
            category = finding.get("category", "Unknown")
            target = finding.get("url", "Unknown")

            # Count by severity
            if severity in distribution["by_severity"]:
                distribution["by_severity"][severity] += 1

            # Count by category
            if category not in distribution["by_category"]:
                distribution["by_category"][category] = 0
            distribution["by_category"][category] += 1

            # Count by target
            if target not in distribution["by_target"]:
                distribution["by_target"][target] = 0
            distribution["by_target"][target] += 1

        return distribution

    def calculate_remediation_priority(
        self,
        findings: List[Dict]
    ) -> List[Dict]:
        """
        Calculate remediation priority for findings.

        Args:
            findings: List of vulnerability findings

        Returns:
            Sorted list of findings with priority scores
        """
        prioritized = []

        for finding in findings:
            severity = finding.get("severity", "low").lower()
            cvss_score = finding.get("cvss_score", 5.0)

            # Priority score = severity weight * CVSS * exploitability
            severity_weight = self.SEVERITY_WEIGHTS.get(severity, 2.5)
            priority_score = severity_weight * cvss_score

            prioritized.append({
                **finding,
                "priority_score": round(priority_score, 2),
                "remediation_effort": self._estimate_remediation_effort(finding)
            })

        # Sort by priority score descending
        prioritized.sort(key=lambda x: x["priority_score"], reverse=True)

        return prioritized

    def _estimate_remediation_effort(self, finding: Dict) -> str:
        """Estimate remediation effort for a finding."""
        category = finding.get("category", "").lower()

        effort_map = {
            "injection": "High",
            "xss": "Medium",
            "csrf": "Low",
            "access control": "Medium",
            "security misconfiguration": "Low",
            "ssrf": "Medium",
        }

        for key, effort in effort_map.items():
            if key in category:
                return effort

        return "Medium"

    def compare_scans(
        self,
        scan1_findings: List[Dict],
        scan2_findings: List[Dict]
    ) -> Dict[str, Any]:
        """
        Compare two scan results.

        Args:
            scan1_findings: First scan findings
            scan2_findings: Second scan findings

        Returns:
            Comparison dictionary
        """
        score1 = self.calculate_security_score(scan1_findings)
        score2 = self.calculate_security_score(scan2_findings)

        improvement = score2.overall_score - score1.overall_score

        return {
            "previous_score": score1.overall_score,
            "current_score": score2.overall_score,
            "improvement": round(improvement, 1),
            "finding_delta": score2.total_findings - score1.total_findings,
            "trend": "improving" if improvement > 0 else "stable" if improvement == 0 else "degrading"
        }
