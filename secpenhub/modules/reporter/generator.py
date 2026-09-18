"""
Report Generator - Create comprehensive security reports
"""

import json
import asyncio
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path

from ...core.logger import Logger


class ReportGenerator:
    """
    Generate security assessment reports in multiple formats.

    Supports:
    - HTML (interactive dashboard)
    - JSON (machine-readable)
    - Markdown (GitHub-compatible)
    - PDF (formal documentation)
    """

    def __init__(self, output_dir: str = "reports"):
        """
        Initialize report generator.

        Args:
            output_dir: Directory for output reports
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.logger = Logger.get_logger("reporter")

    async def generate(
        self,
        scan_data: Dict[str, Any],
        findings: List[Dict],
        format: str = "html"
    ) -> str:
        """
        Generate security report.

        Args:
            scan_data: Scan metadata and configuration
            findings: List of vulnerability findings
            format: Output format (html, json, markdown)

        Returns:
            Path to generated report
        """
        self.logger.info(f"Generating {format} report...")

        if format == "html":
            return await self._generate_html(scan_data, findings)
        elif format == "json":
            return self._generate_json(scan_data, findings)
        elif format == "markdown":
            return self._generate_markdown(scan_data, findings)
        else:
            raise ValueError(f"Unsupported format: {format}")

    async def _generate_html(
        self,
        scan_data: Dict[str, Any],
        findings: List[Dict]
    ) -> str:
        """Generate HTML report."""
        from ..evaluator.risk_score import RiskCalculator

        calculator = RiskCalculator()
        security_score = calculator.calculate_security_score(findings)

        # Calculate statistics
        severity_counts = {
            "critical": security_score.critical_count,
            "high": security_score.high_count,
            "medium": security_score.medium_count,
            "low": security_score.low_count
        }

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report - {scan_data.get('target', 'Unknown')}</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f7fa; color: #333; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px; border-radius: 10px; margin-bottom: 30px; }}
        .header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .header p {{ opacity: 0.9; font-size: 1.1em; }}
        .score-card {{ background: white; border-radius: 10px; padding: 30px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 30px; }}
        .score-display {{ display: flex; align-items: center; justify-content: space-between; }}
        .score-circle {{ width: 150px; height: 150px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 3em; font-weight: bold; color: white; }}
        .score-details {{ flex: 1; margin-left: 30px; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-top: 20px; }}
        .stat-item {{ background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; }}
        .stat-value {{ font-size: 2em; font-weight: bold; }}
        .stat-label {{ color: #666; margin-top: 5px; }}
        .critical {{ color: #dc3545; }}
        .high {{ color: #fd7e14; }}
        .medium {{ color: #ffc107; }}
        .low {{ color: #28a745; }}
        .findings-section {{ background: white; border-radius: 10px; padding: 30px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .finding-item {{ border-left: 4px solid; padding: 20px; margin-bottom: 15px; background: #f8f9fa; border-radius: 5px; }}
        .finding-item.critical {{ border-color: #dc3545; }}
        .finding-item.high {{ border-color: #fd7e14; }}
        .finding-item.medium {{ border-color: #ffc107; }}
        .finding-item.low {{ border-color: #28a745; }}
        .finding-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }}
        .finding-title {{ font-weight: bold; font-size: 1.2em; }}
        .finding-severity {{ padding: 5px 15px; border-radius: 20px; color: white; font-size: 0.9em; }}
        .finding-meta {{ color: #666; font-size: 0.9em; margin-top: 10px; }}
        .footer {{ text-align: center; padding: 20px; color: #666; margin-top: 30px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Security Assessment Report</h1>
            <p>Target: {scan_data.get('target', 'Unknown')}</p>
            <p>Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>

        <div class="score-card">
            <h2>Security Score</h2>
            <div class="score-display">
                <div class="score-circle" style="background: {self._get_score_color(security_score.overall_score)};">
                    {security_score.overall_score}
                </div>
                <div class="score-details">
                    <h3>{security_score.rating}</h3>
                    <p>Security posture assessment based on {security_score.total_findings} vulnerabilities found.</p>
                    <div class="stats-grid">
                        <div class="stat-item">
                            <div class="stat-value critical">{security_score.critical_count}</div>
                            <div class="stat-label">Critical</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-value high">{security_score.high_count}</div>
                            <div class="stat-label">High</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-value medium">{security_score.medium_count}</div>
                            <div class="stat-label">Medium</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-value low">{security_score.low_count}</div>
                            <div class="stat-label">Low</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="findings-section">
            <h2>🔍 Vulnerability Findings</h2>
            <p>{len(findings)} vulnerabilities detected</p>
"""

        for finding in findings:
            severity = finding.get("severity", "low").lower()
            html_content += f"""
            <div class="finding-item {severity}">
                <div class="finding-header">
                    <span class="finding-title">{finding.get('title', 'Unknown Vulnerability')}</span>
                    <span class="finding-severity" style="background: {self._get_severity_color(severity)};">{severity.upper()}</span>
                </div>
                <p>{finding.get('description', 'No description available.')}</p>
                <div class="finding-meta">
                    <strong>URL:</strong> {finding.get('url', 'N/A')} |
                    <strong>CVSS:</strong> {finding.get('cvss_score', 0)} |
                    <strong>Category:</strong> {finding.get('category', 'N/A')}
                </div>
                {f"<p><strong>Remediation:</strong> {finding.get('remediation', 'N/A')}</p>" if finding.get('remediation') else ""}
            </div>
"""

        html_content += f"""
        </div>

        <div class="footer">
            <p>Generated by SecPenHub - Intelligent Penetration Testing Platform</p>
            <p>Report generated at {datetime.now().isoformat()}</p>
        </div>
    </div>
</body>
</html>"""

        # Save report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"security_report_{timestamp}.html"
        filepath = self.output_dir / filename

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)

        self.logger.info(f"HTML report saved to {filepath}")
        return str(filepath)

    def _generate_json(
        self,
        scan_data: Dict[str, Any],
        findings: List[Dict]
    ) -> str:
        """Generate JSON report."""
        from ..evaluator.risk_score import RiskCalculator

        calculator = RiskCalculator()
        security_score = calculator.calculate_security_score(findings)

        report = {
            "report_metadata": {
                "generated_at": datetime.now().isoformat(),
                "tool": "SecPenHub",
                "version": "1.0.0"
            },
            "scan_info": scan_data,
            "security_score": security_score.to_dict(),
            "findings": findings,
            "summary": {
                "total_findings": len(findings),
                "by_severity": {
                    "critical": security_score.critical_count,
                    "high": security_score.high_count,
                    "medium": security_score.medium_count,
                    "low": security_score.low_count
                }
            }
        }

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"security_report_{timestamp}.json"
        filepath = self.output_dir / filename

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        self.logger.info(f"JSON report saved to {filepath}")
        return str(filepath)

    def _generate_markdown(
        self,
        scan_data: Dict[str, Any],
        findings: List[Dict]
    ) -> str:
        """Generate Markdown report."""
        from ..evaluator.risk_score import RiskCalculator

        calculator = RiskCalculator()
        security_score = calculator.calculate_security_score(findings)

        md = f"""# 🔒 Security Assessment Report

## Target Information
- **Target**: {scan_data.get('target', 'Unknown')}
- **Scan Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- **Tool**: SecPenHub v1.0.0

## Security Score: {security_score.overall_score}/100 ({security_score.rating})

### Vulnerability Summary
| Severity | Count |
|----------|-------|
| 🔴 Critical | {security_score.critical_count} |
| 🟠 High | {security_score.high_count} |
| 🟡 Medium | {security_score.medium_count} |
| 🟢 Low | {security_score.low_count} |

## Findings

"""

        for i, finding in enumerate(findings, 1):
            severity = finding.get("severity", "low").lower()
            severity_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(severity, "⚪")

            md += f"""### {i}. {severity_emoji} {finding.get('title', 'Unknown Vulnerability')}

**Severity**: {severity.upper()} | **CVSS**: {finding.get('cvss_score', 0)} | **Category**: {finding.get('category', 'N/A')}

**URL**: `{finding.get('url', 'N/A')}`

**Description**: {finding.get('description', 'No description available.')}

{f"**Remediation**: {finding.get('remediation', 'N/A')}" if finding.get('remediation') else ""}

---

"""

        md += f"""
## Footer
*Report generated by SecPenHub - Intelligent Penetration Testing Platform*
"""

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"security_report_{timestamp}.md"
        filepath = self.output_dir / filename

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(md)

        self.logger.info(f"Markdown report saved to {filepath}")
        return str(filepath)

    def _get_score_color(self, score: float) -> str:
        """Get color for security score."""
        if score >= 90:
            return "#28a745"  # Green
        elif score >= 70:
            return "#6c757d"  # Gray
        elif score >= 50:
            return "#ffc107"  # Yellow
        elif score >= 30:
            return "#fd7e14"  # Orange
        else:
            return "#dc3545"  # Red

    def _get_severity_color(self, severity: str) -> str:
        """Get color for severity level."""
        colors = {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#28a745"
        }
        return colors.get(severity.lower(), "#6c757d")
