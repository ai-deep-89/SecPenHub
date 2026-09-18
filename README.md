# SecPenHub - Intelligent Penetration Testing & Security Assessment Platform

<p align="center">
  <img src="docs/logo.png" alt="SecPenHub Logo" width="200"/>
</p>

<p align="center">
  <a href="https://img.shields.io/badge/Python-3.10+-blue.svg">
    <img src="https://img.shields.io/badge/Python-3.10+-blue.svg" alt="Python Version">
  </a>
  <a href="https://img.shields.io/badge/License-MIT-green.svg">
    <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  </a>
  <a href="https://img.shields.io/badge/OWASP-Top%2010-orange.svg">
    <img src="https://img.shields.io/badge/OWASP-Top%2010-orange.svg" alt="OWASP Top 10">
  </a>
</p>

## Overview

**SecPenHub** (Security Penetration Hub) is an AI-powered penetration testing framework that combines Web application security scanning, network reconnaissance, and intelligent vulnerability analysis into a unified platform. It provides quantifiable security assessments with comprehensive reporting.

### Key Features

- 🕵️ **资产收集 (Asset Reconnaissance)**: Subdomain enumeration, port scanning, service fingerprinting
- 🔍 **Web安全扫描**: OWASP Top 10 vulnerability detection with AI-assisted analysis
- 🤖 **AI Agent Core**: Intelligent attack planning and vulnerability prioritization
- 📊 **量化评估 (Quantified Assessment)**: CVSS scoring, risk analysis, compliance mapping
- 📈 **可视化报告**: Executive summaries and technical details with remediation guidance
- 🔌 **插件系统**: Extensible harnesses and Burp Suite integration

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/bifu-kuku/SecPenHub.git
cd SecPenHub

# Install dependencies
pip install -r requirements.txt

# Run the platform
python main.py --target https://example.com --scan owasp
```

### Basic Usage

```python
from secpenhub import SecPenHub

# Initialize the scanner
scanner = SecPenHub(target="https://example.com")

# Run a comprehensive scan
results = scanner.scan(mode="full")

# Generate report
scanner.generate_report(format="html")
```

## Architecture

```
SecPenHub
├── core/                 # Core engine
│   ├── config.py        # Configuration management
│   ├── logger.py        # Logging utilities
│   └── database.py      # SQLite database
├── modules/
│   ├── recon/           # Asset reconnaissance
│   │   ├── subdomain.py
│   │   ├── portscan.py
│   │   └── fingerprint.py
│   ├── scanner/         # Web vulnerability scanner
│   │   ├── owasp_top10.py
│   │   ├── sql_injection.py
│   │   ├── xss.py
│   │   └── csrf.py
│   ├── ai_agent/        # AI Agent framework
│   │   ├── agent.py
│   │   ├── harness.py
│   │   └── planner.py
│   ├── evaluator/       # Security evaluation
│   │   ├── cvss.py
│   │   └── risk_score.py
│   ├── reporter/        # Report generation
│   │   └── generator.py
│   └── plugins/         # Plugin system
│       └── burp_adapter.py
├── tests/               # Unit tests
├── docs/                # Documentation
└── examples/            # Usage examples
```

## Security Assessment Score

SecPenHub calculates a comprehensive security score based on:

```
Security Score = Σ(Vulnerability_Score × Exploitability × Impact) / Max_Possible_Score × 100
```

### Score Interpretation

| Score Range | Rating | Description |
|------------|--------|-------------|
| 90-100 | 🟢 Excellent | Strong security posture |
| 70-89 | 🟡 Good | Minor vulnerabilities detected |
| 50-69 | 🟠 Fair | Moderate risk, remediation recommended |
| 30-49 | 🔴 Poor | Significant vulnerabilities, action required |
| 0-29 | 🚨 Critical | Critical vulnerabilities, immediate action needed |

## OWASP Top 10 Coverage

| Category | Status | Module |
|----------|--------|--------|
| A01: Broken Access Control | ✅ | `scanner/auth.py` |
| A02: Cryptographic Failures | ✅ | `scanner/crypto.py` |
| A03: Injection | ✅ | `scanner/sql_injection.py` |
| A04: Insecure Design | ✅ | `scanner/design.py` |
| A05: Security Misconfiguration | ✅ | `scanner/config.py` |
| A06: Vulnerable Components | ✅ | `scanner/components.py` |
| A07: Auth Failures | ✅ | `scanner/auth.py` |
| A08: Data Integrity | ✅ | `scanner/integrity.py` |
| A09: Logging Failures | ✅ | `scanner/logging.py` |
| A10: SSRF | ✅ | `scanner/ssrf.py` |

## AI Agent Integration

SecPenHub uses AI agents to enhance penetration testing:

### Available Agents

1. **Attack Planning Agent**: Analyzes target and plans optimal attack path
2. **Vulnerability Analysis Agent**: Prioritizes and validates findings
3. **Report Generation Agent**: Creates comprehensive security reports

### Harness System

The harness system allows custom extensions:

```python
from secpenhub.modules.ai_agent import Harness

class MyHarness(Harness):
    name = "custom_scan"
    
    def execute(self, context):
        # Custom scanning logic
        pass
```

## Documentation

- [Detailed Explanation](docs/detailed-explanation.md) - Comprehensive project documentation
- [API Reference](docs/api.md) - API documentation
- [Usage Examples](examples/) - Example scripts and use cases

## Contributing

Contributions are welcome! Please read our contributing guidelines before submitting PRs.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- OWASP Foundation for security standards
- Contributors of open-source security tools
- Security research community

---

**⚠️ Disclaimer**: SecPenHub is designed for authorized security testing only. Always obtain proper authorization before scanning any target.
