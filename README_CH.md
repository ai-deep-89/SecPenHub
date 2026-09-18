# SecPenHub - 智能渗透测试与安全评估平台

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

## 概述

**SecPenHub** (Security Penetration Hub) 是一个AI驱动的渗透测试框架，将Web应用安全扫描、网络侦察和智能漏洞分析统一集成在单一平台中。它提供可量化的安全评估和全面的报告功能。

### 核心特性

- 🕵️ **资产收集**: 子域名枚举、端口扫描、服务指纹识别
- 🔍 **Web安全扫描**: 基于AI辅助分析的OWASP Top 10漏洞检测
- 🤖 **AI Agent核心**: 智能攻击规划和漏洞优先级排序
- 📊 **量化评估**: CVSS评分、风险分析、合规映射
- 📈 **可视化报告**: 执行摘要和技术细节，包含修复建议
- 🔌 **插件系统**: 可扩展的Harness和Burp Suite集成

## 快速开始

### 安装

```bash
# 克隆仓库
git clone https://github.com/bifu-kuku/SecPenHub.git
cd SecPenHub

# 安装依赖
pip install -r requirements.txt

# 运行平台
python main.py --target https://example.com --scan owasp
```

## 安全评估分数

SecPenHub基于以下公式计算综合安全分数：

```
安全分数 = Σ(漏洞分数 × 可利用性 × 影响) / 最大可能分数 × 100
```

### 分数解读

| 分数范围 | 评级 | 描述 |
|---------|------|------|
| 90-100 | 🟢 优秀 | 安全性态势强 |
| 70-89 | 🟡 良好 | 检测到轻微漏洞 |
| 50-69 | 🟠 一般 | 中等风险，建议修复 |
| 30-49 | 🔴 较差 | 存在显著漏洞，需要处理 |
| 0-29 | 🚨 严重 | 严重漏洞，需立即处理 |

## OWASP Top 10覆盖

| 类别 | 状态 | 模块 |
|------|------|------|
| A01: 访问控制失效 | ✅ | `scanner/auth.py` |
| A02: 加密失败 | ✅ | `scanner/crypto.py` |
| A03: 注入 | ✅ | `scanner/sql_injection.py` |
| A04: 不安全设计 | ✅ | `scanner/design.py` |
| A05: 安全配置错误 | ✅ | `scanner/config.py` |
| A06: 易受攻击的组件 | ✅ | `scanner/components.py` |
| A07: 认证和授权失败 | ✅ | `scanner/auth.py` |
| A08: 数据完整性问题 | ✅ | `scanner/integrity.py` |
| A09: 日志和监控失败 | ✅ | `scanner/logging.py` |
| A10: 服务器端请求伪造 | ✅ | `scanner/ssrf.py` |

## AI Agent集成

SecPenHub使用AI Agent来增强渗透测试：

1. **攻击规划Agent**: 分析目标并规划最优攻击路径
2. **漏洞分析Agent**: 优先排序和验证发现
3. **报告生成Agent**: 创建全面的安全报告

## 文档

- [详细说明](docs/detailed-explanation.md) - 完整的项目文档
- [API参考](docs/api.md) - API文档
- [使用示例](examples/) - 示例脚本和使用案例

## 许可证

MIT许可证 - 详见 [LICENSE](LICENSE)。

## 免责声明

SecPenHub仅设计用于授权的安全测试。在扫描任何目标之前，请务必获得适当授权。
