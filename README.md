# ⚡ LSPTracer - 中文文档

LSPTracer 是一个轻量级静态应用安全测试 (SAST) 工具，核心基于 **Language Server Protocol (LSP)** 构建。

LSPTracer 利用标准的语言服务器（如 **Eclipse JDT.LS**），能够像 IDE 一样精准地理解代码结构、类型继承关系和引用图谱。

> **当前状态**: 完美支持 **Java**。
> **未来计划**: 架构设计通用，未来计划通过接入相应的 LSP 支持 **Golang**, **Python** 和 **JavaScript/TypeScript**。

## ✨ 核心特性

- **🚀 高精度分析**: 利用 IDE 级别的 LSP 协议精准解析方法调用、类继承和变量引用。
- **🛡️ 严格模式 (Strict Mode)**: 智能源过滤机制，仅报告源自有效框架入口点（如 `@RestController`, `@WebFilter`, `HttpServlet`）的漏洞链，极大降低误报噪音。
- **🧩 智能追踪**: 自动从 Sink（危险函数）反向追踪数据流至 Source（用户输入），生成完整的漏洞调用链。
- **🎨 可视化报告**: 生成精美的交互式 HTML 报告，包含完整代码片段、变量定义回溯和调用栈信息。
- **⚙️ 零配置启动**: 自动下载 JDT.LS，自动探测项目根目录，自动配置环境，开箱即用。
- **🛠️ 自定义规则**: 通过简单的 YAML 配置文件即可完全自定义漏洞扫描规则。

## 📦 安装说明

### 前置要求

- **Go** 1.18+
- **JDK** 11 or 17+ (运行 JDT.LS 所需)
- **Maven/Gradle** (目标项目需能被构建)

### 编译安装

```bash
git clone https://github.com/0xr1ngs/LSPTracer.git
cd LSPTracer
go build -o lsptracer cmd/scanner/main.go
```

## 🚀 使用指南

### 1. 基础扫描

对 Java 项目运行扫描。LSPTracer 会自动初始化分析服务并开始扫描。

```bash
./lsptracer -project /path/to/your/java/project
```

### 2. 严格模式 (推荐)

启用 **Strict Mode** 以过滤“孤儿”链。该模式确保报告的漏洞都源自可信的外部入口（如 Controller, Filter, Listener），忽略那些无法从外部直接访问的内部工具类方法。

```bash
./lsptracer -project /path/to/your/java/project -strict
```

### 3. 指定自定义规则

指定自定义规则文件（格式参考 `rules.yaml`）。

```bash
./lsptracer -project /path/to/project -rules my-rules.yaml
```

### 4. 单点狙击模式 (Sink 验证)

针对特定文件和行号进行分析，用于快速验证某个 Sink 点是否可达。

```bash
# 格式: 文件路径:行号
./lsptracer -project /path/to/project -file src/main/java/com/example/Vuln.java:42
```

## 📝 配置规则 (rules.yaml)

LSPTracer 使用 YAML 格式的规则引擎。您可以添加新的 Sink 定义或禁用现有规则。

示例配置：

```yaml
rules:
  - vuln_type: "RCE"
    desc: "Remote Code Execution via Runtime"
    severity: "High"
    class_name: "java.lang.Runtime"
    method_name: "exec"
    skip_safe: true        # Skip if arguments are constants (忽略常量参数)
    is_static: false

  - vuln_type: "SQLI"
    desc: "SQL Injection"
    severity: "High"
    class_name: "java.sql.Statement"
    method_name: "executeQuery"
```

## 🏗️ 架构概览

1.  **初始化**: 启动无头模式的 Eclipse JDT.LS 实例，模拟 IDE 客户端行为。
2.  **索引**: 发送 `initialize` 和 `didOpen` 事件，触发全量项目编译和索引建立。
3.  **扫描**:
    *   **阶段 1 (搜索)**: 使用正则/文本搜索初步筛选 "Sink" 候选点。
    *   **阶段 2 (验证)**: 通过 LSP 请求解析候选点符号，验证其是否精确匹配目标类/方法的签名。
    *   **阶段 3 (追踪)**: 递归执行“反向引用查找 (Find References)”，沿调用栈向上回溯。
4.  **报告**: 聚合已验证的漏洞链，生成 HTML 报告。

## ⚠️ 免责声明

本工具仅供**安全研究和授权测试**使用。请勿用于未授权的系统测试。作者不对任何滥用行为负责。
