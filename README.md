# Memory Shell Detector MCP

基于 FastMCP 构建的 Java 内存马检测和清理工具 MCP 服务器，支持本地执行和 SSH 远程执行。

项目地址：https://github.com/RuoJi6/memory-shell-mcp

## 功能

| 功能 | 工具名称 | 对应命令 |
|------|----------|----------|
| 执行命令（本地/SSH） | `execute_command` | - |
| 下载检测工具 | `download_detector_tools` | - |
| 列出Java进程 | `list_java_processes` | `-l` |
| 扫描指定进程 | `scan_process` | `-s <PID>` |
| 查看可疑类代码 | `view_class_code` | `-v <类名> -p <PID>` |
| 移除内存马 | `remove_memory_shell` | `-r <类名> -p <PID>` |
| 导出检测报告 | `export_report` | `--report` |
| 获取系统信息 | `get_system_info_tool` | - |
| 检测网络状态 | `check_network` | - |

## 安全特性

- 移除内存马前会先获取源代码供 AI 分析确认
- 需要 AI 确认后（`ai_confirmed=True`）才会执行移除操作
- 自动处理移除确认提示

## 环境要求

- Python 3.10+
- JDK 1.8+（目标机器）
- uv（Python 包管理器）

---

## 快速开始（uvx 方式）

发布到 PyPI 后，直接使用 uvx 运行，无需安装：

```bash
uvx memory-shell-mcp
```

### MCP 配置（uvx 方式）

> **支持 MCP 的客户端**：本工具可配置到任何支持 Model Context Protocol 的 AI 客户端，包括但不限于：
> - **IDE/编辑器**：[Cursor](https://cursor.com)、[Windsurf](https://codeium.com/windsurf)、[VS Code](https://code.visualstudio.com)（需安装 Copilot 扩展）、[Zed](https://zed.dev)、[Kiro](https://kiro.dev)
> - **AI 助手**：[Claude Desktop](https://claude.ai/download)、[Claude Code](https://docs.anthropic.com/en/docs/claude-code)
> - **开发工具**：[Cline](https://github.com/cline/cline)（VS Code 扩展）、[Continue](https://continue.dev)、[Roo Code](https://roocode.com)
> - **其他**：[5ire](https://5ire.app)、[BeeAI](https://beeai.dev)、[Genkit](https://firebase.google.com/docs/genkit)、[Goose](https://block.github.io/goose)
>
> 以下是常用客户端的配置示例：

#### Kiro

在 `.kiro/settings/mcp.json` 中添加：

```json
{
  "mcpServers": {
    "memory-shell-detector": {
      "command": "uvx",
      "args": ["memory-shell-mcp"],
      "env": {},
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

#### Claude Desktop

在 `claude_desktop_config.json` 中添加：

```json
{
  "mcpServers": {
    "memory-shell-detector": {
      "command": "uvx",
      "args": ["memory-shell-mcp"],
      "env": {}
    }
  }
}
```

> **说明**：`env` 中的环境变量均为可选配置。不配置时，工具会下载到系统临时目录，SSH 参数可通过 AI 对话传入。

---

## 开发者模式（本地源码）

### 安装

```bash
git clone https://github.com/RuoJi6/memory-shell-mcp.git
cd memory-shell-mcp

# 创建虚拟环境并安装依赖
uv venv --python python3.12
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate   # Windows

uv pip install -e .
```

### 运行

```bash
# 激活虚拟环境后
memory-shell-mcp
```

### MCP 配置（开发者模式）

```json
{
  "mcpServers": {
    "memory-shell-detector": {
      "command": "uv",
      "args": [
        "run",
        "--directory",
        "/path/to/memory-shell-mcp",
        "memory-shell-mcp"
      ],
      "env": {}
    }
  }
}
```

> **说明**：`env` 中的环境变量均为可选配置。不配置时，工具会下载到系统临时目录，SSH 参数可通过 AI 对话传入。

---

## 环境变量说明（可选）

| 变量 | 说明 |
|------|------|
| `TOOLS_DIR` | 检测工具（JAR 文件）存放目录，不设置则下载到系统临时目录 |
| `SSH_HOST` | SSH 主机地址 |
| `SSH_USERNAME` | SSH 用户名 |
| `SSH_PASSWORD` | SSH 密码 |
| `SSH_KEY_PATH` | SSH 私钥路径（与密码二选一） |
| `SSH_PORT` | SSH 端口（默认 22） |
| `JAVA_HOME` | JDK 路径（可选） |

> - 所有环境变量均为可选，不配置也可正常使用
> - 设置环境变量后，调用工具时无需每次传入对应参数
> - 如果 `TOOLS_DIR` 目录中已存在工具文件，`download_detector_tools` 会跳过下载
> - SSH 参数也可以通过 AI 对话动态传入，优先级高于环境变量

---

## 使用流程

### 1. 下载检测工具

```
调用 download_detector_tools
- 不指定 tools_dir 则从 TOOLS_DIR 环境变量读取，都没有则下载到系统临时目录
- 会自动检测网络是否可用
- 如果工具已存在则跳过下载
```

### 2. 列出 Java 进程

```
调用 list_java_processes()
```

### 3. 扫描可疑进程

```
调用 scan_process(pid=进程ID)
```

### 4. 查看可疑类源代码

```
调用 view_class_code(class_name="类名", pid=进程ID)
```

### 5. 移除内存马

```
# 第一次调用：获取源代码供 AI 分析
调用 remove_memory_shell(class_name="类名", pid=进程ID)

# AI 确认后第二次调用：执行移除
调用 remove_memory_shell(class_name="类名", pid=进程ID, ai_confirmed=True)
```

---

## SSH 远程执行

### 方式1：环境变量预设

在 MCP 配置的 `env` 中设置：

```json
"env": {
  "TOOLS_DIR": "/your/tools/directory",
  "SSH_HOST": "192.168.1.100",
  "SSH_USERNAME": "root",
  "SSH_PASSWORD": "password"
}
```

调用时只需设置 `use_ssh=True`：

```
调用 scan_process(pid=12345, use_ssh=True)
```

### 方式2：AI 对话动态传入

直接告诉 AI SSH 连接信息：

```
调用 scan_process(
    pid=12345,
    use_ssh=True,
    ssh_host="192.168.1.100",
    ssh_username="root",
    ssh_password="password"
)
```

> 对话传入的参数优先级高于环境变量

---

## 工具下载地址

工具会自动从以下地址下载：

- Agent JAR: `https://xget.xi-xu.me/gh/RuoJi6/memory-shell-mcp/releases/download/1/detector-agent-1.0.0-SNAPSHOT.jar`
- CLI JAR: `https://xget.xi-xu.me/gh/RuoJi6/memory-shell-mcp/releases/download/1/memory-shell-detector-cli.jar`

## 支持系统

- Windows / Linux / macOS

## 风险等级说明

| 等级 | 说明 |
|------|------|
| CRITICAL | 确认为内存马，需立即处理 |
| HIGH | 高度可疑，建议人工确认 |
| MEDIUM | 中等风险，可能是正常组件 |
| LOW | 低风险，基本可排除 |
| SAFE | 安全，已在白名单中 |

## 注意事项

1. 扫描其他进程需要足够的系统权限
2. 目标进程和检测工具需使用相同或兼容的 JDK 版本
3. Agent JAR 需要和 CLI JAR 放在同一目录下
4. Agent 型内存马无法通过本工具移除，需要重启应用
5. 移除内存马可能影响应用正常运行，建议先备份

---

## 发布到 PyPI

```bash
# 1. 注册 PyPI 账号并获取 API Token
# https://pypi.org/manage/account/token/

# 2. 构建包
uv build

# 3. 发布到 PyPI
uv publish --token YOUR_PYPI_TOKEN

# 4. 发布后即可通过 uvx 运行
uvx memory-shell-mcp
```

## 参考项目

- [memory-shell-detector](https://github.com/private-xss/memory-shell-detector) - Java 内存马检测工具核心实现
- [Xget](https://github.com/xixu-me/Xget) - GitHub 文件加速下载服务

## License

MIT License
