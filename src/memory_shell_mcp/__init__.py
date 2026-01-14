#!/usr/bin/env python3
"""
内存马检测/清理 MCP 服务器
Memory Shell Detector MCP Server

功能：
1. 本地执行命令
2. SSH远程连接执行命令
3. 下载检测工具
4. 列出Java进程 (-l)
5. 扫描指定进程 (-s)
6. 查看可疑类代码 (-v -p)
7. 移除内存马 (-r -p)
"""

import os
import platform
import subprocess
import tempfile
from typing import Optional
from fastmcp import FastMCP

__version__ = "0.1.3"

# 创建MCP服务器实例
mcp = FastMCP(
    name="memory-shell-detector",
    instructions="""
    这是一个Java内存马检测和清理工具的MCP服务器。
    
    使用流程：
    1. 首先使用 download_detector_tools 下载检测工具（或指定本地工具目录）
    2. 使用 list_java_processes 列出Java进程
    3. 使用 scan_process 扫描可疑进程
    4. 使用 view_class_code 查看可疑类的源代码
    5. 使用 remove_memory_shell 移除确认的内存马（会先获取源码让AI判断）
    
    支持本地执行和SSH远程执行两种模式。
    """
)

# 工具下载地址
DETECTOR_AGENT_URL = "https://xget.xi-xu.me/gh/RuoJi6/memory-shell-mcp/releases/download/1/detector-agent-1.0.0-SNAPSHOT.jar"
DETECTOR_CLI_URL = "https://xget.xi-xu.me/gh/RuoJi6/memory-shell-mcp/releases/download/1/memory-shell-detector-cli.jar"


def get_ssh_config() -> dict:
    """从环境变量获取SSH配置"""
    return {
        "host": os.environ.get("SSH_HOST"),
        "username": os.environ.get("SSH_USERNAME"),
        "password": os.environ.get("SSH_PASSWORD"),
        "key_path": os.environ.get("SSH_KEY_PATH"),
        "port": int(os.environ.get("SSH_PORT", 22))
    }


def resolve_ssh_params(
    ssh_host: Optional[str],
    ssh_username: Optional[str],
    ssh_password: Optional[str],
    ssh_key_path: Optional[str],
    ssh_port: int
) -> tuple:
    """解析SSH参数，优先使用传入值，否则从环境变量读取"""
    ssh_config = get_ssh_config()
    return (
        ssh_host or ssh_config["host"],
        ssh_username or ssh_config["username"],
        ssh_password or ssh_config["password"],
        ssh_key_path or ssh_config["key_path"],
        ssh_port if ssh_port != 22 else ssh_config["port"]
    )


def get_temp_dir() -> str:
    """获取系统临时目录"""
    return tempfile.gettempdir()

def get_system_info() -> dict:
    """获取系统信息"""
    return {
        "system": platform.system(),
        "platform": platform.platform(),
        "machine": platform.machine(),
    }


def escape_class_name(class_name: str, for_windows: bool = False) -> str:
    """
    转义类名中的特殊字符，防止 shell 解释
    
    Java 内部类使用 $ 分隔符（如 com.example.Outer$Inner），
    但 $ 在 Unix shell 中是变量引用符号，需要转义。
    Windows cmd/PowerShell 中 $ 不需要转义。
    
    Args:
        class_name: Java 完整类名
        for_windows: 是否为 Windows 系统
    
    Returns:
        转义后的类名
    """
    if for_windows:
        # Windows cmd 中 $ 不是特殊字符，无需转义
        return class_name
    else:
        # Unix shell (bash/zsh) 中需要转义 $
        return class_name.replace("$", "\\$")

def execute_local_command(command: str, timeout: int = 300) -> dict:
    """本地执行命令"""
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "return_code": result.returncode
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "stdout": "",
            "stderr": f"命令执行超时（{timeout}秒）",
            "return_code": -1
        }
    except Exception as e:
        return {
            "success": False,
            "stdout": "",
            "stderr": str(e),
            "return_code": -1
        }

def execute_ssh_command(
    host: str,
    username: str,
    command: str,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    port: int = 22,
    timeout: int = 300
) -> dict:
    """SSH远程执行命令"""
    try:
        import paramiko
        
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        connect_kwargs = {
            "hostname": host,
            "port": port,
            "username": username,
            "timeout": 30
        }
        
        if key_path and os.path.exists(key_path):
            connect_kwargs["key_filename"] = key_path
        elif password:
            connect_kwargs["password"] = password
        else:
            return {
                "success": False,
                "stdout": "",
                "stderr": "需要提供密码或SSH密钥路径",
                "return_code": -1
            }
        
        client.connect(**connect_kwargs)
        
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        
        stdout_str = stdout.read().decode('utf-8', errors='replace')
        stderr_str = stderr.read().decode('utf-8', errors='replace')
        return_code = stdout.channel.recv_exit_status()
        
        client.close()
        
        return {
            "success": return_code == 0,
            "stdout": stdout_str,
            "stderr": stderr_str,
            "return_code": return_code
        }
    except Exception as e:
        return {
            "success": False,
            "stdout": "",
            "stderr": str(e),
            "return_code": -1
        }

def get_download_command(url: str, output_path: str) -> str:
    """根据系统获取下载命令"""
    system = platform.system().lower()
    
    if system == "windows":
        return f'curl -L -o "{output_path}" "{url}" || powershell -Command "Invoke-WebRequest -Uri \'{url}\' -OutFile \'{output_path}\'"'
    else:
        return f'curl -L -o "{output_path}" "{url}" || wget -O "{output_path}" "{url}"'

def check_network_available(test_url: str = "https://xget.xi-xu.me") -> dict:
    """检测网络是否可用"""
    system = platform.system().lower()
    
    if system == "windows":
        cmd = f'curl -s -o nul -w "%{{http_code}}" --connect-timeout 10 "{test_url}" || powershell -Command "(Invoke-WebRequest -Uri \'{test_url}\' -TimeoutSec 10 -UseBasicParsing).StatusCode"'
    else:
        cmd = f'curl -s -o /dev/null -w "%{{http_code}}" --connect-timeout 10 "{test_url}" 2>/dev/null || wget -q --spider --timeout=10 "{test_url}" && echo "200"'
    
    result = execute_local_command(cmd, timeout=30)
    
    if result["success"] or "200" in result["stdout"]:
        return {"available": True, "message": "网络连接正常"}
    else:
        return {"available": False, "message": f"网络连接失败: {result['stderr']}"}


@mcp.tool()
def execute_command(
    command: str,
    use_ssh: bool = False,
    ssh_host: Optional[str] = None,
    ssh_username: Optional[str] = None,
    ssh_password: Optional[str] = None,
    ssh_key_path: Optional[str] = None,
    ssh_port: int = 22,
    timeout: int = 300
) -> dict:
    """
    执行系统命令（本地或通过 SSH 远程执行）
    
    这是一个通用的命令执行工具，可用于：
    - 检查 Java 环境是否正常（java -version）
    - 查看系统进程状态（ps aux）
    - 执行其他辅助命令
    
    注意：内存马检测的核心功能请使用专用工具（list_java_processes、scan_process 等），
    此工具仅用于辅助操作。
    
    Args:
        command: 要执行的 shell 命令
        use_ssh: 是否使用 SSH 远程执行
        ssh_host: SSH 主机地址（不指定则从环境变量 SSH_HOST 读取）
        ssh_username: SSH 用户名（不指定则从环境变量 SSH_USERNAME 读取）
        ssh_password: SSH 密码（不指定则从环境变量 SSH_PASSWORD 读取）
        ssh_key_path: SSH 私钥路径（不指定则从环境变量 SSH_KEY_PATH 读取）
        ssh_port: SSH 端口，默认 22（不指定则从环境变量 SSH_PORT 读取）
        timeout: 命令超时时间（秒），默认 300 秒
    
    Returns:
        执行结果，包含 success、stdout、stderr、return_code
    """
    if use_ssh:
        ssh_config = get_ssh_config()
        ssh_host = ssh_host or ssh_config["host"]
        ssh_username = ssh_username or ssh_config["username"]
        ssh_password = ssh_password or ssh_config["password"]
        ssh_key_path = ssh_key_path or ssh_config["key_path"]
        ssh_port = ssh_port if ssh_port != 22 else ssh_config["port"]
        
        if not ssh_host or not ssh_username:
            return {
                "success": False,
                "stdout": "",
                "stderr": "SSH模式需要提供ssh_host和ssh_username，或设置SSH_HOST和SSH_USERNAME环境变量",
                "return_code": -1
            }
        return execute_ssh_command(
            host=ssh_host,
            username=ssh_username,
            command=command,
            password=ssh_password,
            key_path=ssh_key_path,
            port=ssh_port,
            timeout=timeout
        )
    else:
        return execute_local_command(command, timeout)


@mcp.tool()
def download_detector_tools(
    tools_dir: Optional[str] = None,
    use_ssh: bool = False,
    ssh_host: Optional[str] = None,
    ssh_username: Optional[str] = None,
    ssh_password: Optional[str] = None,
    ssh_key_path: Optional[str] = None,
    ssh_port: int = 22
) -> dict:
    """
    下载 Java 内存马检测工具包（detector-agent.jar 和 detector-cli.jar）
    
    此工具会下载两个核心 jar 包：
    - detector-agent-1.0.0-SNAPSHOT.jar: Java Agent，用于注入目标 JVM 进程
    - memory-shell-detector-cli.jar: 命令行工具，提供扫描、反编译、移除等功能
    
    这是使用内存马检测功能的前置步骤，下载完成后才能执行后续的扫描和分析操作。
    
    Args:
        tools_dir: 工具存放目录，不指定则从环境变量 TOOLS_DIR 读取，都没有则使用系统临时目录
        use_ssh: 是否在远程服务器上下载
        ssh_host: SSH 主机地址（不指定则从环境变量 SSH_HOST 读取）
        ssh_username: SSH 用户名（不指定则从环境变量 SSH_USERNAME 读取）
        ssh_password: SSH 密码（不指定则从环境变量 SSH_PASSWORD 读取）
        ssh_key_path: SSH 私钥路径（不指定则从环境变量 SSH_KEY_PATH 读取）
        ssh_port: SSH 端口（不指定则从环境变量 SSH_PORT 读取）
    
    Returns:
        下载结果，包含工具目录路径和 jar 文件名
    """
    if use_ssh:
        ssh_host, ssh_username, ssh_password, ssh_key_path, ssh_port = resolve_ssh_params(
            ssh_host, ssh_username, ssh_password, ssh_key_path, ssh_port
        )
        if not ssh_host or not ssh_username:
            return {"success": False, "message": "SSH模式需要提供ssh_host和ssh_username，或设置SSH_HOST和SSH_USERNAME环境变量", "tools_dir": None}
    
    if tools_dir:
        target_dir = tools_dir
    elif os.environ.get("TOOLS_DIR"):
        target_dir = os.environ.get("TOOLS_DIR")
    else:
        if use_ssh:
            target_dir = "/tmp/memory-shell-detector"
        else:
            target_dir = os.path.join(get_temp_dir(), "memory-shell-detector")
    
    agent_jar_name = "detector-agent-1.0.0-SNAPSHOT.jar"
    cli_jar_name = "memory-shell-detector-cli.jar"
    
    if not use_ssh:
        agent_path = os.path.join(target_dir, agent_jar_name)
        cli_path = os.path.join(target_dir, cli_jar_name)
        
        if os.path.exists(agent_path) and os.path.exists(cli_path):
            return {
                "success": True,
                "message": "工具已存在，无需下载",
                "tools_dir": target_dir,
                "agent_jar": agent_jar_name,
                "cli_jar": cli_jar_name
            }
    else:
        check_cmd = f'test -f "{target_dir}/{agent_jar_name}" && test -f "{target_dir}/{cli_jar_name}" && echo "exists"'
        result = execute_ssh_command(
            host=ssh_host,
            username=ssh_username,
            command=check_cmd,
            password=ssh_password,
            key_path=ssh_key_path,
            port=ssh_port
        )
        if "exists" in result["stdout"]:
            return {
                "success": True,
                "message": "工具已存在，无需下载",
                "tools_dir": target_dir,
                "agent_jar": agent_jar_name,
                "cli_jar": cli_jar_name
            }
    
    if not use_ssh:
        network_check = check_network_available()
        if not network_check["available"]:
            return {
                "success": False,
                "message": f"网络检测失败: {network_check['message']}",
                "tools_dir": None
            }
    
    if use_ssh:
        mkdir_cmd = f"mkdir -p {target_dir}"
        agent_path = f"{target_dir}/detector-agent-1.0.0-SNAPSHOT.jar"
        cli_path = f"{target_dir}/memory-shell-detector-cli.jar"
        
        download_agent_cmd = f'curl -L -o "{agent_path}" "{DETECTOR_AGENT_URL}" || wget -O "{agent_path}" "{DETECTOR_AGENT_URL}"'
        download_cli_cmd = f'curl -L -o "{cli_path}" "{DETECTOR_CLI_URL}" || wget -O "{cli_path}" "{DETECTOR_CLI_URL}"'
        
        result = execute_ssh_command(host=ssh_host, username=ssh_username, command=mkdir_cmd, password=ssh_password, key_path=ssh_key_path, port=ssh_port)
        if not result["success"]:
            return {"success": False, "message": f"创建目录失败: {result['stderr']}", "tools_dir": None}
        
        result = execute_ssh_command(host=ssh_host, username=ssh_username, command=download_agent_cmd, password=ssh_password, key_path=ssh_key_path, port=ssh_port, timeout=120)
        if not result["success"]:
            return {"success": False, "message": f"下载detector-agent失败: {result['stderr']}", "tools_dir": None}
        
        result = execute_ssh_command(host=ssh_host, username=ssh_username, command=download_cli_cmd, password=ssh_password, key_path=ssh_key_path, port=ssh_port, timeout=120)
        if not result["success"]:
            return {"success": False, "message": f"下载detector-cli失败: {result['stderr']}", "tools_dir": None}
    else:
        os.makedirs(target_dir, exist_ok=True)
        
        agent_path = os.path.join(target_dir, "detector-agent-1.0.0-SNAPSHOT.jar")
        cli_path = os.path.join(target_dir, "memory-shell-detector-cli.jar")
        
        download_cmd = get_download_command(DETECTOR_AGENT_URL, agent_path)
        result = execute_local_command(download_cmd, timeout=120)
        if not result["success"] and not os.path.exists(agent_path):
            return {"success": False, "message": f"下载detector-agent失败: {result['stderr']}", "tools_dir": None}
        
        download_cmd = get_download_command(DETECTOR_CLI_URL, cli_path)
        result = execute_local_command(download_cmd, timeout=120)
        if not result["success"] and not os.path.exists(cli_path):
            return {"success": False, "message": f"下载detector-cli失败: {result['stderr']}", "tools_dir": None}
    
    return {
        "success": True,
        "message": "工具下载完成",
        "tools_dir": target_dir,
        "agent_jar": "detector-agent-1.0.0-SNAPSHOT.jar",
        "cli_jar": "memory-shell-detector-cli.jar"
    }


@mcp.tool()
def list_java_processes(
    tools_dir: Optional[str] = None,
    use_ssh: bool = False,
    ssh_host: Optional[str] = None,
    ssh_username: Optional[str] = None,
    ssh_password: Optional[str] = None,
    ssh_key_path: Optional[str] = None,
    ssh_port: int = 22
) -> dict:
    """
    执行 memory-shell-detector-cli.jar 列出系统中所有运行的 Java 进程
    
    底层命令: java -jar memory-shell-detector-cli.jar -l
    
    此工具通过调用内存马检测器的 CLI jar 包，扫描系统中所有 Java 进程，
    返回进程 PID、进程名称等信息，用于后续选择目标进程进行内存马扫描。
    
    Args:
        tools_dir: 检测工具 jar 包所在目录
        use_ssh: 是否通过 SSH 在远程服务器执行
        ssh_host/ssh_username/ssh_password/ssh_key_path/ssh_port: SSH 连接参数
    
    Returns:
        processes: Java 进程列表信息
    """
    if use_ssh:
        ssh_host, ssh_username, ssh_password, ssh_key_path, ssh_port = resolve_ssh_params(
            ssh_host, ssh_username, ssh_password, ssh_key_path, ssh_port
        )
        if not ssh_host or not ssh_username:
            return {"success": False, "processes": "", "error": "SSH模式需要提供ssh_host和ssh_username，或设置SSH_HOST和SSH_USERNAME环境变量"}
    
    if not tools_dir:
        tools_dir = os.environ.get("TOOLS_DIR")
    if not tools_dir:
        return {"success": False, "processes": "", "error": "未指定tools_dir，请先调用download_detector_tools或设置TOOLS_DIR环境变量"}
    
    cli_jar = os.path.join(tools_dir, "memory-shell-detector-cli.jar") if not use_ssh else f"{tools_dir}/memory-shell-detector-cli.jar"
    cmd = f'java -jar "{cli_jar}" -l'
    
    if use_ssh:
        result = execute_ssh_command(host=ssh_host, username=ssh_username, command=cmd, password=ssh_password, key_path=ssh_key_path, port=ssh_port)
    else:
        result = execute_local_command(cmd)
    
    return {"success": result["success"], "processes": result["stdout"], "error": result["stderr"] if not result["success"] else None}


@mcp.tool()
def scan_process(
    pid: int,
    tools_dir: Optional[str] = None,
    use_ssh: bool = False,
    ssh_host: Optional[str] = None,
    ssh_username: Optional[str] = None,
    ssh_password: Optional[str] = None,
    ssh_key_path: Optional[str] = None,
    ssh_port: int = 22
) -> dict:
    """
    执行 memory-shell-detector-cli.jar 对指定 Java 进程进行内存马扫描检测
    
    底层命令: java -jar memory-shell-detector-cli.jar -s <pid>
    
    此工具通过 Java Agent 技术注入目标 JVM 进程，扫描以下可疑组件：
    - Servlet/Filter/Listener 类型内存马
    - Spring Controller/Interceptor 内存马
    - Agent 类型内存马
    - 其他动态注册的恶意类
    
    扫描结果会列出所有可疑类的完整类名，供后续反编译分析。
    
    Args:
        pid: 目标 Java 进程的 PID
        tools_dir: 检测工具 jar 包所在目录
        use_ssh: 是否通过 SSH 在远程服务器执行
        ssh_host/ssh_username/ssh_password/ssh_key_path/ssh_port: SSH 连接参数
    
    Returns:
        scan_result: 扫描结果，包含可疑类列表
    """
    if use_ssh:
        ssh_host, ssh_username, ssh_password, ssh_key_path, ssh_port = resolve_ssh_params(
            ssh_host, ssh_username, ssh_password, ssh_key_path, ssh_port
        )
        if not ssh_host or not ssh_username:
            return {"success": False, "scan_result": "", "error": "SSH模式需要提供ssh_host和ssh_username，或设置SSH_HOST和SSH_USERNAME环境变量"}
    
    if not tools_dir:
        tools_dir = os.environ.get("TOOLS_DIR")
    if not tools_dir:
        return {"success": False, "scan_result": "", "error": "未指定tools_dir，请先调用download_detector_tools或设置TOOLS_DIR环境变量"}
    
    cli_jar = os.path.join(tools_dir, "memory-shell-detector-cli.jar") if not use_ssh else f"{tools_dir}/memory-shell-detector-cli.jar"
    cmd = f'java -jar "{cli_jar}" -s {pid}'
    
    if use_ssh:
        result = execute_ssh_command(host=ssh_host, username=ssh_username, command=cmd, password=ssh_password, key_path=ssh_key_path, port=ssh_port, timeout=600)
    else:
        result = execute_local_command(cmd, timeout=600)
    
    return {"success": result["success"], "scan_result": result["stdout"], "error": result["stderr"] if not result["success"] else None}


@mcp.tool()
def view_class_code(
    class_name: str,
    pid: int,
    tools_dir: Optional[str] = None,
    use_ssh: bool = False,
    ssh_host: Optional[str] = None,
    ssh_username: Optional[str] = None,
    ssh_password: Optional[str] = None,
    ssh_key_path: Optional[str] = None,
    ssh_port: int = 22
) -> dict:
    """
    执行 memory-shell-detector-cli.jar 从 JVM 内存中提取并反编译指定类的字节码
    
    底层命令: java -jar memory-shell-detector-cli.jar -v <class_name> -p <pid>
    
    此工具通过 Java Agent 从运行中的 JVM 进程内存中 dump 指定类的字节码，
    然后使用内置反编译器将字节码还原为可读的 Java 源代码。
    
    这是分析内存马的关键步骤，可以查看：
    - 类的完整实现逻辑
    - 恶意代码的具体行为（如命令执行、文件操作、网络连接等）
    - 内存马的注入方式和触发条件
    
    Args:
        class_name: 要反编译的完整类名（如 com.example.EvilFilter）
        pid: 目标 Java 进程的 PID
        tools_dir: 检测工具 jar 包所在目录
        use_ssh: 是否通过 SSH 在远程服务器执行
        ssh_host/ssh_username/ssh_password/ssh_key_path/ssh_port: SSH 连接参数
    
    Returns:
        source_code: 反编译后的 Java 源代码
    """
    if use_ssh:
        ssh_host, ssh_username, ssh_password, ssh_key_path, ssh_port = resolve_ssh_params(
            ssh_host, ssh_username, ssh_password, ssh_key_path, ssh_port
        )
        if not ssh_host or not ssh_username:
            return {"success": False, "source_code": "", "error": "SSH模式需要提供ssh_host和ssh_username，或设置SSH_HOST和SSH_USERNAME环境变量"}
    
    if not tools_dir:
        tools_dir = os.environ.get("TOOLS_DIR")
    if not tools_dir:
        return {"success": False, "source_code": "", "error": "未指定tools_dir，请先调用download_detector_tools或设置TOOLS_DIR环境变量"}
    
    cli_jar = os.path.join(tools_dir, "memory-shell-detector-cli.jar") if not use_ssh else f"{tools_dir}/memory-shell-detector-cli.jar"
    # SSH 连接到远程服务器通常是 Linux，本地执行根据当前系统判断
    is_windows = not use_ssh and platform.system().lower() == "windows"
    escaped_class_name = escape_class_name(class_name, for_windows=is_windows)
    cmd = f'java -jar "{cli_jar}" -v {escaped_class_name} -p {pid}'
    
    if use_ssh:
        result = execute_ssh_command(host=ssh_host, username=ssh_username, command=cmd, password=ssh_password, key_path=ssh_key_path, port=ssh_port)
    else:
        result = execute_local_command(cmd)
    
    return {"success": result["success"], "source_code": result["stdout"], "error": result["stderr"] if not result["success"] else None}


@mcp.tool()
def remove_memory_shell(
    class_name: str,
    pid: int,
    tools_dir: Optional[str] = None,
    ai_confirmed: bool = False,
    use_ssh: bool = False,
    ssh_host: Optional[str] = None,
    ssh_username: Optional[str] = None,
    ssh_password: Optional[str] = None,
    ssh_key_path: Optional[str] = None,
    ssh_port: int = 22
) -> dict:
    """
    执行 memory-shell-detector-cli.jar 从 JVM 内存中移除指定的内存马类
    
    底层命令: java -jar memory-shell-detector-cli.jar -r <class_name> -p <pid>
    
    此工具通过 Java Agent 技术从运行中的 JVM 进程中卸载/禁用指定的恶意类，
    实现不重启服务的情况下清除内存马。
    
    移除机制：
    - 对于 Filter/Servlet/Listener：从 Web 容器中注销
    - 对于 Spring 组件：从 Spring 容器中移除 Bean
    - 对于 Agent 类型：尝试还原被 hook 的方法
    
    安全机制：首次调用时会先反编译目标类源码供 AI 分析确认，
    确认是内存马后需设置 ai_confirmed=True 再次调用才会执行移除。
    
    Args:
        class_name: 要移除的内存马完整类名
        pid: 目标 Java 进程的 PID
        tools_dir: 检测工具 jar 包所在目录
        ai_confirmed: AI 是否已确认该类为内存马（首次调用设为 False）
        use_ssh: 是否通过 SSH 在远程服务器执行
        ssh_host/ssh_username/ssh_password/ssh_key_path/ssh_port: SSH 连接参数
    
    Returns:
        首次调用返回反编译源码供分析，确认后返回移除结果
    """
    if use_ssh:
        ssh_host, ssh_username, ssh_password, ssh_key_path, ssh_port = resolve_ssh_params(
            ssh_host, ssh_username, ssh_password, ssh_key_path, ssh_port
        )
        if not ssh_host or not ssh_username:
            return {"success": False, "action": "错误", "message": "SSH模式需要提供ssh_host和ssh_username，或设置SSH_HOST和SSH_USERNAME环境变量"}
    
    if not tools_dir:
        tools_dir = os.environ.get("TOOLS_DIR")
    if not tools_dir:
        return {"success": False, "action": "错误", "message": "未指定tools_dir，请先调用download_detector_tools或设置TOOLS_DIR环境变量"}
    
    cli_jar = os.path.join(tools_dir, "memory-shell-detector-cli.jar") if not use_ssh else f"{tools_dir}/memory-shell-detector-cli.jar"
    # SSH 连接到远程服务器通常是 Linux，本地执行根据当前系统判断
    is_windows = not use_ssh and platform.system().lower() == "windows"
    escaped_class_name = escape_class_name(class_name, for_windows=is_windows)
    
    if not ai_confirmed:
        view_cmd = f'java -jar "{cli_jar}" -v {escaped_class_name} -p {pid}'
        if use_ssh:
            result = execute_ssh_command(host=ssh_host, username=ssh_username, command=view_cmd, password=ssh_password, key_path=ssh_key_path, port=ssh_port)
        else:
            result = execute_local_command(view_cmd)
        
        return {
            "success": True,
            "action": "需要AI确认",
            "message": "请分析以下源代码，确认是否为内存马。如果确认是内存马，请再次调用此工具并设置ai_confirmed=True",
            "source_code": result["stdout"],
            "class_name": class_name,
            "pid": pid
        }
    
    remove_cmd = f'echo "y" | java -jar "{cli_jar}" -r {escaped_class_name} -p {pid}'
    
    if use_ssh:
        result = execute_ssh_command(host=ssh_host, username=ssh_username, command=remove_cmd, password=ssh_password, key_path=ssh_key_path, port=ssh_port)
    else:
        result = execute_local_command(remove_cmd)
    
    return {
        "success": result["success"],
        "action": "移除内存马",
        "result": result["stdout"],
        "error": result["stderr"] if not result["success"] else None,
        "class_name": class_name,
        "pid": pid
    }


@mcp.tool()
def export_report(
    pid: int,
    output_file: str,
    tools_dir: Optional[str] = None,
    format: str = "json",
    use_ssh: bool = False,
    ssh_host: Optional[str] = None,
    ssh_username: Optional[str] = None,
    ssh_password: Optional[str] = None,
    ssh_key_path: Optional[str] = None,
    ssh_port: int = 22
) -> dict:
    """
    执行 memory-shell-detector-cli.jar 生成内存马检测报告
    
    底层命令: java -jar memory-shell-detector-cli.jar --report <output_file> -p <pid> -f <format>
    
    此工具将扫描结果导出为结构化报告，包含：
    - 扫描时间和目标进程信息
    - 检测到的所有可疑类列表
    - 每个可疑类的风险等级和类型判断
    - 反编译的源代码片段
    
    Args:
        pid: 目标 Java 进程的 PID
        output_file: 报告输出文件路径
        tools_dir: 检测工具 jar 包所在目录
        format: 报告格式（json/html/txt）
        use_ssh: 是否通过 SSH 在远程服务器执行
        ssh_host/ssh_username/ssh_password/ssh_key_path/ssh_port: SSH 连接参数
    
    Returns:
        导出结果和报告文件路径
    """
    if use_ssh:
        ssh_host, ssh_username, ssh_password, ssh_key_path, ssh_port = resolve_ssh_params(
            ssh_host, ssh_username, ssh_password, ssh_key_path, ssh_port
        )
        if not ssh_host or not ssh_username:
            return {"success": False, "message": "SSH模式需要提供ssh_host和ssh_username，或设置SSH_HOST和SSH_USERNAME环境变量", "output": "", "error": ""}
    
    if not tools_dir:
        tools_dir = os.environ.get("TOOLS_DIR")
    if not tools_dir:
        return {"success": False, "message": "未指定tools_dir", "output": "", "error": "请先调用download_detector_tools或设置TOOLS_DIR环境变量"}
    
    cli_jar = os.path.join(tools_dir, "memory-shell-detector-cli.jar") if not use_ssh else f"{tools_dir}/memory-shell-detector-cli.jar"
    cmd = f'java -jar "{cli_jar}" --report "{output_file}" -p {pid} -f {format}'
    
    if use_ssh:
        result = execute_ssh_command(host=ssh_host, username=ssh_username, command=cmd, password=ssh_password, key_path=ssh_key_path, port=ssh_port)
    else:
        result = execute_local_command(cmd)
    
    return {
        "success": result["success"],
        "message": f"报告已导出到: {output_file}" if result["success"] else "导出失败",
        "output": result["stdout"],
        "error": result["stderr"] if not result["success"] else None
    }


@mcp.tool()
def get_system_info_tool() -> dict:
    """
    获取当前系统环境信息
    
    返回操作系统类型、平台架构、临时目录等信息，
    用于判断检测工具的兼容性和确定工具存放路径。
    
    Returns:
        system: 操作系统（Linux/Windows/Darwin）
        platform: 完整平台信息
        machine: CPU 架构
        temp_dir: 系统临时目录路径
    """
    info = get_system_info()
    info["temp_dir"] = get_temp_dir()
    return info


@mcp.tool()
def check_network() -> dict:
    """
    检测网络连通性
    
    测试是否能访问工具下载服务器，用于在下载检测工具前确认网络状态。
    如果网络不通，需要手动下载 jar 包或检查网络配置。
    
    Returns:
        available: 网络是否可用
        message: 状态描述信息
    """
    return check_network_available()


def main():
    """MCP服务器入口点"""
    mcp.run()


if __name__ == "__main__":
    main()
