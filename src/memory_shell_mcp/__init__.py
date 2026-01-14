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

__version__ = "0.1.0"

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
    执行命令（本地或SSH远程）
    
    Args:
        command: 要执行的命令
        use_ssh: 是否使用SSH远程执行
        ssh_host: SSH主机地址（不指定则从环境变量SSH_HOST读取）
        ssh_username: SSH用户名（不指定则从环境变量SSH_USERNAME读取）
        ssh_password: SSH密码（不指定则从环境变量SSH_PASSWORD读取）
        ssh_key_path: SSH私钥路径（不指定则从环境变量SSH_KEY_PATH读取）
        ssh_port: SSH端口，默认22（不指定则从环境变量SSH_PORT读取）
        timeout: 命令超时时间（秒）
    
    Returns:
        执行结果字典，包含success、stdout、stderr、return_code
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
    下载内存马检测工具到指定目录
    
    Args:
        tools_dir: 工具存放目录，不指定则从环境变量TOOLS_DIR读取，都没有则使用系统临时目录
        use_ssh: 是否在远程服务器上下载
        ssh_host: SSH主机地址（不指定则从环境变量SSH_HOST读取）
        ssh_username: SSH用户名（不指定则从环境变量SSH_USERNAME读取）
        ssh_password: SSH密码（不指定则从环境变量SSH_PASSWORD读取）
        ssh_key_path: SSH私钥路径（不指定则从环境变量SSH_KEY_PATH读取）
        ssh_port: SSH端口（不指定则从环境变量SSH_PORT读取）
    
    Returns:
        下载结果，包含工具路径
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
    """列出所有Java进程 (对应 -l 命令)"""
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
    """扫描指定Java进程检测内存马 (对应 -s 命令)"""
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
    """查看可疑类的反编译源代码 (对应 -v -p 命令)"""
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
    cmd = f'java -jar "{cli_jar}" -v {class_name} -p {pid}'
    
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
    """移除内存马 (对应 -r -p 命令)，需要AI确认后才能执行"""
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
    
    if not ai_confirmed:
        view_cmd = f'java -jar "{cli_jar}" -v {class_name} -p {pid}'
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
    
    remove_cmd = f'echo "y" | java -jar "{cli_jar}" -r {class_name} -p {pid}'
    
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
    """导出检测报告"""
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
    """获取当前系统信息"""
    info = get_system_info()
    info["temp_dir"] = get_temp_dir()
    return info


@mcp.tool()
def check_network() -> dict:
    """检测网络是否可用（用于判断是否可以下载工具）"""
    return check_network_available()


def main():
    """MCP服务器入口点"""
    mcp.run()


if __name__ == "__main__":
    main()
