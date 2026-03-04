# -*- coding: utf-8 -*-
"""
Metasploit MCP Server - FastMCP Version for Render Deployment
Uses HTTP transport (Streamable HTTP) for production deployment.
"""
import asyncio
import os
import logging
from typing import Any, Dict, List

# Use fastmcp package (NOT mcp.server.fastmcp)
from fastmcp import FastMCP

# --- Configuration & Constants ---
MSF_PASSWORD = os.getenv('MSF_PASSWORD', 'yourpassword')
MSF_SERVER = os.getenv('MSF_SERVER', '127.0.0.1')
MSF_PORT_STR = os.getenv('MSF_PORT', '55553')
MSF_SSL_STR = os.getenv('MSF_SSL', 'false')
LOG_LEVEL = os.getenv('LOG_LEVEL', 'info')

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger("metasploit_mcp_server")
logger.setLevel(LOG_LEVEL.upper())

# Timeouts
RPC_CALL_TIMEOUT = 30

# --- Metasploit Client Setup ---
_msf_client_instance = None

def get_msf_client():
    """Gets or creates the MSF client instance."""
    global _msf_client_instance
    if _msf_client_instance is not None:
        return _msf_client_instance
    
    try:
        from pymetasploit3.msfrpc import MsfRpcClient
        msf_port = int(MSF_PORT_STR)
        msf_ssl = MSF_SSL_STR.lower() == 'true'
        
        logger.info(f"Connecting to Metasploit RPC at {MSF_SERVER}:{msf_port} (SSL: {msf_ssl})...")
        client = MsfRpcClient(
            password=MSF_PASSWORD,
            server=MSF_SERVER,
            port=msf_port,
            ssl=msf_ssl
        )
        version_info = client.core.version
        msf_version = version_info.get('version', 'unknown') if isinstance(version_info, dict) else 'unknown'
        logger.info(f"Connected to Metasploit RPC, version: {msf_version}")
        _msf_client_instance = client
        return _msf_client_instance
    except ImportError:
        logger.warning("pymetasploit3 not installed - Metasploit features will return demo data")
        return None
    except Exception as e:
        logger.warning(f"Failed to connect to Metasploit RPC: {e} - Features will return demo data")
        return None

# --- MCP Server Initialization ---
mcp = FastMCP("Metasploit MCP Server")

# --- MCP Tool Definitions ---

@mcp.tool()
async def list_exploits(search_term: str = "") -> List[str]:
    """
    List available Metasploit exploits, optionally filtered by search term.

    Args:
        search_term: Optional term to filter exploits (case-insensitive).

    Returns:
        List of exploit names matching the term (max 200), or top 100 if no term.
    """
    client = get_msf_client()
    logger.info(f"Listing exploits (search term: '{search_term or 'None'}')")
    
    if client is None:
        # Demo mode - return example data
        demo_exploits = [
            "unix/ftp/vsftpd_234_backdoor",
            "windows/smb/ms17_010_eternalblue",
            "windows/smb/ms08_067_netapi",
            "linux/http/apache_mod_cgi_bash_env_exec",
            "multi/http/tomcat_mgr_upload"
        ]
        if search_term:
            return [e for e in demo_exploits if search_term.lower() in e.lower()][:200]
        return demo_exploits[:100]
    
    try:
        exploits = await asyncio.wait_for(
            asyncio.to_thread(lambda: client.modules.exploits),
            timeout=RPC_CALL_TIMEOUT
        )
        logger.debug(f"Retrieved {len(exploits)} total exploits from MSF.")
        if search_term:
            term_lower = search_term.lower()
            filtered_exploits = [e for e in exploits if term_lower in e.lower()]
            return filtered_exploits[:200]
        else:
            return exploits[:100]
    except asyncio.TimeoutError:
        return [f"Error: Timeout ({RPC_CALL_TIMEOUT}s) while listing exploits"]
    except Exception as e:
        logger.exception("Error listing exploits")
        return [f"Error: {e}"]


@mcp.tool()
async def list_payloads(platform: str = "", arch: str = "") -> List[str]:
    """
    List available Metasploit payloads, optionally filtered by platform and/or architecture.

    Args:
        platform: Optional platform filter (e.g., 'windows', 'linux', 'python', 'php').
        arch: Optional architecture filter (e.g., 'x86', 'x64', 'cmd', 'meterpreter').

    Returns:
        List of payload names matching filters (max 100).
    """
    client = get_msf_client()
    logger.info(f"Listing payloads (platform: '{platform or 'Any'}', arch: '{arch or 'Any'}')")
    
    if client is None:
        # Demo mode
        demo_payloads = [
            "windows/meterpreter/reverse_tcp",
            "windows/x64/meterpreter/reverse_tcp",
            "linux/x86/meterpreter/reverse_tcp",
            "linux/x64/shell_reverse_tcp",
            "cmd/unix/reverse_bash"
        ]
        filtered = demo_payloads
        if platform:
            filtered = [p for p in filtered if platform.lower() in p.lower()]
        if arch:
            filtered = [p for p in filtered if arch.lower() in p.lower()]
        return filtered[:100]
    
    try:
        payloads = await asyncio.wait_for(
            asyncio.to_thread(lambda: client.modules.payloads),
            timeout=RPC_CALL_TIMEOUT
        )
        filtered = payloads
        if platform:
            plat_lower = platform.lower()
            filtered = [p for p in filtered if p.lower().startswith(plat_lower + '/') or f"/{plat_lower}/" in p.lower()]
        if arch:
            arch_lower = arch.lower()
            filtered = [p for p in filtered if f"/{arch_lower}/" in p.lower() or arch_lower in p.lower().split('/')]
        return filtered[:100]
    except asyncio.TimeoutError:
        return [f"Error: Timeout ({RPC_CALL_TIMEOUT}s) while listing payloads"]
    except Exception as e:
        logger.exception("Error listing payloads")
        return [f"Error: {e}"]


@mcp.tool()
async def list_active_sessions() -> Dict[str, Any]:
    """
    List active Metasploit sessions with their details.
    
    Returns:
        Dictionary with status and sessions info.
    """
    client = get_msf_client()
    logger.info("Listing active Metasploit sessions.")
    
    if client is None:
        return {
            "status": "demo",
            "message": "Metasploit not connected - showing demo data",
            "sessions": {},
            "count": 0
        }
    
    try:
        sessions_dict = await asyncio.wait_for(
            asyncio.to_thread(lambda: client.sessions.list),
            timeout=RPC_CALL_TIMEOUT
        )
        sessions_dict_str_keys = {str(k): v for k, v in sessions_dict.items()}
        return {"status": "success", "sessions": sessions_dict_str_keys, "count": len(sessions_dict_str_keys)}
    except asyncio.TimeoutError:
        return {"status": "error", "message": f"Timeout ({RPC_CALL_TIMEOUT}s) while listing sessions"}
    except Exception as e:
        logger.exception("Error listing sessions")
        return {"status": "error", "message": f"Error: {e}"}


@mcp.tool()
async def list_listeners() -> Dict[str, Any]:
    """
    List all active Metasploit jobs, categorizing exploit/multi/handler jobs.
    
    Returns:
        Dictionary with handlers, other jobs, and counts.
    """
    client = get_msf_client()
    logger.info("Listing active listeners/jobs")
    
    if client is None:
        return {
            "status": "demo",
            "message": "Metasploit not connected - showing demo data",
            "handlers": {},
            "other_jobs": {},
            "handler_count": 0,
            "other_job_count": 0,
            "total_job_count": 0
        }
    
    try:
        jobs = await asyncio.wait_for(
            asyncio.to_thread(lambda: client.jobs.list),
            timeout=RPC_CALL_TIMEOUT
        )
        handlers = {}
        other_jobs = {}
        
        for job_id, job_info in jobs.items():
            job_id_str = str(job_id)
            job_data = {'job_id': job_id_str, 'name': 'Unknown', 'details': job_info}
            
            is_handler = False
            if isinstance(job_info, dict):
                job_data['name'] = job_info.get('name', 'Unknown Job')
                job_name_or_info = (job_info.get('name', '') + job_info.get('info', '')).lower()
                if 'exploit/multi/handler' in job_name_or_info:
                    is_handler = True
                datastore = job_info.get('datastore', {})
                if isinstance(datastore, dict):
                    if 'payload' in datastore or ('lhost' in datastore and 'lport' in datastore):
                        is_handler = True
            
            if is_handler:
                handlers[job_id_str] = job_data
            else:
                other_jobs[job_id_str] = job_data
        
        return {
            "status": "success",
            "handlers": handlers,
            "other_jobs": other_jobs,
            "handler_count": len(handlers),
            "other_job_count": len(other_jobs),
            "total_job_count": len(jobs)
        }
    except asyncio.TimeoutError:
        return {"status": "error", "message": f"Timeout ({RPC_CALL_TIMEOUT}s) while listing jobs"}
    except Exception as e:
        logger.exception("Error listing jobs")
        return {"status": "error", "message": f"Error: {e}"}


@mcp.tool()
async def check_msf_connection() -> Dict[str, Any]:
    """
    Check the current status of the Metasploit RPC connection.
    
    Returns:
        Connection status information for debugging.
    """
    client = get_msf_client()
    
    if client is None:
        return {
            "status": "not_connected",
            "server": f"{MSF_SERVER}:{MSF_PORT_STR}",
            "ssl": MSF_SSL_STR,
            "message": "Metasploit client not connected. Set MSF_PASSWORD, MSF_SERVER, MSF_PORT environment variables."
        }
    
    try:
        version_info = await asyncio.wait_for(
            asyncio.to_thread(lambda: client.core.version),
            timeout=RPC_CALL_TIMEOUT
        )
        msf_version = version_info.get('version', 'N/A') if isinstance(version_info, dict) else 'N/A'
        return {
            "status": "connected",
            "server": f"{MSF_SERVER}:{MSF_PORT_STR}",
            "ssl": MSF_SSL_STR,
            "version": msf_version,
            "message": "Connection to Metasploit RPC is healthy"
        }
    except asyncio.TimeoutError:
        return {
            "status": "timeout",
            "server": f"{MSF_SERVER}:{MSF_PORT_STR}",
            "message": f"Metasploit server not responding within {RPC_CALL_TIMEOUT}s"
        }
    except Exception as e:
        return {
            "status": "error",
            "server": f"{MSF_SERVER}:{MSF_PORT_STR}",
            "message": f"Error: {e}"
        }


@mcp.tool()
async def run_exploit(
    module_name: str,
    rhosts: str,
    payload_name: str = "",
    lhost: str = "",
    lport: int = 4444,
    additional_options: str = ""
) -> Dict[str, Any]:
    """
    Run a Metasploit exploit module. Returns the command to execute locally or demo output.
    
    Args:
        module_name: Name of the exploit module (e.g., 'unix/ftp/vsftpd_234_backdoor').
        rhosts: Target host(s) to exploit.
        payload_name: Payload to use (e.g., 'cmd/unix/interact').
        lhost: Local host for reverse connections.
        lport: Local port for reverse connections (default: 4444).
        additional_options: Additional options as comma-separated key=value pairs.
        
    Returns:
        Dictionary with exploit execution details or command.
    """
    client = get_msf_client()
    logger.info(f"Running exploit {module_name} against {rhosts}")
    
    # Build MSF console command
    commands = [
        f"use exploit/{module_name}",
        f"set RHOSTS {rhosts}"
    ]
    if payload_name:
        commands.append(f"set PAYLOAD {payload_name}")
    if lhost:
        commands.append(f"set LHOST {lhost}")
    if lport:
        commands.append(f"set LPORT {lport}")
    if additional_options:
        for opt in additional_options.split(','):
            if '=' in opt:
                commands.append(f"set {opt.strip()}")
    commands.append("exploit")
    
    if client is None:
        return {
            "status": "demo",
            "message": "Metasploit not connected. To run this exploit, execute these commands in msfconsole:",
            "commands": commands,
            "full_command": "; ".join(commands)
        }
    
    try:
        # Use RPC to execute
        module = await asyncio.to_thread(lambda: client.modules.use('exploit', module_name))
        module['RHOSTS'] = rhosts
        if payload_name:
            module['PAYLOAD'] = payload_name
        if lhost:
            module['LHOST'] = lhost
        if lport:
            module['LPORT'] = lport
            
        result = await asyncio.to_thread(lambda: module.execute())
        
        return {
            "status": "success",
            "message": f"Exploit {module_name} launched against {rhosts}",
            "result": result,
            "commands": commands
        }
    except Exception as e:
        logger.exception(f"Error running exploit {module_name}")
        return {
            "status": "error",
            "message": f"Error running exploit: {e}",
            "commands": commands,
            "hint": "Try running manually in msfconsole with the provided commands"
        }


@mcp.tool()
async def start_listener(
    payload_type: str,
    lhost: str,
    lport: int,
    additional_options: str = ""
) -> Dict[str, Any]:
    """
    Start a Metasploit handler (exploit/multi/handler) as a background job.
    
    Args:
        payload_type: The payload to handle (e.g., 'windows/meterpreter/reverse_tcp').
        lhost: Listener host address.
        lport: Listener port (1-65535).
        additional_options: Additional options as comma-separated key=value pairs.
        
    Returns:
        Dictionary with handler status or command.
    """
    client = get_msf_client()
    logger.info(f"Starting listener for {payload_type} on {lhost}:{lport}")
    
    if not (1 <= lport <= 65535):
        return {"status": "error", "message": "Invalid LPORT. Must be between 1 and 65535."}
    
    commands = [
        "use exploit/multi/handler",
        f"set PAYLOAD {payload_type}",
        f"set LHOST {lhost}",
        f"set LPORT {lport}"
    ]
    if additional_options:
        for opt in additional_options.split(','):
            if '=' in opt:
                commands.append(f"set {opt.strip()}")
    commands.append("exploit -j")
    
    if client is None:
        return {
            "status": "demo",
            "message": "Metasploit not connected. To start this listener, execute these commands in msfconsole:",
            "commands": commands,
            "full_command": "; ".join(commands)
        }
    
    try:
        handler = await asyncio.to_thread(lambda: client.modules.use('exploit', 'multi/handler'))
        handler['PAYLOAD'] = payload_type
        handler['LHOST'] = lhost
        handler['LPORT'] = lport
        
        result = await asyncio.to_thread(lambda: handler.execute())
        
        job_id = result.get('job_id')
        return {
            "status": "success",
            "message": f"Listener for {payload_type} started on {lhost}:{lport}",
            "job_id": job_id,
            "result": result,
            "commands": commands
        }
    except Exception as e:
        logger.exception("Error starting listener")
        return {
            "status": "error",
            "message": f"Error starting listener: {e}",
            "commands": commands
        }


@mcp.tool()
async def send_session_command(
    session_id: int,
    command: str
) -> Dict[str, Any]:
    """
    Send a command to an active Metasploit session (Meterpreter or Shell).
    
    Args:
        session_id: ID of the target session.
        command: Command string to execute in the session.
        
    Returns:
        Dictionary with status and command output.
    """
    client = get_msf_client()
    logger.info(f"Sending command to session {session_id}: '{command}'")
    
    if client is None:
        return {
            "status": "demo",
            "message": "Metasploit not connected. Connect to MSF and use session commands directly.",
            "session_id": session_id,
            "command": command
        }
    
    try:
        session_id_str = str(session_id)
        sessions = await asyncio.to_thread(lambda: client.sessions.list)
        
        if session_id_str not in sessions:
            return {"status": "error", "message": f"Session {session_id} not found."}
        
        session = await asyncio.to_thread(lambda: client.sessions.session(session_id_str))
        output = await asyncio.to_thread(lambda: session.run_with_output(command))
        
        return {
            "status": "success",
            "message": "Command executed successfully",
            "output": output
        }
    except Exception as e:
        logger.exception(f"Error sending command to session {session_id}")
        return {"status": "error", "message": f"Error: {e}"}


@mcp.tool()
async def stop_job(job_id: int) -> Dict[str, Any]:
    """
    Stop a running Metasploit job (handler or other).
    
    Args:
        job_id: ID of the job to stop.
        
    Returns:
        Dictionary with status and result.
    """
    client = get_msf_client()
    logger.info(f"Stopping job {job_id}")
    
    if client is None:
        return {
            "status": "demo",
            "message": "Metasploit not connected. Use 'jobs -k {job_id}' in msfconsole.",
            "job_id": job_id
        }
    
    try:
        job_id_str = str(job_id)
        jobs = await asyncio.to_thread(lambda: client.jobs.list)
        
        if job_id_str not in jobs:
            return {"status": "error", "message": f"Job {job_id} not found."}
        
        result = await asyncio.to_thread(lambda: client.jobs.stop(job_id_str))
        
        return {
            "status": "success",
            "message": f"Job {job_id} stopped",
            "result": result
        }
    except Exception as e:
        logger.exception(f"Error stopping job {job_id}")
        return {"status": "error", "message": f"Error: {e}"}


@mcp.tool()
async def terminate_session(session_id: int) -> Dict[str, Any]:
    """
    Forcefully terminate a Metasploit session.
    
    Args:
        session_id: ID of the session to terminate.
        
    Returns:
        Dictionary with status and result message.
    """
    client = get_msf_client()
    logger.info(f"Terminating session {session_id}")
    
    if client is None:
        return {
            "status": "demo",
            "message": "Metasploit not connected. Use 'sessions -k {session_id}' in msfconsole.",
            "session_id": session_id
        }
    
    try:
        session_id_str = str(session_id)
        sessions = await asyncio.to_thread(lambda: client.sessions.list)
        
        if session_id_str not in sessions:
            return {"status": "error", "message": f"Session {session_id} not found."}
        
        session = await asyncio.to_thread(lambda: client.sessions.session(session_id_str))
        await asyncio.to_thread(lambda: session.stop())
        
        return {
            "status": "success",
            "message": f"Session {session_id} terminated"
        }
    except Exception as e:
        logger.exception(f"Error terminating session {session_id}")
        return {"status": "error", "message": f"Error: {e}"}


@mcp.tool()
async def generate_payload(
    payload_type: str,
    format_type: str,
    lhost: str = "",
    lport: int = 4444,
    additional_options: str = ""
) -> Dict[str, Any]:
    """
    Generate a Metasploit payload. Returns the msfvenom command to run locally.
    
    Args:
        payload_type: Type of payload (e.g., windows/meterpreter/reverse_tcp).
        format_type: Output format (raw, exe, python, etc.).
        lhost: Local host for reverse connections.
        lport: Local port for reverse connections.
        additional_options: Additional options as comma-separated key=value pairs.
        
    Returns:
        Dictionary with msfvenom command and details.
    """
    logger.info(f"Generating payload {payload_type} in format {format_type}")
    
    # Build msfvenom command
    cmd_parts = [
        "msfvenom",
        f"-p {payload_type}"
    ]
    if lhost:
        cmd_parts.append(f"LHOST={lhost}")
    if lport:
        cmd_parts.append(f"LPORT={lport}")
    if additional_options:
        for opt in additional_options.split(','):
            if '=' in opt:
                cmd_parts.append(opt.strip())
    cmd_parts.append(f"-f {format_type}")
    
    msfvenom_cmd = " ".join(cmd_parts)
    
    return {
        "status": "success",
        "message": "To generate this payload, run the following command:",
        "msfvenom_command": msfvenom_cmd,
        "payload_type": payload_type,
        "format": format_type,
        "note": "Run this command on a system with Metasploit installed"
    }


# --- Server Startup ---
if __name__ == "__main__":
    # Get port from environment (Render sets this automatically)
    port = int(os.getenv("PORT", 8000))
    
    logger.info(f"Starting Metasploit MCP Server on 0.0.0.0:{port}")
    logger.info(f"MSF Server configured: {MSF_SERVER}:{MSF_PORT_STR}")
    
    # Run with HTTP transport (Streamable HTTP - recommended for production)
    # This creates a /mcp endpoint that accepts POST requests
    mcp.run(
        transport="http",
        host="0.0.0.0",
        port=port
    )
