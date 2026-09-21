import docker
import os
import tempfile
from typing import Dict, Any
# sandbox.py

try:
    import docker
    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False

def execute_in_sandbox(code: str, language: str = "python"):
    if not DOCKER_AVAILABLE:
        # Fallback simulation mode for cloud environments without local Docker daemon
        return {
            "status": "simulated",
            "output": "[Sandbox Simulation] Docker engine not detected in cloud runtime. Executing in dry-run mode."
        }
    
    try:
        client = docker.from_env()
        # Your docker container execution logic here...
        return {"status": "success", "output": "Execution completed in Docker container."}
    except Exception as e:
        return {"status": "error", "output": f"Docker execution error: {str(e)}"}

def execute_in_sandbox(code_snippet: str, language: str = "python", timeout_seconds: int = 5) -> Dict[str, Any]:
    """
    Executes user code in a securely constrained, short-lived Docker container.
    """
    client = docker.from_env()
    
    # Map language to lightweight base image and execution command
    IMAGE_MAP = {
        "python": ("python:3.11-slim", ["python", "-c"]),
        "javascript": ("node:20-alpine", ["node", "-e"]),
    }

    if language not in IMAGE_MAP:
        return {"error": f"Unsupported language: {language}"}

    image_name, cmd_prefix = IMAGE_MAP[language]

    # Create a temporary file on the host to hold the code
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as temp_file:
        temp_file.write(code_snippet)
        temp_file_path = temp_file.name

    container = None
    try:
        # Launch isolated container with strict security parameters
        container = client.containers.run(
            image=image_name,
            command=cmd_prefix + [code_snippet],
            
            # --- SECURITY ISOLATION HARDENING ---
            network_mode="none",             # Disable external/internal networking
            mem_limit="128m",                 # Hard cap on RAM (prevents OOM bombs)
            nano_cpus=500000000,              # Cap CPU usage at 0.5 cores
            pids_limit=64,                    # Prevent fork bombs
            read_only=True,                   # Make root filesystem read-only
            cap_drop=["ALL"],                 # Drop all Linux capabilities (rootless behavior)
            security_opt=["no-new-privileges:true"], # Prevent privilege escalation
            
            detach=True,
            stdout=True,
            stderr=True
        )

        # Wait for completion or enforce timeout
        result = container.wait(timeout=timeout_seconds)
        logs = container.logs(stdout=True, stderr=True).decode('utf-8')

        return {
            "status": "SUCCESS",
            "exit_code": result.get("StatusCode", -1),
            "output": logs
        }

    except docker.errors.ContainerError as e:
        return {"status": "EXECUTION_ERROR", "output": str(e)}
    except Exception as e:
        # Handles timeout or runtime errors
        return {"status": "TIMEOUT_OR_FAILED", "output": f"Execution failed or timed out ({timeout_seconds}s limit). Details: {str(e)}"}
    finally:
        # Cleanup: Force kill and remove container & temp files
        if container:
            try:
                container.remove(force=True)
            except Exception:
                pass
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)