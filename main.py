import asyncio
import json
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.sse import EventSourceResponse
from pydantic import BaseModel

app = FastAPI()

# Enable CORS for local VS Code frontend server
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class AuditRequest(BaseModel):
    code_snippet: str
    language: str

async def generate_agent_audit_stream(code: str, language: str):
    """
    Simulates or executes real AI agent processing states 
    and streams events back to the client via Server-Sent Events (SSE).
    """
    # 1. Orchestrator Agent Phase
    yield {
        "event": "log",
        "data": json.dumps({"agent": "Orchestrator", "msg": f"Ingesting {language} AST context...", "color": "text-indigo-400"})
    }
    await asyncio.sleep(1)

    # 2. SAST Analysis Phase (Connect real OpenAI/LangChain LLM call here)
    yield {
        "event": "log",
        "data": json.dumps({"agent": "SAST Agent", "msg": "Analyzing AST patterns against OWASP rulesets...", "color": "text-yellow-400"})
    }
    await asyncio.sleep(1.5)

    # 3. Dynamic RedTeam Sandbox Exploit Phase
    yield {
        "event": "log",
        "data": json.dumps({"agent": "RedTeam Agent", "msg": "Attempting payload execution in Docker sandbox...", "color": "text-red-400"})
    }
    await asyncio.sleep(2)

    # 4. Patch Generation Phase
    yield {
        "event": "log",
        "data": json.dumps({"agent": "Patch Agent", "msg": "Patch verified! Parameterized query generated.", "color": "text-emerald-400"})
    }
    
    # 5. Finished
    yield {
        "event": "complete",
        "data": json.dumps({"status": "SUCCESS", "message": "Audit completed."})
    }

@app.post("/api/audit")
async def run_audit(request: AuditRequest):
    return EventSourceResponse(
        generate_agent_audit_stream(request.code_snippet, request.language)
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
    import json
import asyncio
from fastapi import FastAPI
from fastapi.sse import EventSourceResponse
from pydantic import BaseModel
from sandbox import execute_in_sandbox

app = FastAPI()

class AuditRequest(BaseModel):
    code_snippet: str
    language: str

async def generate_agent_audit_stream(code: str, language: str):
    # 1. Orchestrator Phase
    yield {
        "event": "log",
        "data": json.dumps({"agent": "Orchestrator", "msg": f"Ingesting payload for dynamic verification...", "color": "text-indigo-400"})
    }
    await asyncio.sleep(0.5)

    # 2. RedTeam Agent Phase: Spawning Docker Sandbox
    yield {
        "event": "log",
        "data": json.dumps({"agent": "RedTeam Agent", "msg": "Spawning isolated ephemeral container (Network: NONE, RAM: 128MB)...", "color": "text-red-400"})
    }

    # Execute code inside container asynchronously
    loop = asyncio.get_event_loop()
    execution_result = await loop.run_in_executor(None, execute_in_sandbox, code, language)

    # 3. Report Results from Container
    output_msg = execution_result.get("output", "").strip() or "No output returned."
    
    yield {
        "event": "log",
        "data": json.dumps({"agent": "RedTeam Agent", "msg": f"Sandbox Output:\n{output_msg}", "color": "text-yellow-300"})
    }

@app.post("/api/audit")
async def run_audit(request: AuditRequest):
    return EventSourceResponse(generate_agent_audit_stream(request.code_snippet, request.language))
import asyncio
import json
from fastapi import FastAPI
from fastapi.sse import EventSourceResponse
from pydantic import BaseModel
from patch_agent import generate_patch

app = FastAPI()

class AuditRequest(BaseModel):
    code_snippet: str
    language: str

async def generate_agent_audit_stream(code: str, language: str):
    # 1. Orchestrator State
    yield {
        "event": "log",
        "data": json.dumps({"agent": "Orchestrator", "msg": f"Ingesting payload for LLM analysis...", "color": "text-indigo-400"})
    }
    await asyncio.sleep(0.5)

    # 2. Call OpenAI / LangChain Patch Agent
    yield {
        "event": "log",
        "data": json.dumps({"agent": "Patch Agent", "msg": "Querying GPT model for secure AST patch...", "color": "text-cyan-400"})
    }

    loop = asyncio.get_event_loop()
    # Run sync LangChain call asynchronously
    patch_data = await loop.run_in_executor(None, generate_patch, code, language)

    # 3. Stream Patch Results back to UI
    yield {
        "event": "log",
        "data": json.dumps({
            "agent": "Patch Agent",
            "msg": f"Patch generated successfully!\nFlaw: {patch_data.vulnerability_identified}\nFix: {patch_data.explanation}",
            "color": "text-emerald-400 font-semibold",
            # Send patch payload to populate the side-by-side diff UI
            "vulnerable_diff": patch_data.vulnerable_snippet,
            "patched_diff": patch_data.patched_code
        })
    }

@app.post("/api/audit")
async def run_audit(request: AuditRequest):
    return EventSourceResponse(generate_agent_audit_stream(request.code_snippet, request.language))
import os
from fastapi import FastAPI, Depends, HTTPException, Header
from supabase import create_client, Client
from pydantic import BaseModel

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY") # Service key bypasses RLS for backend writes
supabase: Client | None = (
    create_client(SUPABASE_URL, SUPABASE_KEY)
    if SUPABASE_URL and SUPABASE_KEY
    else None
)

app = FastAPI()

class SaveReportRequest(BaseModel):
    language: str
    vulnerable_code: str
    patched_code: str
    vulnerability_details: str

# Helper to extract and verify the user from JWT
async def get_current_user(authorization: str = Header(None)):
    if supabase is None:
        raise HTTPException(status_code=503, detail="Supabase is not configured")

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid token")
    
    token = authorization.split(" ")[1]
    user_response = supabase.auth.get_user(token)
    
    if not user_response.user:
        raise HTTPException(status_code=401, detail="Invalid session token")
    
    return user_response.user

@app.post("/api/reports/save")
async def save_report(payload: SaveReportRequest, user = Depends(get_current_user)):
    """Saves completed security audit to PostgreSQL tied to the user's ID."""
    data = {
        "user_id": user.id,
        "language": payload.language,
        "vulnerable_code": payload.vulnerable_code,
        "patched_code": payload.patched_code,
        "vulnerability_details": payload.vulnerability_details,
        "status": "APPROVED"
    }
    
    response = supabase.table("audit_reports").insert(data).execute()
    return {"status": "SUCCESS", "report_id": response.data[0]["id"]}

@app.get("/api/reports/history")
async def get_history(user = Depends(get_current_user)):
    """Fetches past audit reports for the authenticated user."""
    response = supabase.table("audit_reports").select("*").eq("user_id", user.id).order("created_at", desc=True).execute()
    return {"reports": response.data}