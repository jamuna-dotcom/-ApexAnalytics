import json
from dataclasses import dataclass, asdict
from typing import Optional, List
from groq import Groq

# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------

@dataclass
class AnalystOutput:
    has_vulnerability: bool
    vulnerability_type: str
    severity: str
    cwe_id: str
    description: str

@dataclass
class RedTeamOutput:
    poc_exploit: str
    exploitability_notes: str

@dataclass
class BlueTeamOutput:
    patched_code: str
    remediation_notes: str

@dataclass
class ConsensusResult:
    is_true_positive: bool
    confidence_score: float  # 0.0 to 1.0
    final_verdict: str
    analyst: AnalystOutput
    red_team: RedTeamOutput
    blue_team: BlueTeamOutput
    judge_reasoning: str


# ---------------------------------------------------------------------------
# Multi-Agent Consensus Engine
# ---------------------------------------------------------------------------

class AgentShieldConsensusEngine:
    def __init__(self, api_key: str, model: str = "llama-3.3-70b-versatile"):
        self.client = Groq(api_key=api_key)
        self.model = model

    def _call_llm(self, system_prompt: str, user_prompt: str, json_mode: bool = True) -> str:
        kwargs = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "temperature": 0.2
        }
        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}
            
        response = self.client.chat.completions.create(**kwargs)
        return response.choices[0].message.content

    # --- Agent 1: Analyst ---
    def run_analyst(self, code: str) -> AnalystOutput:
        system_prompt = """You are an elite AppSec Code Reviewer.
Analyze the provided code snippet strictly for security vulnerabilities.
Return JSON matching this schema:
{
    "has_vulnerability": bool,
    "vulnerability_type": "string",
    "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE",
    "cwe_id": "string",
    "description": "string"
}"""
        raw = self._call_llm(system_prompt, f"Code to audit:\n```\n{code}\n```")
        data = json.loads(raw)
        return AnalystOutput(**data)

    # --- Agent 2: Red Team ---
    def run_red_team(self, code: str, analyst: AnalystOutput) -> RedTeamOutput:
        system_prompt = """You are an Offensive Security Specialist / Penetration Tester.
Your goal is to demonstrate a working Proof-of-Concept (PoC) exploit for the reported vulnerability.
Return JSON matching this schema:
{
    "poc_exploit": "string (Python snippet / curl command / payload string)",
    "exploitability_notes": "string"
}"""
        prompt = f"Code:\n```\n{code}\n```\nAnalyst Finding:\n{json.dumps(asdict(analyst), indent=2)}"
        raw = self._call_llm(system_prompt, prompt)
        data = json.loads(raw)
        return RedTeamOutput(**data)

    # --- Agent 3: Blue Team ---
    def run_blue_team(self, code: str, analyst: AnalystOutput) -> BlueTeamOutput:
        system_prompt = """You are a Principal Security Engineer / Defensive Developer.
Refactor the provided code to completely fix the reported vulnerability while preserving original functionality.
Return JSON matching this schema:
{
    "patched_code": "string",
    "remediation_notes": "string"
}"""
        prompt = f"Original Code:\n```\n{code}\n```\nAnalyst Finding:\n{json.dumps(asdict(analyst), indent=2)}"
        raw = self._call_llm(system_prompt, prompt)
        data = json.loads(raw)
        return BlueTeamOutput(**data)

    # --- Agent 4: Judge / Consensus Evaluator ---
    def run_judge(
        self, 
        code: str, 
        analyst: AnalystOutput, 
        red_team: RedTeamOutput, 
        blue_team: BlueTeamOutput
    ) -> ConsensusResult:
        system_prompt = """You are the Chief Information Security Officer (CISO) and Lead Security Auditor.
Your job is to review the debate between the Analyst, Red Team, and Blue Team to make the final determination:
1. Is this a TRUE POSITIVE or FALSE POSITIVE?
2. Is the Red Team's PoC exploit feasible?
3. Does the Blue Team's patch resolve the issue cleanly?

Return JSON matching this schema:
{
    "is_true_positive": bool,
    "confidence_score": float (0.0 to 1.0),
    "final_verdict": "CONFIRMED_VULNERABILITY" | "FALSE_POSITIVE" | "INCONCLUSIVE",
    "judge_reasoning": "string"
}"""
        