import json
from dataclasses import asdict, dataclass

from groq import Groq


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
    confidence_score: float
    final_verdict: str
    analyst: AnalystOutput
    red_team: RedTeamOutput
    blue_team: BlueTeamOutput
    judge_reasoning: str


class AgentShieldConsensusEngine:
    def __init__(self, api_key: str, model: str = "llama-3.3-70b-versatile"):
        self.client = Groq(api_key=api_key)
        self.model = model

    def _call_llm(self, system_prompt: str, user_prompt: str) -> str:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.2,
            response_format={"type": "json_object"},
        )
        return response.choices[0].message.content

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
        return AnalystOutput(**json.loads(raw))

    def run_red_team(self, code: str, analyst: AnalystOutput) -> RedTeamOutput:
        system_prompt = """You are an Offensive Security Specialist / Penetration Tester.
Describe a safe, non-destructive proof of concept for the reported vulnerability.
Return JSON matching this schema:
{
    "poc_exploit": "string",
    "exploitability_notes": "string"
}"""
        prompt = f"Code:\n```\n{code}\n```\nAnalyst Finding:\n{json.dumps(asdict(analyst), indent=2)}"
        return RedTeamOutput(**json.loads(self._call_llm(system_prompt, prompt)))

    def run_blue_team(self, code: str, analyst: AnalystOutput) -> BlueTeamOutput:
        system_prompt = """You are a Principal Security Engineer / Defensive Developer.
Refactor the provided code to completely fix the reported vulnerability while preserving original functionality.
Return JSON matching this schema:
{
    "patched_code": "string",
    "remediation_notes": "string"
}"""
        prompt = f"Original Code:\n```\n{code}\n```\nAnalyst Finding:\n{json.dumps(asdict(analyst), indent=2)}"
        return BlueTeamOutput(**json.loads(self._call_llm(system_prompt, prompt)))

    def run_judge(
        self,
        code: str,
        analyst: AnalystOutput,
        red_team: RedTeamOutput,
        blue_team: BlueTeamOutput,
    ) -> ConsensusResult:
        system_prompt = """You are the Chief Information Security Officer and Lead Security Auditor.
Review the analyst finding, red-team notes, and blue-team patch. Decide whether the finding is confirmed.
Return JSON matching this schema:
{
    "is_true_positive": bool,
    "confidence_score": float,
    "final_verdict": "CONFIRMED_VULNERABILITY" | "FALSE_POSITIVE" | "INCONCLUSIVE",
    "judge_reasoning": "string"
}"""
        user_prompt = (
            f"Code Snippet:\n```\n{code}\n```\n"
            f"Analyst:\n{json.dumps(asdict(analyst), indent=2)}\n"
            f"Red Team:\n{json.dumps(asdict(red_team), indent=2)}\n"
            f"Blue Team:\n{json.dumps(asdict(blue_team), indent=2)}"
        )
        judgment = json.loads(self._call_llm(system_prompt, user_prompt))
        return ConsensusResult(
            **judgment,
            analyst=analyst,
            red_team=red_team,
            blue_team=blue_team,
        )

    def analyze(self, code: str) -> ConsensusResult:
        analyst = self.run_analyst(code)
        red_team = self.run_red_team(code, analyst)
        blue_team = self.run_blue_team(code, analyst)
        return self.run_judge(code, analyst, red_team, blue_team)
