import ast
import difflib
import io
import json
import os
import time
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
import streamlit as st
from github import Github, GithubException
from langchain_groq import ChatGroq
from pydantic import BaseModel, Field

# ReportLab imports for PDF generation
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Paragraph, Preformatted, SimpleDocTemplate, Spacer, Table, TableStyle

# Optional: Custom consensus engine import if available
try:
    from consensus_engine import AgentShieldConsensusEngine
except ImportError:
    AgentShieldConsensusEngine = None

# --- Page Configuration ---
st.set_page_config(
    page_title="ApexAnalytics",
    page_icon="🛡️",
    layout="wide",
)

# Custom CSS Styling
st.markdown(
    """
<style>
    .stApp { background-color: #05070d; color: #f1f5f9; }
    .stTextArea textarea {
        background-color: #0b0f19 !important;
        color: #00f2fe !important;
        font-family: 'JetBrains Mono', 'Fira Code', monospace !important;
        border: 1px solid rgba(0, 242, 254, 0.3) !important;
    }
    .terminal-window {
        background-color: #020617;
        border: 1px solid #1e293b;
        padding: 14px;
        border-radius: 8px;
        font-family: 'Courier New', monospace;
        color: #38bdf8;
    }
    .diff-added { background-color: rgba(16, 185, 129, 0.2); color: #34d399; }
    .diff-removed { background-color: rgba(239, 68, 68, 0.2); color: #f87171; }
    .diff-info { color: #94a3b8; }
</style>
""",
    unsafe_allow_html=True,
)


# --- Pydantic Data Models ---
class CVSSMetrics(BaseModel):
    cvss_score: float = Field(description="CVSS v3.1 Base Score from 0.0 to 10.0")
    vector_string: str = Field(
        description="CVSS Vector string e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    )
    exploitability_score: float = Field(description="Exploitability sub-score 0.0 to 4.0")


class MultiAgentAuditReport(BaseModel):
    vulnerability_detected: bool = Field(description="True if security flaw is confirmed")
    owasp_category: str = Field(description="OWASP Top 10 Category name")
    cwe_id: str = Field(description="Common Weakness Enumeration ID e.g., CWE-89")
    cvss: CVSSMetrics
    patched_code: str = Field(description="Refactored, production-ready secure code patch")
    technical_breakdown: str = Field(
        description="In-depth root cause analysis for security engineers"
    )
    remediation_steps: str = Field(
        description="Specific steps developers must take to fix the issue"
    )
    agent_confidence: float = Field(description="Confidence score between 0.0 and 1.0")


# --- Static Analysis Utilities ---
def analyze_ast_security_metrics(code: str):
    metrics = {
        "Total AST Nodes": 0,
        "Function Calls": 0,
        "String Concatenations": 0,
        "Formatted Strings (f-strings)": 0,
        "Evaluations / Dynamic Exec": 0,
        "Imports": 0,
    }
    try:
        tree = ast.parse(code)
        for node in ast.walk(tree):
            metrics["Total AST Nodes"] += 1
            if isinstance(node, ast.Call):
                metrics["Function Calls"] += 1
                if hasattr(node.func, "id") and node.func.id in [
                    "eval",
                    "exec",
                    "system",
                    "popen",
                ]:
                    metrics["Evaluations / Dynamic Exec"] += 1
            elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                metrics["String Concatenations"] += 1
            elif isinstance(node, ast.JoinedStr):
                metrics["Formatted Strings (f-strings)"] += 1
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                metrics["Imports"] += 1
    except SyntaxError:
        pass
    return metrics


def get_available_groq_models(api_key: str):
    default_models = [
        "llama-3.3-70b-versatile",
        "llama-3.1-8b-instant",
        "mixtral-8x7b-32768",
    ]

    if not api_key:
        return default_models

    try:
        headers = {"Authorization": f"Bearer {api_key.strip()}"}
        res = requests.get(
            "https://api.groq.com/openai/v1/models", headers=headers, timeout=4
        )
        if res.status_code == 200:
            models_data = res.json().get("data", [])
            excluded_terms = [
                "whisper",
                "guard",
                "orpheus",
                "canopylabs",
                "vision",
                "tts",
                "stt",
            ]
            text_models = [
                model["id"]
                for model in models_data
                if not any(term in model["id"].lower() for term in excluded_terms)
            ]
            return text_models if text_models else default_models
    except Exception:
        pass

    return default_models


# --- Defensive Audit Engine ---
def execute_defensive_audit(
    code: str, language: str, api_key: str, model_name: str
) -> MultiAgentAuditReport:
    active_key = api_key.strip() if api_key else ""

    if not active_key or not active_key.startswith("gsk_"):
        raise ValueError("Valid Groq API key starting with 'gsk_' is required.")

    llm = ChatGroq(model=model_name, groq_api_key=active_key, temperature=0.1)

    prompt_str = (
        f"You are AgentShield's Chief Security Scientist.\n"
        f"Perform a deep defensive audit on this {language} code snippet:\n\n"
        f"```{language}\n{code}\n```\n\n"
        "Analyze the code for vulnerabilities.\n"
        "Return ONLY a valid JSON object matching this structure (no markdown formatting):\n"
        "{\n"
        '  "vulnerability_detected": true,\n'
        '  "owasp_category": "A03:2021-Injection",\n'
        '  "cwe_id": "CWE-89",\n'
        '  "cvss": {\n'
        '    "cvss_score": 9.8,\n'
        '    "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",\n'
        '    "exploitability_score": 3.9\n'
        "  },\n"
        '  "patched_code": "def login(username, password):\\n    query = \'SELECT * FROM users WHERE user = %s AND pass = %s\'\\n    cursor.execute(query, (username, password))\\n    return cursor.fetchone()",\n'
        '  "technical_breakdown": "Insecure string formatting exposes database queries to raw input execution.",\n'
        '  "remediation_steps": "Replace string interpolation with parameterized database queries.",\n'
        '  "agent_confidence": 0.98\n'
        "}"
    )

    response = llm.invoke(prompt_str)
    clean_text = (
        response.content.strip()
        .replace("```json", "")
        .replace("```", "")
        .strip()
    )
    parsed_json = json.loads(clean_text)

    cvss_obj = CVSSMetrics(**parsed_json["cvss"])
    parsed_json["cvss"] = cvss_obj
    return MultiAgentAuditReport(**parsed_json)


# --- Export Utilities & GitHub PR Automation ---
def generate_pdf_report(
    report: MultiAgentAuditReport, code_input: str, language: str
) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36,
    )
    story = []

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "TitleStyle",
        parent=styles["Heading1"],
        fontSize=20,
        textColor=colors.HexColor("#00f2fe"),
        spaceAfter=12,
    )
    heading_style = ParagraphStyle(
        "HeadingStyle",
        parent=styles["Heading2"],
        fontSize=12,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=10,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "BodyStyle",
        parent=styles["BodyText"],
        fontSize=9,
        textColor=colors.HexColor("#334155"),
        leading=12,
    )
    code_style = ParagraphStyle(
        "CodeStyle",
        parent=styles["Code"],
        fontSize=8,
        textColor=colors.HexColor("#0f172a"),
        backColor=colors.HexColor("#f1f5f9"),
        borderPadding=6,
    )

    story.append(
        Paragraph("AgentShield Pro — Executive Compliance Report", title_style)
    )
    story.append(
        Paragraph(
            f"Generated on: {time.strftime('%Y-%m-%d %H:%M:%S UTC')} | Target Stack: {language}",
            body_style,
        )
    )
    story.append(Spacer(1, 12))

    table_data = [
        [
            "Threat Status",
            "CRITICAL FLAW" if report.vulnerability_detected else "SECURE",
        ],
        ["CVSS v3.1 Base Score", f"{report.cvss.cvss_score} / 10.0"],
        ["OWASP Category", report.owasp_category],
        ["CWE Identifier", report.cwe_id],
        ["CVSS Vector String", report.cvss.vector_string],
        ["Agent Confidence", f"{int(report.agent_confidence * 100)}%"],
    ]

    t = Table(table_data, colWidths=[150, 370])
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f8fafc")),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#0f172a")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("PADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(t)
    story.append(Spacer(1, 14))

    story.append(Paragraph("Root Cause & Technical Analysis", heading_style))
    story.append(Paragraph(report.technical_breakdown, body_style))
    story.append(Spacer(1, 10))

    story.append(Paragraph("Remediation Strategy", heading_style))
    story.append(Paragraph(report.remediation_steps, body_style))
    story.append(Spacer(1, 14))

    story.append(Paragraph("Vulnerable Code Snippet", heading_style))
    story.append(Preformatted(code_input, code_style))
    story.append(Spacer(1, 10))

    story.append(Paragraph("Remediated Patch", heading_style))
    story.append(Preformatted(report.patched_code, code_style))

    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()


def generate_sarif_report(
    report: MultiAgentAuditReport, code_input: str, language: str
) -> str:
    level = (
        "error"
        if report.cvss.cvss_score >= 7.0
        else "warning" if report.cvss.cvss_score >= 4.0 else "note"
    )
    sarif_log = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AgentShield Pro",
                        "semanticVersion": "1.0.0",
                        "rules": [
                            {
                                "id": report.cwe_id,
                                "name": report.owasp_category.replace(" ", "_"),
                                "shortDescription": {
                                    "text": report.owasp_category
                                },
                                "fullDescription": {
                                    "text": report.technical_breakdown
                                },
                                "help": {"text": report.remediation_steps},
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": report.cwe_id,
                        "level": level,
                        "message": {
                            "text": f"{report.technical_breakdown} Remediation: {report.remediation_steps}"
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": f"src/app.{'py' if 'python' in language.lower() else 'js'}"
                                    },
                                    "region": {
                                        "startLine": 1,
                                        "startColumn": 1,
                                    },
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }
    return json.dumps(sarif_log, indent=2)


def create_github_pull_request(
    repo_name: str,
    file_path: str,
    patched_code: str,
    github_token: str,
    report: MultiAgentAuditReport,
):
    g = Github(github_token)
    repo = g.get_repo(repo_name)

    default_branch = repo.default_branch
    base_ref = repo.get_git_ref(f"heads/{default_branch}")
    base_sha = base_ref.object.sha

    branch_name = f"agentshield-patch-{int(time.time())}"
    repo.create_git_ref(ref=f"refs/heads/{branch_name}", sha=base_sha)

    try:
        contents = repo.get_contents(file_path, ref=branch_name)
        file_sha = contents.sha
        repo.update_file(
            path=file_path,
            message=f"security: automated fix for {report.cwe_id} ({report.owasp_category})",
            content=patched_code,
            sha=file_sha,
            branch=branch_name,
        )
    except GithubException:
        repo.create_file(
            path=file_path,
            message=f"security: automated fix for {report.cwe_id} ({report.owasp_category})",
            content=patched_code,
            branch=branch_name,
        )

    pr_body = (
        f"### 🛡️ AgentShield Pro Automated Security Patch\n"
        f"**Vulnerability:** {report.cwe_id} — {report.owasp_category}\n"
        f"**CVSS v3.1 Score:** {report.cvss.cvss_score}\n\n"
        f"#### Technical Details\n"
        f"{report.technical_breakdown}\n\n"
        f"#### Applied Fix\n"
        f"{report.remediation_steps}\n"
    )

    pr = repo.create_pull(
        title=f"[AgentShield] Security Fix: {report.cwe_id} ({report.owasp_category})",
        body=pr_body,
        head=branch_name,
        base=default_branch,
    )
    return pr.html_url


# --- Main UI Layout ---

# Session States Initialization
if "report" not in st.session_state:
    st.session_state.report = None
if "ast_data" not in st.session_state:
    st.session_state.ast_data = {}

# 1. Main Application Header & Subtitle
st.title(" 🛡️ ApexAnalytics")
st.caption(
    "AST Vector Analysis, Dynamic Patching & Quantitative Vulnerability Assessment"
)

# 2. Sidebar Configuration
with st.sidebar:
    st.header("⚙️ Platform Configuration")
    language = st.selectbox(
        "Target Runtime",
        ["Python", "JavaScript / Node.js", "C / C++", "Go", "Java"],
    )
    
    st.divider()
    st.markdown("### 🤖 Active Diagnostic Modules")
    st.markdown("🟢 **AST Static Parser** (`Rule-Based`)")
    st.markdown("🟢 **Defense & Patch Agent** (`Remediation`)")
    st.markdown("🟢 **Risk Scoring Engine** (`CVSS v3.1`)")

# 3. API Key & Model Inputs (Main Workspace)
col_key, col_model = st.columns([2, 1])

with col_key:
    groq_key_input = st.text_input(
        "🔑 Groq API Key:",
        value=os.getenv("GROQ_API_KEY", ""),
        type="password",
        placeholder="Enter your gsk_... API key here",
        help="Get your key at https://console.groq.com/keys",
    )

with col_model:
    available_models = get_available_groq_models(groq_key_input)
    selected_model = st.selectbox("LLM Inference Engine", available_models)

# 4. Source Code Input
st.subheader("1. Source Code Repository Input")
default_snippet = """def login(username, password):
    # Unsanitized user inputs passed into SQL query
    query = f"SELECT * FROM users WHERE user = '{username}' AND pass = '{password}'"
    result = cursor.execute(query)
    return result.fetchone()"""

code_input = st.text_area(
    "Paste code snippet to audit:", value=default_snippet, height=180
)

# 5. Multi-Agent Audit Trigger Button
if st.button("🚀 Run Multi-Agent Audit", type="primary", use_container_width=True):
    if not groq_key_input.strip():
        st.error("Please enter your Groq API Key above before running the audit.")
    elif not code_input.strip():
        st.error("Please provide source code to initiate audit.")
    else:
        st.divider()
        st.subheader("2. Telemetry & Parsing Logs")
        terminal = st.empty()

        terminal.markdown(
            '<div class="terminal-window">[Module 1: AST_Parser] Tokenizing Abstract Syntax Tree...</div>',
            unsafe_allow_html=True,
        )
        time.sleep(0.3)
        st.session_state.ast_data = analyze_ast_security_metrics(code_input)

        terminal.markdown(
            f'<div class="terminal-window">[Module 2: Defense_Agent] Analyzing code patterns & generating patches via {selected_model}...</div>',
            unsafe_allow_html=True,
        )

        try:
            audit_result = execute_defensive_audit(
                code_input, language, groq_key_input, selected_model
            )
            st.session_state.report = audit_result
            terminal.markdown(
                '<div class="terminal-window">[Audit Engine] Analysis complete! Report compiled successfully.</div>',
                unsafe_allow_html=True,
            )
        except Exception as err:
            st.error(f"Audit Execution Failed: {str(err)}")

# --- Results & Diagnostic Output ---
if st.session_state.report:
    report: MultiAgentAuditReport = st.session_state.report
    ast_metrics = st.session_state.ast_data

    st.divider()
    st.subheader("3. Executive Security Analytics & Quantitative Scoring")

    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.metric(
            "Threat Status",
            "CRITICAL FLAW" if report.vulnerability_detected else "SECURE",
        )
    with m2:
        st.metric("CVSS v3.1 Base Score", f"{report.cvss.cvss_score} / 10.0")
    with m3:
        st.metric("OWASP Top 10", report.owasp_category)
    with m4:
        st.metric("CWE Identifier", report.cwe_id)

    st.caption(f"**CVSS Vector String:** `{report.cvss.vector_string}`")

    # Visualizations
    col_chart1, col_chart2 = st.columns(2)

    with col_chart1:
        st.markdown("#### 📊 AST Security Feature Density")
        df_ast = pd.DataFrame(
            list(ast_metrics.items()), columns=["Node Type", "Count"]
        )
        fig_bar = px.bar(
            df_ast,
            x="Count",
            y="Node Type",
            orientation="h",
            color="Count",
            color_continuous_scale="Viridis",
            title="AST Token Distribution",
        )
        fig_bar.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color="#38bdf8",
        )
        st.plotly_chart(fig_bar, use_container_width=True)

    with col_chart2:
        st.markdown("#### 🎯 Risk Matrix Assessment Radar")
        radar_categories = [
            "CVSS Score",
            "Exploitability",
            "Agent Confidence",
            "AST Risk Density",
        ]
        radar_values = [
            report.cvss.cvss_score,
            report.cvss.exploitability_score * 2.5,
            report.agent_confidence * 10,
            min(10, ast_metrics.get("String Concatenations", 0) * 3 + 2),
        ]

        fig_radar = go.Figure(
            data=go.Scatterpolar(
                r=radar_values,
                theta=radar_categories,
                fill="toself",
                line_color="#00f2fe",
            )
        )
        fig_radar.update_layout(
            polar=dict(radialaxis=dict(visible=True, range=[0, 10])),
            paper_bgcolor="rgba(0,0,0,0)",
            font_color="#38bdf8",
            title="Security Risk Vector Assessment",
        )
        st.plotly_chart(fig_radar, use_container_width=True)

    # --- Code Comparison Section ---
    st.divider()
    st.subheader("4. Developer Review & Git Diff Inspector")

    diff_mode = st.radio(
        "Diff Format View:",
        ["Side-by-Side Comparison", "Unified Git Diff"],
        horizontal=True,
    )

    old_lines = code_input.splitlines()
    new_lines = report.patched_code.splitlines()

    if diff_mode == "Side-by-Side Comparison":
        col_orig, col_patched = st.columns(2)
        with col_orig:
            st.markdown("❌ **Original / Vulnerable Code**")
            st.code(code_input, language=language.lower().split()[0])
        with col_patched:
            st.markdown("✅ **Remediated Secure Patch**")
            st.code(report.patched_code, language=language.lower().split()[0])
    else:
        st.markdown("📄 **Unified Patch Diff**")
        diff = list(
            difflib.unified_diff(
                old_lines,
                new_lines,
                fromfile="vulnerable_code",
                tofile="patched_code",
                lineterm="",
            )
        )
        if diff:
            diff_html = []
            for line in diff:
                if line.startswith("+") and not line.startswith("+++"):
                    diff_html.append(f'<div class="diff-added">{line}</div>')
                elif line.startswith("-") and not line.startswith("---"):
                    diff_html.append(f'<div class="diff-removed">{line}</div>')
                else:
                    diff_html.append(f'<div class="diff-info">{line}</div>')
            st.markdown(
                f'<div class="terminal-window">{"".join(diff_html)}</div>',
                unsafe_allow_html=True,
            )
        else:
            st.info("No structural code differences detected.")

    # --- Export & PR Submissions ---
    st.divider()
    st.subheader("5. One-Click Pull Request & Export Hub")

    tab_pr, tab_export = st.tabs(
        [
            "🚀 One-Click GitHub Pull Request",
            "📦 Download Reports (PDF / SARIF)",
        ]
    )

    with tab_pr:
        st.markdown(
            "Automatically submit this security fix to your repository as a new GitHub Pull Request."
        )
        pr_col1, pr_col2 = st.columns(2)

        with pr_col1:
            gh_token = st.text_input(
                "GitHub Personal Access Token (PAT)",
                type="password",
                help="Requires 'repo' scope access",
            )
            target_repo = st.text_input(
                "Target Repository (e.g., owner/repository_name)",
                placeholder="octocat/Hello-World",
            )

        with pr_col2:
            target_file_path = st.text_input(
                "Target File Path in Repo", value="src/login.py"
            )
            submit_pr_btn = st.button(
                "✨ Create Pull Request", type="primary", use_container_width=True
            )

        if submit_pr_btn:
            if not gh_token or not target_repo or not target_file_path:
                st.error(
                    "Please fill in GitHub Token, Target Repository, and Target File Path."
                )
            else:
                with st.spinner(
                    "Creating branch, committing sanitized patch, and opening Pull Request..."
                ):
                    try:
                        pr_url = create_github_pull_request(
                            repo_name=target_repo,
                            file_path=target_file_path,
                            patched_code=report.patched_code,
                            github_token=gh_token,
                            report=report,
                        )
                        st.balloons()
                        st.success(
                            f"Pull Request successfully created! [View Pull Request on GitHub]({pr_url})"
                        )
                    except Exception as pr_err:
                        st.error(f"Failed to create Pull Request: {str(pr_err)}")

    with tab_export:
        exp_col1, exp_col2 = st.columns(2)
        with exp_col1:
            pdf_bytes = generate_pdf_report(report, code_input, language)
            st.download_button(
                label="📄 Download Executive Compliance PDF",
                data=pdf_bytes,
                file_name=f"agentshield_report_{int(time.time())}.pdf",
                mime="application/pdf",
                use_container_width=True,
            )
        with exp_col2:
            sarif_json = generate_sarif_report(report, code_input, language)
            st.download_button(
                label="⚙️ Download SARIF v2.1.0 Log (VS Code / GitHub)",
                data=sarif_json,
                file_name=f"agentshield_audit_{int(time.time())}.sarif",
                mime="application/json",
                use_container_width=True,
            )