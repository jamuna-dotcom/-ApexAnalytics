# 🛡️ ApexAnalytics — AI-Powered Security Code Auditor

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![Streamlit](https://img.shields.io/badge/Streamlit-1.30%2B-FF4B4B)
![LangChain](https://img.shields.io/badge/LangChain-Groq-green)
![License](https://img.shields.io/badge/License-MIT-brightgreen)

**ApexAnalytics** is an advanced AI-powered static code analysis and vulnerability remediation platform. Built with Streamlit and Groq LLM inference engines, it parses Abstract Syntax Trees (AST), calculates quantitative vulnerability scores (CVSS v3.1), generates refactored secure patches, and automates pull requests to GitHub repositories.

---

## ✨ Features

- **🔍 AST Static Analysis:** Calculates security metrics, AST node distributions, call types, and string concatenation risk indicators.
- **🛡️ Defensive AI Engine:** Leverages Groq-hosted LLMs (`llama-3.3-70b-versatile`, `mixtral-8x7b`, etc.) to perform deep vulnerability audits.
- **📊 Quantitative CVSS v3.1 Scoring:** Provides threat status, OWASP Top 10 classifications, CWE identifiers, and CVSS v3.1 base scores.
- **🎨 Interactive Data Visualizations:** Radar charts and distribution bar charts powered by Plotly for risk density analysis.
- **⚡ Git Diff & Patch Viewer:** Interactive side-by-side and unified git diff views comparing vulnerable and patched code.
- **🚀 One-Click GitHub PR Automation:** Creates a new branch, commits the security patch, and opens a Pull Request automatically.
- **📦 Compliance Export Hub:** Export executive reports instantly as PDF documents or SARIF v2.1.0 logs for IDE integration.

---

## 🛠️ Tech Stack

- **Frontend / Framework:** [Streamlit](https://streamlit.io/)
- **LLM Engine & Orchestration:** [LangChain Groq](https://python.langchain.com/), Groq API
- **Code Parser:** Python `ast` module
- **Data & Charts:** Pandas, Plotly Express
- **Git Integration:** PyGithub
- **PDF & Export Generation:** ReportLab, SARIF standard JSON

---

## 🚀 Quickstart Guide

### 1. Prerequisites

Make sure you have Python 3.9 or higher installed.

### 2. Clone the Repository

```bash
git clone [https://github.com/your-username/ApexAnalytics.git](https://github.com/your-username/ApexAnalytics.git)
cd ApexAnalytics
