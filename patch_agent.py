import os
from pydantic import BaseModel, Field
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate

# 1. Define Structured Output Schema
class SecurityPatch(BaseModel):
    vulnerability_identified: str = Field(description="Summary of the vulnerability vector found")
    vulnerable_snippet: str = Field(description="Exact line or snippet of code that was unsafe")
    patched_code: str = Field(description="Sanitized, secure replacement code")
    explanation: str = Field(description="Brief technical explanation of why this patch fixes the flaw")

# 2. Build the Patch Agent Chain
def generate_patch(vulnerable_code: str, language: str) -> SecurityPatch:
    """Uses GPT to analyze vulnerable code and generate a structured AST-compliant patch."""
    
    # Initialize OpenAI Chat Model via LangChain
    llm = ChatOpenAI(model="gpt-4o", temperature=0)
    structured_llm = llm.with_structured_output(SecurityPatch)

    prompt = ChatPromptTemplate.from_messages([
        ("system", """You are an expert Security Engineer and AST Patch Agent.
Your job is to analyze code snippets identified by SAST tools and generate a secure, sanitized patch.
Ensure non-breaking logic and strict compliance with OWASP guidelines."""),
        ("user", "Language: {language}\n\nVulnerable Code:\n```{language}\n{code}\n```")
    ])

    chain = prompt | structured_llm
    
    # Execute chain
    return chain.invoke({"language": language, "code": vulnerable_code})

# Test run locally
if __name__ == "__main__":
    test_code = """
    def get_user(user_id):
        query = f"SELECT * FROM users WHERE id = '{user_id}'"
        return db.execute(query)
    """
    patch_result = generate_patch(test_code, "python")
    print("Vulnerability:", patch_result.vulnerability_identified)
    print("Patched Code:\n", patch_result.patched_code)