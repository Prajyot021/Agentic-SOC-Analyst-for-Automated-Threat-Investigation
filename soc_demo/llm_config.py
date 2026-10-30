"""
LLM configuration for agents.
Supports Ollama with qwen2.5-coder:7b.
"""

import os
from typing import Any
from langchain_ollama import ChatOllama
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


def get_llm() -> Any:
    """
    Get configured LLM instance.
    
    Returns:
        LangChain LLM instance (Ollama)
    """
    backend = os.getenv("SOC_DEMO_BACKEND", "ollama")
    
    if backend == "ollama":
        return ChatOllama(
            model=os.getenv("OLLAMA_MODEL", "qwen3:4b-instruct"),
            base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
            temperature=0.1,  # Low temperature for consistent reasoning
            num_predict=2048,  # Max tokens to generate
        )
    else:
        raise ValueError(f"Unsupported backend: {backend}")


def test_llm():
    """Test that LLM is working."""
    print("Testing LLM connection...\n")
    
    llm = get_llm()
    
    # Simple test
    response = llm.invoke("Say 'Hello, I am ready to help analyze security alerts!'")
    
    print("✅ LLM Response:")
    print(response.content)
    
    return True


if __name__ == "__main__":
    test_llm()