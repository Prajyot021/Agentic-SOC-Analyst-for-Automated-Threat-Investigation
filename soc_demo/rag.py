"""
RAG (Retrieval-Augmented Generation) helper for agents.
Provides a simple interface for MITRE ATT&CK context retrieval.
"""

from typing import List, Dict, Any
from soc_demo.vector_store import MITREVectorStore


class MITRERetriever:
    """
    Simple interface for agents to retrieve MITRE context.
    """
    
    def __init__(self):
        """Initialize the retriever."""
        self.store = MITREVectorStore()
        
        # Verify collection exists
        info = self.store.get_collection_info()
        if not info['exists']:
            raise RuntimeError(
                "MITRE ATT&CK vector store not found. "
                "Run: python soc_demo/vector_store.py"
            )
    
    def retrieve_context(
        self,
        query: str,
        k: int = 3
    ) -> List[Dict[str, Any]]:
        """
        Retrieve relevant MITRE techniques for a query.
        
        This is the function that agents will call as a tool.
        
        Args:
            query: Description of the activity (e.g., "base64 encoded powershell")
            k: Number of techniques to return
            
        Returns:
            List of relevant techniques with metadata
        """
        results = self.store.search(query, limit=k)
        return results
    
    def format_for_prompt(
        self,
        results: List[Dict[str, Any]]
    ) -> str:
        """
        Format retrieval results for inclusion in an agent prompt.
        
        Args:
            results: Results from retrieve_context()
            
        Returns:
            Formatted string for LLM context
        """
        if not results:
            return "No relevant MITRE techniques found."
        
        formatted = "Relevant MITRE ATT&CK Techniques:\n\n"
        
        for i, result in enumerate(results, 1):
            formatted += f"{i}. {result['technique_id']} - {result['name']}\n"
            formatted += f"   Tactics: {', '.join(result['tactics'])}\n"
            formatted += f"   Platforms: {', '.join(result['platforms'])}\n"
            formatted += f"   Relevance Score: {result['score']:.2f}\n"
            
            # Extract first 200 chars of description
            desc_lines = result['description'].split('\n')
            desc_start = next(
                (line for line in desc_lines if line.startswith('Description:')),
                ''
            )
            if desc_start:
                desc_text = desc_start.replace('Description:', '').strip()
                formatted += f"   Summary: {desc_text[:200]}...\n"
            
            formatted += f"   Reference: {result['url']}\n\n"
        
        return formatted


# Global instance for easy import
_retriever = None

def get_retriever() -> MITRERetriever:
    """Get or create the global retriever instance."""
    global _retriever
    if _retriever is None:
        _retriever = MITRERetriever()
    return _retriever


def main():
    """Test the retriever."""
    retriever = get_retriever()
    
    print("Testing MITRE Retriever\n" + "="*70 + "\n")
    
    # Test query
    query = "suspicious powershell execution with encoded commands"
    print(f"Query: {query}\n")
    
    results = retriever.retrieve_context(query, k=3)
    formatted = retriever.format_for_prompt(results)
    
    print(formatted)


if __name__ == "__main__":
    main()