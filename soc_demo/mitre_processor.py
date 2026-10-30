"""
MITRE ATT&CK data processor.
Downloads, parses, chunks, and embeds MITRE ATT&CK techniques for RAG.
"""

import json
import logging
from typing import List, Dict, Any
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class MITREProcessor:
    """
    Processes MITRE ATT&CK data into chunks suitable for embedding.
    """
    
    def __init__(self, mitre_json_path: str):
        """
        Initialize the processor.
        
        Args:
            mitre_json_path: Path to enterprise-attack.json
        """
        self.mitre_json_path = Path(mitre_json_path)
        self.techniques = []
        
    def load_mitre_data(self) -> None:
        """
        Load and parse the MITRE ATT&CK JSON file.
        
        The STIX format has all data in an 'objects' array.
        We extract only 'attack-pattern' objects (techniques).
        """
        logger.info(f"Loading MITRE data from {self.mitre_json_path}")
        
        if not self.mitre_json_path.exists():
            raise FileNotFoundError(
                f"MITRE ATT&CK file not found: {self.mitre_json_path}\n"
                f"Run the download script first."
            )
        
        with open(self.mitre_json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Filter for attack-pattern objects only (these are techniques)
        all_objects = data.get('objects', [])
        attack_patterns = [
            obj for obj in all_objects 
            if obj.get('type') == 'attack-pattern'
        ]
        
        logger.info(f"Found {len(attack_patterns)} attack patterns")
        
        # Parse into our format
        for pattern in attack_patterns:
            technique = self._parse_technique(pattern)
            if technique:
                self.techniques.append(technique)
        
        logger.info(f"Parsed {len(self.techniques)} techniques")
    
    def _parse_technique(self, pattern: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse a single MITRE technique from STIX format.
        
        Args:
            pattern: STIX attack-pattern object
            
        Returns:
            Technique dictionary with relevant fields
        """
        # Get external references to find the technique ID
        external_refs = pattern.get('external_references', [])
        mitre_ref = next(
            (ref for ref in external_refs if ref.get('source_name') == 'mitre-attack'),
            None
        )
        
        if not mitre_ref:
            return None
        
        technique_id = mitre_ref.get('external_id', 'Unknown')
        technique_url = mitre_ref.get('url', '')
        
        # Extract kill chain phases (tactics)
        kill_chain_phases = pattern.get('kill_chain_phases', [])
        tactics = [
            phase.get('phase_name', '').replace('-', ' ').title()
            for phase in kill_chain_phases
        ]
        
        # Get platforms
        platforms = pattern.get('x_mitre_platforms', [])
        
        # Check if it's a sub-technique
        is_subtechnique = '.' in technique_id
        
        return {
            'technique_id': technique_id,
            'name': pattern.get('name', 'Unknown'),
            'description': pattern.get('description', ''),
            'tactics': tactics,
            'platforms': platforms,
            'url': technique_url,
            'is_subtechnique': is_subtechnique,
            'mitre_id': pattern.get('id', ''),  # STIX ID
        }
    
    def create_chunks(self) -> List[Dict[str, Any]]:
        """
        Create text chunks for embedding.
        
        Each technique becomes one chunk with:
        - Technique ID and name as title
        - Description as main content
        - Metadata for filtering
        
        Returns:
            List of chunk dictionaries
        """
        chunks = []
        
        for technique in self.techniques:
            # Create searchable text combining key fields
            text_content = (
                f"MITRE ATT&CK Technique: {technique['technique_id']} - {technique['name']}\n\n"
                f"Tactics: {', '.join(technique['tactics'])}\n"
                f"Platforms: {', '.join(technique['platforms'])}\n\n"
                f"Description:\n{technique['description']}"
            )
            
            chunk = {
                'text': text_content,
                'metadata': {
                    'technique_id': technique['technique_id'],
                    'name': technique['name'],
                    'tactics': technique['tactics'],
                    'platforms': technique['platforms'],
                    'url': technique['url'],
                    'is_subtechnique': technique['is_subtechnique'],
                    'source': 'mitre_attack',
                }
            }
            
            chunks.append(chunk)
        
        logger.info(f"Created {len(chunks)} chunks for embedding")
        return chunks
    
    def get_technique_by_id(self, technique_id: str) -> Dict[str, Any]:
        """
        Get a specific technique by its ID.
        
        Args:
            technique_id: MITRE technique ID (e.g., 'T1110' or 'T1110.001')
            
        Returns:
            Technique dictionary or None if not found
        """
        for technique in self.techniques:
            if technique['technique_id'] == technique_id:
                return technique
        return None


def main():
    """
    Test the MITRE processor.
    """
    # Get project root
    project_root = Path(__file__).parent.parent
    mitre_file = project_root / "data" / "mitre" / "enterprise-attack.json"
    
    # Initialize processor
    processor = MITREProcessor(mitre_file)
    
    # Load data
    processor.load_mitre_data()
    
    # Create chunks
    chunks = processor.create_chunks()
    
    # Show some examples
    print("\n" + "="*70)
    print("Sample MITRE ATT&CK Chunks")
    print("="*70)
    
    # Show first 3 chunks
    for i, chunk in enumerate(chunks[:3]):
        print(f"\nChunk {i+1}:")
        print("-" * 70)
        print(chunk['text'][:300] + "...")
        print(f"\nMetadata: {chunk['metadata']['technique_id']} - {chunk['metadata']['name']}")
    
    print("\n" + "="*70)
    print(f"Total chunks created: {len(chunks)}")
    print("="*70)
    
    # Test lookup
    print("\nTesting technique lookup:")
    brute_force = processor.get_technique_by_id('T1110')
    if brute_force:
        print(f"Found: {brute_force['technique_id']} - {brute_force['name']}")
        print(f"Tactics: {', '.join(brute_force['tactics'])}")


if __name__ == "__main__":
    main()