"""
Vector store service for MITRE ATT&CK embeddings using Qdrant.
"""

import logging
from typing import List, Dict, Any
from pathlib import Path

from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams, PointStruct
from sentence_transformers import SentenceTransformer

from soc_demo.mitre_processor import MITREProcessor

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class MITREVectorStore:
    """
    Manages MITRE ATT&CK embeddings in Qdrant vector database.
    """
    
    COLLECTION_NAME = "mitre_attack"
    EMBEDDING_MODEL = "all-MiniLM-L6-v2"  # Fast, good quality, 384 dimensions
    
    def __init__(self, qdrant_url: str = "http://localhost:6333"):
        """
        Initialize the vector store.
        
        Args:
            qdrant_url: Qdrant server URL
        """
        self.qdrant_url = qdrant_url
        self.client = QdrantClient(url=qdrant_url)
        
        # Initialize embedding model
        logger.info(f"Loading embedding model: {self.EMBEDDING_MODEL}")
        self.embedder = SentenceTransformer(self.EMBEDDING_MODEL)
        self.embedding_dim = self.embedder.get_sentence_embedding_dimension()
        logger.info(f"Embedding dimension: {self.embedding_dim}")
    
    def collection_exists(self) -> bool:
        """Check if the MITRE collection exists."""
        collections = self.client.get_collections()
        return any(col.name == self.COLLECTION_NAME for col in collections.collections)
    
    def create_collection(self) -> None:
        """
        Create the Qdrant collection for MITRE data.
        """
        if self.collection_exists():
            logger.info(f"Collection '{self.COLLECTION_NAME}' already exists")
            return
        
        logger.info(f"Creating collection '{self.COLLECTION_NAME}'")
        
        self.client.create_collection(
            collection_name=self.COLLECTION_NAME,
            vectors_config=VectorParams(
                size=self.embedding_dim,
                distance=Distance.COSINE  # Cosine similarity for text
            )
        )
        
        logger.info("Collection created successfully")
    
    def delete_collection(self) -> None:
        """Delete the collection (for rebuilding)."""
        if self.collection_exists():
            logger.info(f"Deleting collection '{self.COLLECTION_NAME}'")
            self.client.delete_collection(collection_name=self.COLLECTION_NAME)
    
    def embed_chunks(self, chunks: List[Dict[str, Any]]) -> List[List[float]]:
        """
        Generate embeddings for text chunks.
        
        Args:
            chunks: List of chunk dictionaries with 'text' key
            
        Returns:
            List of embedding vectors
        """
        texts = [chunk['text'] for chunk in chunks]
        
        logger.info(f"Generating embeddings for {len(texts)} chunks...")
        embeddings = self.embedder.encode(
            texts,
            show_progress_bar=True,
            batch_size=32
        )
        
        return embeddings.tolist()
    
    def ingest_mitre_data(self, mitre_json_path: str) -> None:
        """
        Complete ingestion pipeline:
        1. Parse MITRE data
        2. Create chunks
        3. Generate embeddings
        4. Upload to Qdrant
        
        Args:
            mitre_json_path: Path to enterprise-attack.json
        """
        # Step 1: Parse MITRE data
        logger.info("Step 1/4: Parsing MITRE ATT&CK data...")
        processor = MITREProcessor(mitre_json_path)
        processor.load_mitre_data()
        chunks = processor.create_chunks()
        
        # Step 2: Create collection
        logger.info("Step 2/4: Creating Qdrant collection...")
        self.create_collection()
        
        # Step 3: Generate embeddings
        logger.info("Step 3/4: Generating embeddings...")
        embeddings = self.embed_chunks(chunks)
        
        # Step 4: Upload to Qdrant
        logger.info("Step 4/4: Uploading to Qdrant...")
        
        points = []
        for idx, (chunk, embedding) in enumerate(zip(chunks, embeddings)):
            point = PointStruct(
                id=idx,
                vector=embedding,
                payload={
                    'text': chunk['text'],
                    'technique_id': chunk['metadata']['technique_id'],
                    'name': chunk['metadata']['name'],
                    'tactics': chunk['metadata']['tactics'],
                    'platforms': chunk['metadata']['platforms'],
                    'url': chunk['metadata']['url'],
                    'is_subtechnique': chunk['metadata']['is_subtechnique'],
                }
            )
            points.append(point)
        
        # Upload in batches
        batch_size = 100
        for i in range(0, len(points), batch_size):
            batch = points[i:i + batch_size]
            self.client.upsert(
                collection_name=self.COLLECTION_NAME,
                points=batch
            )
            logger.info(f"Uploaded {min(i + batch_size, len(points))}/{len(points)} points")
        
        logger.info("✅ MITRE ATT&CK data ingestion complete!")
    
    def search(self, query: str, limit: int = 5) -> List[Dict[str, Any]]:
        """
        Semantic search for relevant MITRE techniques.
        
        Args:
            query: Search query (e.g., "powershell obfuscated command")
            limit: Number of results to return
            
        Returns:
            List of technique dictionaries with scores
        """
        # Generate query embedding
        query_vector = self.embedder.encode(query).tolist()
        
        # Search Qdrant
        results = self.client.search(
            collection_name=self.COLLECTION_NAME,
            query_vector=query_vector,
            limit=limit
        )
        
        # Format results
        formatted_results = []
        for result in results:
            formatted_results.append({
                'technique_id': result.payload['technique_id'],
                'name': result.payload['name'],
                'tactics': result.payload['tactics'],
                'platforms': result.payload['platforms'],
                'url': result.payload['url'],
                'score': result.score,
                'description': result.payload['text'],
            })
        
        return formatted_results
    
    def get_collection_info(self) -> Dict[str, Any]:
        """Get information about the collection."""
        if not self.collection_exists():
            return {'exists': False}
        
        info = self.client.get_collection(collection_name=self.COLLECTION_NAME)
        return {
            'exists': True,
            'vectors_count': info.vectors_count,
            'points_count': info.points_count,
        }


def main():
    """
    Build the MITRE ATT&CK vector store.
    """
    # Paths
    project_root = Path(__file__).parent.parent
    mitre_file = project_root / "data" / "mitre" / "enterprise-attack.json"
    
    # Initialize vector store
    store = MITREVectorStore()
    
    # Check if already exists
    info = store.get_collection_info()
    if info['exists']:
        print(f"\n⚠️  Collection already exists with {info['points_count']} points")
        print("Do you want to rebuild it? (y/n): ", end='')
        response = input().strip().lower()
        if response == 'y':
            store.delete_collection()
        else:
            print("Skipping ingestion. Testing search instead...\n")
            test_search(store)
            return
    
    # Ingest MITRE data
    print("\n" + "="*70)
    print("Building MITRE ATT&CK Vector Store")
    print("="*70 + "\n")
    
    store.ingest_mitre_data(str(mitre_file))
    
    # Test search
    print("\n" + "="*70)
    print("Testing Search")
    print("="*70 + "\n")
    
    test_search(store)


def test_search(store: MITREVectorStore):
    """Test search functionality."""
    test_queries = [
        "powershell encoded command obfuscation",
        "brute force password guessing",
        "command and control communication",
    ]
    
    for query in test_queries:
        print(f"\nQuery: '{query}'")
        print("-" * 70)
        
        results = store.search(query, limit=3)
        
        for i, result in enumerate(results, 1):
            print(f"\n{i}. {result['technique_id']} - {result['name']}")
            print(f"   Tactics: {', '.join(result['tactics'])}")
            print(f"   Platforms: {', '.join(result['platforms'])}")
            print(f"   Similarity Score: {result['score']:.4f}")
            print(f"   URL: {result['url']}")


if __name__ == "__main__":
    main()