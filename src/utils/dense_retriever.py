import numpy as np
from typing import List, Optional

class DenseRetriever:
    """
    Semantic search using embeddings and cosine similarity.
    """
    def __init__(self):
        self.corpus_embeddings = None
        self.corpus = None

    def set_corpus(self, corpus_embeddings, corpus: Optional[List[str]] = None):
        """
        Set the corpus embeddings for search.
        corpus_embeddings: List of embedding vectors (floats)
        corpus: Optional original text for debugging/direct access
        """
        self.corpus_embeddings = np.array(corpus_embeddings, dtype=np.float32)
        self.corpus = corpus
        # Normalize for cosine similarity (dot product of normalized vectors)
        norms = np.linalg.norm(self.corpus_embeddings, axis=1, keepdims=True)
        # Avoid division by zero
        norms[norms == 0] = 1.0
        self.corpus_embeddings = self.corpus_embeddings / norms

    def search(self, query_embedding: List[float], top_n: int = -1) -> List[int]:
        """
        Perform semantic search using the query embedding.
        query_embedding: Embedding vector for the query
        top_n: Return top_n results; if top_n = -1, return all documents sorted
        return: List of indices sorted by similarity in descending order
        """
        if self.corpus_embeddings is None:
            raise ValueError("Corpus embeddings have not been set. Please call set_corpus() first.")

        query_vec = np.array(query_embedding, dtype=np.float32)
        query_norm = np.linalg.norm(query_vec)
        if query_norm > 0:
            query_vec = query_vec / query_norm
        
        # Cosine similarity is just the dot product since both are normalized
        similarities = np.dot(self.corpus_embeddings, query_vec)
        
        # Sort indices by similarity in descending order
        sorted_indices = np.argsort(similarities)[::-1]
        
        if top_n == -1:
            return sorted_indices.tolist()
        return sorted_indices[:top_n].tolist()

if __name__ == "__main__":
    # Test
    retriever = DenseRetriever()
    mock_embeddings = [
        [1.0, 0.0, 0.0],
        [0.0, 1.0, 0.0],
        [0.7, 0.7, 0.0]
    ]
    retriever.set_corpus(mock_embeddings)
    
    query = [0.8, 0.6, 0.0]
    results = retriever.search(query)
    print("Sorted indices by similarity:", results)
    # Expected order: 2 (0.7*0.8+0.7*0.6=0.98), 0 (1*0.8=0.8), 1 (1*0.6=0.6)
