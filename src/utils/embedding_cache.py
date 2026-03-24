import json
import os
from pathlib import Path
from typing import Dict, List, Optional

class EmbeddingCache:
    """
    Simple file-based cache for embeddings.
    """
    def __init__(self, cache_path: str):
        self.cache_path = Path(cache_path)
        self.cache: Dict[str, List[float]] = {}
        self._load_cache()

    def _load_cache(self):
        if self.cache_path.exists():
            try:
                with open(self.cache_path, "r", encoding="utf-8") as f:
                    self.cache = json.load(f)
            except Exception as e:
                print(f"[CACHE] Error loading cache: {e}")
                self.cache = {}

    def save_cache(self):
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(self.cache_path, "w", encoding="utf-8") as f:
                json.dump(self.cache, f, ensure_ascii=False)
        except Exception as e:
            print(f"[CACHE] Error saving cache: {e}")

    def get(self, text: str) -> Optional[List[float]]:
        return self.cache.get(text)

    def set(self, text: str, embedding: List[float]):
        self.cache[text] = embedding

    def get_many(self, texts: List[str]) -> List[Optional[List[float]]]:
        return [self.cache.get(text) for text in texts]

    def set_many(self, texts: List[str], embeddings: List[List[float]]):
        for text, emb in zip(texts, embeddings):
            self.cache[text] = emb
