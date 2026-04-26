"""
EmbeddingCache — SQLite 기반 임베딩 캐시
=========================================
기존 JSON 방식은 959MB 파일을 통째로 메모리에 올려 OOM을 유발했다.
SQLite를 사용하면 get/set 시 필요한 행만 I/O하므로 메모리 사용량이
corpus 크기에 무관하게 상수 수준으로 유지된다.

이전 embeddings.json이 있으면 자동으로 마이그레이션한다.
"""

import json
import sqlite3
import struct
from pathlib import Path
from typing import List, Optional


# 1536-dim float32 벡터 → 6144 bytes binary
_DIM = 1536
_PACK_FMT = f"{_DIM}f"


def _encode(vec: List[float]) -> bytes:
    return struct.pack(_PACK_FMT, *vec)


def _decode(blob: bytes) -> List[float]:
    return list(struct.unpack(_PACK_FMT, blob))


class EmbeddingCache:
    """
    SQLite 기반 임베딩 캐시.

    스키마:
        embeddings(text TEXT PRIMARY KEY, vector BLOB)

    기존 embeddings.json 이 같은 디렉토리에 있으면 DB 생성 시 1회 마이그레이션.
    마이그레이션 후 JSON 파일은 .bak으로 이름을 바꿔 보존한다.
    """

    def __init__(self, cache_path: str):
        # .json 확장자로 넘어와도 .db 로 저장
        p = Path(cache_path)
        self.db_path = p.with_suffix(".db")
        self.json_path = p.with_suffix(".json")

        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS embeddings "
            "(text TEXT PRIMARY KEY, vector BLOB NOT NULL)"
        )
        self._conn.commit()

        # 최초 1회 JSON → DB 마이그레이션
        if self.json_path.exists() and not self._already_migrated():
            self._migrate_from_json()

    # ── 내부 헬퍼 ──────────────────────────────────────────────

    def _already_migrated(self) -> bool:
        row = self._conn.execute("SELECT COUNT(*) FROM embeddings").fetchone()
        return row[0] > 0

    # 이 크기 이상이면 json.load() 자체가 OOM이 되므로 마이그레이션 없이 .bak 처리
    _MIGRATE_SIZE_LIMIT = 100 * 1024 * 1024  # 100 MB

    def _migrate_from_json(self) -> None:
        size = self.json_path.stat().st_size
        bak = self.json_path.with_suffix(".json.bak")

        if size > self._MIGRATE_SIZE_LIMIT:
            self.json_path.rename(bak)
            print(
                f"[CACHE] embeddings.json ({size // 1024 // 1024} MB) is too large to migrate. "
                f"Renamed to {bak.name}. Embeddings will be rebuilt from scratch.",
                flush=True,
            )
            return

        print(f"[CACHE] migrating {self.json_path.name} → {self.db_path.name} ...",
              flush=True)
        try:
            with open(self.json_path, "r", encoding="utf-8") as f:
                data: dict = json.load(f)

            batch = []
            for text, vec in data.items():
                if len(vec) == _DIM:
                    batch.append((text, _encode(vec)))
                if len(batch) >= 1000:
                    self._conn.executemany(
                        "INSERT OR IGNORE INTO embeddings VALUES (?,?)", batch
                    )
                    self._conn.commit()
                    batch.clear()
            if batch:
                self._conn.executemany(
                    "INSERT OR IGNORE INTO embeddings VALUES (?,?)", batch
                )
                self._conn.commit()

            self.json_path.rename(bak)
            print(f"[CACHE] migration done ({self._count()} entries). "
                  f"original → {bak.name}", flush=True)
        except Exception as e:
            print(f"[CACHE] migration failed: {e}", flush=True)

    def _count(self) -> int:
        return self._conn.execute("SELECT COUNT(*) FROM embeddings").fetchone()[0]

    # ── 공개 API ───────────────────────────────────────────────

    def get(self, text: str) -> Optional[List[float]]:
        row = self._conn.execute(
            "SELECT vector FROM embeddings WHERE text = ?", (text,)
        ).fetchone()
        return _decode(row[0]) if row else None

    def set(self, text: str, embedding: List[float]) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO embeddings VALUES (?,?)",
            (text, _encode(embedding)),
        )
        self._conn.commit()

    def get_many(self, texts: List[str]) -> List[Optional[List[float]]]:
        """texts 순서를 유지하며 캐시 히트/미스 반환."""
        if not texts:
            return []
        placeholders = ",".join("?" * len(texts))
        rows = self._conn.execute(
            f"SELECT text, vector FROM embeddings WHERE text IN ({placeholders})",
            texts,
        ).fetchall()
        hit: dict[str, List[float]] = {r[0]: _decode(r[1]) for r in rows}
        return [hit.get(t) for t in texts]

    def set_many(self, texts: List[str], embeddings: List[List[float]]) -> None:
        self._conn.executemany(
            "INSERT OR REPLACE INTO embeddings VALUES (?,?)",
            [(t, _encode(e)) for t, e in zip(texts, embeddings)],
        )
        self._conn.commit()

    def save_cache(self) -> None:
        """하위 호환용 no-op. SQLite는 set/set_many 시 즉시 커밋된다."""
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()
