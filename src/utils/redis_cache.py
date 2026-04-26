from __future__ import annotations

import json
import os
from typing import Any, Optional

from redis.asyncio import Redis


class RedisCache:
    def __init__(self) -> None:
        self._enabled = os.getenv("REDIS_ENABLED", "false").lower() == "true"
        self._client: Optional[Redis] = None

        if self._enabled:
            host = os.getenv("REDIS_HOST", "localhost")
            port = int(os.getenv("REDIS_PORT", "6379"))
            db = int(os.getenv("REDIS_DB", "0"))
            self._client = Redis(
                host=host,
                port=port,
                db=db,
                decode_responses=True,
            )

    @property
    def enabled(self) -> bool:
        return self._enabled and self._client is not None

    async def get_json(self, key: str) -> Optional[dict[str, Any]]:
        if not self.enabled:
            return None

        value = await self._client.get(key)
        if value is None:
            return None

        return json.loads(value)

    async def set_json(
        self,
        key: str,
        value: dict[str, Any],
        *,
        project: str,
        revision: str,
    ) -> None:
        """
        JSON 캐시 저장 + 해당 revision의 index set에 key 등록
        """
        if not self.enabled:
            return

        await self._client.set(key, json.dumps(value, ensure_ascii=False))
        await self._client.sadd(self._index_key(project, revision), key)

    async def delete(self, key: str) -> None:
        if not self.enabled:
            return

        await self._client.delete(key)

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()

    # ─────────────────────────────────────────────────────────────
    # Active revision 관리
    # ─────────────────────────────────────────────────────────────

    def _active_revision_key(self, project: str) -> str:
        return f"nld:active_cpg:{project}"

    async def get_active_revision(self, project: str) -> Optional[str]:
        """
        현재 project에 대해 활성화된 CPG revision 조회
        """
        if not self.enabled:
            return None

        return await self._client.get(self._active_revision_key(project))

    async def set_active_revision(self, project: str, revision: str) -> None:
        """
        현재 project의 active revision 설정
        """
        if not self.enabled:
            return

        await self._client.set(self._active_revision_key(project), revision)

    async def ensure_active_revision(self, project: str, revision: str) -> bool:
        """
        active revision이 현재 revision과 같은지 확인하고,
        다르면 갱신.

        return:
          True  -> active revision이 변경됨
          False -> 기존과 동일
        """
        if not self.enabled:
            return False

        key = self._active_revision_key(project)
        current = await self._client.get(key)

        if current == revision:
            return False

        await self._client.set(key, revision)
        return True

    # ─────────────────────────────────────────────────────────────
    # Revision별 캐시 인덱스 관리
    # ─────────────────────────────────────────────────────────────

    def _index_key(self, project: str, revision: str) -> str:
        return f"nld:index:{project}:rev{revision}"

    async def clear_revision_cache(self, project: str, revision: str) -> None:
        """
        특정 revision에 속한 캐시 key들을 모두 삭제
        """
        if not self.enabled:
            return

        index_key = self._index_key(project, revision)
        keys = await self._client.smembers(index_key)

        if keys:
            await self._client.delete(*keys)

        await self._client.delete(index_key)

    # ─────────────────────────────────────────────────────────────
    # Key 생성 유틸
    # ─────────────────────────────────────────────────────────────

    @staticmethod
    def _sanitize_component(value: str) -> str:
        """
        Redis key 구분자 ':' 충돌을 줄이기 위한 간단한 sanitize
        """
        return value.replace(":", "_")

    def make_cpg_summary_key(
        self,
        project: str,
        revision: str,
        file_path: str,
        function_name: str,
    ) -> str:
        project = self._sanitize_component(project)
        file_path = self._sanitize_component(file_path)
        function_name = self._sanitize_component(function_name)

        return f"nld:cpg_summary:{project}:rev{revision}:{file_path}:{function_name}"

    def make_dataflow_key(
        self,
        project: str,
        revision: str,
        file_path: str,
        function_name: str,
        sink_kind: str,
    ) -> str:
        project = self._sanitize_component(project)
        file_path = self._sanitize_component(file_path)
        function_name = self._sanitize_component(function_name)
        sink_kind = self._sanitize_component(sink_kind)

        return f"nld:dataflow:{project}:rev{revision}:{file_path}:{function_name}:{sink_kind}"

    def make_guard_key(
        self,
        project: str,
        revision: str,
        file_path: str,
        function_name: str,
    ) -> str:
        project = self._sanitize_component(project)
        file_path = self._sanitize_component(file_path)
        function_name = self._sanitize_component(function_name)

        return f"nld:guard:{project}:rev{revision}:{file_path}:{function_name}"