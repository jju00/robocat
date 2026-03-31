"""Tool 0: check_cpg_status
==========================
Joern workspace 현재 상태 확인 (진단용).
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from src.mcp.tools.cpg_tools import _fmt_executor, _get_executor

# ──────────────────────────────────────────────────────────────────────────────
# Tool 0: check_cpg_status
# ──────────────────────────────────────────────────────────────────────────────


async def check_cpg_status() -> str:
    """
    Joern workspace 의 현재 상태를 반환한다 (진단용).

    CPG 쿼리 전에 호출하면 프로젝트가 로드됐는지, 어떤 이름으로 저장됐는지 확인할 수 있다.
    CPG import 헤더 없이 순수 Joern 상태를 조회한다.

    Returns:
        JSON 문자열 with keys:
          - workspace_projects: workspace 에 저장된 프로젝트 이름 목록
          - active_cpg_root:    현재 활성 CPG 의 root 경로 (없으면 "none")
    """
    q = """
import ujson._

val projects = workspace.projects.map(_.name).l
val activeRoot = try {
  cpg.metaData.l.headOption.map(_.root).getOrElse("(empty cpg)")
} catch {
  case _: Throwable => "none"
}

val out = Map(
  "workspace_projects" -> projects,
  "active_cpg_root"    -> activeRoot
)

println("OUTPUT: " + ujson.write(ujson.read(out.toJson)))
"""
    result = await _get_executor().run_query(q)
    return _fmt_executor(result)


def register(mcp: FastMCP) -> None:
    """tool 등록 — server.py 에서 mcp 인스턴스를 받아 호출."""
    mcp.tool()(check_cpg_status)
