"""Tool 0: check_cpg_status
==========================
Joern workspace 현재 상태 확인 (진단용).
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from src.mcp.tools.cpg_tools import _fmt_executor, _run_cpg_query

# ──────────────────────────────────────────────────────────────────────────────
# Tool 0: check_cpg_status
# ──────────────────────────────────────────────────────────────────────────────


async def check_cpg_status() -> str:
    """
    Joern workspace 의 현재 상태를 반환한다 (진단용).

    import_cpg.scala 헤더를 먼저 실행하여 프로젝트를 open 한 뒤
    workspace 상태를 조회한다. 다른 CPG 쿼리와 동일한 실행 경로를 사용하므로
    헤더 실행 후 실제로 CPG 가 활성화됐는지 함께 진단할 수 있다.

    Returns:
        JSON 문자열 with keys:
          - workspace_projects: workspace 에 저장된 프로젝트 이름 목록
          - active_cpg_root:    현재 활성 CPG 의 root 경로 (없으면 "none")
    """
    q = """
val projects = workspace.projects.map(_.name).l
val activeRoot = try {
  cpg.metaData.l.headOption.map(_.root).getOrElse("(empty cpg)")
} catch {
  case _: Throwable => "none"
}
val overlayCallgraph = try {
  __NLD_OVERLAY_CALLGRAPH_STATUS.toString
} catch {
  case _: Throwable => "unknown"
}
val overlayDataflow = try {
  __NLD_OVERLAY_DATAFLOW_STATUS.toString
} catch {
  case _: Throwable => "unknown"
}
val callCount = try { cpg.call.size } catch { case _: Throwable => -1 }
val methodCount = try { cpg.method.size } catch { case _: Throwable => -1 }

val __OUTPUT__ = ujson.write(ujson.Obj(
  "workspace_projects" -> ujson.Arr.from(projects),
  "active_cpg_root"    -> activeRoot,
  "method_count"       -> methodCount,
  "call_count"         -> callCount,
  "overlay_callgraph"  -> overlayCallgraph,
  "overlay_dataflow"   -> overlayDataflow
))
"""
    result = await _run_cpg_query(q, ensure_overlays=True)
    return _fmt_executor(result)


def register(mcp: FastMCP) -> None:
    """tool 등록 — server.py 에서 mcp 인스턴스를 받아 호출."""
    mcp.tool()(check_cpg_status)
