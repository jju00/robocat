import ujson._

// ── CPG HEADER ────────────────────────────────────────────────────────────────
if (workspace.projects.isEmpty) {
  importCode.$JOERN_IMPORT("$TARGET_PATH", "$PROJECT_NAME")

  // importCode 실패 감지: 실행 후에도 workspace 가 비어 있으면 명시적 에러
  if (workspace.projects.isEmpty) {
    throw new Exception(
      s"[NLD] importCode.$JOERN_IMPORT failed: workspace still empty. " +
      s"Check that '$TARGET_PATH' exists inside the Joern container and contains source files."
    )
  }
} else {
  open(workspace.projects.head.name)
}

// taint 분석이 필요한 경우에만 ossdataflow 실행
if ("$RUN_DATAFLOW" == "true") {
  run.ossdataflow
}
// ── END CPG HEADER ────────────────────────────────────────────────────────────
