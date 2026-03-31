import ujson._

// ── CONFIG ───────────────────────────────────────────────────────────────
val projectName = "$PROJECT_NAME"
val targetPath  = "$TARGET_PATH"
val runDataflow = "$RUN_DATAFLOW" == "true"

// ── HELPERS ──────────────────────────────────────────────────────────────
def projectExists(name: String): Boolean =
  workspace.projects.map(_.name).contains(name)

def ensureProject(): Unit = {
  if (!projectExists(projectName)) {
    importCode.$JOERN_IMPORT(targetPath, projectName)

    if (!projectExists(projectName)) {
      throw new Exception(
        s"[NLD] importCode.$JOERN_IMPORT failed for '$projectName' at '$targetPath'"
      )
    }
  }
  open(projectName)
}

// 간단한 헬스체크
def isHealthy(): Boolean = {
  try {
    val m = cpg.method.size
    val c = cpg.call.size
    m > 0 && c >= 0
  } catch {
    case _: Throwable => false
  }
}

// ── MAIN ─────────────────────────────────────────────────────────────────
ensureProject()

// 상태가 이상하면 아예 cpg 재생성
if (!isHealthy()) {
  delete(projectName)
  importCode.$JOERN_IMPORT(targetPath, projectName)
  open(projectName)
}
