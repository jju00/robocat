import ujson._

// ── CONFIG ───────────────────────────────────────────────────────────────
val projectName    = "$PROJECT_NAME"
val targetPath     = "$TARGET_PATH"
val ensureOverlays = "$ENSURE_OVERLAYS" == "true"
var overlayCallgraphStatus = "disabled"
var overlayDataflowStatus  = "disabled"

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

// callgraph + ossdataflow 오버레이 적용.
// 이미 적용된 경우 Joern 이 예외를 던질 수 있으므로 try/catch 로 감싸되,
// 결과(성공/실패 메시지)는 stderr 로 출력하여 진단 가능하게 한다.
def runOverlays(): Unit = {
  if (!ensureOverlays) return

  overlayCallgraphStatus = try {
    run.callgraph
    "ok"
  } catch {
    case e: Throwable => s"error(${Option(e.getMessage).getOrElse(e.getClass.getSimpleName)})"
  }
  System.err.println(s"[NLD] overlay callgraph   : $overlayCallgraphStatus")

  overlayDataflowStatus = try {
    run.ossdataflow
    "ok"
  } catch {
    case e: Throwable => s"error(${Option(e.getMessage).getOrElse(e.getClass.getSimpleName)})"
  }
  System.err.println(s"[NLD] overlay ossdataflow : $overlayDataflowStatus")
}

// ── MAIN ─────────────────────────────────────────────────────────────────
ensureProject()

// 상태가 이상하면 cpg 재생성
if (!isHealthy()) {
  delete(projectName)
  importCode.$JOERN_IMPORT(targetPath, projectName)
  open(projectName)
}

// ensureOverlays == true 인 경우 callgraph + ossdataflow 오버레이를 적용
runOverlays()

val __NLD_OVERLAY_CALLGRAPH_STATUS = overlayCallgraphStatus
val __NLD_OVERLAY_DATAFLOW_STATUS  = overlayDataflowStatus
