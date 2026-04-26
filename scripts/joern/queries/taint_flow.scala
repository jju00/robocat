import io.joern.dataflowengineoss.language.*
import io.shiftleft.codepropertygraph.generated.nodes._
import ujson._

// ── 타겟 함수 범위 ────────────────────────────────────────────────
val targetMethods =
  cpg.method
    .nameExact("$TARGET_FUNCTION")
    .filter(m => !m.isExternal && m.filename.endsWith("$TARGET_FILE"))
    .l

// ── source ────────────────────────────────────────────────────────
val sourceList =
  $SOURCE_EXPR
    .dedup.l

// ── 내부 source (타겟 함수 파라미터/struct field 접근) ───────────
val internalParamSources =
  targetMethods.iterator
    .flatMap(_.parameter.l)
    .toList

val internalFieldSources =
  targetMethods.iterator
    .flatMap(_.ast.isCall.name("(<operator>\\.fieldAccess|<operator>\\.indirectFieldAccess)").l)
    .toList

val internalSourceList =
  (internalParamSources ++ internalFieldSources).distinct

// ── sink ─────────────────────────────────────────────────────────
// local sinks: 타겟 함수 내부 sink
val localSinks =
  targetMethods.iterator
    .flatMap(_.ast.isCall.name("$SINK_REGEX").l)
    .toList

// global sinks: 프로젝트 전역 sink (내부 source -> 전역 sink 케이스용)
val globalSinks =
  cpg.call
    .name("$SINK_REGEX")
    .l

// ── alloc / free 사이트 (UAF 메타용) ─────────────────────────────
val allocCalls =
  targetMethods.iterator
    .flatMap(_.ast.isCall.name("(malloc|calloc|realloc|alloca|strdup|xmalloc)").l)
    .toList

val freeCalls =
  targetMethods.iterator
    .flatMap(_.ast.isCall.name("(free|delete|kfree|xfree|g_free)").l)
    .toList

val freeLines = freeCalls.flatMap(_.lineNumber).toSet

// ── 경로 상대화 헬퍼 ──────────────────────────────────────────────
val basePath = "$TARGET_PATH"

def relPath(f: String): String =
  if (basePath.nonEmpty && f.startsWith(basePath))
    f.substring(basePath.length).stripPrefix("/")
  else f

// ── flow 추출 및 역할 태깅 ────────────────────────────────────────
def flowToJson(flow: io.joern.dataflowengineoss.language.Path, caseKind: String): ujson.Obj = {
  val elems    = flow.elements
  val total    = elems.size
  val sinkLine = elems.lastOption.flatMap(_.lineNumber).getOrElse(-1)
  val hasPostFreeUse =
    freeLines.nonEmpty && freeLines.exists(fl => fl > 0 && fl < sinkLine)
  ujson.Obj(
    "case_kind" -> caseKind,
    "post_free_use" -> hasPostFreeUse,
    "nodes" -> ujson.Arr.from(
      elems.zipWithIndex.map { case (node, idx) =>
        val role =
          if (idx == 0) "source"
          else if (idx == total - 1) "sink"
          else "intermediate"
        ujson.Obj(
          "role" -> role,
          "line" -> node.lineNumber.getOrElse(-1),
          "code" -> node.code.take(120),
          "type" -> node.label,
          "file" -> relPath(node.file.name.headOption.getOrElse(""))
        )
      }
    )
  )
}

// 기존 케이스: 전역 source -> 타겟 함수 내부 sink
val flowsGlobalSourceToLocalSink =
  localSinks
    .reachableByFlows(sourceList)
    .map(flow => flowToJson(flow, "global_source_to_local_sink"))
    .l

// 추가 케이스 1: 타겟 함수 내부 source -> 타겟 함수 내부 sink (intra 중심)
val flowsInternalSourceToLocalSink =
  localSinks
    .reachableByFlows(internalSourceList)
    .map(flow => flowToJson(flow, "internal_source_to_local_sink"))
    .l

// 추가 케이스 2: 타겟 함수 내부 source -> 전역 sink
val flowsInternalSourceToGlobalSink =
  globalSinks
    .reachableByFlows(internalSourceList)
    .map(flow => flowToJson(flow, "internal_source_to_global_sink"))
    .l

val flows =
  (flowsGlobalSourceToLocalSink ++
    flowsInternalSourceToLocalSink ++
    flowsInternalSourceToGlobalSink)

// ── UAF 메타 ──────────────────────────────────────────────────────
val uafMeta = ujson.Obj(
  "alloc_sites" -> ujson.Arr.from(
    allocCalls.map(c => ujson.Obj(
      "line" -> c.lineNumber.getOrElse(-1),
      "code" -> c.code.take(120)
    ))
  ),
  "free_sites" -> ujson.Arr.from(
    freeCalls.map(c => ujson.Obj(
      "line" -> c.lineNumber.getOrElse(-1),
      "code" -> c.code.take(120)
    ))
  )
)

val outJson = ujson.Obj(
  "project_name"    -> "$PROJECT_NAME",
  "language"        -> "$LANGUAGE",
  "target_file"     -> "$TARGET_FILE",
  "target_function" -> "$TARGET_FUNCTION",
  "sink_name"       -> "$SINK_NAME",
  "source_count"    -> sourceList.size,
  "internal_source_count" -> internalSourceList.size,
  "effective_source_count" -> (sourceList ++ internalSourceList).distinct.size,
  "sink_count"      -> localSinks.size,
  "global_sink_count" -> globalSinks.size,
  "flow_count"      -> flows.size,
  "flows"           -> ujson.Arr.from(flows),
  "uaf_meta"        -> uafMeta
)

val __OUTPUT__ = ujson.write(outJson)
