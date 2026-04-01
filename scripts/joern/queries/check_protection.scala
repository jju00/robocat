import io.shiftleft.codepropertygraph.generated.nodes._
import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language.*
import ujson._

// ── 타겟 함수 범위 ────────────────────────────────────────────────
val targetMethods =
  cpg.method
    .nameExact("$FUNCTION_NAME")
    .filter(_.filename.endsWith("$FILE_PATH"))
    .filter(m => !m.isExternal)
    .l

// ── source (전역) ────────────────────────────────────────────────
val sourceList =
  $SOURCE_EXPR
    .dedup
    .l

// ── 내부 source (타겟 함수 파라미터/field access) ───────────────
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

// ── sink 집합 ───────────────────────────────────────────────────
val localSinks =
  targetMethods.iterator
    .flatMap(_.ast.isCall.name("$SINK_REGEX").l)
    .toList

val globalSinks =
  cpg.call
    .name("$SINK_REGEX")
    .l

// ── flow 분석 헬퍼 ───────────────────────────────────────────────
def analyzeFlows(
  caseKind: String,
  sinks: List[Call],
  sources: List[StoredNode]
): List[Obj] = {
  sinks
    .reachableByFlows(sources)
    .map { flow =>
      val elements = flow.elements.l
      val sinkLine = elements.lastOption.flatMap(_.lineNumber).getOrElse(-1)

      val matchedSanitizers = elements.collect {
        case c: Call if c.name.matches("$SANITIZER_REGEX") =>
          Obj(
            "name" -> c.name,
            "line" -> c.lineNumber.getOrElse(-1),
            "expression" -> c.code
          )
      }

      val matchedGuards = elements.collect {
        case c: Call if c.name.matches("$GUARD_REGEX") =>
          Obj(
            "name" -> c.name,
            "line" -> c.lineNumber.getOrElse(-1),
            "expression" -> c.code
          )
      }

      val guardDominatesSinkOnFlow =
        matchedGuards.exists(g => g("line").num.toInt >= 0 && g("line").num.toInt < sinkLine)

      Obj(
        "case_kind" -> caseKind,
        "is_sanitized" -> matchedSanitizers.nonEmpty,
        "matched_sanitizers" -> Arr.from(matchedSanitizers),
        "flow_path" -> Arr.from(
          elements.map(node =>
            Obj(
              "line" -> node.lineNumber.getOrElse(-1),
              "code" -> node.code
            )
          )
        ),
        "sink_line" -> sinkLine,
        "guards_on_flow" -> Arr.from(matchedGuards),
        "guard_dominates_sink_on_flow" -> guardDominatesSinkOnFlow
      )
    }
    .l
}

// case 1: 전역 source -> diff 함수 내부 sink
val case1 = analyzeFlows(
  "global_source_to_local_sink",
  localSinks,
  sourceList
)

// case 2: diff 함수 내부 source -> 전역 sink
val case2 = analyzeFlows(
  "internal_source_to_global_sink",
  globalSinks,
  internalSourceList
)

// case 3: diff 함수 내부 source -> diff 함수 내부 sink (intra 중심)
val case3 = analyzeFlows(
  "internal_source_to_local_sink",
  localSinks,
  internalSourceList
)

val allResults = case1 ++ case2 ++ case3

val caseStats = List(
  Obj(
    "case_kind" -> "global_source_to_local_sink",
    "flow_count" -> case1.size,
    "protected_flows" -> case1.count(_("is_sanitized").bool),
    "flows_with_guard_dominance" -> case1.count(_("guard_dominates_sink_on_flow").bool)
  ),
  Obj(
    "case_kind" -> "internal_source_to_global_sink",
    "flow_count" -> case2.size,
    "protected_flows" -> case2.count(_("is_sanitized").bool),
    "flows_with_guard_dominance" -> case2.count(_("guard_dominates_sink_on_flow").bool)
  ),
  Obj(
    "case_kind" -> "internal_source_to_local_sink",
    "flow_count" -> case3.size,
    "protected_flows" -> case3.count(_("is_sanitized").bool),
    "flows_with_guard_dominance" -> case3.count(_("guard_dominates_sink_on_flow").bool)
  )
)

val sinkGuardMappings =
  allResults.map { d =>
    Obj(
      "case_kind" -> d("case_kind").str,
      "sink_line" -> d("sink_line").num.toInt,
      "related_guards" -> d("guards_on_flow"),
      "guard_dominates_sink" -> d("guard_dominates_sink_on_flow").bool
    )
  }

val finalOutput = Obj(
  "sink_category" -> "$SINK_NAME",
  "total_flows" -> allResults.size,
  "protected_flows" -> allResults.count(_("is_sanitized").bool),
  "details" -> Arr.from(allResults),
  "case_stats" -> Arr.from(caseStats),
  "guard_dominance" -> Obj(
    "total_sinks" -> sinkGuardMappings.size,
    "sinks_with_dominating_guard" -> sinkGuardMappings.count(_("guard_dominates_sink").bool),
    "sink_guard_mappings" -> Arr.from(sinkGuardMappings)
  )
)

val __OUTPUT__ = ujson.write(finalOutput)
