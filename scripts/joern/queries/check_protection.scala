import io.shiftleft.codepropertygraph.generated.nodes._
import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language.*
import overflowdb.traversal._

val sources = $SOURCE_EXPR
val sinks = cpg.call.name("$SINK_REGEX").l

val flows = sinks.reachableByFlows(sources).l

val results = flows.map { flow =>
  val elements = flow.elements.l
  
  val matchedSanitizers = elements.collect {
    case c: Call if c.name.matches("$SANITIZER_REGEX") => 
      Map("name" -> c.name, "line" -> c.lineNumber.getOrElse(-1))
  }

  Map(
    "is_sanitized" -> matchedSanitizers.nonEmpty,
    "matched_sanitizers" -> matchedSanitizers,
    "flow_path" -> elements.map(node => Map("line" -> node.lineNumber.getOrElse(-1), "code" -> node.code))
  )
}

val finalOutput = Map(
  "sink_category" -> "$SINK_NAME",
  "total_flows" -> results.size,
  "protected_flows" -> results.count(_("is_sanitized").asInstanceOf[Boolean]),
  "details" -> results
)

println("OUTPUT: " + ujson.write(finalOutput))