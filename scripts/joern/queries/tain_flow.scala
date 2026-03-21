import io.joern.dataflowengineoss.language.*
import ujson._

open("$PROJECT_NAME")
run.ossdataflow

val sources =
  $SOURCE_EXPR
    .l

val sinks =
  cpg.call
    .name("$SINK_REGEX")
    .argument
    .l

val flows =
  sinks.reachableByFlows(sources)
    .map(flow =>
      flow.elements.map(node =>
        Map(
          "line" -> node.lineNumber,
          "code" -> node.code,
          "type" -> node.label,
          "file" -> node.file.name.headOption.getOrElse("")
        )
      )
    ).l

val out =
  Map(
    "project_name" -> "$PROJECT_NAME",
    "language" -> "$LANGUAGE",
    "target_path" -> "$TARGET_PATH",
    "sink_name" -> "$SINK_NAME",
    "source_count" -> sources.size,
    "sink_count" -> sinks.size,
    "flow_count" -> flows.size,
    "flows" -> flows
  )

ujson.write(ujson.read(out.toJson), indent = 2)