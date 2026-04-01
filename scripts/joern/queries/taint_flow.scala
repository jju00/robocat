import io.joern.dataflowengineoss.language.*
import ujson._

val sourceList =
  $SOURCE_EXPR
    .dedup.l

val sinks =
  cpg.call
    .name("$SINK_REGEX")
    .argument
    .l

val flows =
  sinks.reachableByFlows(sourceList)
    .map { flow =>
      ujson.Arr.from(
        flow.elements.map { node =>
          ujson.Obj(
            "line" -> node.lineNumber.getOrElse(-1),
            "code" -> node.code.take(200),
            "type" -> node.label,
            "file" -> node.file.name.headOption.getOrElse("")
          )
        }
      )
    }.l

val outJson = ujson.Obj(
  "project_name"  -> "$PROJECT_NAME",
  "language"      -> "$LANGUAGE",
  "target_path"   -> "$TARGET_PATH",
  "sink_name"     -> "$SINK_NAME",
  "source_count"  -> sourceList.size,
  "sink_count"    -> sinks.size,
  "flow_count"    -> flows.size,
  "flows"         -> ujson.Arr.from(flows)
)

val __OUTPUT__ = ujson.write(outJson)
