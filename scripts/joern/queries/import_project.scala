import ujson._

importCode.$JOERN_IMPORT("$TARGET_PATH", "$PROJECT_NAME")
open("$PROJECT_NAME")
run.ossdataflow

val summary =
  Map(
    "project_name" -> "$PROJECT_NAME",
    "language" -> "$LANGUAGE",
    "target_path" -> "$TARGET_PATH",
    "files" -> cpg.file.name.l.size,
    "methods" -> cpg.method.name.l.size,
    "calls" -> cpg.call.name.l.size,
    "identifiers" -> cpg.identifier.name.l.size
  )

println("OUTPUT: " + ujson.write(ujson.read(summary.toJson), indent = 2))