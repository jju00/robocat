import ujson._

// workspace에 이미 있으면 importCode 생략, open만 실행
val alreadyLoaded = workspace.projects.map(_.name).contains("$PROJECT_NAME")

if (!alreadyLoaded) {
  importCode.$JOERN_IMPORT("$TARGET_PATH", "$PROJECT_NAME")
}

open("$PROJECT_NAME")

// taint 분석이 필요한 경우에만 ossdataflow 실행 ($RUN_DATAFLOW = "true" | "false")
if ("$RUN_DATAFLOW" == "true") {
  run.ossdataflow
}

val summary = Map(
  "project_name"   -> "$PROJECT_NAME",
  "language"       -> "$LANGUAGE",
  "target_path"    -> "$TARGET_PATH",
  "already_loaded" -> alreadyLoaded.toString,
  "ran_dataflow"   -> "$RUN_DATAFLOW",
  "files"          -> cpg.file.name.l.size,
  "methods"        -> cpg.method.name.l.size,
  "calls"          -> cpg.call.name.l.size,
  "identifiers"    -> cpg.identifier.name.l.size
)

ujson.write(ujson.read(summary.toJson), indent = 2)
