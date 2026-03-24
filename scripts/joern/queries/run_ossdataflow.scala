import ujson._

open("$PROJECT_NAME")
run.ossdataflow

ujson.write(
  ujson.Obj(
    "status"       -> "ossdataflow complete",
    "project_name" -> "$PROJECT_NAME"
  ),
  indent = 2
)
