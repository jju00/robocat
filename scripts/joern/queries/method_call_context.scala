import ujson._

open("$PROJECT_NAME")

val targetFile = "$FILE_PATH"
val targetFunction = "$FUNCTION_NAME"

val targetMethods =
  cpg.method
    .nameExact(targetFunction)
    .filter(m => !m.isExternal)
    .filter(m => m.filename == targetFile)
    .l

val results =
  targetMethods.map { m =>
    val callees =
      m.callOut.map { call =>
        Map(
          "call_name" -> call.name,
          "callee_method_name" -> call.callee.name.headOption.getOrElse(""),
          "callee_full_name" -> call.methodFullName,
          "call_code" -> call.code,
          "line" -> call.lineNumber,
          "file" -> call.file.name.headOption.getOrElse("")
        )
      }.l

    val callers =
      m.callIn.map { call =>
        Map(
          "call_name" -> call.name,
          "caller_method_name" -> call.method.name,
          "caller_full_name" -> call.method.fullName,
          "call_code" -> call.code,
          "line" -> call.lineNumber,
          "file" -> call.file.name.headOption.getOrElse("")
        )
      }.l

    Map(
      "method_name" -> m.name,
      "method_full_name" -> m.fullName,
      "signature" -> m.signature,
      "file" -> m.filename,
      "line" -> m.lineNumber,
      "callee_count" -> callees.size,
      "caller_count" -> callers.size,
      "callees" -> callees,
      "callers" -> callers
    )
  }

val out =
  Map(
    "project_name" -> "$PROJECT_NAME",
    "language" -> "$LANGUAGE",
    "target_path" -> "$TARGET_PATH",
    "query_file_path" -> targetFile,
    "query_function_name" -> targetFunction,
    "result_count" -> results.size,
    "results" -> results
  )

println("OUTPUT: " + ujson.write(ujson.read(out.toJson)))