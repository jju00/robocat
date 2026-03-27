import ujson._

val targetFile     = "$FILE_PATH"
val targetFunction = "$FUNCTION_NAME"

val targetMethods =
  cpg.method
    .nameExact(targetFunction)
    .filter(m => !m.isExternal)
    .filter(m => m.filename == targetFile)
    .l

val resultsJson: ujson.Arr = ujson.Arr.from(
  targetMethods.map { m =>

    val calleesJson: ujson.Arr = ujson.Arr.from(
      m.call.map { c =>
        ujson.Obj(
          "call_name"        -> c.name,
          "callee_full_name" -> c.methodFullName,
          "call_code"        -> c.code.take(120),
          "line"             -> c.lineNumber.getOrElse(-1)
        )
      }.l
    )

    val callersJson: ujson.Arr = ujson.Arr.from(
      m.callIn.map { c =>
        ujson.Obj(
          "caller_method_name" -> c.method.name,
          "caller_full_name"   -> c.method.fullName,
          "call_code"          -> c.code.take(120),
          "line"               -> c.lineNumber.getOrElse(-1)
        )
      }.l
    )

    ujson.Obj(
      "method_name"      -> m.name,
      "method_full_name" -> m.fullName,
      "signature"        -> m.signature,
      "file"             -> m.filename,
      "line"             -> m.lineNumber.getOrElse(-1),
      "callee_count"     -> calleesJson.arr.size,
      "caller_count"     -> callersJson.arr.size,
      "callees"          -> calleesJson,
      "callers"          -> callersJson
    )
  }
)

val outJson = ujson.Obj(
  "project_name"        -> "$PROJECT_NAME",
  "query_file_path"     -> targetFile,
  "query_function_name" -> targetFunction,
  "result_count"        -> targetMethods.size,
  "results"             -> resultsJson
)

val __OUTPUT__ = ujson.write(outJson)
