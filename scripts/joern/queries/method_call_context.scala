import ujson._

val targetFile     = "$FILE_PATH"
val targetFunction = "$FUNCTION_NAME"
val nldOverlayCallgraphStatus =
  try __NLD_OVERLAY_CALLGRAPH_STATUS.toString
  catch { case _: Throwable => "unknown" }
val nldOverlayDataflowStatus =
  try __NLD_OVERLAY_DATAFLOW_STATUS.toString
  catch { case _: Throwable => "unknown" }

// Fallback 1: nameExact + exact filename + non-external
val candidates1 =
  cpg.method
    .nameExact(targetFunction)
    .filter(m => !m.isExternal && m.filename == targetFile)
    .l

// Fallback 2: nameExact + non-external
val candidates2 =
  if (candidates1.nonEmpty) candidates1
  else
    cpg.method
      .nameExact(targetFunction)
      .filter(m => !m.isExternal)
      .l

// Fallback 3: nameExact + filename.endsWith
val candidates3 =
  if (candidates2.nonEmpty) candidates2
  else
    cpg.method
      .nameExact(targetFunction)
      .filter(m => !m.isExternal && m.filename.endsWith(targetFile))
      .l

// Prefer likely definitions: non-external first, then richer body
val targetMethods =
  candidates3.sortBy(m => (if (m.isExternal) 1 else 0, -m.ast.size))

val resultsJson: ujson.Arr = ujson.Arr.from(
  targetMethods.map { m =>
    val calleesFromCallGraph = m.callee.dedup.l
    val callersFromCallGraph = m.caller.dedup.l

    val calleesJson: ujson.Arr = ujson.Arr.from(
      if (calleesFromCallGraph.nonEmpty)
        calleesFromCallGraph.map { callee =>
          ujson.Obj(
            "source"           -> "callee",
            "method_name"      -> callee.name,
            "method_full_name" -> callee.fullName,
            "signature"        -> callee.signature,
            "file"             -> callee.filename,
            "line"             -> callee.lineNumber.getOrElse(-1)
          )
        }
      else
        m.ast.isCall.map { c =>
          ujson.Obj(
            "source"           -> "ast_call",
            "method_name"      -> c.name,
            "method_full_name" -> c.methodFullName,
            "signature"        -> "",
            "file"             -> "",
            "line"             -> c.lineNumber.getOrElse(-1)
          )
        }.l
    )

    val callersJson: ujson.Arr = ujson.Arr.from(
      if (callersFromCallGraph.nonEmpty)
        callersFromCallGraph.map { caller =>
          ujson.Obj(
            "source"           -> "caller",
            "method_name"      -> caller.name,
            "method_full_name" -> caller.fullName,
            "signature"        -> caller.signature,
            "file"             -> caller.filename,
            "line"             -> caller.lineNumber.getOrElse(-1)
          )
        }
      else
        cpg.call
          .methodFullNameExact(m.fullName)
          .map { c =>
          val callerName = try c.method.name catch { case _: Throwable => "" }
          val callerFullName = try c.method.fullName catch { case _: Throwable => "" }
          val callerSig = try c.method.signature catch { case _: Throwable => "" }
          val callerFile = try c.method.filename catch { case _: Throwable => "" }
          ujson.Obj(
            "source"           -> "callsite",
            "method_name"      -> callerName,
            "method_full_name" -> callerFullName,
            "signature"        -> callerSig,
            "file"             -> callerFile,
            "line"             -> c.lineNumber.getOrElse(-1)
          )
        }.l
    )

    ujson.Obj(
      "method_name"      -> m.name,
      "method_full_name" -> m.fullName,
      "signature"        -> m.signature,
      "file"             -> m.filename,
      "line"             -> m.lineNumber.getOrElse(-1),
      "ast_size"         -> m.ast.size,
      "callee_count"     -> calleesJson.arr.size,
      "caller_count"     -> callersJson.arr.size,
      "callees"          -> calleesJson,
      "callers"          -> callersJson
    )
  }
)

val matchedFile     = targetMethods.headOption.map(_.filename).getOrElse("")
val matchedFullName = targetMethods.headOption.map(_.fullName).getOrElse("")

val outJson = ujson.Obj(
  "project_name"         -> "$PROJECT_NAME",
  "query_file_path"      -> targetFile,
  "query_function_name"  -> targetFunction,
  "matched_file"         -> matchedFile,
  "matched_full_name"    -> matchedFullName,
  "overlay_callgraph"    -> nldOverlayCallgraphStatus,
  "overlay_dataflow"     -> nldOverlayDataflowStatus,
  "candidate_count"      -> candidates3.size,
  "result_count"         -> targetMethods.size,
  "results"              -> resultsJson
)

val __OUTPUT__ = ujson.write(outJson)
