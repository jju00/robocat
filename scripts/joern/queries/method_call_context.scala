import ujson._

val targetFile     = "$FILE_PATH"
val targetFunction = "$FUNCTION_NAME"
val maxDepth =
  try "$DEPTH".toInt
  catch { case _: Throwable => 1 }
val duplicateMode = "$DUPLICATE_MODE"
val targetLine =
  try "$TARGET_LINE".toInt
  catch { case _: Throwable => -1 }
val nldOverlayCallgraphStatus =
  try __NLD_OVERLAY_CALLGRAPH_STATUS.toString
  catch { case _: Throwable => "unknown" }
val nldOverlayDataflowStatus =
  try __NLD_OVERLAY_DATAFLOW_STATUS.toString
  catch { case _: Throwable => "unknown" }

// Candidate pools for duplicate resolution
val exactFileCandidates =
  cpg.method
    .nameExact(targetFunction)
    .filter(m => !m.isExternal && m.filename == targetFile)
    .l

val exactFileLineCandidates =
  if (targetLine > 0)
    exactFileCandidates.filter(m => m.lineNumber.getOrElse(-1) == targetLine)
  else Nil

// Fallback chain for auto mode
val nonExternalCandidates =
  cpg.method
    .nameExact(targetFunction)
    .filter(m => !m.isExternal)
    .l

val endsWithCandidates =
  cpg.method
    .nameExact(targetFunction)
    .filter(m => !m.isExternal && m.filename.endsWith(targetFile))
    .l

val candidates3 =
  if (duplicateMode == "exact_file_line") exactFileLineCandidates
  else if (duplicateMode == "exact_file") exactFileCandidates
  else if (exactFileCandidates.nonEmpty) exactFileCandidates
  else if (nonExternalCandidates.nonEmpty) nonExternalCandidates
  else endsWithCandidates

// Prefer likely definitions: non-external first, then richer body
val targetMethods =
  candidates3
    .sortBy(m => (if (m.isExternal) 1 else 0, -m.ast.size))
    .take(1)

val resultsJson: ujson.Arr = ujson.Arr.from(
  targetMethods.map { m =>
    val normalizedDepth = if (maxDepth <= 0) 1 else maxDepth

    val calleesFromCallGraph =
      if (normalizedDepth <= 1) m.callee.dedup.l
      else {
        var visited = m.callee.dedup.l
        var frontier = visited
        var depthNow = 1
        while (depthNow < normalizedDepth && frontier.nonEmpty) {
          val next = frontier
            .flatMap(x => x.callee.l)
            .filterNot(n => visited.exists(_.fullName == n.fullName))
          visited = (visited ++ next).groupBy(_.fullName).map(_._2.head).toList
          frontier = next
          depthNow = depthNow + 1
        }
        visited
      }

    val callersFromCallGraph =
      if (normalizedDepth <= 1) m.caller.dedup.l
      else {
        var visited = m.caller.dedup.l
        var frontier = visited
        var depthNow = 1
        while (depthNow < normalizedDepth && frontier.nonEmpty) {
          val next = frontier
            .flatMap(x => x.caller.l)
            .filterNot(n => visited.exists(_.fullName == n.fullName))
          visited = (visited ++ next).groupBy(_.fullName).map(_._2.head).toList
          frontier = next
          depthNow = depthNow + 1
        }
        visited
      }
    val callsitesToCallees = m.ast.isCall.l

    val calleeCallsiteMap: Map[String, List[Int]] =
      callsitesToCallees
        .groupBy(c => try c.methodFullName catch { case _: Throwable => "" })
        .map { case (k, calls) =>
          val lines = calls
            .map(c => try c.lineNumber.getOrElse(-1) catch { case _: Throwable => -1 })
            .distinct
            .sorted
          k -> lines
        }

    val incomingCallsites = cpg.call.methodFullNameExact(m.fullName).l
    val callerCallsiteMap: Map[String, List[Int]] =
      incomingCallsites
        .groupBy(c => try c.method.fullName catch { case _: Throwable => "" })
        .map { case (k, calls) =>
          val lines = calls
            .map(c => try c.lineNumber.getOrElse(-1) catch { case _: Throwable => -1 })
            .distinct
            .sorted
          k -> lines
        }

    val calleesJson: ujson.Arr = ujson.Arr.from(
      if (calleesFromCallGraph.nonEmpty)
        calleesFromCallGraph.map { callee =>
          val csLines = calleeCallsiteMap.getOrElse(callee.fullName, Nil)
          val firstCsLine = csLines.headOption.getOrElse(-1)
          ujson.Obj(
            "source"           -> "callee",
            "method_name"      -> callee.name,
            "method_full_name" -> callee.fullName,
            "signature"        -> callee.signature,
            "file"             -> callee.filename,
            "line"             -> callee.lineNumber.getOrElse(-1),
            "callsite_file"    -> m.filename,
            "callsite_line"    -> firstCsLine,
            "callsite_lines"   -> ujson.Arr.from(csLines.map(v => ujson.Num(v)))
          )
        }
      else
        m.ast.isCall.map { c =>
          val csLine = c.lineNumber.getOrElse(-1)
          ujson.Obj(
            "source"           -> "ast_call",
            "method_name"      -> c.name,
            "method_full_name" -> c.methodFullName,
            "signature"        -> "",
            "file"             -> "",
            "line"             -> csLine,
            "callsite_file"    -> m.filename,
            "callsite_line"    -> csLine,
            "callsite_lines"   -> ujson.Arr.from(Seq(ujson.Num(csLine)))
          )
        }.l
    )

    val callersJson: ujson.Arr = ujson.Arr.from(
      if (callersFromCallGraph.nonEmpty)
        callersFromCallGraph.map { caller =>
          val csLines = callerCallsiteMap.getOrElse(caller.fullName, Nil)
          val firstCsLine = csLines.headOption.getOrElse(-1)
          ujson.Obj(
            "source"           -> "caller",
            "method_name"      -> caller.name,
            "method_full_name" -> caller.fullName,
            "signature"        -> caller.signature,
            "file"             -> caller.filename,
            "line"             -> caller.lineNumber.getOrElse(-1),
            "callsite_file"    -> caller.filename,
            "callsite_line"    -> firstCsLine,
            "callsite_lines"   -> ujson.Arr.from(csLines.map(v => ujson.Num(v)))
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
          val callerDefLine = try c.method.lineNumber.getOrElse(-1) catch { case _: Throwable => -1 }
          val csLine = c.lineNumber.getOrElse(-1)
          ujson.Obj(
            "source"           -> "callsite",
            "method_name"      -> callerName,
            "method_full_name" -> callerFullName,
            "signature"        -> callerSig,
            "file"             -> callerFile,
            "line"             -> callerDefLine,
            "callsite_file"    -> callerFile,
            "callsite_line"    -> csLine,
            "callsite_lines"   -> ujson.Arr.from(Seq(ujson.Num(csLine)))
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
