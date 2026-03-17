import os
import re
import json
import argparse
from typing import Any, Dict, List, Optional, Tuple, Set


SUPERGLOBAL_RE = re.compile(r"\$_(GET|POST|REQUEST|COOKIE|SERVER)\b", re.IGNORECASE)

SINK_CALL_PATTERNS = {
    "sqli": re.compile(r"\b(mysqli_query|mysql_query)\b", re.IGNORECASE),
    "include": re.compile(r"\b(include|include_once|require|require_once)\b", re.IGNORECASE),
    "command": re.compile(r"\b(exec|system|passthru|shell_exec)\b", re.IGNORECASE),
    "eval": re.compile(r"\beval\b", re.IGNORECASE),
    "xss": re.compile(r"\b(echo|print)\b", re.IGNORECASE),
}

SINK_PRIORITY_WEIGHT = {
    "command": 1.0,
    "include": 0.9,
    "eval": 0.9,
    "sqli": 0.85,
    "xss": 0.6,
}


def normalize_rel_path(path: str) -> str:
    path = path.replace("\\", "/").strip()
    path = re.sub(r"/+", "/", path)
    return path.lstrip("./")


def normalize_trace_path_to_rel(trace_path: str, trace_webroot: str) -> Optional[str]:
    trace_path = trace_path.replace("\\", "/").strip()
    trace_webroot = trace_webroot.replace("\\", "/").rstrip("/")

    if trace_path.startswith(trace_webroot + "/"):
        return normalize_rel_path(trace_path[len(trace_webroot) + 1 :])

    if trace_path == trace_webroot:
        return ""

    return None


def read_text_lines(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.readlines()


def load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path: str, data: Any) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def parse_xdebug_trace(trace_path: str, trace_webroot: str) -> Dict[str, Any]:
    executed_pairs: Set[Tuple[str, int]] = set()
    per_file_lines: Dict[str, Set[int]] = {}

    total_lines = 0
    matched_lines = 0

    with open(trace_path, "r", encoding="utf-8", errors="ignore") as f:
        for raw in f:
            total_lines += 1
            line = raw.rstrip("\n")
            if not line:
                continue
            if line.startswith("Version:") or line.startswith("File format:") or line.startswith("TRACE START"):
                continue

            parts = line.split("\t")
            if len(parts) <= 9:
                continue

            event_type = parts[2].strip()
            if event_type != "0":
                continue

            raw_file = parts[8].strip()
            raw_line_no = parts[9].strip()

            if not raw_line_no.isdigit():
                continue

            rel_file = normalize_trace_path_to_rel(raw_file, trace_webroot)
            if rel_file is None:
                continue

            line_no = int(raw_line_no)
            executed_pairs.add((rel_file, line_no))
            per_file_lines.setdefault(rel_file, set()).add(line_no)
            matched_lines += 1

    return {
        "trace_name": os.path.basename(trace_path),
        "trace_path": trace_path,
        "trace_webroot": trace_webroot,
        "executed_pairs": executed_pairs,
        "per_file_lines": per_file_lines,
        "summary": {
            "total_trace_lines": total_lines,
            "matched_execution_entries": matched_lines,
            "unique_executed_pairs": len(executed_pairs),
            "unique_files": len(per_file_lines),
        },
    }


def parse_trace_dir(trace_dir: str, trace_webroot: str) -> Dict[str, Any]:
    trace_files = sorted(
        os.path.join(trace_dir, name)
        for name in os.listdir(trace_dir)
        if name.endswith(".xt")
    )

    trace_indexes = []
    union_pairs: Set[Tuple[str, int]] = set()
    union_per_file: Dict[str, Set[int]] = {}

    for trace_path in trace_files:
        idx = parse_xdebug_trace(trace_path, trace_webroot)
        trace_indexes.append(idx)

        for pair in idx["executed_pairs"]:
            union_pairs.add(pair)

        for rel_file, lines in idx["per_file_lines"].items():
            union_per_file.setdefault(rel_file, set()).update(lines)

    return {
        "trace_dir": trace_dir,
        "trace_webroot": trace_webroot,
        "trace_count": len(trace_indexes),
        "trace_indexes": trace_indexes,
        "union_index": {
            "trace_name": "__union__",
            "trace_path": trace_dir,
            "trace_webroot": trace_webroot,
            "executed_pairs": union_pairs,
            "per_file_lines": union_per_file,
            "summary": {
                "unique_executed_pairs": len(union_pairs),
                "unique_files": len(union_per_file),
                "trace_count": len(trace_indexes),
            },
        },
    }


def load_taint_file(taint_path: str) -> Dict[str, Any]:
    data = load_json(taint_path)
    parsed = data.get("parsed", {})
    sink_name = parsed.get("sink_name", os.path.splitext(os.path.basename(taint_path))[0])
    flows = parsed.get("flows", [])

    return {
        "taint_path": taint_path,
        "sink_name": sink_name,
        "project_name": parsed.get("project_name"),
        "source_count": parsed.get("source_count"),
        "sink_count": parsed.get("sink_count"),
        "flow_count": parsed.get("flow_count"),
        "flows": flows,
    }


def annotate_flow_with_execution(flow_nodes: List[Dict[str, Any]], executed_pairs: Set[Tuple[str, int]]) -> List[Dict[str, Any]]:
    out = []
    for idx, node in enumerate(flow_nodes):
        file_rel = normalize_rel_path(str(node.get("file", "")))
        line_no = node.get("line")
        executed = False

        if isinstance(line_no, int) and file_rel:
            executed = (file_rel, line_no) in executed_pairs

        new_node = dict(node)
        new_node["flow_index"] = idx
        new_node["executed"] = executed
        out.append(new_node)
    return out


def find_source_node(flow_nodes: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    for node in flow_nodes:
        code = str(node.get("code", ""))
        if SUPERGLOBAL_RE.search(code):
            return node
    return None


def is_sink_match(sink_name: str, node: Dict[str, Any]) -> bool:
    pattern = SINK_CALL_PATTERNS.get(sink_name)
    if not pattern:
        return False

    code = str(node.get("code", ""))
    if pattern.search(code):
        return True

    node_type = str(node.get("type", "")).upper()
    if sink_name == "xss" and node_type in {"CALL", "IDENTIFIER", "UNKNOWN"} and pattern.search(code):
        return True

    return False


def find_sink_node(sink_name: str, flow_nodes: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    for node in reversed(flow_nodes):
        if is_sink_match(sink_name, node):
            return node

    for node in reversed(flow_nodes):
        if str(node.get("type", "")).upper() == "CALL":
            return node

    return flow_nodes[-1] if flow_nodes else None


def compute_flow_runtime_metrics(
    flow_nodes: List[Dict[str, Any]],
    source_node: Optional[Dict[str, Any]],
    sink_node: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    valid_nodes = [
        n for n in flow_nodes
        if isinstance(n.get("line"), int) and n.get("line", -1) > 0 and str(n.get("file", "")).strip()
    ]
    executed_nodes = [n for n in valid_nodes if n.get("executed") is True]

    source_executed = bool(source_node and source_node.get("executed") is True)
    sink_executed = bool(sink_node and sink_node.get("executed") is True)

    ratio = (len(executed_nodes) / len(valid_nodes)) if valid_nodes else 0.0

    return {
        "total_nodes": len(flow_nodes),
        "valid_nodes": len(valid_nodes),
        "executed_nodes": len(executed_nodes),
        "execution_ratio": round(ratio, 4),
        "source_executed": source_executed,
        "sink_executed": sink_executed,
        "runtime_reachable": bool(source_executed and sink_executed),
    }


def resolve_local_file(source_root: str, rel_file: str) -> str:
    rel_file = normalize_rel_path(rel_file)
    return os.path.join(source_root, *rel_file.split("/"))


def find_class_name(lines: List[str], target_line: int) -> Optional[str]:
    pattern = re.compile(r'^\s*(abstract\s+|final\s+)?class\s+([A-Za-z_][A-Za-z0-9_]*)')
    for i in range(min(target_line - 1, len(lines) - 1), -1, -1):
        m = pattern.search(lines[i])
        if m:
            return m.group(2)
    return None


def find_function_range(lines: List[str], target_line: int) -> Optional[Dict[str, Any]]:
    func_pattern = re.compile(
        r'^\s*(public|protected|private)?\s*(static\s+)?function\s+&?\s*([A-Za-z_][A-Za-z0-9_]*)\s*\('
    )

    idx = max(0, min(target_line - 1, len(lines) - 1))
    start = None
    func_name = None

    for i in range(idx, -1, -1):
        m = func_pattern.search(lines[i])
        if m:
            start = i
            func_name = m.group(3)
            break

    if start is None:
        return None

    brace_balance = 0
    seen_open = False
    end = None

    for j in range(start, len(lines)):
        line = lines[j]
        opens = line.count("{")
        closes = line.count("}")

        if opens > 0:
            seen_open = True

        brace_balance += opens
        brace_balance -= closes

        if seen_open and brace_balance <= 0:
            end = j
            break

    if end is None:
        end = min(len(lines) - 1, start + 250)

    return {
        "function_name": func_name,
        "start_line": start + 1,
        "end_line": end + 1,
    }


def make_window_slice(
    lines: List[str],
    focus_lines: List[int],
    outer_start: int,
    outer_end: int,
    pad: int = 8,
) -> Dict[str, Any]:
    if not focus_lines:
        start = outer_start
        end = outer_end
    else:
        start = max(outer_start, min(focus_lines) - pad)
        end = min(outer_end, max(focus_lines) + pad)

    code = "".join(lines[start - 1 : end])
    return {
        "slice_start": start,
        "slice_end": end,
        "slice_code": code,
    }


def build_node_context(
    source_root: str,
    rel_file: str,
    anchor_line: int,
    flow_nodes_in_file: List[Dict[str, Any]],
    role: str,
    source_node: Optional[Dict[str, Any]],
    sink_node: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    local_path = resolve_local_file(source_root, rel_file)

    if not os.path.exists(local_path):
        return {
            "file": rel_file,
            "local_path": local_path,
            "exists": False,
            "role": role,
            "error": "file_not_found",
        }

    lines = read_text_lines(local_path)
    function_range = find_function_range(lines, anchor_line)
    class_name = find_class_name(lines, anchor_line)

    if function_range:
        func_start = function_range["start_line"]
        func_end = function_range["end_line"]
        function_name = function_range["function_name"]
        full_code = "".join(lines[func_start - 1 : func_end])
    else:
        func_start = max(1, anchor_line - 60)
        func_end = min(len(lines), anchor_line + 60)
        function_name = None
        full_code = "".join(lines[func_start - 1 : func_end])

    function_flow_lines = sorted({
        n["line"] for n in flow_nodes_in_file
        if isinstance(n.get("line"), int) and func_start <= n["line"] <= func_end
    })

    source_lines = [
        n["line"] for n in flow_nodes_in_file
        if SUPERGLOBAL_RE.search(str(n.get("code", "")))
        and isinstance(n.get("line"), int)
        and func_start <= n["line"] <= func_end
    ]

    sink_lines = []
    if sink_node and normalize_rel_path(str(sink_node.get("file", ""))) == rel_file and isinstance(sink_node.get("line"), int):
        if func_start <= sink_node["line"] <= func_end:
            sink_lines.append(sink_node["line"])

    focused_slice = make_window_slice(
        lines=lines,
        focus_lines=function_flow_lines or [anchor_line],
        outer_start=func_start,
        outer_end=func_end,
        pad=8,
    )

    function_key = f"{rel_file}:{function_name or '__unknown__'}:{func_start}-{func_end}"

    return {
        "role": role,
        "file": rel_file,
        "local_path": local_path,
        "exists": True,
        "class_name": class_name,
        "function_name": function_name,
        "function_start": func_start,
        "function_end": func_end,
        "function_key": function_key,
        "anchor_line": anchor_line,
        "full_code": full_code,
        "flow_lines": function_flow_lines,
        "source_lines": source_lines,
        "sink_lines": sink_lines,
        "focused_slice": focused_slice,
    }


def group_flow_nodes_by_file(flow_nodes: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for node in flow_nodes:
        rel_file = normalize_rel_path(str(node.get("file", "")))
        if not rel_file:
            continue
        grouped.setdefault(rel_file, []).append(node)
    return grouped


def build_all_contexts(source_root: str, grouped_nodes: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    out = []

    for rel_file, nodes_in_file in grouped_nodes.items():
        local_path = resolve_local_file(source_root, rel_file)
        if not os.path.exists(local_path):
            out.append({
                "file": rel_file,
                "local_path": local_path,
                "exists": False,
                "error": "file_not_found",
            })
            continue

        lines = read_text_lines(local_path)
        line_numbers = sorted({
            n["line"] for n in nodes_in_file
            if isinstance(n.get("line"), int) and n["line"] > 0
        })
        anchor_line = line_numbers[0] if line_numbers else 1
        class_name = find_class_name(lines, anchor_line)

        focused_slice = make_window_slice(
            lines=lines,
            focus_lines=line_numbers or [anchor_line],
            outer_start=max(1, anchor_line - 80),
            outer_end=min(len(lines), anchor_line + 80),
            pad=8,
        )

        out.append({
            "file": rel_file,
            "local_path": local_path,
            "exists": True,
            "class_name": class_name,
            "flow_lines": line_numbers,
            "focused_slice": focused_slice,
        })

    return out


def compute_trace_matches(
    flow_nodes: List[Dict[str, Any]],
    trace_indexes: List[Dict[str, Any]],
    source_node: Optional[Dict[str, Any]],
    sink_node: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    matched_traces = []

    for idx in trace_indexes:
        executed_pairs = idx["executed_pairs"]
        executed_count = 0
        valid_count = 0

        for node in flow_nodes:
            rel_file = normalize_rel_path(str(node.get("file", "")))
            line_no = node.get("line")
            if isinstance(line_no, int) and line_no > 0 and rel_file:
                valid_count += 1
                if (rel_file, line_no) in executed_pairs:
                    executed_count += 1

        source_executed = False
        sink_executed = False

        if source_node:
            sf = normalize_rel_path(str(source_node.get("file", "")))
            sl = source_node.get("line")
            if isinstance(sl, int) and (sf, sl) in executed_pairs:
                source_executed = True

        if sink_node:
            tf = normalize_rel_path(str(sink_node.get("file", "")))
            tl = sink_node.get("line")
            if isinstance(tl, int) and (tf, tl) in executed_pairs:
                sink_executed = True

        runtime_reachable = source_executed and sink_executed
        ratio = (executed_count / valid_count) if valid_count else 0.0

        if executed_count > 0 or runtime_reachable:
            matched_traces.append({
                "trace_name": idx["trace_name"],
                "executed_nodes": executed_count,
                "valid_nodes": valid_count,
                "execution_ratio": round(ratio, 4),
                "source_executed": source_executed,
                "sink_executed": sink_executed,
                "runtime_reachable": runtime_reachable,
            })

    matched_traces.sort(key=lambda x: (x["runtime_reachable"], x["execution_ratio"], x["executed_nodes"]), reverse=True)

    return {
        "matched_trace_count": len(matched_traces),
        "matched_traces": matched_traces,
    }


def score_flow(
    sink_name: str,
    runtime: Dict[str, Any],
    matched_trace_count: int,
    total_trace_count: int,
) -> float:
    weight = SINK_PRIORITY_WEIGHT.get(sink_name, 0.5)
    ratio = float(runtime.get("execution_ratio", 0.0))
    source_bonus = 0.15 if runtime.get("source_executed") else 0.0
    sink_bonus = 0.20 if runtime.get("sink_executed") else 0.0
    both_bonus = 0.25 if runtime.get("runtime_reachable") else 0.0

    trace_ratio = (matched_trace_count / total_trace_count) if total_trace_count > 0 else 0.0
    trace_bonus = min(trace_ratio * 0.3, 0.3)

    score = weight * 0.35 + ratio * 0.35 + source_bonus + sink_bonus + both_bonus + trace_bonus
    return round(min(score, 1.0), 4)


def build_llm_case(
    sink_name: str,
    flow_id: int,
    source_node: Optional[Dict[str, Any]],
    sink_node: Optional[Dict[str, Any]],
    runtime: Dict[str, Any],
    source_context: Optional[Dict[str, Any]],
    sink_context: Optional[Dict[str, Any]],
    annotated_flow: List[Dict[str, Any]],
    priority_score: float,
    matched_trace_info: Dict[str, Any],
) -> Dict[str, Any]:
    evidence = []
    for node in annotated_flow:
        evidence.append({
            "file": node.get("file"),
            "line": node.get("line"),
            "code": node.get("code"),
            "type": node.get("type"),
            "executed": node.get("executed"),
        })

    return {
        "flow_id": flow_id,
        "sink_name": sink_name,
        "priority_score": priority_score,
        "runtime": runtime,
        "matched_trace_count": matched_trace_info["matched_trace_count"],
        "matched_traces": matched_trace_info["matched_traces"],
        "source": source_node,
        "sink": sink_node,
        "source_function_key": source_context.get("function_key") if source_context else None,
        "sink_function_key": sink_context.get("function_key") if sink_context else None,
        "same_function": bool(
            source_context
            and sink_context
            and source_context.get("function_key") == sink_context.get("function_key")
        ),
        "source_context": {
            "file": source_context.get("file") if source_context else None,
            "function_name": source_context.get("function_name") if source_context else None,
            "class_name": source_context.get("class_name") if source_context else None,
            "function_start": source_context.get("function_start") if source_context else None,
            "function_end": source_context.get("function_end") if source_context else None,
            "function_key": source_context.get("function_key") if source_context else None,
            "focused_slice": source_context.get("focused_slice", {}).get("slice_code") if source_context else None,
            "full_code": source_context.get("full_code") if source_context else None,
        },
        "sink_context": {
            "file": sink_context.get("file") if sink_context else None,
            "function_name": sink_context.get("function_name") if sink_context else None,
            "class_name": sink_context.get("class_name") if sink_context else None,
            "function_start": sink_context.get("function_start") if sink_context else None,
            "function_end": sink_context.get("function_end") if sink_context else None,
            "function_key": sink_context.get("function_key") if sink_context else None,
            "focused_slice": sink_context.get("focused_slice", {}).get("slice_code") if sink_context else None,
            "full_code": sink_context.get("full_code") if sink_context else None,
        },
        "evidence_flow": evidence,
    }


def build_prompt_ready_context(
    sink_name: str,
    flow_id: int,
    source_node: Optional[Dict[str, Any]],
    sink_node: Optional[Dict[str, Any]],
    runtime: Dict[str, Any],
    source_context: Optional[Dict[str, Any]],
    sink_context: Optional[Dict[str, Any]],
    priority_score: float,
    matched_trace_info: Dict[str, Any],
) -> str:
    parts = []
    parts.append("[Flow Summary]")
    parts.append(f"- sink_category: {sink_name}")
    parts.append(f"- flow_id: {flow_id}")
    parts.append(f"- priority_score: {priority_score}")
    parts.append(f"- execution_ratio_union: {runtime.get('execution_ratio')}")
    parts.append(f"- runtime_reachable_union: {runtime.get('runtime_reachable')}")
    parts.append(f"- source_executed_union: {runtime.get('source_executed')}")
    parts.append(f"- sink_executed_union: {runtime.get('sink_executed')}")
    parts.append(f"- matched_trace_count: {matched_trace_info.get('matched_trace_count')}")
    parts.append(f"- same_function: {bool(source_context and sink_context and source_context.get('function_key') == sink_context.get('function_key'))}")

    if source_node:
        parts.append("\n[Source Anchor]")
        parts.append(f"- file: {source_node.get('file')} | line: {source_node.get('line')} | code: {source_node.get('code')}")

    if sink_node:
        parts.append("\n[Sink Anchor]")
        parts.append(f"- file: {sink_node.get('file')} | line: {sink_node.get('line')} | code: {sink_node.get('code')}")

    if matched_trace_info.get("matched_traces"):
        parts.append("\n[Matched Traces]")
        for mt in matched_trace_info["matched_traces"][:10]:
            parts.append(
                f"- {mt['trace_name']} | executed_nodes={mt['executed_nodes']}/{mt['valid_nodes']} "
                f"| ratio={mt['execution_ratio']} | source_executed={mt['source_executed']} "
                f"| sink_executed={mt['sink_executed']} | runtime_reachable={mt['runtime_reachable']}"
            )

    if source_context:
        parts.append("\n[Source Function Context]")
        parts.append(f"- function_key: {source_context.get('function_key')}")
        parts.append(f"- file: {source_context.get('file')}")
        parts.append(f"- function_name: {source_context.get('function_name')}")
        parts.append(f"- class_name: {source_context.get('class_name')}")
        parts.append(f"- function_range: {source_context.get('function_start')}..{source_context.get('function_end')}")
        parts.append("\n[Source Focused Slice]")
        parts.append(source_context.get("focused_slice", {}).get("slice_code", ""))
        parts.append("\n[Source Full Function Code]")
        parts.append(source_context.get("full_code", ""))

    if sink_context:
        parts.append("\n[Sink Function Context]")
        parts.append(f"- function_key: {sink_context.get('function_key')}")
        parts.append(f"- file: {sink_context.get('file')}")
        parts.append(f"- function_name: {sink_context.get('function_name')}")
        parts.append(f"- class_name: {sink_context.get('class_name')}")
        parts.append(f"- function_range: {sink_context.get('function_start')}..{sink_context.get('function_end')}")
        parts.append("\n[Sink Focused Slice]")
        parts.append(sink_context.get("focused_slice", {}).get("slice_code", ""))
        parts.append("\n[Sink Full Function Code]")
        parts.append(sink_context.get("full_code", ""))

    return "\n".join(parts)


def build_detect_prompt_case(llm_case: Dict[str, Any]) -> Dict[str, Any]:
    source_ctx = llm_case.get("source_context", {})
    sink_ctx = llm_case.get("sink_context", {})
    source = llm_case.get("source", {})
    sink = llm_case.get("sink", {})
    runtime = llm_case.get("runtime", {})
    matched_traces = llm_case.get("matched_traces", [])

    matched_trace_text = "\n".join(
        f"- {mt['trace_name']} | ratio={mt['execution_ratio']} | source_executed={mt['source_executed']} | sink_executed={mt['sink_executed']} | runtime_reachable={mt['runtime_reachable']}"
        for mt in matched_traces[:10]
    )

    prompt = f"""You are assisting vulnerability detection for a PHP project.

[Task]
Decide whether this flow is a likely real vulnerability candidate.
Focus on whether attacker-controlled input can reach the sink in a dangerous way.

[Metadata]
- sink_name: {llm_case.get("sink_name")}
- flow_id: {llm_case.get("flow_id")}
- priority_score: {llm_case.get("priority_score")}
- same_function: {llm_case.get("same_function")}
- matched_trace_count: {llm_case.get("matched_trace_count")}
- source_executed_union: {runtime.get("source_executed")}
- sink_executed_union: {runtime.get("sink_executed")}
- execution_ratio_union: {runtime.get("execution_ratio")}

[Matched Traces]
{matched_trace_text}

[Source Anchor]
file={source.get("file")} line={source.get("line")}
code={source.get("code")}

[Sink Anchor]
file={sink.get("file")} line={sink.get("line")}
code={sink.get("code")}

[Source Function Slice]
{source_ctx.get("focused_slice")}

[Source Function Full Code]
{source_ctx.get("full_code")}

[Sink Function Slice]
{sink_ctx.get("focused_slice")}

[Sink Function Full Code]
{sink_ctx.get("full_code")}

Return:
1. vulnerability_likely: yes/no
2. vulnerability_type
3. attacker_control_reason
4. sink_reachability_reason
5. sanitization_or_barrier
6. confidence: low/medium/high
7. short_summary
"""
    return {
        "flow_id": llm_case.get("flow_id"),
        "sink_name": llm_case.get("sink_name"),
        "priority_score": llm_case.get("priority_score"),
        "prompt": prompt,
    }


def process_taint_file(
    taint_path: str,
    source_root: str,
    trace_indexes: List[Dict[str, Any]],
    union_index: Dict[str, Any],
) -> Dict[str, Any]:
    taint = load_taint_file(taint_path)
    union_pairs = union_index["executed_pairs"]

    out_flows = []
    runtime_reachable_count = 0

    for flow_id, raw_flow_nodes in enumerate(taint["flows"]):
        annotated_nodes = annotate_flow_with_execution(raw_flow_nodes, union_pairs)
        source_node = find_source_node(annotated_nodes)
        sink_node = find_sink_node(taint["sink_name"], annotated_nodes)
        runtime = compute_flow_runtime_metrics(annotated_nodes, source_node, sink_node)

        grouped = group_flow_nodes_by_file(annotated_nodes)

        source_context = None
        if source_node:
            src_file = normalize_rel_path(str(source_node.get("file", "")))
            src_line = source_node.get("line")
            if src_file in grouped and isinstance(src_line, int) and src_line > 0:
                source_context = build_node_context(
                    source_root=source_root,
                    rel_file=src_file,
                    anchor_line=src_line,
                    flow_nodes_in_file=grouped[src_file],
                    role="source",
                    source_node=source_node,
                    sink_node=sink_node,
                )

        sink_context = None
        if sink_node:
            sink_file = normalize_rel_path(str(sink_node.get("file", "")))
            sink_line = sink_node.get("line")
            if sink_file in grouped and isinstance(sink_line, int) and sink_line > 0:
                sink_context = build_node_context(
                    source_root=source_root,
                    rel_file=sink_file,
                    anchor_line=sink_line,
                    flow_nodes_in_file=grouped[sink_file],
                    role="sink",
                    source_node=source_node,
                    sink_node=sink_node,
                )

        all_contexts = build_all_contexts(source_root=source_root, grouped_nodes=grouped)

        matched_trace_info = compute_trace_matches(
            flow_nodes=annotated_nodes,
            trace_indexes=trace_indexes,
            source_node=source_node,
            sink_node=sink_node,
        )

        if runtime["runtime_reachable"]:
            runtime_reachable_count += 1

        priority_score = score_flow(
            sink_name=taint["sink_name"],
            runtime=runtime,
            matched_trace_count=matched_trace_info["matched_trace_count"],
            total_trace_count=len(trace_indexes),
        )

        llm_case = build_llm_case(
            sink_name=taint["sink_name"],
            flow_id=flow_id,
            source_node=source_node,
            sink_node=sink_node,
            runtime=runtime,
            source_context=source_context,
            sink_context=sink_context,
            annotated_flow=annotated_nodes,
            priority_score=priority_score,
            matched_trace_info=matched_trace_info,
        )

        out_flows.append({
            "flow_id": flow_id,
            "sink_name": taint["sink_name"],
            "priority_score": priority_score,
            "source": source_node,
            "sink": sink_node,
            "runtime": runtime,
            "matched_trace_count": matched_trace_info["matched_trace_count"],
            "matched_traces": matched_trace_info["matched_traces"],
            "annotated_flow": annotated_nodes,
            "source_context": source_context,
            "sink_context": sink_context,
            "all_contexts": all_contexts,
            "llm_case": llm_case,
            "detect_prompt_case": build_detect_prompt_case(llm_case),
            "prompt_ready_context": build_prompt_ready_context(
                sink_name=taint["sink_name"],
                flow_id=flow_id,
                source_node=source_node,
                sink_node=sink_node,
                runtime=runtime,
                source_context=source_context,
                sink_context=sink_context,
                priority_score=priority_score,
                matched_trace_info=matched_trace_info,
            ),
        })

    out_flows.sort(key=lambda x: (x["priority_score"], x["matched_trace_count"]), reverse=True)

    return {
        "taint_path": taint_path,
        "sink_name": taint["sink_name"],
        "project_name": taint["project_name"],
        "source_count": taint["source_count"],
        "sink_count": taint["sink_count"],
        "static_flow_count": taint["flow_count"],
        "runtime_reachable_flow_count_union": runtime_reachable_count,
        "flows": out_flows,
    }


def collect_taint_files(input_paths: List[str]) -> List[str]:
    out = []
    for path in input_paths:
        if os.path.isdir(path):
            for name in os.listdir(path):
                if name.startswith("taint_") and name.endswith(".json") and name != "taint_results_all.json":
                    out.append(os.path.join(path, name))
        else:
            out.append(path)
    return sorted(set(out))


def build_overview(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    summary = {}
    for item in results:
        top_score = item["flows"][0]["priority_score"] if item["flows"] else None
        max_matched_traces = max((f["matched_trace_count"] for f in item["flows"]), default=0)

        summary[item["sink_name"]] = {
            "static_flow_count": item["static_flow_count"],
            "runtime_reachable_flow_count_union": item["runtime_reachable_flow_count_union"],
            "source_count": item["source_count"],
            "sink_count": item["sink_count"],
            "top_priority_score": top_score,
            "max_matched_trace_count": max_matched_traces,
        }
    return summary


def build_llm_cases(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    cases = []
    for item in results:
        for flow in item["flows"]:
            cases.append(flow["llm_case"])
    cases.sort(key=lambda x: (x["priority_score"], x["matched_trace_count"]), reverse=True)
    return cases


def build_detect_prompts(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    prompts = []
    for item in results:
        for flow in item["flows"]:
            prompts.append(flow["detect_prompt_case"])
    prompts.sort(key=lambda x: x["priority_score"], reverse=True)
    return prompts


def run_union_mode(
    source_root: str,
    trace_indexes: List[Dict[str, Any]],
    union_index: Dict[str, Any],
    taint_files: List[str],
    output_dir: str,
) -> None:
    ensure_dir(output_dir)
    results = []

    trace_meta = {
        "mode": "union",
        "trace_count": len(trace_indexes),
        "trace_names": [t["trace_name"] for t in trace_indexes],
        "summary": union_index["summary"],
        "per_file_executed_line_count": {
            k: len(v) for k, v in union_index["per_file_lines"].items()
        },
    }
    save_json(os.path.join(output_dir, "dynamic_trace_index_union.json"), trace_meta)

    for taint_path in taint_files:
        print(f"[*] union processing: {taint_path}")
        merged = process_taint_file(
            taint_path=taint_path,
            source_root=source_root,
            trace_indexes=trace_indexes,
            union_index=union_index,
        )
        results.append(merged)

        sink_name = merged["sink_name"]
        save_json(os.path.join(output_dir, f"merged_union_{sink_name}.json"), merged)

    overview = build_overview(results)
    llm_cases = build_llm_cases(results)
    detect_prompts = build_detect_prompts(results)

    save_json(os.path.join(output_dir, "overview_union.json"), overview)
    save_json(os.path.join(output_dir, "merged_union_all.json"), results)
    save_json(os.path.join(output_dir, "llm_cases_union.json"), llm_cases)
    save_json(os.path.join(output_dir, "detect_prompts_union.json"), detect_prompts)

    print(json.dumps(overview, indent=2, ensure_ascii=False))


def run_separate_mode(
    source_root: str,
    trace_indexes: List[Dict[str, Any]],
    taint_files: List[str],
    output_dir: str,
) -> None:
    ensure_dir(output_dir)

    separate_overview = {}

    for trace_idx in trace_indexes:
        trace_name = trace_idx["trace_name"]
        safe_name = re.sub(r'[^A-Za-z0-9._-]+', "_", trace_name)
        trace_out_dir = os.path.join(output_dir, safe_name)
        ensure_dir(trace_out_dir)

        trace_meta = {
            "mode": "separate",
            "trace_name": trace_name,
            "summary": trace_idx["summary"],
            "per_file_executed_line_count": {
                k: len(v) for k, v in trace_idx["per_file_lines"].items()
            },
        }
        save_json(os.path.join(trace_out_dir, "dynamic_trace_index.json"), trace_meta)

        results = []
        for taint_path in taint_files:
            print(f"[*] separate processing [{trace_name}]: {taint_path}")
            merged = process_taint_file(
                taint_path=taint_path,
                source_root=source_root,
                trace_indexes=[trace_idx],
                union_index=trace_idx,
            )
            results.append(merged)

            sink_name = merged["sink_name"]
            save_json(os.path.join(trace_out_dir, f"merged_{sink_name}.json"), merged)

        overview = build_overview(results)
        llm_cases = build_llm_cases(results)
        detect_prompts = build_detect_prompts(results)

        save_json(os.path.join(trace_out_dir, "overview.json"), overview)
        save_json(os.path.join(trace_out_dir, "merged_all.json"), results)
        save_json(os.path.join(trace_out_dir, "llm_cases.json"), llm_cases)
        save_json(os.path.join(trace_out_dir, "detect_prompts.json"), detect_prompts)

        separate_overview[trace_name] = overview

    save_json(os.path.join(output_dir, "overview_separate_all.json"), separate_overview)


def main():
    parser = argparse.ArgumentParser(description="NLD merge/slice v4 with multi-trace union/separate support.")
    parser.add_argument("--source-root", required=True, help="로컬 phpMyAdmin 루트 경로")
    parser.add_argument("--trace-webroot", default="/var/www/html", help="Xdebug trace 안 웹루트 경로")
    parser.add_argument("--taint", nargs="+", required=True, help="taint json 파일 또는 디렉터리")
    parser.add_argument("--output-dir", required=True, help="출력 디렉터리")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--trace", help=".xt 파일 하나")
    group.add_argument("--trace-dir", help=".xt 파일들이 들어있는 디렉터리")

    parser.add_argument(
        "--mode",
        choices=["union", "separate", "both"],
        default="union",
        help="trace-dir 사용 시 union / separate / both",
    )

    args = parser.parse_args()
    ensure_dir(args.output_dir)

    taint_files = collect_taint_files(args.taint)

    if args.trace:
        trace_idx = parse_xdebug_trace(args.trace, args.trace_webroot)
        run_union_mode(
            source_root=args.source_root,
            trace_indexes=[trace_idx],
            union_index=trace_idx,
            taint_files=taint_files,
            output_dir=args.output_dir,
        )
        return

    multi = parse_trace_dir(args.trace_dir, args.trace_webroot)
    trace_indexes = multi["trace_indexes"]
    union_index = multi["union_index"]

    if args.mode in {"union", "both"}:
        run_union_mode(
            source_root=args.source_root,
            trace_indexes=trace_indexes,
            union_index=union_index,
            taint_files=taint_files,
            output_dir=os.path.join(args.output_dir, "union"),
        )

    if args.mode in {"separate", "both"}:
        run_separate_mode(
            source_root=args.source_root,
            trace_indexes=trace_indexes,
            taint_files=taint_files,
            output_dir=os.path.join(args.output_dir, "separate"),
        )


if __name__ == "__main__":
    main()