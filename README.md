# robocat

**robocat** is an LLM-agent-driven automated vulnerability analysis system for open-source software. It combines diff-based function extraction, hybrid RAG-powered knowledge retrieval, and on-demand static analysis via a Model Context Protocol (MCP) server to systematically identify security vulnerabilities in C, C++, and PHP codebases.

---

## How It Works

```
git diff (old → new)
      │
      ▼
diff_functions.json          diff_retriever.json
      │                              │
      ▼                              ▼
 LLM Agent  ◄──── MCP stdio ────  MCP Server
(Dual-Pass)                     (9 tools)
      │                              │
      ▼                        ┌─────┴──────┐
results/<target>.md         Joern CPG    Redis Cache
                            (Docker)    (by revision)
```

### Pipeline Steps

1. **Diff Extraction** — `run_target_pipeline.sh` checks out the two version tags, extracts modified functions, and emits `diff_functions.json`.
2. **Hybrid RAG** — Dense (×2) + BM25 retrieval, fused with RRF, then re-ranked by a GPT-4o-mini selector. Outputs `retriever_output_top1.json` with the closest known vulnerability pattern.
3. **LLM Agent Analysis** — Claude (or Codex) runs a **Dual-Pass Protocol** (broad candidate discovery → strict confirmation) over each diff'd function. The agent calls MCP tools on demand.
4. **MCP Tools** — The agent reaches into Joern CPG, source files, and the RAG knowledge base through 9 typed tools (see [MCP Tools](#mcp-tools)).
5. **Output** — Confirmed findings are written to `results/<target>.md`. A CVE-form-ready draft can be generated from strict results.

---

## MCP Tools

| Group | Tool | Role |
|---|---|---|
| **config** | `check_cpg_status` | Diagnose Joern workspace state (once before analysis) |
| **retriever** | `get_retrieved_knowledge` | Return similar CVE / vulnerability type hints from RAG |
| **cpg** | `get_cpg_summary` | Resolve function signatures, callers, callees, callsites |
| **cpg** | `find_dataflow` | Trace source → sink data-flow paths (primary CPG evidence) |
| **cpg** | `find_sanitizer_or_guard` | Check validation / guard existence and sink dominance |
| **source** | `read_source_context` | Read source around a specific function or line |
| **source** | `read_definition` | Look up symbol definitions via ctags |
| **source** | `find_references` | Find symbol / pattern usages via ripgrep |
| **source** | `map_vuln_context` | Collect vulnerable slices within a function (heuristic) |

---

## Repository Layout

```
robocat/
├── run_target_pipeline.sh       # End-to-end pipeline entry point
├── docker-compose.yml           # Joern CPG + Redis services
├── requirements.txt
│
├── src/
│   ├── mcp/                     # FastMCP server (stdio transport)
│   │   ├── server.py
│   │   └── tools/               # config / retriever / cpg / source tool groups
│   ├── pipelines/
│   │   ├── diff_extraction/     # C_CPP and PHP diff extractors
│   │   ├── rag/                 # Hybrid retriever (BM25 + dense + RRF)
│   │   └── knowledge_transformation/
│   ├── utils/                   # Joern executor, Redis cache, LLM client, embeddings
│   ├── dto/                     # Pydantic data transfer objects
│   └── prompts/                 # YAML prompt templates
│
├── scripts/
│   ├── generate_diff_retriever.py
│   ├── joern/                   # Joern query builders and runners
│   └── build_dataset/           # Knowledge base construction utilities
│
├── data/
│   ├── C/                       # Per-target diff and retriever artifacts
│   ├── CPP/
│   ├── PHP/
│   ├── knowledge/               # Vulnerability knowledge base (by language)
│   └── cache/                   # Embedding cache (SQLite)
│
├── results/                     # Analysis outputs per target
├── tests/
└── AGENTS.md                    # LLM agent analysis protocol (Dual-Pass)
```

---

## Quick Start

### 1. Start infrastructure

```bash
docker compose up -d
```

Brings up Joern CPG server (port 9000) and Redis (port 6379).

### 2. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 3. Run the pipeline

```bash
./run_target_pipeline.sh \
  --target target name \
  --repo /path/to/target name \
  --old v3.8.0 \
  --new v3.8.1 \
  --host-workspace-root /path/to/workspace
```

This produces:

| Artifact | Location |
|---|---|
| Extracted diff functions | `data/C/<target>/diff/diff_functions.json` |
| Retriever-ready diff | `data/C/<target>/diff/diff_retriever.json` |
| RAG top-1 match | `data/C/<target>/retriever/retriever_output_top1.json` |
| Joern config | `scripts/joern/runners/configs/<target>.json` |

### 4. Configure environment variables

Create a `.env` file in the project root before starting the MCP server or running docker-compose.

```bash
# .env

# ── Docker / Infrastructure ──────────────────────────────────────
JOERN_CONTAINER_NAME=robocat-joern
JOERN_PORT=9000
HOST_TARGETS_ROOT=/absolute/path/to/targets      # parent dir of <target>/source
HOST_WORKSPACE_ROOT=/absolute/path/to/workspace  # Joern workspace root

# ── MCP Server ───────────────────────────────────────────────────
JOERN_CONFIG=target_name      # target name; maps to scripts/joern/runners/configs/<name>.json
JOERN_HOST=localhost
JOERN_PORT=9000
REDIS_ENABLED=true           # set false to disable query caching

# ── Analysis paths (auto-derived from JOERN_CONFIG if omitted) ──
# RETRIEVER_OUTPUT_PATH=data/C/target_name/retriever/retriever_output_top1.json
# DIFF_RETRIEVER_PATH=data/C/target_name/diff/diff_retriever.json

# ── LLM ─────────────────────────────────────────────────────────
OPENAI_API_KEY=sk-...        # required for Hybrid RAG (GPT-4o-mini selector)
```

> Change `JOERN_CONFIG` to the target name each time you switch targets. All other values stay fixed across targets.

---

### 5. Connect the LLM agent via MCP

The MCP server uses **stdio transport** — the agent CLI starts it as a subprocess and communicates over stdin/stdout. Register it once; update `JOERN_CONFIG` in `.env` per target.

#### Claude Code (claude CLI)

```bash
# Register (one-time)
claude mcp add robocat -- python3 /absolute/path/to/robocat/src/mcp/server.py

# Verify
claude mcp list
```

If you need to override env vars per-target without editing `.env`, pass `-e` flags:

```bash
claude mcp add robocat \
  -e JOERN_CONFIG=<target name> \
  -e JOERN_HOST=localhost \
  -e JOERN_PORT=9000 \
  -e REDIS_ENABLED=true \
  -- python3 /absolute/path/to/src/mcp/server.py
```

To update an existing entry:

```bash
claude mcp remove robocat
claude mcp add robocat -- python3 /absolute/path/to/robocat/src/mcp/server.py
```

#### Codex CLI (openai/codex)

Add the server to `~/.codex/config.toml` (or a project-level `codex.toml`):

```toml
[[mcp_servers]]
name    = "robocat"
command = "python3"
args    = ["/absolute/path/to/robocat/src/mcp/server.py"]
```

Env vars are read from `.env` automatically (the server calls `load_dotenv` on startup). To pin a target explicitly:

```toml
[[mcp_servers]]
name    = "robocat"
command = "python3"
args    = ["/absolute/path/to/robocat/src/mcp/server.py"]

[mcp_servers.env]
JOERN_CONFIG  = "target name"
JOERN_HOST    = "localhost"
JOERN_PORT    = "9000"
REDIS_ENABLED = "true"
```

---

### 6. Run analysis

Once the MCP server is registered, open a Claude or Codex session in the project directory. The agent follows the Dual-Pass protocol in `AGENTS.md` and writes confirmed findings to:

```
results/<target>.md
```

---

## Analysis Protocol (Dual-Pass)

Defined in `AGENTS.md`:

- **Pass 1 — Broad Discovery**: surface all plausible vulnerability candidates with explicit uncertainty markers.
- **Pass 2 — Strict Confirmation**: re-evaluate Pass 1 findings; require a complete attacker-controlled source → memory-operation sink path with no dominating guard.

Only `strict_results` with `status=confirmed` are included in CVE drafts.

---

## Prompt Design — AGENTS.md

`AGENTS.md` is the system prompt loaded into the LLM agent. The design decisions below address failure modes observed during real analysis runs.

### 1. Dual-Pass to balance recall vs. precision

A single-pass strict agent misses real vulnerabilities because it discards uncertain-but-plausible candidates too early. A single-pass broad agent produces too many false positives to be actionable.

The two-pass design separates concerns: Pass 1 casts a wide net with explicit uncertainty markers; Pass 2 applies strict evidentiary criteria to that same candidate set only. This makes the precision/recall trade-off transparent and auditable.

**Rule enforced**: Pass 2 may not introduce findings that were absent from Pass 1. It can only confirm or reject.

---

### 2. MCP tool invocation as a mandatory evidence gate

LLMs hallucinate interprocedural context — callers, struct layouts, allocation sizes — when that context is not in the local snippet. The prompt explicitly instructs the agent to invoke MCP tools whenever local context is insufficient, rather than guessing.

This grounds analysis in actual code facts:

- `get_cpg_summary` / `find_dataflow` for call graph and taint paths
- `find_sanitizer_or_guard` before claiming a guard is absent
- `read_source_context` / `read_definition` for final fact-checking

The agent is blocked from claiming a proven source-to-sink path without tool-backed evidence.

---

### 3. Attacker-controlled source as a hard requirement

A dangerous memory operation without a reachable attacker-controlled input is not a vulnerability — it is a code quality issue. In Strict mode, the prompt rejects any finding that cannot trace back to an external source (file input, network, argv, env vars, parsed size fields). In Broad mode, such findings are permitted only as low-confidence candidates.

This eliminates a large class of false positives where the agent flags `memcpy` or `malloc` calls without checking whether the size argument is actually attacker-influenced.

---

### 4. Diff analysis anti-pattern — do not assume the new code is safe

When given a diff, LLMs tend to treat it as a patch and implicitly assume the new code fixes the problem. This is the opposite of what we want.

The prompt explicitly overrides this behavior:

- Do not identify what was patched.
- Treat modified functions as potentially vulnerable code in their own right.
- Prioritize analysis of newly introduced logic as the highest-risk surface.

---

### 5. Production reachability — reject test/example-only paths

A vulnerability reachable only through `tests/`, `examples/`, or `benchmarks/` does not affect downstream applications. The prompt carries an explicit rejection rule for this case, accumulated from real false positives where the agent cited test harnesses as valid trigger paths.

In Broad mode, such paths may appear as low-confidence context only, never as confirmed impact.

---

### 6. Scope limitation — function as the primary analysis unit

Without an explicit scope boundary, the agent expands laterally across the codebase and either times out or produces findings far outside the diff. The prompt treats each diff'd function as the primary unit and permits cross-function expansion only when necessary to confirm exploitability (e.g., to verify a guard exists in a caller).

---

### 7. Structured XML output for deterministic post-processing

Free-form natural language findings cannot be reliably parsed into CVE drafts or compared across runs. The output schema enforces:

- Separate `<broad_results>` and `<strict_results>` blocks
- Per-finding `<confidence>`, `<finding_type>`, and `<change_analysis>` fields
- `<strict_revalidation>` tracking which broad candidate each strict finding originates from

This makes the pipeline end-to-end deterministic: `results/<target>.md` → CVE form fill.

---

### 8. Rejection log as a living document

`AGENTS.md` carries a `Rejection Reasons` section that accumulates patterns from real false positives. Each entry documents the rejection condition and its rationale, so the agent internalizes past mistakes rather than repeating them across targets.

---


## Supported Languages

| Language | Diff Extractor | Knowledge Base |
|---|---|---|
| C | `src/pipelines/diff_extraction/C_CPP/` | `data/knowledge/C/` |
| C++ | `src/pipelines/diff_extraction/C_CPP/` | `data/knowledge/CPP/` |
| PHP | `src/pipelines/diff_extraction/PHP/` | `data/knowledge/PHP/` |

Additional language support can be added by implementing a diff extractor and populating the corresponding knowledge base.

---

## Infrastructure

| Service | Image | Purpose |
|---|---|---|
| Joern | `local-joern:latest` | Code Property Graph — taint flow, guard dominance queries |
| Redis | `redis:7-alpine` | CPG query result cache (keyed by revision) |

---

## CVE Reporting

`CLAUDE.md` contains the CVE form writing guide. To generate a report from strict results:

```
results/<target>.md       → analysis findings
results/<target>_report.md → CVE-form-ready plain text (Section A) + PoC notes (Section B)
```

Reports are drafted from `strict_results` only. Broad candidates are never cited as CVE evidence.
