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
  --target libarchive \
  --repo /path/to/libarchive \
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

### 4. Run the LLM agent

Start the MCP server and point your Claude or Codex CLI session at it. The agent will follow the Dual-Pass protocol defined in `AGENTS.md` and write confirmed findings to:

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
