#!/usr/bin/env bash
set -Eeuo pipefail

# 사용 예시:
# ./run_target_pipeline.sh \
#   --target libarchive \
#   --language c \          # 기본값이 C라 생략 가능
#   --repo /mnt/d/Projects/nuclei/targets/libarchive/source \
#   --old v3.8.5 \
#   --new v3.8.6 \

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

TARGET=""
LANGUAGE="C"
REPO=""
OLD_VER=""
NEW_VER=""
HOST_WORKSPACE_ROOT=""
CANDIDATE_K="20"
FINAL_K="1"

usage() {
  cat <<EOF
Usage:
  $0 --target <name> --repo <path> --old <old_tag> --new <new_tag> --host-workspace-root <path> [options]

Required:
  --target                  target name (e.g. libarchive)
  --repo                    local repo path
  --old                     old version/tag
  --new                     new version/tag

Optional:
  --joern-port              default: 9000
  --joern-host              default: localhost
  --container-source-root   default: /app/source
  --container-workspace-root default: /app/workspace
  --language                default: c
  --candidate-k             default: 20
  --final-k                 default: 1
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) TARGET="$2"; shift 2 ;;
    --repo) REPO="$2"; shift 2 ;;
    --old) OLD_VER="$2"; shift 2 ;;
    --new) NEW_VER="$2"; shift 2 ;;
    --joern-port) JOERN_PORT="$2"; shift 2 ;;
    --joern-host) JOERN_HOST="$2"; shift 2 ;;
    --host-workspace-root) HOST_WORKSPACE_ROOT="$2"; shift 2 ;;
    --container-source-root) CONTAINER_SOURCE_ROOT="$2"; shift 2 ;;
    --container-workspace-root) CONTAINER_WORKSPACE_ROOT="$2"; shift 2 ;;
    --language) LANGUAGE="$2"; shift 2 ;;
    --candidate-k) CANDIDATE_K="$2"; shift 2 ;;
    --final-k) FINAL_K="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "[ERROR] Unknown arg: $1"; usage; exit 1 ;;
  esac
done

if [[ -z "$TARGET" || -z "$REPO" || -z "$OLD_VER" || -z "$NEW_VER" ]]; then
  echo "[ERROR] Missing required args"
  usage
  exit 1
fi

if [[ ! -d "$REPO" ]]; then
  echo "[ERROR] Repo path does not exist: $REPO"
  exit 1
fi

# -----------------------------
# Derived paths
# -----------------------------
export JOERN_CONFIG="$TARGET"
export HOST_SOURCE_ROOT="$REPO"
export HOST_WORKSPACE_ROOT="$HOST_WORKSPACE_ROOT"

DIFF_DIR="$PROJECT_ROOT/data/$LANGUAGE/$TARGET/diff"
CONFIG_PATH="$PROJECT_ROOT/scripts/joern/runners/configs/$TARGET.json"
DIFF_FUNCTIONS_PATH="$DIFF_DIR/diff_functions.json"
DIFF_RETRIEVER_PATH="$DIFF_DIR/diff_retriever.json"
RETRIEVER_OUTPUT_PATH="$DIFF_DIR/../retriever/retriever_output_top1.json"

mkdir -p "$DIFF_DIR"
mkdir -p "$(dirname "$CONFIG_PATH")"

echo "[+] PROJECT_ROOT           = $PROJECT_ROOT"
echo "[+] TARGET                 = $TARGET"
echo "[+] REPO                   = $REPO"
echo "[+] OLD_VER                = $OLD_VER"
echo "[+] NEW_VER                = $NEW_VER"
echo "[+] DIFF_DIR               = $DIFF_DIR"
echo "[+] CONFIG_PATH            = $CONFIG_PATH"

# -----------------------------
# 1) configs/<target>.json 생성
# workspace_project는 target 기준으로 자동 생성
# -----------------------------
WORKSPACE_PROJECT="${TARGET}_root_test"

cat > "$CONFIG_PATH" <<EOF
{
  "project": {
    "name": "$TARGET",
    "language": "$LANGUAGE"
  },
  "paths": {
    "local_source_root": "\${HOST_SOURCE_ROOT}",
    "container_source_root": "\${CONTAINER_SOURCE_ROOT}",
    "taint_dir": "\${HOST_TAINT_DIR}",
    "trace_dir": null,
    "output_dir": "\${HOST_OUTPUT_DIR}"
  },
  "joern": {
    "server_url": "http://localhost:\${JOERN_PORT}",
    "workspace_project": "$WORKSPACE_PROJECT"
  },
  "trace": {
    "webroot": null
  },
  "analysis": {
    "mode": "static",
    "enabled_sink_categories": [
      "command",
      "memory",
      "format",
      "file"
    ]
  }
}
EOF

echo "[+] Generated config: $CONFIG_PATH"

# -----------------------------
# 2) diff_functions.json 생성
# 주의:
# c_extractor.py가 실제로 어디에 출력하는지에 따라 아래 부분은 조정 필요
# -----------------------------
export PYTHONPATH="$PROJECT_ROOT:${PYTHONPATH:-}"

echo "[+] Running c_extractor.py"
python3 src/pipelines/diff_extraction/C_CPP/c_extractor.py \
  --repo "$REPO" \
  --old "$OLD_VER" \
  --new "$NEW_VER" \
  --output-dir "$DIFF_DIR"

if [[ ! -f "$DIFF_FUNCTIONS_PATH" ]]; then
  echo "[ERROR] diff_functions.json not found: $DIFF_FUNCTIONS_PATH"
  exit 1
fi
echo "[+] diff_functions.json -> $DIFF_FUNCTIONS_PATH"
echo "[+] diff.txt            -> $DIFF_DIR/diff.txt"

# -----------------------------
# 3) 거르기 단계
# 현재는 skip
# -----------------------------
# 예:
# python3 -m src.pipelines.diff_extraction.prune \
#   --input "$DIFF_FUNCTIONS_PATH" \
#   --output "$DIFF_FUNCTIONS_PATH"

echo "[+] Pruning step: currently skipped"

# -----------------------------
# 4) diff_retriever.json 생성
# -----------------------------
echo "[+] Running generate_diff_retriever.py"
python3 scripts/generate_diff_retriever.py \
  --input "$DIFF_FUNCTIONS_PATH" \
  --output "$DIFF_RETRIEVER_PATH"

# -----------------------------
# 5) retriever_output_top1.json 생성
# -----------------------------
KNOWLEDGE_DIR="$PROJECT_ROOT/data/knowledge/$LANGUAGE"
if [[ ! -d "$KNOWLEDGE_DIR" ]]; then
  echo "[ERROR] knowledge dir not found: $KNOWLEDGE_DIR"
  echo "        data/knowledge/ 아래에 '$LANGUAGE' 디렉토리가 있어야 합니다."
  exit 1
fi
echo "[+] knowledge_dir = $KNOWLEDGE_DIR"

echo "[+] Running retriever.py"
python3 src/pipelines/rag/retriever.py \
  --diff-path "$DIFF_RETRIEVER_PATH" \
  --knowledge-dir "$KNOWLEDGE_DIR" \
  --output-path "$RETRIEVER_OUTPUT_PATH" \
  --candidate-k "$CANDIDATE_K" \
  --final-k "$FINAL_K"

echo
echo "[DONE]"
echo "  config                : $CONFIG_PATH"
echo "  diff_functions        : $DIFF_FUNCTIONS_PATH"
echo "  diff_retriever        : $DIFF_RETRIEVER_PATH"
echo "  retriever_output_top1 : $RETRIEVER_OUTPUT_PATH"