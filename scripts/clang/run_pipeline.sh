#!/usr/bin/env bash
# run_pipeline.sh  —  컨테이너 안에서 직접 실행하는 빌드 + AST 추출 스크립트
#
# 이 스크립트는 clang-builder 컨테이너 내부에서 실행된다.
# 호스트에서는 run.sh 를 통해 docker exec 으로 호출한다.
#
# Usage (컨테이너 내부):
#   bash /app/workspace/scripts/clang/run_pipeline.sh [TARGET]
#
# Usage (호스트):
#   ./scripts/clang/run.sh [TARGET]
#
# 마운트 경로 (docker-compose.yml 기준):
#   ./scripts              → /app/workspace/scripts      (ro)
#   $HOST_SOURCE_ROOT      → /app/source
#   $HOST_WORKSPACE_ROOT/clang → /app/workspace
#
# 출력물 (/app/workspace/<TARGET>/):
#   compile_commands.json  빌드 인터셉트 결과
#   ast_result.json        함수 정의 위치 + 참조 파일 목록

set -euo pipefail

TARGET="${1:-lighttpd}"

WORKSPACE="/app/workspace"
SCRIPTS="$WORKSPACE/scripts"
CONFIG_FILE="$SCRIPTS/joern/runners/configs/$TARGET.json"

if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "[!] 설정 파일을 찾을 수 없습니다: $CONFIG_FILE" >&2
    exit 1
fi

# ── 타겟 JSON에서 build 설정 읽기 ────────────────────────────────────────────
read_cfg() {
    local key="$1"
    local default="${2:-}"
    python3 - << PYEOF
import json
with open("$CONFIG_FILE") as f:
    d = json.load(f)
val = d.get("build", {}).get("$key")
print(str(val) if val is not None else "$default")
PYEOF
}

BUILD_SYSTEM=$(read_cfg build_system "make")
SOURCE_DIR=$(read_cfg source_dir "/app/source")
BUILD_DIR=$(read_cfg build_dir "$WORKSPACE/$TARGET/build")
CONFIGURE_CMD=$(read_cfg configure_cmd "")
BUILD_CMD=$(read_cfg build_cmd "make -j$(nproc)")
COMPILE_DB_MODE=$(read_cfg compile_db_mode "bear")

OUTPUT_DIR="$WORKSPACE/$TARGET"
CC_JSON="$OUTPUT_DIR/compile_commands.json"
AST_JSON="$OUTPUT_DIR/ast_result.json"

echo "══════════════════════════════════════════════"
echo " 타겟        : $TARGET"
echo " build_system: $BUILD_SYSTEM"
echo " source_dir  : $SOURCE_DIR"
echo " build_dir   : $BUILD_DIR"
echo " build_cmd   : $BUILD_CMD"
echo " db_mode     : $COMPILE_DB_MODE"
echo "══════════════════════════════════════════════"

# ── Step 1: 출력 디렉토리 생성 ────────────────────────────────────────────────
echo "[1/3] 출력 디렉토리 생성: $OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

# ── Step 2: compile_commands.json 생성 ───────────────────────────────────────
echo "[2/3] compile_commands.json 생성"

if [[ -f "$CC_JSON" ]]; then
    echo "[*] compile_commands.json 이미 존재합니다. 빌드를 건너뜁니다."
    echo "    삭제 후 재실행하면 재빌드: rm $CC_JSON"
else
    case "$BUILD_SYSTEM" in

      autotools)
        if [[ -n "$CONFIGURE_CMD" ]]; then
            echo "[*] configure 단계: $CONFIGURE_CMD"
            cd "$SOURCE_DIR"
            eval "$CONFIGURE_CMD"
        fi

        case "$COMPILE_DB_MODE" in
          bear)
            mkdir -p "$BUILD_DIR"
            if [[ "$BUILD_DIR" == "$SOURCE_DIR" ]]; then
                cd "$SOURCE_DIR"
            else
                cd "$BUILD_DIR"
            fi
            echo "[*] bear -- $BUILD_CMD"
            bear -- bash -c "$BUILD_CMD"
            cp compile_commands.json "$CC_JSON"
            ;;
          *)
            echo "[!] autotools 는 compile_db_mode=bear 만 지원합니다." >&2
            exit 1
            ;;
        esac
        ;;

      cmake)
        mkdir -p "$BUILD_DIR"
        case "$COMPILE_DB_MODE" in
          cmake)
            echo "[*] CMake configure (native export)..."
            cd "$BUILD_DIR"
            # shellcheck disable=SC2086
            cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON $CONFIGURE_CMD "$SOURCE_DIR"
            # shellcheck disable=SC2086
            cmake --build . -- $BUILD_CMD
            cp compile_commands.json "$CC_JSON"
            ;;
          bear)
            echo "[*] CMake configure + bear 인터셉트..."
            cd "$BUILD_DIR"
            # shellcheck disable=SC2086
            cmake $CONFIGURE_CMD "$SOURCE_DIR"
            # shellcheck disable=SC2086
            bear -- cmake --build . -- $BUILD_CMD
            cp compile_commands.json "$CC_JSON"
            ;;
          *)
            echo "[!] cmake 는 compile_db_mode=cmake|bear 만 지원합니다." >&2
            exit 1
            ;;
        esac
        ;;

      meson)
        echo "[*] Meson setup..."
        # shellcheck disable=SC2086
        meson setup "$BUILD_DIR" "$SOURCE_DIR" $CONFIGURE_CMD
        ninja -C "$BUILD_DIR"
        cp "$BUILD_DIR/compile_commands.json" "$CC_JSON"
        ;;

      make|*)
        echo "[*] bear -- $BUILD_CMD"
        cd "$SOURCE_DIR"
        bear -- bash -c "$BUILD_CMD"
        cp compile_commands.json "$CC_JSON"
        ;;

    esac
    echo "[+] compile_commands.json 저장: $CC_JSON"
fi

# ── Step 3: extract_ast.py → ast_result.json ─────────────────────────────────
echo "[3/3] AST 추출 → $AST_JSON"
python3 "$SCRIPTS/clang/extract_ast.py" \
    "$CC_JSON" \
    --output "$AST_JSON"

# ── 완료 ─────────────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════"
echo " 완료"
echo "══════════════════════════════════════════════"
echo "  compile_commands : $CC_JSON"
echo "  ast_result       : $AST_JSON"
