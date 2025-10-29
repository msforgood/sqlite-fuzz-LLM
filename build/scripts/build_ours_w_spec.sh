#!/bin/bash -eu
# Build + Run + Coverage for ours_w_spec (libFuzzer)
# DURATION_SEC, TIMEOUT_SEC, CC, CXX, LLVM_PROFDATA, LLVM_COV, SQLITE_SRC, SRC_ROOT, FORCE_BUILD

set -o pipefail

DURATION=${DURATION_SEC:-10}
TIMEOUT=${TIMEOUT_SEC:-10}
CC=${CC:-clang-18}
CXX=${CXX:-clang++-18}
LLVM_PROFDATA=${LLVM_PROFDATA:-llvm-profdata-18}
LLVM_COV=${LLVM_COV:-llvm-cov-18}

# fallback
command -v "$CC" >/dev/null 2>&1 || CC=clang
command -v "$CXX" >/dev/null 2>&1 || CXX=clang++
command -v "$LLVM_PROFDATA" >/dev/null 2>&1 || LLVM_PROFDATA=llvm-profdata
command -v "$LLVM_COV" >/dev/null 2>&1 || LLVM_COV=llvm-cov

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEPS_DIR="$ROOT_DIR/build/dependencies"
FUZZER_DIR="$ROOT_DIR/fuzzers/ours_w_spec"
OBJ_DIR="$ROOT_DIR/build/obj"

OUT_BIN="$ROOT_DIR/ours_w_spec_standalone"
COV_DIR="$ROOT_DIR/coverage_results/ours_w_spec"
ART_DIR="$ROOT_DIR/artifacts/ours_w_spec"
CORPUS_DIR="$ROOT_DIR/corpus/ours_w_spec"

SQLITE_SRC="${SQLITE_SRC:-$DEPS_DIR/sqlite3.c}"
SRC_ROOT="${SRC_ROOT:-$ROOT_DIR}"

echo "Using compilers: CC=$CC, CXX=$CXX"
echo "llvm tools: llvm-profdata=$LLVM_PROFDATA, llvm-cov=$LLVM_COV"
echo "Duration: ${DURATION}s, Timeout: ${TIMEOUT}s"
echo "Root: $ROOT_DIR"
echo ""

mkdir -p "$OBJ_DIR" "$COV_DIR" "$ART_DIR" "$CORPUS_DIR"

# 최소 시드
if [ -z "$(ls -A "$CORPUS_DIR" 2>/dev/null || true)" ]; then
  echo "corpus is empty; creating minimal seed..."
  echo "SELECT 1;" > "$CORPUS_DIR/seed.sql"
fi

# 공통 플래그(문자열로)
COV_FLAGS="-fprofile-instr-generate -fcoverage-mapping -g -O1"
COMMON_DEFS="-DSQLITE_ENABLE_JSON1 -DSQLITE_ENABLE_FTS3 -DSQLITE_ENABLE_FTS5 -DSQLITE_ENABLE_RTREE -DSQLITE_THREADSAFE=0 -DSQLITE_OMIT_RANDOMNESS=1"
FUZZ_FLAGS="-fsanitize=fuzzer,address"
LDLIBS="-lpthread -ldl -lm"

# 빌드
if [[ ! -x "$OUT_BIN" || "${FORCE_BUILD:-0}" = "1" ]]; then
  echo "Building libFuzzer-style ours_w_spec -> $OUT_BIN"

  echo "Compiling sqlite3.c..."
  $CC $COV_FLAGS $COMMON_DEFS -I"$DEPS_DIR" -c "$DEPS_DIR/sqlite3.c" -o "$OBJ_DIR/sqlite3.o"

  echo "Compiling fuzz.c..."
  $CC $COV_FLAGS $COMMON_DEFS -I"$DEPS_DIR" -I"$FUZZER_DIR" -c "$FUZZER_DIR/fuzz.c" -o "$OBJ_DIR/fuzz.o"

  echo "Compiling btree_harness.c..."
  $CC $COV_FLAGS $COMMON_DEFS -I"$DEPS_DIR" -I"$FUZZER_DIR" -c "$FUZZER_DIR/btree_harness.c" -o "$OBJ_DIR/btree_harness.o"

  echo "Compiling autovacuum_harness.c..."
  $CC $COV_FLAGS $COMMON_DEFS -I"$DEPS_DIR" -I"$FUZZER_DIR" -c "$FUZZER_DIR/autovacuum_harness.c" -o "$OBJ_DIR/autovacuum_harness.o"

  echo "Compiling freespace_harness.c..."
  $CC $COV_FLAGS $COMMON_DEFS -I"$DEPS_DIR" -I"$FUZZER_DIR" -c "$FUZZER_DIR/freespace_harness.c" -o "$OBJ_DIR/freespace_harness.o"

  echo "Compiling pagemanagement_harness.c..."
  $CC $COV_FLAGS $COMMON_DEFS -I"$DEPS_DIR" -I"$FUZZER_DIR" -c "$FUZZER_DIR/pagemanagement_harness.c" -o "$OBJ_DIR/pagemanagement_harness.o"

  echo "Compiling tablecursor_harness.c..."
  $CC $COV_FLAGS $COMMON_DEFS -I"$DEPS_DIR" -I"$FUZZER_DIR" -c "$FUZZER_DIR/tablecursor_harness.c" -o "$OBJ_DIR/tablecursor_harness.o"

  echo "Compiling btree_trans_harness.c..."
  $CC $COV_FLAGS $COMMON_DEFS -I"$DEPS_DIR" -I"$FUZZER_DIR" -c "$FUZZER_DIR/btree_trans_harness.c" -o "$OBJ_DIR/btree_trans_harness.o"

  echo "Compiling cell_check_harness.c..."
  $CC $COV_FLAGS $COMMON_DEFS -I"$DEPS_DIR" -I"$FUZZER_DIR" -c "$FUZZER_DIR/cell_check_harness.c" -o "$OBJ_DIR/cell_check_harness.o"

  echo "Compiling create_table_harness.c..."
  $CC $COV_FLAGS $COMMON_DEFS -I"$DEPS_DIR" -I"$FUZZER_DIR" -c "$FUZZER_DIR/create_table_harness.c" -o "$OBJ_DIR/create_table_harness.o"

  echo "Compiling cursor_harness.c..."
  $CC $COV_FLAGS $COMMON_DEFS -I"$DEPS_DIR" -I"$FUZZER_DIR" -c "$FUZZER_DIR/cursor_harness.c" -o "$OBJ_DIR/cursor_harness.o"

  echo "Compiling drop_table_harness.c..."
  $CC $COV_FLAGS $COMMON_DEFS -I"$DEPS_DIR" -I"$FUZZER_DIR" -c "$FUZZER_DIR/drop_table_harness.c" -o "$OBJ_DIR/drop_table_harness.o"

  echo "Compiling page_ops_harness.c..."
  $CC $COV_FLAGS $COMMON_DEFS -I"$DEPS_DIR" -I"$FUZZER_DIR" -c "$FUZZER_DIR/page_ops_harness.c" -o "$OBJ_DIR/page_ops_harness.o"

  echo "Compiling vdbe_ops_harness.c..."
  $CC $COV_FLAGS $COMMON_DEFS -I"$DEPS_DIR" -I"$FUZZER_DIR" -c "$FUZZER_DIR/vdbe_ops_harness.c" -o "$OBJ_DIR/vdbe_ops_harness.o"
  echo "Compiling parser_harness.c..."
  $CC $COV_FLAGS $COMMON_DEFS -I"$DEPS_DIR" -I"$FUZZER_DIR" -c "$FUZZER_DIR/parser_harness.c" -o "$OBJ_DIR/parser_harness.o"
  echo "Compiling btree_advanced_harness.c..."
  $CC $COV_FLAGS $COMMON_DEFS -I"$DEPS_DIR" -I"$FUZZER_DIR" -c "$FUZZER_DIR/btree_advanced_harness.c" -o "$OBJ_DIR/btree_advanced_harness.o"

  echo "Compiling btree_extended_harness.c..."
  $CC $COV_FLAGS $COMMON_DEFS -I"$DEPS_DIR" -I"$FUZZER_DIR" -c "$FUZZER_DIR/btree_extended_harness.c" -o "$OBJ_DIR/btree_extended_harness.o"

  echo "Linking $OUT_BIN with libFuzzer..."
  $CXX $COV_FLAGS $FUZZ_FLAGS "$OBJ_DIR/sqlite3.o" "$OBJ_DIR/fuzz.o" "$OBJ_DIR/btree_harness.o" "$OBJ_DIR/autovacuum_harness.o" "$OBJ_DIR/freespace_harness.o" "$OBJ_DIR/pagemanagement_harness.o" "$OBJ_DIR/tablecursor_harness.o" "$OBJ_DIR/btree_trans_harness.o" "$OBJ_DIR/cell_check_harness.o" "$OBJ_DIR/create_table_harness.o" "$OBJ_DIR/cursor_harness.o" "$OBJ_DIR/drop_table_harness.o" "$OBJ_DIR/page_ops_harness.o" "$OBJ_DIR/vdbe_ops_harness.o" "$OBJ_DIR/parser_harness.o" "$OBJ_DIR/btree_advanced_harness.o" "$OBJ_DIR/btree_extended_harness.o" $LDLIBS -o "$OUT_BIN"
  chmod +x "$OUT_BIN"
else
  echo "Found existing binary: $OUT_BIN (skipping build)"
fi
echo ""

# 퍼저 실행
export LLVM_PROFILE_FILE="$COV_DIR/fuzzer-%p.profraw"
echo "Running fuzzer: $OUT_BIN for $DURATION seconds..."
set +e
"$OUT_BIN" \
  -max_total_time="$DURATION" \
  -timeout="$TIMEOUT" \
  -use_value_profile=1 \
  -print_final_stats=1 \
  -artifact_prefix="$ART_DIR/" \
  -max_len=4096 \
  "$CORPUS_DIR"
rc=$?
set -e
echo "fuzzer exit code: $rc"
echo ""

# 프로파일 병합
shopt -s nullglob
profs=( "$COV_DIR"/fuzzer-*.profraw )
shopt -u nullglob
if [ ${#profs[@]} -eq 0 ]; then
  echo "No profraw files found in $COV_DIR — fuzzer may have exited early. Exiting."
  exit 1
fi

echo "Merging ${#profs[@]} profraw files..."
"$LLVM_PROFDATA" merge -sparse "${profs[@]}" -o "$COV_DIR/fuzzer.profdata"

# 리포트 생성(전체)
echo "Generating llvm-cov summary (overall)..."
"$LLVM_COV" report "$OUT_BIN" -instr-profile="$COV_DIR/fuzzer.profdata" > "$COV_DIR/coverage_summary.txt" || true
echo "Saved: $COV_DIR/coverage_summary.txt"

# sqlite3.c 전용
if [ -f "$SQLITE_SRC" ]; then
  echo "Generating sqlite-only report for $SQLITE_SRC..."
  "$LLVM_COV" report "$OUT_BIN" -instr-profile="$COV_DIR/fuzzer.profdata" "$SQLITE_SRC" > "$COV_DIR/sqlite_summary.txt" || true
  echo "Saved: $COV_DIR/sqlite_summary.txt"

  echo "Generating sqlite-only HTML..."
  if ! "$LLVM_COV" show "$OUT_BIN" -instr-profile="$COV_DIR/fuzzer.profdata" -format=html -output-dir="$COV_DIR/html_sqlite" -show-line-counts -show-regions -show-instantiations "$SQLITE_SRC" >/dev/null 2>&1; then
    mkdir -p "$COV_DIR/html_sqlite"
    "$LLVM_COV" show "$OUT_BIN" -instr-profile="$COV_DIR/fuzzer.profdata" -show-line-counts -show-regions -show-instantiations "$SQLITE_SRC" > "$COV_DIR/html_sqlite/index.html"
  fi
  echo "Saved HTML: $COV_DIR/html_sqlite/index.html"
else
  echo "SQLITE_SRC not found ($SQLITE_SRC). Generating approximate sqlite report by ignoring driver files..."
  IGNORE='(test_main|fuzzers/ours_w_spec/fuzz\.c|fuzzers/.*/test_main|fuzzers/.*/ossfuzz|test_main)'
  "$LLVM_COV" report "$OUT_BIN" -instr-profile="$COV_DIR/fuzzer.profdata" -ignore-filename-regex="$IGNORE" > "$COV_DIR/sqlite_summary.txt" || true
  mkdir -p "$COV_DIR/html_sqlite"
  "$LLVM_COV" show "$OUT_BIN" -instr-profile="$COV_DIR/fuzzer.profdata" -ignore-filename-regex="$IGNORE" -show-line-counts -show-regions -show-instantiations > "$COV_DIR/html_sqlite/index.html" || true
  echo "Saved approximate HTML: $COV_DIR/html_sqlite/index.html"
fi

echo ""
echo "Done. Reports:"
echo "  $COV_DIR/coverage_summary.txt"
echo "  $COV_DIR/sqlite_summary.txt"
echo "  $COV_DIR/html_sqlite/index.html"
echo ""