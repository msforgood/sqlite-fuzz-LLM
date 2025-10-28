#!/bin/bash -eu
# Run two libFuzzer targets for N seconds, then generate llvm-cov reports
# Usage:
#   DURATION_SEC=300 TIMEOUT_SEC=10 SRC_ROOT=. SQLITE_SRC=build/dependencies/sqlite3.c \
#   LLVM_PROFDATA=llvm-profdata-18 LLVM_COV=llvm-cov-18 \
#   bash analysis/scripts/run_fuzz_compare_with_cov.sh

# ---- settings ----
DURATION=${DURATION_SEC:-300}
TIMEOUT=${TIMEOUT_SEC:-10}

# fuzzer binaries (당신 환경에 맞게 수정: original/advanced 로 쓰는 경우 아래 두 줄 바꾸세요)
BASELINE_BIN="${BASELINE_BIN:-baseline_fuzzer_coverage}"
OURS_WO_SPEC_BIN="${OURS_WO_SPEC_BIN:-ours_wo_spec_fuzzer_coverage}"

# corpus/artifacts
BASE_CORPUS="${BASE_CORPUS:-corpus/baseline}"
OURS_WO_SPEC_CORPUS="${OURS_WO_SPEC_CORPUS:-corpus/ours_wo_spec}"
BASE_ART="${BASE_ART:-artifacts/baseline}"
OURS_WO_SPEC_ART="${OURS_WO_SPEC_ART:-artifacts/ours_wo_spec}"

# coverage outputs
BASE_OUT="coverage_results/baseline"
OURS_WO_SPEC_OUT="coverage_results/ours_wo_spec"

# llvm tools (버전 고정 권장: llvm-profdata-18 / llvm-cov-18)
LLVM_PROFDATA_BIN="${LLVM_PROFDATA:-llvm-profdata}"
LLVM_COV_BIN="${LLVM_COV:-llvm-cov}"

# optional: 소스 자동 탐지 루트 & sqlite3.c 단독 경로
SRC_ROOT="${SRC_ROOT:-.}"
SQLITE_SRC="${SQLITE_SRC:-build/dependencies/sqlite3.c}"  # 실제 경로 확인

# ---- checks ----
command -v "$LLVM_PROFDATA_BIN" >/dev/null || { echo "ERROR: $LLVM_PROFDATA_BIN not found"; exit 1; }
command -v "$LLVM_COV_BIN" >/dev/null || { echo "ERROR: $LLVM_COV_BIN not found"; exit 1; }
[[ -x "./$BASELINE_BIN" ]] || { echo "ERROR: ./$BASELINE_BIN not found"; exit 1; }
[[ -x "./$OURS_WO_SPEC_BIN"     ]] || { echo "ERROR: ./$OURS_WO_SPEC_BIN not found"; exit 1; }

mkdir -p "$BASE_CORPUS" "$OURS_WO_SPEC_CORPUS" "$BASE_ART" "$OURS_WO_SPEC_ART" "$BASE_OUT" "$OURS_WO_SPEC_OUT"

# ---- run fuzzers with coverage profiles ----
# 프로파일 파일은 PID 포함해서 여러 개 생성 → 나중에 merge
echo "[Baseline] fuzz ${DURATION}s ..."
rm -f "$BASE_OUT"/fuzzer-*.profraw || true
export LLVM_PROFILE_FILE="$BASE_OUT/fuzzer-%p.profraw"
"./$BASELINE_BIN" \
  -max_total_time="$DURATION" \
  -timeout="$TIMEOUT" \
  -print_final_stats=1 \
  -artifact_prefix="$BASE_ART/" \
  "$BASE_CORPUS" || true

echo
echo "[Ours_wo_spec] fuzz ${DURATION}s ..."
rm -f "$OURS_WO_SPEC_OUT"/fuzzer-*.profraw || true
export LLVM_PROFILE_FILE="$OURS_WO_SPEC_OUT/fuzzer-%p.profraw"
"./$OURS_WO_SPEC_BIN" \
  -max_total_time="$DURATION" \
  -timeout="$TIMEOUT" \
  -print_final_stats=1 \
  -artifact_prefix="$OURS_WO_SPEC_ART/" \
  "$OURS_WO_SPEC_CORPUS" || true

# ---- merge profiles ----
merge_profiles() {
  local outdir=$1
  shopt -s nullglob
  local raws=( "$outdir"/fuzzer-*.profraw )
  shopt -u nullglob
  if [[ ${#raws[@]} -eq 0 ]]; then
    echo "WARN: no raw profiles in $outdir"
    return 1
  fi
  "$LLVM_PROFDATA_BIN" merge -sparse "${raws[@]}" -o "$outdir/fuzzer.profdata"
}

merge_profiles "$BASE_OUT"
merge_profiles "$OURS_WO_SPEC_OUT"

# ---- generate reports (전체 + sqlite만) ----
report_set() {
  local bin=$1 outdir=$2

  [[ -f "$outdir/fuzzer.profdata" ]] || { echo "WARN: no profdata at $outdir"; return; }

  # 1) 전체 요약
  "$LLVM_COV_BIN" report "./$bin" -instr-profile="$outdir/fuzzer.profdata" \
    > "$outdir/coverage_summary.txt"

  # 2) 전체 HTML (버전에 따라 output-dir 미지원시 폴백)
  if ! "$LLVM_COV_BIN" show "./$bin" -instr-profile="$outdir/fuzzer.profdata" \
        -format=html -output-dir="$outdir/html" \
        -show-line-counts -show-regions -show-instantiations >/dev/null 2>&1; then
    mkdir -p "$outdir/html"
    "$LLVM_COV_BIN" show "./$bin" -instr-profile="$outdir/fuzzer.profdata" \
      -show-line-counts -show-regions -show-instantiations > "$outdir/html/index.html"
  fi

  # 3) sqlite3.c만 (경로가 맞다면 이게 가장 깔끔)
  if [[ -f "$SQLITE_SRC" ]]; then
    "$LLVM_COV_BIN" report "./$bin" -instr-profile="$outdir/fuzzer.profdata" \
      "$SQLITE_SRC" > "$outdir/sqlite_summary.txt"

    "$LLVM_COV_BIN" show "./$bin" -instr-profile="$outdir/fuzzer.profdata" \
      -format=html -output-dir="$outdir/html_sqlite" \
      -show-line-counts -show-regions -show-instantiations \
      "$SQLITE_SRC" >/dev/null 2>&1 || {
        mkdir -p "$outdir/html_sqlite"
        "$LLVM_COV_BIN" show "./$bin" -instr-profile="$outdir/fuzzer.profdata" \
          -show-line-counts -show-regions -show-instantiations \
          "$SQLITE_SRC" > "$outdir/html_sqlite/index.html"
      }
  else
    # sqlite 경로를 모르면 드라이버/테스트 제외하는 정규식으로 근사치
    IGNORE='(test_main|fuzzers/(baseline|ours_wo_spec)/ossfuzz\.c)$'
    "$LLVM_COV_BIN" report "./$bin" -instr-profile="$outdir/fuzzer.profdata" \
      -ignore-filename-regex="$IGNORE" > "$outdir/sqlite_summary.txt"
    "$LLVM_COV_BIN" show "./$bin" -instr-profile="$outdir/fuzzer.profdata" \
      -format=html -output-dir="$outdir/html_sqlite" \
      -ignore-filename-regex="$IGNORE" \
      -show-line-counts -show-regions -show-instantiations >/dev/null 2>&1 || {
        mkdir -p "$outdir/html_sqlite"
        "$LLVM_COV_BIN" show "./$bin" -instr-profile="$outdir/fuzzer.profdata" \
          -ignore-filename-regex="$IGNORE" \
          -show-line-counts -show-regions -show-instantiations \
          > "$outdir/html_sqlite/index.html"
      }
  fi

  # 4) 함수 목록 (소스 자동탐지 실패 시 JSON 폴백)
  mapfile -t SRC_LIST < <(find "$SRC_ROOT" -maxdepth 4 -type f \( -name '*.c' -o -name '*.cc' -o -name '*.cpp' \) | sort)
  if [[ ${#SRC_LIST[@]} -gt 0 ]] && \
     "$LLVM_COV_BIN" report "./$bin" -instr-profile="$outdir/fuzzer.profdata" \
       -show-functions "${SRC_LIST[@]}" > "$outdir/function_coverage.txt" 2>/dev/null; then
    :
  else
    "$LLVM_COV_BIN" export "./$bin" -instr-profile="$outdir/fuzzer.profdata" \
      > "$outdir/coverage.json"
    python3 - <<'PY' "$outdir/coverage.json" > "$outdir/function_coverage.txt"
import json,sys
data=json.load(open(sys.argv[1]))
funcs=[]
for entry in data.get("data", []):
    funcs.extend(entry.get("functions", []))
    for file in entry.get("files", []):
        funcs.extend(file.get("functions", []))
print("Function Regions Missed Coverage")
for f in funcs:
    name=f.get("name","")
    regions=f.get("regions", [])
    total=0; covered=0
    if isinstance(regions, list):
        total=len(regions)
        for r in regions:
            if isinstance(r, dict):
                if r.get("count",0)>0: covered+=1
            elif isinstance(r, list) and len(r)>0:
                last=r[-1]
                if isinstance(last,(int,float)) and last>0: covered+=1
    cov=f.get("percent")
    if cov is None:
        cov = f"{(covered/total*100):.1f}%" if total>0 else "0.0%"
    missed=max(0,total-covered)
    print(f"{name} {total} {missed} {cov}")
PY
  fi
}

report_set "$BASELINE_BIN" "$BASE_OUT"
report_set "$OURS_WO_SPEC_BIN" "$OURS_WO_SPEC_OUT"

echo
echo "Done. Open:"
echo "  $BASE_OUT/sqlite_summary.txt"
echo "  $BASE_OUT/html_sqlite/index.html"
echo "  $OURS_WO_SPEC_OUT/sqlite_summary.txt"
echo "  $OURS_WO_SPEC_OUT/html_sqlite/index.html"
