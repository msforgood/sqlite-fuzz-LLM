#!/bin/bash -eu
# Coverage Comparison Script for SQLite3 Fuzzers

echo "=== SQLite3 Fuzzer Coverage Comparison ==="
echo ""

# -------- LLVM 도구 자동 감지/환경변수 --------
LLVM_PROFDATA_BIN="${LLVM_PROFDATA:-llvm-profdata}"
LLVM_COV_BIN="${LLVM_COV:-llvm-cov}"
command -v "$LLVM_PROFDATA_BIN" >/dev/null 2>&1 || { echo "ERROR: $LLVM_PROFDATA_BIN not found"; exit 1; }
command -v "$LLVM_COV_BIN" >/dev/null 2>&1 || { echo "ERROR: $LLVM_COV_BIN not found"; exit 1; }

# -------- 빌드 산출물 이름(당신 환경에 맞게 수정) --------
# 빌드 스크립트가 original/advanced 를 만든다면 아래 두 줄을 그 이름으로 바꾸세요.
BASELINE_BIN="baseline_fuzzer_coverage"
OURS_WO_SPEC_BIN="ours_wo_spec_fuzzer_coverage"

[[ -x "./$BASELINE_BIN" ]] || echo "WARN: ./$BASELINE_BIN not found or not executable"
[[ -x "./$OURS_WO_SPEC_BIN"     ]] || echo "WARN: ./$OURS_WO_SPEC_BIN not found or not executable"

# -------- 출력 디렉토리 --------
mkdir -p coverage_results/{baseline,ours_wo_spec}

# -------- 테스트 데이터 생성 --------
echo "Creating comprehensive test dataset..."
mkdir -p coverage_testdata
echo "SELECT 1;" > coverage_testdata/simple.sql
echo "CREATE TABLE t(x); INSERT INTO t VALUES(1); SELECT * FROM t;" > coverage_testdata/crud.sql
echo "SELECT abs(-42), length('test'), random();" > coverage_testdata/functions.sql
echo "BEGIN; CREATE TABLE tx(id); INSERT INTO tx VALUES(1); COMMIT;" > coverage_testdata/transaction.sql
echo "SELECT json_extract('{\"a\":1}', '\$.a');" > coverage_testdata/json.sql
printf "\x00\x10SELECT randomblob(100);" > coverage_testdata/blob.bin
printf "\x00\x20CREATE VIEW v AS SELECT 1;" > coverage_testdata/ddl.bin
printf "\x00\x30WITH RECURSIVE r(x) AS (SELECT 1 UNION SELECT x+1 FROM r WHERE x<5) SELECT * FROM r;" > coverage_testdata/recursive.bin

ALL_TEST_CASES=(
  "coverage_testdata/simple.sql"
  "coverage_testdata/crud.sql"
  "coverage_testdata/functions.sql"
  "coverage_testdata/transaction.sql"
  "coverage_testdata/json.sql"
  "coverage_testdata/blob.bin"
  "coverage_testdata/ddl.bin"
  "coverage_testdata/recursive.bin"
)

echo "Running coverage tests..."

run_coverage_test() {
  local fuzzer_name=$1        # 예: Baseline / Ours_wo_spec
  local fuzzer_binary=$2      # 실행 파일
  local output_dir=$3         # 출력 디렉토리

  echo "Testing $fuzzer_name fuzzer..."
  mkdir -p "$output_dir"
  rm -f "$output_dir"/fuzzer*.profraw || true

  # 프로파일 파일: PID 포함(동시 실행/덮어쓰기 방지)
  export LLVM_PROFILE_FILE="$output_dir/fuzzer-%p.profraw"

  local ran_any=0
  for test_case in "${ALL_TEST_CASES[@]}"; do
    if [[ -f "$test_case" ]]; then
      echo "  Running $test_case"
      set +e
      "./$fuzzer_binary" "$test_case" >/dev/null 2>&1
      rc=$?
      set -e
      if [[ $rc -ne 0 ]]; then
        echo "  WARN: $fuzzer_binary returned $rc on $test_case"
      fi
      ran_any=1
    fi
  done

  # 프로파일 병합
  shopt -s nullglob
  profs=( "$output_dir"/fuzzer-*.profraw )
  shopt -u nullglob
  if [[ ${#profs[@]} -gt 0 ]]; then
    "$LLVM_PROFDATA_BIN" merge -sparse "${profs[@]}" -o "$output_dir/fuzzer.profdata"

    # HTML 상세 리포트
    set +e
    "$LLVM_COV_BIN" show "./$fuzzer_binary" -instr-profile="$output_dir/fuzzer.profdata" \
      -format=html -output-dir="$output_dir/html" \
      -show-line-counts -show-regions -show-instantiations
    html_rc=$?
    set -e
    if [[ $html_rc -ne 0 ]]; then
      echo "  NOTE: html output-dir unsupported. Falling back to single index.html"
      mkdir -p "$output_dir/html"
      "$LLVM_COV_BIN" show "./$fuzzer_binary" -instr-profile="$output_dir/fuzzer.profdata" \
        -show-line-counts -show-regions -show-instantiations > "$output_dir/html/index.html"
    fi

    # 요약 리포트
    "$LLVM_COV_BIN" report "./$fuzzer_binary" -instr-profile="$output_dir/fuzzer.profdata" \
      > "$output_dir/coverage_summary.txt"

    # 함수 목록 생성: 소스 자동탐지 → 실패 시 JSON 폴백
    SRC_ROOT="${SRC_ROOT:-.}"
    # 깊이가 너무 깊으면 느려질 수 있으니 필요 시 -maxdepth 조절
    mapfile -t SRC_LIST < <(find "$SRC_ROOT" -maxdepth 3 -type f \( -name '*.c' -o -name '*.cc' -o -name '*.cpp' \) | sort)

    gen_func_list() {
      "$LLVM_COV_BIN" report "./$fuzzer_binary" -instr-profile="$output_dir/fuzzer.profdata" \
        -show-functions "${SRC_LIST[@]}" > "$output_dir/function_coverage.txt"
    }

    if [[ ${#SRC_LIST[@]} -gt 0 ]]; then
      if ! gen_func_list; then
        echo "  NOTE: -show-functions with discovered sources failed. Falling back to JSON export."
        "$LLVM_COV_BIN" export "./$fuzzer_binary" -instr-profile="$output_dir/fuzzer.profdata" \
          > "$output_dir/coverage.json"
        python3 - <<'PY' "$output_dir/coverage.json" > "$output_dir/function_coverage.txt"
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
    else
      echo "  NOTE: No source files found under SRC_ROOT=$SRC_ROOT. Using JSON export for function list."
      "$LLVM_COV_BIN" export "./$fuzzer_binary" -instr-profile="$output_dir/fuzzer.profdata" \
        > "$output_dir/coverage.json"
      python3 - <<'PY' "$output_dir/coverage.json" > "$output_dir/function_coverage.txt"
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

    echo "  Coverage data generated in $output_dir/"
  else
    echo "  Warning: No profile data generated for $fuzzer_name"
  fi
}

# -------- 실행 --------
run_coverage_test "Baseline" "$BASELINE_BIN" "coverage_results/baseline"
run_coverage_test "Ours_wo_spec" "$OURS_WO_SPEC_BIN" "coverage_results/ours_wo_spec"

echo ""
echo "=== Coverage Analysis Complete ==="
echo ""

# -------- 요약 비교 --------
echo "=== Coverage Summary Comparison ==="
echo ""
if [[ -f "coverage_results/baseline/coverage_summary.txt" && -f "coverage_results/ours_wo_spec/coverage_summary.txt" ]]; then
  echo "Baseline Fuzzer Coverage:"
  head -10 coverage_results/baseline/coverage_summary.txt || true
  echo ""
  echo "Ours_wo_spec Fuzzer Coverage:"
  head -10 coverage_results/ours_wo_spec/coverage_summary.txt || true
  echo ""

  echo "=== Key Metrics Comparison ==="
  echo ""
  orig_line_coverage=$(grep "TOTAL" coverage_results/baseline/coverage_summary.txt | awk '{print $4}' | head -1 || echo "N/A")
  adv_line_coverage=$(grep "TOTAL" coverage_results/ours_wo_spec/coverage_summary.txt | awk '{print $4}' | head -1 || echo "N/A")
  orig_func_coverage=$(grep "TOTAL" coverage_results/baseline/coverage_summary.txt | awk '{print $2}' | head -1 || echo "N/A")
  adv_func_coverage=$(grep "TOTAL" coverage_results/ours_wo_spec/coverage_summary.txt | awk '{print $2}' | head -1 || echo "N/A")

  echo "Line Coverage:"
  echo "  Baseline Fuzzer: $orig_line_coverage"
  echo "  Ours_wo_spec Fuzzer: $adv_line_coverage"
  echo ""
  echo "Function Coverage:"
  echo "  Baseline Fuzzer: $orig_func_coverage"
  echo "  Ours_wo_spec Fuzzer: $adv_func_coverage"
  echo ""
else
  echo "Coverage summary files not found. Check errors above."
fi

# -------- 함수 목록 비교 --------
echo "=== Generating Function Coverage Analysis ==="
python3 - <<'PY' 2>/dev/null || echo "Python analysis failed - coverage files may not exist yet"
def parse(p):
    try:
        with open(p,'r') as f:
            out={}
            for line in f:
                s=line.strip()
                if not s or s.startswith('Filename') or s.startswith('-'): continue
                parts=s.split()
                if len(parts)>=4:
                    out[parts[0]]={'regions':parts[1],'missed':parts[2],'coverage':parts[3]}
            return out
    except FileNotFoundError:
        return {}
orig=parse('coverage_results/baseline/function_coverage.txt')
adv=parse('coverage_results/ours_wo_spec/function_coverage.txt')
only_adv=set(adv)-set(orig); only_orig=set(orig)-set(adv); common=set(orig)&set(adv)
print(f'Functions only covered by ours_wo_spec fuzzer: {len(only_adv)}')
print(f'Functions only covered by baseline fuzzer: {len(only_orig)}')
print(f'Functions covered by both: {len(common)}\n')
if only_adv:
    print('Functions only hit by ours_wo_spec fuzzer:')
    for func in sorted(list(only_adv))[:20]: print('  '+func)
    if len(only_adv)>20: print(f'  ... and {len(only_adv)-20} more'); print()
if only_orig:
    print('Functions only hit by baseline fuzzer:')
    for func in sorted(list(only_orig))[:20]: print('  '+func)
    if len(only_orig)>20: print(f'  ... and {len(only_orig)-20} more')
PY

echo ""
echo "=== Coverage Reports Generated ==="
echo ""
echo "Detailed HTML reports available at:"
echo "  Baseline: coverage_results/baseline/html/index.html"
echo "  Ours_wo_spec: coverage_results/ours_wo_spec/html/index.html"
echo ""
echo "Text reports available at:"
echo "  Baseline: coverage_results/baseline/coverage_summary.txt"
echo "  Ours_wo_spec: coverage_results/ours_wo_spec/coverage_summary.txt"
echo ""
echo "Function coverage lists:"
echo "  Baseline: coverage_results/baseline/function_coverage.txt"
echo "  Ours_wo_spec: coverage_results/ours_wo_spec/function_coverage.txt"
