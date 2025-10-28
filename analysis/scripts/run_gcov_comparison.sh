#!/bin/bash -eu
# GCov Coverage Comparison Script for SQLite3 Fuzzers

echo "=== SQLite3 Fuzzer GCov Coverage Comparison ==="
echo ""

# Create gcov output directories
mkdir -p gcov_results/{original,advanced}

# Create test data if not exists
if [ ! -d "coverage_testdata" ]; then
    echo "Creating test dataset..."
    mkdir -p coverage_testdata
    echo "SELECT 1;" > coverage_testdata/simple.sql
    echo "CREATE TABLE t(x); INSERT INTO t VALUES(1); SELECT * FROM t;" > coverage_testdata/crud.sql
    echo "SELECT abs(-42), length('test'), random();" > coverage_testdata/functions.sql
    echo "BEGIN; CREATE TABLE tx(id); INSERT INTO tx VALUES(1); COMMIT;" > coverage_testdata/transaction.sql
    echo "SELECT json_extract('{\"a\":1}', '\$.a');" > coverage_testdata/json.sql
    printf "\x00\x10SELECT randomblob(100);" > coverage_testdata/blob.bin
    printf "\x00\x20CREATE VIEW v AS SELECT 1;" > coverage_testdata/ddl.bin
    printf "\x00\x30WITH RECURSIVE r(x) AS (SELECT 1 UNION SELECT x+1 FROM r WHERE x<5) SELECT * FROM r;" > coverage_testdata/recursive.bin
fi

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

# Function to run gcov test
run_gcov_test() {
    local fuzzer_name=$1
    local fuzzer_binary=$2
    local output_dir=$3
    local build_dir=$4
    
    echo "Testing $fuzzer_name fuzzer..."
    
    # Clean previous gcov data
    rm -f gcov_build/*.gcda
    
    # Run the fuzzer on all test cases
    for test_case in "${ALL_TEST_CASES[@]}"; do
        if [ -f "$test_case" ]; then
            echo "  Running $test_case"
            ./$fuzzer_binary "$test_case" >/dev/null 2>&1 || true
        fi
    done
    
    # Generate gcov data
    cd gcov_build
    
    # Run gcov on the main source files
    gcov sqlite3_gcov.o ${fuzzer_name,,}_gcov.o >/dev/null 2>&1 || true
    
    # Copy gcov files to results directory
    cp *.gcov "../$output_dir/" 2>/dev/null || true
    
    cd ..
    
    # Generate summary
    echo "  Generating coverage summary for $fuzzer_name..."
    
    # Count total lines and covered lines in SQLite3
    if [ -f "$output_dir/sqlite3.c.gcov" ]; then
        total_lines=$(grep -c ":" "$output_dir/sqlite3.c.gcov" || echo "0")
        covered_lines=$(grep -c "^[[:space:]]*[1-9]" "$output_dir/sqlite3.c.gcov" || echo "0")
        uncovered_lines=$(grep -c "^[[:space:]]*#####:" "$output_dir/sqlite3.c.gcov" || echo "0")
        
        if [ "$total_lines" -gt 0 ]; then
            coverage_percent=$(echo "scale=2; $covered_lines * 100 / $total_lines" | bc -l 2>/dev/null || echo "0")
        else
            coverage_percent="0"
        fi
        
        echo "$fuzzer_name Coverage Summary:" > "$output_dir/summary.txt"
        echo "Total lines: $total_lines" >> "$output_dir/summary.txt"
        echo "Covered lines: $covered_lines" >> "$output_dir/summary.txt"
        echo "Uncovered lines: $uncovered_lines" >> "$output_dir/summary.txt"
        echo "Coverage percentage: ${coverage_percent}%" >> "$output_dir/summary.txt"
        
        echo "  Coverage: ${coverage_percent}% ($covered_lines/$total_lines lines)"
    else
        echo "  Warning: No sqlite3.c.gcov file generated"
    fi
}

# Test original fuzzer
run_gcov_test "Original" "original_fuzzer_gcov" "gcov_results/original" "gcov_build"

# Test advanced fuzzer  
run_gcov_test "Advanced" "advanced_fuzzer_gcov" "gcov_results/advanced" "gcov_build"

echo ""
echo "=== Coverage Analysis Complete ==="
echo ""

# Compare coverage summaries
echo "=== Coverage Summary Comparison ==="
echo ""

if [ -f "gcov_results/original/summary.txt" ]; then
    echo "Original Fuzzer:"
    cat gcov_results/original/summary.txt
    echo ""
fi

if [ -f "gcov_results/advanced/summary.txt" ]; then
    echo "Advanced Fuzzer:"
    cat gcov_results/advanced/summary.txt
    echo ""
fi

# Analyze function coverage differences
echo "=== Function Coverage Analysis ==="
echo ""

# Extract function coverage from gcov files
extract_function_coverage() {
    local gcov_file=$1
    local output_file=$2
    
    if [ -f "$gcov_file" ]; then
        # Find function definitions and their coverage
        grep -n "^function.*called" "$gcov_file" | while read line; do
            line_num=$(echo "$line" | cut -d: -f1)
            func_info=$(echo "$line" | cut -d: -f2-)
            
            # Extract function name and call count
            func_name=$(echo "$func_info" | sed 's/^function \([^ ]*\).*/\1/')
            call_count=$(echo "$func_info" | sed 's/.*called \([0-9]*\).*/\1/')
            
            echo "$func_name:$call_count"
        done > "$output_file" 2>/dev/null || true
    fi
}

if [ -f "gcov_results/original/sqlite3.c.gcov" ] && [ -f "gcov_results/advanced/sqlite3.c.gcov" ]; then
    extract_function_coverage "gcov_results/original/sqlite3.c.gcov" "gcov_results/original/functions.txt"
    extract_function_coverage "gcov_results/advanced/sqlite3.c.gcov" "gcov_results/advanced/functions.txt"
    
    # Compare function coverage
    python3 -c "
try:
    # Read function coverage data
    orig_funcs = {}
    adv_funcs = {}
    
    try:
        with open('gcov_results/original/functions.txt', 'r') as f:
            for line in f:
                if ':' in line:
                    func, count = line.strip().split(':', 1)
                    orig_funcs[func] = int(count) if count.isdigit() else 0
    except FileNotFoundError:
        pass
        
    try:
        with open('gcov_results/advanced/functions.txt', 'r') as f:
            for line in f:
                if ':' in line:
                    func, count = line.strip().split(':', 1)
                    adv_funcs[func] = int(count) if count.isdigit() else 0
    except FileNotFoundError:
        pass
    
    # Analyze differences
    only_advanced = set(adv_funcs.keys()) - set(orig_funcs.keys())
    only_original = set(orig_funcs.keys()) - set(adv_funcs.keys())
    common_funcs = set(orig_funcs.keys()) & set(adv_funcs.keys())
    
    # Count functions actually called (call count > 0)
    orig_called = sum(1 for count in orig_funcs.values() if count > 0)
    adv_called = sum(1 for count in adv_funcs.values() if count > 0)
    
    print(f'Total functions found:')
    print(f'  Original fuzzer: {len(orig_funcs)} ({orig_called} called)')
    print(f'  Advanced fuzzer: {len(adv_funcs)} ({adv_called} called)')
    print(f'  Common functions: {len(common_funcs)}')
    print(f'  Only in advanced: {len(only_advanced)}')
    print(f'  Only in original: {len(only_original)}')
    print()
    
    if only_advanced:
        called_only_adv = [f for f in only_advanced if adv_funcs.get(f, 0) > 0]
        print(f'New functions hit by advanced fuzzer: {len(called_only_adv)}')
        for func in sorted(called_only_adv)[:10]:
            print(f'  {func} (called {adv_funcs[func]} times)')
        if len(called_only_adv) > 10:
            print(f'  ... and {len(called_only_adv) - 10} more')
        print()
        
    # Show functions with increased call counts
    increased_calls = []
    for func in common_funcs:
        if adv_funcs[func] > orig_funcs[func]:
            increased_calls.append((func, orig_funcs[func], adv_funcs[func]))
    
    if increased_calls:
        print(f'Functions with increased call frequency: {len(increased_calls)}')
        for func, orig_count, adv_count in sorted(increased_calls, key=lambda x: x[2]-x[1], reverse=True)[:10]:
            print(f'  {func}: {orig_count} -> {adv_count} (+{adv_count-orig_count})')
        print()
        
except Exception as e:
    print(f'Function analysis failed: {e}')
" 2>/dev/null
else
    echo "GCov files not found for function analysis"
fi

echo ""
echo "=== Coverage Reports Generated ==="
echo ""
echo "GCov reports available at:"
echo "  Original: gcov_results/original/"
echo "  Advanced: gcov_results/advanced/"
echo ""
echo "Key files:"
echo "  gcov_results/original/summary.txt - Coverage summary"
echo "  gcov_results/advanced/summary.txt - Coverage summary"
echo "  gcov_results/original/sqlite3.c.gcov - Detailed line coverage"
echo "  gcov_results/advanced/sqlite3.c.gcov - Detailed line coverage"