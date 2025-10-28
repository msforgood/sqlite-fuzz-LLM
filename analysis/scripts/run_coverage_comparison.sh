#!/bin/bash -eu
# Coverage Comparison Script for SQLite3 Fuzzers

echo "=== SQLite3 Fuzzer Coverage Comparison ==="
echo ""

# Create coverage output directories
mkdir -p coverage_results/{original,advanced}

# Test cases to run
TEST_CASES=(
    "testcases/basic.sql"
    "testcases/comprehensive.sql"
    "testcases/invalid.sql"
)

# Create comprehensive test data for fair comparison
echo "Creating comprehensive test dataset..."
mkdir -p coverage_testdata

# Generate test cases that both fuzzers can handle
echo "SELECT 1;" > coverage_testdata/simple.sql
echo "CREATE TABLE t(x); INSERT INTO t VALUES(1); SELECT * FROM t;" > coverage_testdata/crud.sql
echo "SELECT abs(-42), length('test'), random();" > coverage_testdata/functions.sql
echo "BEGIN; CREATE TABLE tx(id); INSERT INTO tx VALUES(1); COMMIT;" > coverage_testdata/transaction.sql
echo "SELECT json_extract('{\"a\":1}', '\$.a');" > coverage_testdata/json.sql

# Binary test cases (both fuzzers handle these as mode 0)
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

# Function to run coverage test
run_coverage_test() {
    local fuzzer_name=$1
    local fuzzer_binary=$2
    local output_dir=$3
    
    echo "Testing $fuzzer_name fuzzer..."
    
    # Remove any existing profile data
    rm -f default.profraw
    
    # Set profile output
    export LLVM_PROFILE_FILE="$output_dir/fuzzer.profraw"
    
    # Run the fuzzer on all test cases
    for test_case in "${ALL_TEST_CASES[@]}"; do
        if [ -f "$test_case" ]; then
            echo "  Running $test_case"
            ./$fuzzer_binary "$test_case" >/dev/null 2>&1 || true
        fi
    done
    
    # Generate coverage data
    if [ -f "$output_dir/fuzzer.profraw" ]; then
        llvm-profdata merge -sparse "$output_dir/fuzzer.profraw" -o "$output_dir/fuzzer.profdata"
        
        # Generate detailed coverage report
        llvm-cov show ./$fuzzer_binary -instr-profile="$output_dir/fuzzer.profdata" \
            -format=html -output-dir="$output_dir/html" \
            -show-line-counts -show-regions -show-instantiations
            
        # Generate summary report
        llvm-cov report ./$fuzzer_binary -instr-profile="$output_dir/fuzzer.profdata" \
            > "$output_dir/coverage_summary.txt"
            
        # Generate function coverage list
        llvm-cov report ./$fuzzer_binary -instr-profile="$output_dir/fuzzer.profdata" \
            -show-functions > "$output_dir/function_coverage.txt"
            
        echo "  Coverage data generated in $output_dir/"
    else
        echo "  Warning: No profile data generated for $fuzzer_name"
    fi
}

# Test original fuzzer
run_coverage_test "Original" "original_fuzzer_coverage" "coverage_results/original"

# Test advanced fuzzer  
run_coverage_test "Advanced" "advanced_fuzzer_coverage" "coverage_results/advanced"

echo ""
echo "=== Coverage Analysis Complete ==="
echo ""

# Compare coverage summaries
echo "=== Coverage Summary Comparison ==="
echo ""

if [ -f "coverage_results/original/coverage_summary.txt" ] && [ -f "coverage_results/advanced/coverage_summary.txt" ]; then
    echo "Original Fuzzer Coverage:"
    head -10 coverage_results/original/coverage_summary.txt
    echo ""
    echo "Advanced Fuzzer Coverage:"
    head -10 coverage_results/advanced/coverage_summary.txt
    echo ""
    
    # Extract key metrics
    echo "=== Key Metrics Comparison ==="
    echo ""
    
    orig_line_coverage=$(grep "TOTAL" coverage_results/original/coverage_summary.txt | awk '{print $4}' | head -1)
    adv_line_coverage=$(grep "TOTAL" coverage_results/advanced/coverage_summary.txt | awk '{print $4}' | head -1)
    
    orig_func_coverage=$(grep "TOTAL" coverage_results/original/coverage_summary.txt | awk '{print $2}' | head -1)
    adv_func_coverage=$(grep "TOTAL" coverage_results/advanced/coverage_summary.txt | awk '{print $2}' | head -1)
    
    echo "Line Coverage:"
    echo "  Original Fuzzer: $orig_line_coverage"
    echo "  Advanced Fuzzer: $adv_line_coverage"
    echo ""
    echo "Function Coverage:"
    echo "  Original Fuzzer: $orig_func_coverage"  
    echo "  Advanced Fuzzer: $adv_func_coverage"
    echo ""
else
    echo "Coverage summary files not found. Check for errors above."
fi

# Generate function comparison
echo "=== Generating Function Coverage Analysis ==="
python3 -c "
import sys, re

def parse_function_coverage(file_path):
    functions = {}
    try:
        with open(file_path, 'r') as f:
            for line in f:
                if line.strip() and not line.startswith('Filename') and not line.startswith('-'):
                    parts = line.split()
                    if len(parts) >= 4:
                        func_name = parts[0]
                        regions = parts[1] 
                        missed = parts[2]
                        coverage = parts[3]
                        functions[func_name] = {
                            'regions': regions,
                            'missed': missed, 
                            'coverage': coverage
                        }
    except FileNotFoundError:
        print(f'File not found: {file_path}')
        return {}
    return functions

# Parse both function coverage files
orig_funcs = parse_function_coverage('coverage_results/original/function_coverage.txt')
adv_funcs = parse_function_coverage('coverage_results/advanced/function_coverage.txt')

# Find functions only covered by advanced fuzzer
only_advanced = set(adv_funcs.keys()) - set(orig_funcs.keys())
only_original = set(orig_funcs.keys()) - set(adv_funcs.keys())
common_funcs = set(orig_funcs.keys()) & set(adv_funcs.keys())

print(f'Functions only covered by advanced fuzzer: {len(only_advanced)}')
print(f'Functions only covered by original fuzzer: {len(only_original)}')  
print(f'Functions covered by both: {len(common_funcs)}')
print()

if only_advanced:
    print('Functions only hit by advanced fuzzer:')
    for func in sorted(only_advanced)[:20]:  # Show first 20
        print(f'  {func}')
    if len(only_advanced) > 20:
        print(f'  ... and {len(only_advanced) - 20} more')
    print()

if only_original:
    print('Functions only hit by original fuzzer:')
    for func in sorted(only_original)[:20]:  # Show first 20
        print(f'  {func}')
    if len(only_original) > 20:
        print(f'  ... and {len(only_original) - 20} more')
" 2>/dev/null || echo "Python analysis failed - coverage files may not exist yet"

echo ""
echo "=== Coverage Reports Generated ==="
echo ""
echo "Detailed HTML reports available at:"
echo "  Original: coverage_results/original/html/index.html"
echo "  Advanced: coverage_results/advanced/html/index.html"
echo ""
echo "Text reports available at:"
echo "  Original: coverage_results/original/coverage_summary.txt"
echo "  Advanced: coverage_results/advanced/coverage_summary.txt"
echo ""
echo "Function coverage lists:"
echo "  Original: coverage_results/original/function_coverage.txt"
echo "  Advanced: coverage_results/advanced/function_coverage.txt"