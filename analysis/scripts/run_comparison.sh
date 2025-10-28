#!/bin/bash -eu
# Performance Comparison Script for Competition Submission

echo "=== SQLite3 Fuzzer Performance Comparison ==="
echo ""

# Set paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
RESULTS_DIR="$ROOT_DIR/analysis/results"

# Ensure results directories exist
mkdir -p "$RESULTS_DIR/coverage" "$RESULTS_DIR/performance" "$RESULTS_DIR/reports"

echo "1. Building fuzzers with coverage instrumentation..."
cd "$ROOT_DIR"
make coverage

echo ""
echo "2. Running GCov-based comparison..."
cd "$ROOT_DIR/analysis/scripts"
./run_gcov_comparison.sh

echo ""
echo "3. Running detailed coverage analysis..."
cd "$ROOT_DIR/analysis/tools"
python3 coverage_analyzer.py

echo ""
echo "4. Generating performance reports..."
cd "$ROOT_DIR/analysis/scripts"
./generate_reports.sh

echo ""
echo "=== Comparison Complete ==="
echo ""
echo "Results available in:"
echo "  $RESULTS_DIR/coverage/    - Coverage data"
echo "  $RESULTS_DIR/performance/ - Performance metrics"
echo "  $RESULTS_DIR/reports/     - Generated reports"