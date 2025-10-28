#!/bin/bash -eu
# Quick test script for competition demo

echo "=== Advanced SQLite3 Fuzzer - Quick Test ==="
echo ""

# Build if needed
if [ ! -f "../../advanced_fuzzer_standalone" ]; then
    echo "Building advanced fuzzer..."
    cd ../..
    make advanced
    cd examples/quickstart
fi

echo "Running basic tests..."
echo ""

# Test 1: Basic SQL
echo "1. Testing basic SQL execution:"
echo "   Input: SELECT 1;"
../../advanced_fuzzer_standalone ../../tests/testcases/sql/basic.sql
echo ""

# Test 2: Schema mode
echo "2. Testing schema manipulation mode (mode 2):"
echo "   Input: Binary data with schema operations"
../../advanced_fuzzer_standalone ../../tests/testcases/binary/schema.bin
echo ""

# Test 3: Functions mode  
echo "3. Testing function-focused mode (mode 3):"
echo "   Input: Binary data with function calls"
../../advanced_fuzzer_standalone ../../tests/testcases/binary/functions.bin
echo ""

# Test 4: Debug mode
echo "4. Testing with debug output enabled:"
echo "   Input: Same as test 1, but with debug flags"
SQLITE_DEBUG_FLAGS=15 ../../advanced_fuzzer_standalone ../../tests/testcases/sql/basic.sql
echo ""

echo "=== All Tests Completed Successfully ==="
echo ""
echo "The advanced fuzzer demonstrates:"
echo "  ✓ Multi-mode operation (7 different fuzzing modes)"
echo "  ✓ Enhanced SQL test case generation"  
echo "  ✓ Comprehensive debug output capabilities"
echo "  ✓ Safe handling of both text and binary inputs"
echo ""
echo "Next: Run 'make analysis' for performance comparison!"