#!/bin/bash -eu
# Coverage Build Script for SQLite3 Fuzzers
# Builds both original and advanced fuzzers with coverage instrumentation

echo "Building SQLite3 Fuzzers with Coverage Instrumentation..."

# Create coverage build directory
mkdir -p coverage_build
cd coverage_build

# Coverage flags for clang
export CC=clang
export CXX=clang++
export COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping -g -O0"
export CFLAGS="$COVERAGE_FLAGS -DSQLITE_MAX_LENGTH=128000000 \
               -DSQLITE_MAX_SQL_LENGTH=128000000 \
               -DSQLITE_MAX_MEMORY=25000000 \
               -DSQLITE_PRINTF_PRECISION_LIMIT=1048576 \
               -DSQLITE_DEBUG=1 \
               -DSQLITE_MAX_PAGE_COUNT=16384 \
               -DSQLITE_ENABLE_JSON1=1 \
               -DSQLITE_ENABLE_FTS3=1 \
               -DSQLITE_ENABLE_FTS5=1 \
               -DSQLITE_ENABLE_RTREE=1 \
               -DSQLITE_ENABLE_GEOPOLY=1 \
               -DSQLITE_ENABLE_DBSTAT_VTAB=1 \
               -DSQLITE_ENABLE_DBPAGE_VTAB=1 \
               -DSQLITE_ENABLE_STMTVTAB=1 \
               -DSQLITE_THREADSAFE=0 \
               -DSQLITE_OMIT_RANDOMNESS=1"

export CXXFLAGS="$COVERAGE_FLAGS"

# Build SQLite3 with coverage
echo "Building SQLite3 with coverage instrumentation..."
$CC $CFLAGS -I.. -c ../sqlite3.c -o sqlite3_coverage.o

# Build original fuzzer with coverage
echo "Building original fuzzer with coverage..."
$CC $CFLAGS -I.. -c ../ossfuzz.c -o ossfuzz_coverage.o

# Build advanced fuzzer with coverage
echo "Building advanced fuzzer with coverage..."
$CC $CFLAGS -I.. -c ../advanced_fuzzer.c -o advanced_fuzzer_coverage.o

# Create test main for both fuzzers
cat > test_main_original.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// Declare the original fuzzer function  
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Usage: %s <test_file>\n", argv[0]);
        return 1;
    }
    
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        printf("Cannot open file: %s\n", argv[1]);
        return 1;
    }
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    if (size <= 0 || size > 1000000) {
        printf("Invalid file size: %ld\n", size);
        fclose(f);
        return 1;
    }
    
    uint8_t *data = malloc(size);
    if (!data) {
        printf("Memory allocation failed\n");
        fclose(f);
        return 1;
    }
    
    size_t read_size = fread(data, 1, size, f);
    fclose(f);
    
    if (read_size != size) {
        printf("Read error\n");
        free(data);
        return 1;
    }
    
    printf("Testing original fuzzer with %zu bytes...\n", size);
    int result = LLVMFuzzerTestOneInput(data, size);
    printf("Original fuzzer returned: %d\n", result);
    
    free(data);
    return 0;
}
EOF

cp test_main_original.c test_main_advanced.c
sed -i 's/original fuzzer/advanced fuzzer/g' test_main_advanced.c

# Compile test mains
$CC $CFLAGS -I.. -c test_main_original.c -o test_main_original.o
$CC $CFLAGS -I.. -c test_main_advanced.c -o test_main_advanced.o

# Link original fuzzer
echo "Linking original fuzzer..."
$CC $CFLAGS \
    ossfuzz_coverage.o sqlite3_coverage.o test_main_original.o \
    -o ../original_fuzzer_coverage \
    -lpthread -ldl -lm

# Link advanced fuzzer  
echo "Linking advanced fuzzer..."
$CC $CFLAGS \
    advanced_fuzzer_coverage.o sqlite3_coverage.o test_main_advanced.o \
    -o ../advanced_fuzzer_coverage \
    -lpthread -ldl -lm

cd ..

echo "Coverage builds completed!"
echo ""
echo "Coverage-enabled executables created:"
echo "  ./original_fuzzer_coverage"
echo "  ./advanced_fuzzer_coverage"
echo ""
echo "To run coverage analysis:"
echo "  ./run_coverage_comparison.sh"