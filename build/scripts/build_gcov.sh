#!/bin/bash -eu
# GCov Coverage Build Script for SQLite3 Fuzzers

echo "Building SQLite3 Fuzzers with GCov Coverage..."

# Create gcov build directory
mkdir -p gcov_build
cd gcov_build

# GCov flags for gcc
export CC=gcc
export CXX=g++
export COVERAGE_FLAGS="-fprofile-arcs -ftest-coverage -g -O0"
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
export LDFLAGS="$COVERAGE_FLAGS"

# Build SQLite3 with coverage
echo "Building SQLite3 with gcov instrumentation..."
$CC $CFLAGS -I.. -c ../sqlite3.c -o sqlite3_gcov.o

# Build original fuzzer with coverage
echo "Building original fuzzer with gcov..."
$CC $CFLAGS -I.. -c ../ossfuzz.c -o ossfuzz_gcov.o

# Build advanced fuzzer with coverage
echo "Building advanced fuzzer with gcov..."
$CC $CFLAGS -I.. -c ../fuzz.c -o advanced_fuzzer_gcov.o

# Use the same test main from coverage build
cp ../coverage_build/test_main_original.c .
cp ../coverage_build/test_main_advanced.c .

# Compile test mains
$CC $CFLAGS -I.. -c test_main_original.c -o test_main_original.o
$CC $CFLAGS -I.. -c test_main_advanced.c -o test_main_advanced.o

# Link original fuzzer
echo "Linking original fuzzer..."
$CC $LDFLAGS \
    ossfuzz_gcov.o sqlite3_gcov.o test_main_original.o \
    -o ../original_fuzzer_gcov \
    -lpthread -ldl -lm -lgcov

# Link advanced fuzzer  
echo "Linking advanced fuzzer..."
$CC $LDFLAGS \
    advanced_fuzzer_gcov.o sqlite3_gcov.o test_main_advanced.o \
    -o ../advanced_fuzzer_gcov \
    -lpthread -ldl -lm -lgcov

cd ..

echo "GCov builds completed!"
echo ""
echo "GCov-enabled executables created:"
echo "  ./original_fuzzer_gcov"
echo "  ./advanced_fuzzer_gcov"
echo ""
echo "To run gcov coverage analysis:"
echo "  ./run_gcov_comparison.sh"