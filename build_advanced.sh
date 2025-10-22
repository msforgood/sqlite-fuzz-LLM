#!/bin/bash -eu
# Advanced SQLite3 Fuzzer Build Script
# Based on original build.sh with enhancements

echo "Building Advanced SQLite3 Fuzzer..."

# Create build directory
mkdir -p bld
cd bld

# Set environment variables for fuzzing
export ASAN_OPTIONS=detect_leaks=0

# Enhanced compiler flags for better coverage and debugging
export CFLAGS="$CFLAGS -DSQLITE_MAX_LENGTH=128000000 \
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

# Check if we have SQLite3 source
if [ ! -f "../sqlite3.c" ]; then
    echo "Getting SQLite3 amalgamation..."
    
    # Try to find sqlite3.c in the system
    SQLITE_SRC_PATH=""
    
    # Check common locations
    if [ -f "/home/minseo/oss-fuzz/build/out/sqlite3/src/sqlite3/bld/sqlite3.c" ]; then
        SQLITE_SRC_PATH="/home/minseo/oss-fuzz/build/out/sqlite3/src/sqlite3/bld"
    elif [ -f "../build/out/sqlite3/src/sqlite3/bld/sqlite3.c" ]; then
        SQLITE_SRC_PATH="../build/out/sqlite3/src/sqlite3/bld"
    else
        echo "SQLite3 source not found. Downloading amalgamation..."
        wget -q https://www.sqlite.org/2023/sqlite-amalgamation-3440200.zip || {
            echo "Failed to download SQLite3. Please manually copy sqlite3.c and sqlite3.h to the parent directory."
            exit 1
        }
        unzip -q sqlite-amalgamation-3440200.zip
        cp sqlite-amalgamation-3440200/sqlite3.c ../
        cp sqlite-amalgamation-3440200/sqlite3.h ../
        SQLITE_SRC_PATH=".."
    fi
    
    if [ -n "$SQLITE_SRC_PATH" ]; then
        echo "Copying SQLite3 source from $SQLITE_SRC_PATH"
        cp "$SQLITE_SRC_PATH/sqlite3.c" ../
        cp "$SQLITE_SRC_PATH/sqlite3.h" ../
    fi
fi

# Compile the advanced fuzzer
echo "Compiling advanced fuzzer..."

# Set default compiler if not set
if [ -z "${CC:-}" ]; then
    CC=clang
fi

if [ -z "${CXX:-}" ]; then
    CXX=clang++
fi

# Compile SQLite3 first
$CC $CFLAGS -I.. -c ../sqlite3.c -o sqlite3.o

# Compile our advanced fuzzer
$CC $CFLAGS -I.. -c ../advanced_fuzzer.c -o advanced_fuzzer.o

# Link everything together
if [ -n "${LIB_FUZZING_ENGINE:-}" ]; then
    # OSS-Fuzz environment
    $CXX $CXXFLAGS \
        advanced_fuzzer.o sqlite3.o -o ../advanced_ossfuzz \
        $LIB_FUZZING_ENGINE
else
    # Standalone testing
    echo "Building standalone version for testing..."
    
    # Create a simple main function for standalone testing
    cat > test_main.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// Declare the fuzzer function
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
    
    printf("Testing with %zu bytes...\n", size);
    int result = LLVMFuzzerTestOneInput(data, size);
    printf("Fuzzer returned: %d\n", result);
    
    free(data);
    return 0;
}
EOF
    
    $CC $CFLAGS -I.. -c test_main.c -o test_main.o
    
    $CC $CFLAGS \
        advanced_fuzzer.o sqlite3.o test_main.o \
        -o ../advanced_fuzzer_standalone \
        -lpthread -ldl -lm
        
    echo "Standalone fuzzer built: ../advanced_fuzzer_standalone"
fi

echo "Build completed successfully!"

# Create some test cases
echo "Creating test cases..."
cd ..

mkdir -p testcases

# Basic SQL test
echo "SELECT 1;" > testcases/basic.sql

# Schema test (mode 2)
printf "\x02\x10CREATE TABLE test(id INTEGER);" > testcases/schema.bin

# Function test (mode 3)  
printf "\x03\x20SELECT abs(-42);" > testcases/functions.bin

# Blob test (mode 4)
printf "\x04\x30SELECT randomblob(100);" > testcases/blob.bin

# Transaction test (mode 5)
printf "\x05\x40BEGIN; INSERT INTO t VALUES(1); COMMIT;" > testcases/transaction.bin

echo "Test cases created in testcases/ directory"
echo ""
echo "To run standalone tests:"
echo "  ./advanced_fuzzer_standalone testcases/basic.sql"
echo "  ./advanced_fuzzer_standalone testcases/schema.bin"
echo ""
echo "To enable debug output, set environment variables:"
echo "  export SQLITE_DEBUG_FLAGS=15  # Enable all debug output"