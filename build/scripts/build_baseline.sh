#!/bin/bash -eu
# Build script for baseline fuzzers

echo "=== Building Baseline SQLite3 Fuzzers ==="

# Set paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
DEPS_DIR="$ROOT_DIR/build/dependencies"
BUILD_DIR="$ROOT_DIR/bld"
FUZZER_DIR="$ROOT_DIR/fuzzers/baseline"

# Create build directory
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# Compiler settings
CC=${CC:-gcc}
CFLAGS="-O2 -g -Wall -Wextra"

# SQLite compile options
SQLITE_FLAGS="-DSQLITE_ENABLE_JSON1=1 -DSQLITE_ENABLE_FTS3=1 -DSQLITE_ENABLE_FTS5=1 -DSQLITE_ENABLE_RTREE=1"

echo "Compiling SQLite3..."
$CC $CFLAGS $SQLITE_FLAGS -c "$DEPS_DIR/sqlite3.c" -o sqlite3.o

echo "Building baseline fuzzers..."

# Build main ossfuzz fuzzer
if [ -f "$FUZZER_DIR/ossfuzz.c" ]; then
    echo "  Building ossfuzz..."
    $CC $CFLAGS -c "$FUZZER_DIR/ossfuzz.c" -o ossfuzz.o
    
    # Standalone version
    $CC $CFLAGS -DSTANDALONE_FUZZER -o "$ROOT_DIR/ossfuzz_standalone" \
        ossfuzz.o sqlite3.o -ldl -lm -lpthread
    
    echo "  ✓ ossfuzz_standalone created"
fi

# Build other baseline fuzzers
for fuzzer in dbfuzz dbfuzz2 optfuzz sessionfuzz; do
    if [ -f "$FUZZER_DIR/${fuzzer}.c" ]; then
        echo "  Building $fuzzer..."
        $CC $CFLAGS -c "$FUZZER_DIR/${fuzzer}.c" -o "${fuzzer}.o"
        $CC $CFLAGS -DSTANDALONE_FUZZER -o "$ROOT_DIR/${fuzzer}_standalone" \
            "${fuzzer}.o" sqlite3.o -ldl -lm -lpthread
        echo "  ✓ ${fuzzer}_standalone created"
    fi
done

echo ""
echo "=== Baseline Fuzzers Built Successfully ==="
echo "Available binaries:"
ls -la "$ROOT_DIR"/*_standalone 2>/dev/null || echo "No standalone binaries found"