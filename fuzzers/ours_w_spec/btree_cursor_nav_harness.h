/*
** SQLite3 B-Tree Cursor Navigation Harness Header
** Target functions: btreeCursorWithLock, btreeLast, btreeNext
** Critical B-Tree cursor navigation and positioning functions
*/
#ifndef BTREE_CURSOR_NAV_HARNESS_H
#define BTREE_CURSOR_NAV_HARNESS_H

#include "fuzz.h"

/* Packet structures for cursor navigation fuzzing */
typedef struct {
    uint8_t lockMode;
    uint8_t scenario;
    uint8_t flags;
    uint8_t cursorType;
    uint32_t pgnoRoot;
    uint32_t lockTimeout;
    uint32_t testParams[4];
} btree_cursor_lock_packet;

typedef struct {
    uint8_t navigationMode;
    uint8_t scenario;
    uint8_t flags;
    uint8_t cursorIndex;
    uint32_t pageHints;
    uint32_t seekCounter;
    uint32_t testParams[4];
} btree_last_packet;

typedef struct {
    uint8_t iterationMode;
    uint8_t scenario;
    uint8_t flags;
    uint8_t padding;
    uint32_t maxIterations;
    uint32_t startId;
    uint32_t testParams[4];
} btree_next_packet;

/* Function declarations for B-Tree cursor navigation harnesses */
int fuzz_btree_cursor_with_lock(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_btree_last(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_btree_next(FuzzCtx *ctx, const uint8_t *data, size_t size);

#endif /* BTREE_CURSOR_NAV_HARNESS_H */