/*
** B-Tree Core Operations Functions Harness Header
** Target functions: sqlite3BtreeCursorIsValid, sqlite3BtreeClearCache, sqlite3BtreeCursorPin,
**                   hasSharedCacheTableLock, sqlite3BtreeCursorSize, sqlite3BtreeClosesWithCursor
** High-frequency functions with critical cursor and cache management
*/
#ifndef BTREE_CORE_OPS_HARNESS_H
#define BTREE_CORE_OPS_HARNESS_H

#include "fuzz.h"

/* Packet structures for B-Tree core operations functions */
typedef struct BtreeCursorValidPacket {
    uint8_t  cursorState;
    uint8_t  scenario;
    uint8_t  flags;
    uint8_t  pageType;
    uint32_t pgnoRoot;
    uint8_t  keyData[32];
    uint32_t testParams[4];
} BtreeCursorValidPacket;

typedef struct BtreeClearCachePacket {
    uint8_t  cacheMode;
    uint8_t  scenario;
    uint8_t  flags;
    uint8_t  reserved;
    uint32_t pageCount;
    uint32_t memoryLimit;
    uint32_t cacheSize;
    uint32_t testParams[4];
} BtreeClearCachePacket;

typedef struct BtreeCursorPinPacket {
    uint8_t  pinMode;
    uint8_t  scenario;
    uint8_t  flags;
    uint8_t  cursorIndex;
    uint32_t referenceCount;
    uint32_t pageNumber;
    uint32_t testParams[4];
} BtreeCursorPinPacket;

typedef struct SharedCacheLockPacket {
    uint8_t  lockType;
    uint8_t  scenario;
    uint8_t  flags;
    uint8_t  reserved;
    uint32_t tableNumber;
    uint32_t lockMask;
    uint32_t threadId;
    uint32_t testParams[4];
} SharedCacheLockPacket;

typedef struct BtreeCursorSizePacket {
    uint8_t  sizeMode;
    uint8_t  scenario;
    uint8_t  flags;
    uint8_t  alignment;
    uint32_t extraSize;
    uint32_t testParams[4];
} BtreeCursorSizePacket;

typedef struct BtreeClosesCursorPacket {
    uint8_t  closeMode;
    uint8_t  scenario;
    uint8_t  flags;
    uint8_t  cursorCount;
    uint32_t connectionId;
    uint32_t testParams[4];
} BtreeClosesCursorPacket;

/* Function prototypes */
int fuzz_sqlite3_btree_cursor_is_valid(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_sqlite3_btree_clear_cache(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_sqlite3_btree_cursor_pin(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_has_shared_cache_table_lock(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_sqlite3_btree_cursor_size(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_sqlite3_btree_closes_with_cursor(FuzzCtx *ctx, const uint8_t *data, size_t size);

#endif /* BTREE_CORE_OPS_HARNESS_H */