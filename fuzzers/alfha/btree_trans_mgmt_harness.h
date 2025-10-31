/*
** B-Tree Transaction Management Functions Harness Header
** Target functions: sqlite3BtreeBeginTrans, sqlite3BtreeClearCursor, btreeReleaseAllCursorPages, querySharedCacheTableLock
** High complexity B-Tree transaction and cursor management functions
*/
#ifndef BTREE_TRANS_MGMT_HARNESS_H
#define BTREE_TRANS_MGMT_HARNESS_H

#include "fuzz.h"

/* Packet structures for B-Tree transaction management functions */
typedef struct BtreeBeginTransPacket {
    uint8_t  transactionType;
    uint8_t  wrflag;
    uint8_t  scenario;
    uint8_t  flags;
    uint32_t schemaVersion;
    uint16_t savepoint;
    uint32_t testData[6];
} BtreeBeginTransPacket;

typedef struct BtreeClearCursorPacket {
    uint8_t  cursorState;
    uint8_t  scenario;
    uint8_t  flags;
    uint8_t  cursorType;
    uint32_t keySize;
    uint32_t pgnoRoot;
    uint32_t testData[4];
} BtreeClearCursorPacket;

typedef struct BtreeReleaseAllPagesPacket {
    uint8_t  pageCount;
    uint8_t  scenario;
    uint8_t  flags;
    uint8_t  releaseType;
    uint16_t cursorIndex;
    uint16_t pageIndexes[8];
    uint32_t testData[2];
} BtreeReleaseAllPagesPacket;

typedef struct QuerySharedCacheLockPacket {
    uint32_t tableNumber;
    uint8_t  lockType;
    uint8_t  scenario;
    uint8_t  flags;
    uint8_t  dbIndex;
    uint8_t  conflictCheck;
    uint16_t lockTimeout;
    uint32_t testData[3];
} QuerySharedCacheLockPacket;

/* Function prototypes */
int fuzz_btree_begin_trans(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_btree_clear_cursor(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_btree_release_all_pages(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_query_shared_cache_lock(FuzzCtx *ctx, const uint8_t *data, size_t size);

#endif /* BTREE_TRANS_MGMT_HARNESS_H */