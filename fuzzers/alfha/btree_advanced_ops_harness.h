/*
** B-Tree Advanced Operations Functions Harness Header
** Target functions: btreeParseCellPtr, cursorOnLastPage, sqlite3BtreeCursorHasMoved, 
**                   sqlite3BtreeInsert, sqlite3BtreeIndexMoveto, clearAllSharedCacheTableLocks
** High complexity B-Tree cursor navigation, cell parsing, and lock management functions
*/
#ifndef BTREE_ADVANCED_OPS_HARNESS_H
#define BTREE_ADVANCED_OPS_HARNESS_H

#include "fuzz.h"

/* Packet structures for B-Tree advanced operations functions */
typedef struct BtreeParseCellPacket {
    uint8_t  pageType;
    uint16_t cellOffset;
    uint16_t cellSize;
    uint32_t payloadSize;
    int64_t  keySize;
    uint16_t nLocal;
    uint8_t  flags;
    uint8_t  cellData[64];
} BtreeParseCellPacket;

typedef struct CursorLastPagePacket {
    uint8_t  cursorState;
    uint8_t  pageDepth;
    uint16_t currentPage;
    uint32_t rootPage;
    uint8_t  flags;
    uint8_t  scenario;
    uint32_t testData[4];
} CursorLastPagePacket;

typedef struct CursorMovedPacket {
    uint8_t  cursorState;
    uint8_t  eState;
    uint8_t  skipNext;
    uint8_t  curFlags;
    uint32_t pageNumber;
    uint16_t cellIndex;
    uint8_t  flags;
    uint8_t  scenario;
    uint32_t validationData[3];
} CursorMovedPacket;

typedef struct BtreeInsertPacket {
    int64_t  keySize;
    uint32_t dataSize;
    uint8_t  flags;
    uint8_t  seekResult;
    uint8_t  scenario;
    uint8_t  spaceCheck;
    uint16_t payloadFlags;
    uint8_t  keyData[32];
    uint8_t  valueData[64];
    uint32_t testParams[4];
} BtreeInsertPacket;

typedef struct BtreeIndexMovetoPacket {
    uint16_t keyFields;
    uint32_t keyLength;
    uint8_t  searchType;
    uint8_t  scenario;
    uint8_t  flags;
    uint8_t  collationType;
    uint8_t  keyData[128];
    uint32_t searchParams[6];
} BtreeIndexMovetoPacket;

typedef struct SharedCacheClearPacket {
    uint8_t  lockCount;
    uint8_t  tableCount;
    uint8_t  scenario;
    uint8_t  flags;
    uint8_t  lockTypes[8];
    uint32_t tableNumbers[8];
    uint32_t testData[4];
} SharedCacheClearPacket;

/* Function prototypes */
int fuzz_btree_parse_cell_ptr(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_cursor_on_last_page(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_sqlite3_btree_cursor_has_moved(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_sqlite3_btree_insert(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_sqlite3_btree_index_moveto(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_clear_all_shared_cache_locks(FuzzCtx *ctx, const uint8_t *data, size_t size);

#endif /* BTREE_ADVANCED_OPS_HARNESS_H */