/*
** High-Impact Operations Functions Harness Header
** Target functions: sqlite3BtreeClearTable, sqlite3VdbeSorterInit, sqlite3WhereExprAnalyze,
**                   sqlite3VdbeSorterWrite, sqlite3DbMallocSize, downgradeAllSharedCacheTableLocks
** High-frequency functions with maximum crash discovery potential
*/
#ifndef HIGH_IMPACT_OPS_HARNESS_H
#define HIGH_IMPACT_OPS_HARNESS_H

#include "fuzz.h"

/* Packet structures for high-impact operations functions */
typedef struct BtreeClearTablePacket {
    uint32_t iTable;
    uint8_t  clearMode;
    uint8_t  scenario;
    uint8_t  flags;
    uint8_t  transactionType;
    uint32_t pageCount;
    uint32_t testData[6];
} BtreeClearTablePacket;

typedef struct VdbeSorterInitPacket {
    uint16_t nField;
    uint8_t  scenario;
    uint8_t  flags;
    uint32_t memLimitKB;
    uint32_t mxKeySize;
    uint8_t  sortOrder;
    uint8_t  collationType;
    uint32_t testData[4];
} VdbeSorterInitPacket;

typedef struct WhereExprAnalyzePacket {
    uint8_t  exprType;
    uint8_t  exprDepth;
    uint8_t  scenario;
    uint8_t  flags;
    uint8_t  tableCount;
    uint8_t  termCount;
    uint8_t  opType;
    uint8_t  exprData[64];
    uint32_t testParams[8];
} WhereExprAnalyzePacket;

typedef struct VdbeSorterWritePacket {
    uint32_t recordSize;
    uint8_t  scenario;
    uint8_t  flags;
    uint16_t sortKeySize;
    uint8_t  dataType;
    uint8_t  compression;
    uint8_t  recordData[128];
    uint32_t testParams[6];
} VdbeSorterWritePacket;

typedef struct DbMallocSizePacket {
    uint32_t ptrOffset;
    uint8_t  scenario;
    uint8_t  flags;
    uint32_t allocSize;
    uint8_t  alignment;
    uint8_t  ptrType;
    uint32_t testData[4];
} DbMallocSizePacket;

typedef struct DowngradeLocksPacket {
    uint8_t  lockCount;
    uint8_t  scenario;
    uint8_t  flags;
    uint8_t  transactionState;
    uint8_t  lockTypes[8];
    uint32_t tableIds[8];
    uint32_t testData[4];
} DowngradeLocksPacket;

/* Function prototypes */
int fuzz_sqlite3_btree_clear_table(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_sqlite3_vdbe_sorter_init(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_sqlite3_where_expr_analyze(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_sqlite3_vdbe_sorter_write(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_sqlite3_db_malloc_size(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_downgrade_all_shared_cache_locks(FuzzCtx *ctx, const uint8_t *data, size_t size);

#endif /* HIGH_IMPACT_OPS_HARNESS_H */