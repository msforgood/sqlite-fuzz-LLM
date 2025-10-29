/*
** Query WHERE Clause Functions Harness Header
** Target functions: freeIdxStr, freeIndexInfo, whereInfoFree, whereLoopAddBtreeIndex
** Specification-based fuzzing for query WHERE clause operations
*/
#ifndef QUERY_WHERE_HARNESS_H
#define QUERY_WHERE_HARNESS_H

#include "fuzz.h"

/* WHERE clause fuzzing test scenarios */
#define WHERE_SCENARIO_NORMAL           0x01  /* Normal operation */
#define WHERE_SCENARIO_VIRTUAL_TABLE    0x02  /* Virtual table operations */
#define WHERE_SCENARIO_INDEX_CLEANUP    0x03  /* Index cleanup scenarios */
#define WHERE_SCENARIO_MEMORY_PRESSURE  0x04  /* Memory pressure conditions */
#define WHERE_SCENARIO_COMPLEX_QUERY    0x05  /* Complex query optimization */
#define WHERE_SCENARIO_CONSTRAINT_HEAVY 0x06  /* Heavy constraint scenarios */
#define WHERE_SCENARIO_LOOP_MANAGEMENT  0x07  /* Loop management edge cases */
#define WHERE_SCENARIO_CORRUPTION       0x08  /* Corruption handling */

/* Index operation types */
#define IDX_OP_CLEANUP      0
#define IDX_OP_CONSTRAINT   1
#define IDX_OP_OPTIMIZATION 2
#define IDX_OP_COST_ANALYSIS 3

/* Constraint operation codes (matching SQLite) */
#define SQLITE_INDEX_CONSTRAINT_EQ         2
#define SQLITE_INDEX_CONSTRAINT_GT         4
#define SQLITE_INDEX_CONSTRAINT_LE         8
#define SQLITE_INDEX_CONSTRAINT_LT        16
#define SQLITE_INDEX_CONSTRAINT_GE        32
#define SQLITE_INDEX_CONSTRAINT_MATCH     64
#define SQLITE_INDEX_CONSTRAINT_LIKE     65
#define SQLITE_INDEX_CONSTRAINT_GLOB     66
#define SQLITE_INDEX_CONSTRAINT_REGEXP   67
#define SQLITE_INDEX_CONSTRAINT_NE       68
#define SQLITE_INDEX_CONSTRAINT_ISNOT    69
#define SQLITE_INDEX_CONSTRAINT_ISNOTNULL 70
#define SQLITE_INDEX_CONSTRAINT_ISNULL  71
#define SQLITE_INDEX_CONSTRAINT_IS       72
#define SQLITE_INDEX_CONSTRAINT_LIMIT   73
#define SQLITE_INDEX_CONSTRAINT_OFFSET  74

/* Input packet for freeIdxStr fuzzing */
typedef struct FreeIdxStrPacket {
  uint8_t scenario;              /* Test scenario selector */
  uint8_t needToFreeFlag;        /* needToFreeIdxStr flag state */
  uint16_t constraintCount;      /* Number of constraints */
  uint16_t orderByCount;         /* Number of order by terms */
  uint16_t idxStrLength;         /* Index string length */
  uint32_t estimatedCost;        /* Cost estimation */
  uint32_t corruption_flags;     /* Corruption pattern */
  uint8_t testData[16];          /* Test content */
} FreeIdxStrPacket;

/* Input packet for freeIndexInfo fuzzing */
typedef struct FreeIndexInfoPacket {
  uint8_t scenario;              /* Test scenario selector */
  uint8_t constraintCount;       /* Number of constraints */
  uint8_t orderByCount;          /* Number of order by terms */
  uint8_t rhsValueCount;         /* Number of RHS values */
  uint16_t idxStrLength;         /* Index string length */
  uint32_t parseContext;         /* Parse context flags */
  uint32_t dbContext;            /* Database context flags */
  uint32_t corruption_flags;     /* Corruption pattern */
  uint8_t constraintData[20];    /* Constraint test data */
} FreeIndexInfoPacket;

/* Input packet for whereInfoFree fuzzing */
typedef struct WhereInfoFreePacket {
  uint8_t scenario;              /* Test scenario selector */
  uint8_t loopCount;             /* Number of WHERE loops */
  uint8_t memBlockCount;         /* Number of memory blocks */
  uint8_t levelCount;            /* Number of WHERE levels */
  uint16_t clauseTermCount;      /* Number of clause terms */
  uint32_t bitmaskValue;         /* Test bitmask value */
  uint32_t sortedFlag;           /* Sorted optimization flag */
  uint32_t corruption_flags;     /* Corruption pattern */
  uint8_t whereData[16];         /* WHERE clause test data */
} WhereInfoFreePacket;

/* Input packet for whereLoopAddBtreeIndex fuzzing */
typedef struct WhereLoopAddBtreeIndexPacket {
  uint8_t scenario;              /* Test scenario selector */
  uint8_t indexColumnCount;      /* Number of index columns */
  uint8_t whereTermCount;        /* Number of WHERE terms */
  uint8_t constraintOp;          /* Constraint operation type */
  uint16_t whereFlags;           /* WHERE operation flags */
  uint32_t bitmaskPrereq;        /* Prerequisite bitmask */
  uint32_t logEstimate;          /* Cost log estimate */
  uint32_t tableSize;            /* Table size estimation */
  uint32_t corruption_flags;     /* Corruption pattern */
  uint8_t indexData[20];         /* Index test data */
} WhereLoopAddBtreeIndexPacket;

/* Function declarations for query WHERE clause fuzzing */
void fuzz_free_idx_str(FuzzCtx *pCtx, const FreeIdxStrPacket *pPacket);
void fuzz_free_index_info(FuzzCtx *pCtx, const FreeIndexInfoPacket *pPacket);
void fuzz_where_info_free(FuzzCtx *pCtx, const WhereInfoFreePacket *pPacket);
void fuzz_where_loop_add_btree_index(FuzzCtx *pCtx, const WhereLoopAddBtreeIndexPacket *pPacket);

#endif /* QUERY_WHERE_HARNESS_H */