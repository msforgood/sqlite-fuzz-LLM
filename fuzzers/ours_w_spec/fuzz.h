/*
** Enhanced SQLite3 Fuzzer Header
** Target: allocateBtreePage function
** Specification-based fuzzing implementation
*/
#ifndef SQLITE3_ENHANCED_FUZZ_H
#define SQLITE3_ENHANCED_FUZZ_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "sqlite3.h"

/* Fuzzing mode selector values */
#define FUZZ_MODE_BTREE_ALLOC    0x01  /* Target allocateBtreePage specifically */
#define FUZZ_MODE_FREELIST_FULL  0x02  /* Test freelist scenarios */
#define FUZZ_MODE_CORRUPTION     0x03  /* Test corruption detection */
#define FUZZ_MODE_MEMORY_STRESS  0x04  /* Test memory pressure */
#define FUZZ_MODE_CONCURRENT     0x05  /* Test concurrent access */
#define FUZZ_MODE_AUTOVACUUM     0x06  /* Target autoVacuumCommit specifically */
#define FUZZ_MODE_FREESPACE      0x07  /* Target btreeComputeFreeSpace specifically */
#define FUZZ_MODE_PAGEMANAGEMENT 0x08  /* Target page management functions */
#define FUZZ_MODE_TABLECURSOR    0x09  /* Target table/cursor management functions */
#define FUZZ_MODE_BTREE_TRANS    0x0A  /* Target btreeBeginTrans */
#define FUZZ_MODE_CELL_CHECK     0x0B  /* Target btreeCellSizeCheck */
#define FUZZ_MODE_CREATE_TABLE   0x0C  /* Target btreeCreateTable */
#define FUZZ_MODE_CURSOR         0x0D  /* Target btreeCursor */
#define FUZZ_MODE_DROP_TABLE     0x0E  /* Target btreeDropTable */
#define FUZZ_MODE_FREE_PAGE      0x10  /* Target freePage specifically */
#define FUZZ_MODE_CLEAR_PAGE     0x11  /* Target clearDatabasePage specifically */
#define FUZZ_MODE_DEFRAG_PAGE    0x12  /* Target defragmentPage specifically */
#define FUZZ_MODE_CLOSE_CURSOR   0x13  /* Target sqlite3BtreeCloseCursor specifically */
#define FUZZ_MODE_DELETE_AUXDATA  0x14  /* Target sqlite3VdbeDeleteAuxData specifically */
#define FUZZ_MODE_SET_NUMCOLS     0x15  /* Target sqlite3VdbeSetNumCols specifically */
#define FUZZ_MODE_MEM_WRITEABLE   0x16  /* Target sqlite3VdbeMemMakeWriteable specifically */
#define FUZZ_MODE_VALUE_FREE      0x17  /* Target sqlite3_value_free specifically */
#define FUZZ_MODE_CODE_TABLE_LOCKS      0x20  /* Target codeTableLocks specifically */
#define FUZZ_MODE_DESTROY_ROOT_PAGE     0x21  /* Target destroyRootPage specifically */
#define FUZZ_MODE_CODE_VERIFY_SCHEMA    0x22  /* Target sqlite3CodeVerifySchema specifically */
#define FUZZ_MODE_BTREE_BUSY_HANDLER    0x30  /* Target btreeInvokeBusyHandler specifically */
#define FUZZ_MODE_BTREE_RESTORE_CURSOR  0x31  /* Target btreeRestoreCursorPosition specifically */
#define FUZZ_MODE_BTREE_SHARED_CACHE_LOCK 0x32  /* Target setSharedCacheTableLock specifically */

/* Allocation mode values from btree.c */
#define BTALLOC_ANY    0   /* Allocate any page */
#define BTALLOC_EXACT  1   /* Allocate exact page if possible */
#define BTALLOC_LE     2   /* Allocate any page <= the parameter */

/* Enhanced fuzzing context */
typedef struct FuzzCtx {
  sqlite3 *db;               /* Database connection */
  sqlite3_int64 iCutoffTime; /* Stop processing at this time */
  sqlite3_int64 iLastCb;     /* Time recorded for previous progress callback */
  sqlite3_int64 mxInterval;  /* Longest interval between two progress calls */
  unsigned nCb;              /* Number of progress callbacks */
  unsigned execCnt;          /* Number of calls to sqlite3_exec callback */
  
  /* Enhanced fuzzing state */
  uint8_t fuzzMode;          /* Current fuzzing mode */
  uint32_t targetPgno;       /* Target page number for allocation */
  uint8_t allocMode;         /* Allocation mode (BTALLOC_*) */
  uint32_t corruptionSeed;   /* Seed for corruption scenarios */
  uint32_t memoryLimit;      /* Memory limit for stress testing */
} FuzzCtx;

/* Input packet structure for allocateBtreePage fuzzing */
typedef struct BtreeAllocPacket {
  uint8_t mode;              /* Fuzzing mode selector */
  uint8_t allocType;         /* BTALLOC_ANY/EXACT/LE */
  uint16_t flags;            /* Various test flags */
  uint32_t nearbyPgno;       /* Nearby page number hint */
  uint32_t corruptionMask;   /* Corruption pattern mask */
  uint32_t memoryPressure;   /* Memory pressure simulation */
  uint8_t payload[32];       /* Additional test data */
} BtreeAllocPacket;

/* Input packet structure for autoVacuumCommit fuzzing */
typedef struct AutoVacuumPacket {
  uint8_t vacuumMode;        /* Auto-vacuum mode (0=NONE, 1=FULL, 2=INCREMENTAL) */
  uint8_t pageSize;          /* Page size selector (512, 1024, 4096, etc.) */
  uint16_t scenario;         /* Test scenario selector */
  uint32_t dbPages;          /* Initial database size in pages */
  uint32_t freePages;        /* Number of pages to free before vacuum */
  uint32_t corruptionSeed;   /* Seed for corruption injection */
  uint32_t customVacFunc;    /* Custom vacuum function behavior */
  uint8_t testData[24];      /* Additional test parameters */
} AutoVacuumPacket;

/* Input packet for btreeBeginTrans fuzzing */
typedef struct BtreeTransPacket {
  uint8_t transType;         /* Transaction type (0=READ, 1=WRITE) */
  uint8_t flags;             /* Test flags */
  uint16_t scenario;         /* Test scenario selector */
  uint32_t schemaVersion;    /* Schema version number */
  uint32_t corruptionMask;   /* Corruption simulation mask */
  uint8_t testData[20];      /* Additional test parameters */
} BtreeTransPacket;

/* Input packet for btreeCellSizeCheck fuzzing */
typedef struct CellCheckPacket {
  uint8_t pageType;          /* Page type (leaf/interior/index) */
  uint8_t corruption;        /* Corruption scenario selector */
  uint16_t cellCount;        /* Number of cells on page */
  uint32_t pageSize;         /* Page size */
  uint32_t corruptOffset;    /* Offset for corruption injection */
  uint8_t cellData[20];      /* Cell data pattern */
} CellCheckPacket;

/* Input packet for btreeCreateTable fuzzing */
typedef struct CreateTablePacket {
  uint8_t createFlags;       /* Table creation flags */
  uint8_t pageType;          /* Initial page type */
  uint16_t scenario;         /* Test scenario */
  uint32_t initialPages;     /* Initial page allocation */
  uint32_t tableId;          /* Preferred table ID */
  uint8_t testData[20];      /* Additional parameters */
} CreateTablePacket;

/* Input packet for btreeCursor fuzzing */
typedef struct CursorPacket {
  uint8_t wrFlag;            /* Write flag (0=READ, 1=WRITE, 2=FORDELETE) */
  uint8_t keyType;           /* Key type selector */
  uint16_t scenario;         /* Test scenario */
  uint32_t tableRoot;        /* Root page number */
  uint32_t keyFields;        /* Number of key fields */
  uint8_t keyData[20];       /* Key pattern data */
} CursorPacket;

/* Input packet for btreeDropTable fuzzing */
typedef struct DropTablePacket {
  uint8_t dropMode;          /* Drop mode selector */
  uint8_t compactAfter;      /* Whether to compact after drop */
  uint16_t scenario;         /* Test scenario */
  uint32_t tableRoot;        /* Table root page to drop */
  uint32_t expectedMoved;    /* Expected moved page */
  uint8_t testData[20];      /* Additional parameters */
} DropTablePacket;

/* Core function declarations */
int progress_handler(void *pClientData);
int exec_handler(void *pClientData, int argc, char **argv, char **namev);
int block_debug_pragmas(void *Notused, int eCode, const char *zArg1, 
                        const char *zArg2, const char *zArg3, const char *zArg4);
sqlite3_int64 timeOfDay(void);


/* Include harness headers */
#include "parser_advanced_harness.h"
#include "btree_meta_harness.h"

/* Debug and utility functions */
void ossfuzz_set_debug_flags(unsigned x);

#endif /* SQLITE3_ENHANCED_FUZZ_H */