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

/* Core function declarations */
int progress_handler(void *pClientData);
int exec_handler(void *pClientData, int argc, char **argv, char **namev);
int block_debug_pragmas(void *Notused, int eCode, const char *zArg1, 
                        const char *zArg2, const char *zArg3, const char *zArg4);
sqlite3_int64 timeOfDay(void);


/* Debug and utility functions */
void ossfuzz_set_debug_flags(unsigned x);

#endif /* SQLITE3_ENHANCED_FUZZ_H */