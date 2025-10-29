/*
** Storage Pager Harness Header
** Targets: pagerAcquireMapPage, pagerBeginReadTransaction, pagerExclusiveLock, getPageNormal
** Enhanced coverage for Storage Page Management operations
*/
#ifndef STORAGE_PAGER_HARNESS_H
#define STORAGE_PAGER_HARNESS_H

#include "fuzz.h"

/* Storage pager fuzzing modes */
#define FUZZ_MODE_PAGER_ACQUIRE_MMAP     39  /* pagerAcquireMapPage */
#define FUZZ_MODE_PAGER_BEGIN_READ_TXN   40  /* pagerBeginReadTransaction */
#define FUZZ_MODE_PAGER_EXCLUSIVE_LOCK   41  /* pagerExclusiveLock */
#define FUZZ_MODE_PAGER_GET_PAGE_NORMAL  42  /* getPageNormal */

/* Test scenarios for pager operations */
#define PAGER_SCENARIO_NORMAL      0x01  /* Normal operation */
#define PAGER_SCENARIO_MMAP        0x02  /* Memory mapping scenarios */
#define PAGER_SCENARIO_WAL         0x03  /* WAL mode testing */
#define PAGER_SCENARIO_LOCKING     0x04  /* Lock contention */
#define PAGER_SCENARIO_CORRUPTION  0x05  /* Corruption handling */
#define PAGER_SCENARIO_MEMORY      0x06  /* Memory pressure */
#define PAGER_SCENARIO_BOUNDARY    0x07  /* Boundary conditions */
#define PAGER_SCENARIO_READONLY    0x08  /* Read-only scenarios */

/* Lock levels for testing */
#define LOCK_NONE      0
#define LOCK_SHARED    1  
#define LOCK_RESERVED  2
#define LOCK_PENDING   3
#define LOCK_EXCLUSIVE 4

/* Pager states */
#define PAGER_OPEN           0
#define PAGER_READER         1
#define PAGER_WRITER_LOCKED  2
#define PAGER_WRITER_CACHEMOD 3
#define PAGER_WRITER_DBMOD   4
#define PAGER_WRITER_FINISHED 5
#define PAGER_ERROR          6

/* Input packet for pagerAcquireMapPage fuzzing */
typedef struct PagerAcquireMapPacket {
  uint8_t scenario;          /* Test scenario selector */
  uint8_t lockLevel;         /* Current lock level */
  uint32_t pgno;             /* Page number to acquire */
  uint32_t pageSize;         /* Page size selector */
  uint32_t mmapSize;         /* Memory map size */
  uint32_t corruption_flags; /* Corruption pattern */
  uint8_t testData[16];      /* Test content */
} PagerAcquireMapPacket;

/* Input packet for pagerBeginReadTransaction fuzzing */
typedef struct PagerBeginReadTxnPacket {
  uint8_t scenario;          /* Test scenario selector */
  uint8_t pagerState;        /* Initial pager state */
  uint8_t lockLevel;         /* Current lock level */
  uint8_t walEnabled;        /* WAL mode enabled */
  uint32_t changeCounter;    /* Change counter value */
  uint32_t walSize;          /* WAL file size */
  int32_t readMark;          /* Read mark index */
  uint32_t corruption_flags; /* Corruption pattern */
  uint8_t testData[12];      /* Test parameters */
} PagerBeginReadTxnPacket;

/* Input packet for pagerExclusiveLock fuzzing */
typedef struct PagerExclusiveLockPacket {
  uint8_t scenario;          /* Test scenario selector */
  uint8_t currentLock;       /* Current lock level */
  uint8_t exclusiveMode;     /* Exclusive mode flag */
  uint8_t readOnly;          /* Read-only flag */
  uint8_t tempFile;          /* Temporary file flag */
  uint32_t timeout;          /* Lock timeout */
  uint32_t syncFlags;        /* Synchronization flags */
  uint32_t corruption_flags; /* Corruption pattern */
  uint8_t testData[12];      /* Test parameters */
} PagerExclusiveLockPacket;

/* Input packet for getPageNormal fuzzing */
typedef struct GetPageNormalPacket {
  uint8_t scenario;          /* Test scenario selector */
  uint8_t pagerState;        /* Pager state */
  uint8_t fetchFlags;        /* Page fetch flags */
  uint8_t noContent;         /* No content flag */
  uint32_t pgno;             /* Page number */
  uint32_t pageSize;         /* Page size */
  uint32_t cacheSize;        /* Cache size limit */
  uint32_t corruption_flags; /* Corruption pattern */
  uint8_t testData[12];      /* Test content */
} GetPageNormalPacket;

/* Function declarations for storage pager fuzzing */
int fuzz_pager_acquire_mmap(FuzzCtx *pCtx, const PagerAcquireMapPacket *pPacket);
int fuzz_pager_begin_read_txn(FuzzCtx *pCtx, const PagerBeginReadTxnPacket *pPacket);
int fuzz_pager_exclusive_lock(FuzzCtx *pCtx, const PagerExclusiveLockPacket *pPacket);
int fuzz_get_page_normal(FuzzCtx *pCtx, const GetPageNormalPacket *pPacket);

#endif /* STORAGE_PAGER_HARNESS_H */