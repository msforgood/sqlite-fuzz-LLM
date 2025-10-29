/*
** Storage Pager Functions Harness Header  
** Target functions: assert_pager_state, checkPage, pageInJournal, pagerFixMaplimit
** Specification-based fuzzing for storage pager operations
*/
#ifndef STORAGE_PAGER_HARNESS_H
#define STORAGE_PAGER_HARNESS_H

#include "fuzz.h"

/* Storage pager fuzzing modes - defined in fuzz.h */

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

/* Packet structures defined in fuzz.h */

/* Function declarations for storage pager fuzzing */
void fuzz_assert_pager_state(FuzzCtx *pCtx, const AssertPagerStatePacket *pPacket);
void fuzz_check_page(FuzzCtx *pCtx, const CheckPagePacket *pPacket);
void fuzz_page_in_journal(FuzzCtx *pCtx, const PageInJournalPacket *pPacket);
void fuzz_pager_fix_maplimit(FuzzCtx *pCtx, const PagerFixMaplimitPacket *pPacket);

#endif /* STORAGE_PAGER_HARNESS_H */