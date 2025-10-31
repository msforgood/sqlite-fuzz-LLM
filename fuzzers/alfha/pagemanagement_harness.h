/*
** Page Management Harness Header
** Targets: btreeClearHasContent, btreeGetHasContent, btreeInitPage
** Enhanced coverage for B-Tree page management operations
*/
#ifndef PAGEMANAGEMENT_HARNESS_H
#define PAGEMANAGEMENT_HARNESS_H

#include "fuzz.h"

/* Page management test scenarios */
#define PAGEMGMT_SCENARIO_NORMAL         0x01  /* Normal page operations */
#define PAGEMGMT_SCENARIO_BITVEC_STRESS  0x02  /* Bitvec allocation stress */
#define PAGEMGMT_SCENARIO_CORRUPTION     0x03  /* Page corruption scenarios */
#define PAGEMGMT_SCENARIO_TRANSACTION    0x04  /* Transaction state testing */
#define PAGEMGMT_SCENARIO_MIXED_PAGES    0x05  /* Mixed page type handling */
#define PAGEMGMT_SCENARIO_BOUNDARY       0x06  /* Boundary condition testing */
#define PAGEMGMT_SCENARIO_CONCURRENT     0x07  /* Concurrent access patterns */
#define PAGEMGMT_SCENARIO_MEMORY_STRESS  0x08  /* Memory pressure scenarios */

/* Page type definitions */
#define PAGE_TYPE_INTERIOR_TABLE  2
#define PAGE_TYPE_LEAF_TABLE      13
#define PAGE_TYPE_INTERIOR_INDEX  5
#define PAGE_TYPE_LEAF_INDEX      10

/* Test operation types */
#define OPERATION_INIT_PAGE       0x01
#define OPERATION_CHECK_CONTENT   0x02
#define OPERATION_CLEAR_CONTENT   0x04
#define OPERATION_MIXED           0x08

/* Input packet structure for page management fuzzing */
typedef struct PageMgmtPacket {
  uint8_t scenario;          /* Test scenario selector */
  uint8_t operations;        /* Operations to perform bitmask */
  uint16_t pageCount;        /* Number of pages to work with */
  uint16_t pageSize;         /* Page size selector */
  uint32_t bitvecSize;       /* Bitvec size for testing */
  uint32_t corruptionMask;   /* Corruption pattern mask */
  uint8_t pageTypes[8];      /* Page types to test */
  uint32_t pageNumbers[8];   /* Page numbers for testing */
  uint8_t testData[16];      /* Additional test parameters */
} PageMgmtPacket;

/* Function declarations for page management fuzzing */
void fuzz_page_management(FuzzCtx *pCtx, const PageMgmtPacket *pPacket);
int setup_page_management_db(FuzzCtx *pCtx, const PageMgmtPacket *pPacket);
int test_page_initialization(FuzzCtx *pCtx, const PageMgmtPacket *pPacket);
int test_bitvec_operations(FuzzCtx *pCtx, const PageMgmtPacket *pPacket);
int test_content_tracking(FuzzCtx *pCtx, const PageMgmtPacket *pPacket);
int test_transaction_lifecycle(FuzzCtx *pCtx, const PageMgmtPacket *pPacket);
int test_page_corruption_detection(FuzzCtx *pCtx, const PageMgmtPacket *pPacket);
int test_mixed_page_types(FuzzCtx *pCtx, const PageMgmtPacket *pPacket);

#endif /* PAGEMANAGEMENT_HARNESS_H */