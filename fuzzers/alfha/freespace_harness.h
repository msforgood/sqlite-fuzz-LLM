/*
** FreeSpace Harness Header
** Target: btreeComputeFreeSpace function (btree.c:2091)
** Enhanced coverage for B-Tree free space computation
*/
#ifndef FREESPACE_HARNESS_H
#define FREESPACE_HARNESS_H

#include "fuzz.h"

/* Free space computation test scenarios */
#define FREESPACE_SCENARIO_NORMAL       0x01  /* Normal free space calculation */
#define FREESPACE_SCENARIO_CORRUPTION   0x02  /* Corrupted freeblock chains */
#define FREESPACE_SCENARIO_OVERLAP      0x03  /* Overlapping freeblocks */
#define FREESPACE_SCENARIO_BOUNDARY     0x04  /* Boundary condition testing */
#define FREESPACE_SCENARIO_FRAGMENTED   0x05  /* Highly fragmented pages */
#define FREESPACE_SCENARIO_EMPTY        0x06  /* Empty or nearly empty pages */
#define FREESPACE_SCENARIO_FULL         0x07  /* Full or nearly full pages */
#define FREESPACE_SCENARIO_INVALID      0x08  /* Invalid header data */

/* Page types for testing */
#define PAGE_TYPE_LEAF_TABLE     0
#define PAGE_TYPE_INTERIOR_TABLE 1
#define PAGE_TYPE_LEAF_INDEX     2
#define PAGE_TYPE_INTERIOR_INDEX 3

/* Corruption patterns */
#define CORRUPT_FREEBLOCK_CHAIN   0x01
#define CORRUPT_HEADER_OFFSETS    0x02
#define CORRUPT_CELL_CONTENT      0x04
#define CORRUPT_SIZE_OVERFLOW     0x08
#define CORRUPT_NEGATIVE_FREE     0x10

/* Input packet structure for btreeComputeFreeSpace fuzzing */
typedef struct FreeSpacePacket {
  uint8_t scenario;          /* Test scenario selector */
  uint8_t pageType;          /* Page type (leaf/interior, table/index) */
  uint16_t pageSize;         /* Page size selector */
  uint16_t cellCount;        /* Number of cells on page */
  uint16_t freeblockCount;   /* Number of freeblocks */
  uint32_t corruptionMask;   /* Corruption pattern mask */
  uint16_t cellSizes[16];    /* Cell sizes for layout */
  uint8_t testData[16];      /* Additional test parameters */
} FreeSpacePacket;

/* Function declarations for free space fuzzing */
void fuzz_freespace_computation(FuzzCtx *pCtx, const FreeSpacePacket *pPacket);
int setup_freespace_database(FuzzCtx *pCtx, const FreeSpacePacket *pPacket);
int create_test_page_layout(FuzzCtx *pCtx, const FreeSpacePacket *pPacket);
int inject_freeblock_corruption(FuzzCtx *pCtx, const FreeSpacePacket *pPacket);
int test_boundary_conditions(FuzzCtx *pCtx, const FreeSpacePacket *pPacket);
int test_fragmentation_scenarios(FuzzCtx *pCtx, const FreeSpacePacket *pPacket);
int validate_freespace_calculation(FuzzCtx *pCtx, const FreeSpacePacket *pPacket);

#endif /* FREESPACE_HARNESS_H */