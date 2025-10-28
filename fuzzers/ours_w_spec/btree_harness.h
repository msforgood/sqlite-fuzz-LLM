/*
** B-Tree Allocation Fuzzing Harness Header
** Target: allocateBtreePage function (btree.c:6475)
*/
#ifndef BTREE_HARNESS_H
#define BTREE_HARNESS_H

#include "fuzz.h"

/* B-Tree harness function declarations */
void generate_btree_sql(char *zSql, size_t sqlSize, const BtreeAllocPacket *pPacket);
int setup_btree_environment(FuzzCtx *pCtx, const BtreeAllocPacket *pPacket);
int test_freelist_scenarios(FuzzCtx *pCtx, const BtreeAllocPacket *pPacket);
int test_memory_stress(FuzzCtx *pCtx, const BtreeAllocPacket *pPacket);
int test_corruption_detection(FuzzCtx *pCtx, const BtreeAllocPacket *pPacket);
int fuzz_btree_allocation(FuzzCtx *pCtx, const BtreeAllocPacket *pPacket);

#endif /* BTREE_HARNESS_H */