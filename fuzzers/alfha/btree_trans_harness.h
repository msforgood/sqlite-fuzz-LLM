/*
** B-Tree Transaction Harness Header
** Target: btreeBeginTrans function (btree.c:3594)
** Focus: Transaction state management and validation
*/
#ifndef BTREE_TRANS_HARNESS_H
#define BTREE_TRANS_HARNESS_H

#include "fuzz.h"

/* Transaction test scenarios */
#define TRANS_SCENARIO_BASIC     0x01
#define TRANS_SCENARIO_NESTED    0x02
#define TRANS_SCENARIO_READONLY  0x03
#define TRANS_SCENARIO_CORRUPT   0x04
#define TRANS_SCENARIO_BUSY      0x05

/* Function declarations */
void fuzz_btree_transaction(FuzzCtx *pCtx, const BtreeTransPacket *pPacket);

#endif /* BTREE_TRANS_HARNESS_H */