#ifndef BTREE_COMMITPHASE2_HARNESS_H
#define BTREE_COMMITPHASE2_HARNESS_H

#include "fuzz.h"

// Function declarations for B-Tree commit phase two harness
int test_sqlite3BtreeCommitPhaseTwo(const uint8_t *data, size_t size);

#endif // BTREE_COMMITPHASE2_HARNESS_H