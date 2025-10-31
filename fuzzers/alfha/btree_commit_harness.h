#ifndef BTREE_COMMIT_HARNESS_H
#define BTREE_COMMIT_HARNESS_H

#include "fuzz.h"

// Function declarations for btree commit phase harness
int test_sqlite3BtreeCommitPhaseOne(const uint8_t *data, size_t size);

#endif // BTREE_COMMIT_HARNESS_H