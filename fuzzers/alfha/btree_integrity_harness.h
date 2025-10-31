#ifndef BTREE_INTEGRITY_HARNESS_H
#define BTREE_INTEGRITY_HARNESS_H

#include "fuzz.h"

// Function declarations for B-Tree integrity check harness
int test_sqlite3BtreeIntegrityCheck(const uint8_t *data, size_t size);

#endif // BTREE_INTEGRITY_HARNESS_H