#ifndef BTREE_PAGESIZE_HARNESS_H
#define BTREE_PAGESIZE_HARNESS_H

#include "fuzz.h"

// Function declarations for B-Tree page size configuration harness
int test_sqlite3BtreeSetPageSize(const uint8_t *data, size_t size);

#endif // BTREE_PAGESIZE_HARNESS_H