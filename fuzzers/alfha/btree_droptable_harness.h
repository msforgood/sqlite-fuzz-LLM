#ifndef BTREE_DROPTABLE_HARNESS_H
#define BTREE_DROPTABLE_HARNESS_H

#include "fuzz.h"

// Function declarations for btree drop table harness
int test_sqlite3BtreeDropTable(const uint8_t *data, size_t size);

#endif // BTREE_DROPTABLE_HARNESS_H