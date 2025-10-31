#ifndef BTREE_CURSOR_RESTORE_HARNESS_H
#define BTREE_CURSOR_RESTORE_HARNESS_H

#include "fuzz.h"

// Function declarations for B-Tree cursor restore harness
int test_sqlite3BtreeCursorRestore(const uint8_t *data, size_t size);

#endif // BTREE_CURSOR_RESTORE_HARNESS_H