#ifndef BTREE_MUTEX_BATCH_HARNESS_H
#define BTREE_MUTEX_BATCH_HARNESS_H

#include "fuzz.h"

// Function declarations for batch mutex operations harness
int test_batch_btree_mutex_functions(const uint8_t *data, size_t size);

#endif // BTREE_MUTEX_BATCH_HARNESS_H