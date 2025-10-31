#ifndef VDBE_API_BATCH_HARNESS_H
#define VDBE_API_BATCH_HARNESS_H

#include "fuzz.h"

// Function declarations for VDBE API batch harness
int test_batch_vdbe_api_functions(const uint8_t *data, size_t size);

#endif // VDBE_API_BATCH_HARNESS_H