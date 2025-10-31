/*
** VDBE Auxiliary Extended Functions Harness Header
** Target functions: columnMallocFailure, freeP4, vdbeAssertFieldCountWithinLimits
** Specification-based fuzzing for VDBE auxiliary operations
*/
#ifndef VDBE_AUXILIARY_EXTENDED_HARNESS_H
#define VDBE_AUXILIARY_EXTENDED_HARNESS_H

#include "fuzz.h"

/* Function declarations for VDBE auxiliary extended fuzzing */
void fuzz_column_malloc_failure(FuzzCtx *pCtx, const ColumnMallocFailurePacket *pPacket);
void fuzz_free_p4(FuzzCtx *pCtx, const FreeP4Packet *pPacket);
void fuzz_assert_field_count(FuzzCtx *pCtx, const AssertFieldCountPacket *pPacket);

#endif /* VDBE_AUXILIARY_EXTENDED_HARNESS_H */