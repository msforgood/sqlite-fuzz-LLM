/*
** VDBE Value API Functions Harness Header
** Target functions: sqlite3_value_bytes16, sqlite3_value_nochange, sqlite3_vtab_in_first
** High priority VDBE API interface functions for value operations
*/
#ifndef VDBE_VALUE_API_HARNESS_H
#define VDBE_VALUE_API_HARNESS_H

#include "fuzz.h"

/* Packet structures for VDBE value API functions */
typedef struct ValueBytes16Packet {
    uint8_t  valueType;
    uint16_t textLength;
    uint8_t  encoding;
    uint16_t flags;
    uint8_t  scenario;
    char     testData[64];
} ValueBytes16Packet;

typedef struct ValueNochangePacket {
    uint16_t flags;
    uint8_t  flagsCombination;
    uint16_t nullZeroMask;
    uint8_t  scenario;
    uint32_t testFlags;
    uint8_t  testData[32];
} ValueNochangePacket;

typedef struct VtabInFirstPacket {
    uint16_t valueListSize;
    uint8_t  iteratorPosition;
    uint8_t  valueType;
    uint8_t  scenario;
    uint8_t  padding;
    char     valueData[128];
} VtabInFirstPacket;

/* Function prototypes */
int fuzz_value_bytes16(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_value_nochange(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_vtab_in_first(FuzzCtx *ctx, const uint8_t *data, size_t size);

#endif /* VDBE_VALUE_API_HARNESS_H */