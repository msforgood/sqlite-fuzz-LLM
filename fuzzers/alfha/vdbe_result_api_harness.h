/*
** VDBE Result API Functions Harness Header
** Target functions: sqlite3_result_text16, sqlite3_result_zeroblob64, sqlite3_stmt_scanstatus
** High complexity VDBE result and status functions
*/
#ifndef VDBE_RESULT_API_HARNESS_H
#define VDBE_RESULT_API_HARNESS_H

#include "fuzz.h"

/* Packet structures for VDBE result API functions */
typedef struct ResultText16Packet {
    uint32_t textLength;
    uint8_t  encoding;
    uint8_t  deleterType;
    uint8_t  scenario;
    uint8_t  flags;
    char     textData[256];
} ResultText16Packet;

typedef struct ResultZeroblob64Packet {
    uint64_t blobSize;
    uint16_t sizeMultiplier;
    uint8_t  scenario;
    uint8_t  flags;
    uint32_t testPattern;
} ResultZeroblob64Packet;

typedef struct StmtScanstatusPacket {
    uint32_t scanIndex;
    uint32_t statusOperation;
    uint8_t  outputType;
    uint8_t  scenario;
    uint16_t flags;
    uint32_t testData[8];
} StmtScanstatusPacket;

/* Function prototypes */
int fuzz_result_text16(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_result_zeroblob64(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_stmt_scanstatus(FuzzCtx *ctx, const uint8_t *data, size_t size);

#endif /* VDBE_RESULT_API_HARNESS_H */