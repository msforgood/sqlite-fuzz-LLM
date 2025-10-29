#ifndef VDBE_MEMORY_HARNESS_H
#define VDBE_MEMORY_HARNESS_H

#include "fuzz.h"

/* VDBE Memory Management Packet Headers */
typedef struct {
    uint8_t fuzzSelector;
    uint8_t expireMode;
    uint8_t vdbeCount;
    uint8_t flags;
    uint32_t expireCode;
    uint32_t corruptionMask;
    uint8_t testData[48];
} VdbeExpireStmtPacket;

typedef struct {
    uint8_t fuzzSelector;
    uint8_t probeMode;
    uint8_t fieldCount;
    uint8_t flags;
    uint32_t memorySize;
    uint32_t corruptionMask;
    uint8_t testData[48];
} VdbeStat4ProbePacket;

typedef struct {
    uint8_t fuzzSelector;
    uint8_t valueType;
    uint8_t memFlags;
    uint8_t flags;
    uint32_t valueSize;
    uint32_t corruptionMask;
    uint8_t testData[48];
} VdbeValueFreePacket;

typedef struct {
    uint8_t fuzzSelector;
    uint8_t funcFlags;
    uint8_t argCount;
    uint8_t flags;
    uint32_t nameLength;
    uint32_t corruptionMask;
    uint8_t testData[48];
} VdbeEphemeralFuncPacket;

/* VDBE Memory Fuzzing Modes */
#define FUZZ_MODE_VDBE_EXPIRE_STMT     35
#define FUZZ_MODE_VDBE_STAT4_PROBE     36
#define FUZZ_MODE_VDBE_VALUE_FREE      37
#define FUZZ_MODE_VDBE_EPHEMERAL_FUNC  38

/* Function declarations */
void fuzz_vdbe_expire_statements(FuzzCtx *pCtx, const VdbeExpireStmtPacket *pPacket);
void fuzz_vdbe_stat4_probe_free(FuzzCtx *pCtx, const VdbeStat4ProbePacket *pPacket);
void fuzz_vdbe_value_free(FuzzCtx *pCtx, const VdbeValueFreePacket *pPacket);
void fuzz_vdbe_ephemeral_function(FuzzCtx *pCtx, const VdbeEphemeralFuncPacket *pPacket);

#endif /* VDBE_MEMORY_HARNESS_H */