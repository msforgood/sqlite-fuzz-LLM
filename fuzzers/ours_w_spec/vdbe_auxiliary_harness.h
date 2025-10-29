/*
** VDBE Auxiliary Functions Harness Header
** Targets: checkActiveVdbeCnt, sqlite3VdbeAddFunctionCall, sqlite3VdbeAddOp4, sqlite3VdbeAddOp4Dup8
** Enhanced coverage for VDBE auxiliary operations
*/
#ifndef VDBE_AUXILIARY_HARNESS_H
#define VDBE_AUXILIARY_HARNESS_H

#include "fuzz.h"

/* VDBE auxiliary fuzzing modes */
#define FUZZ_MODE_VDBE_CHECK_ACTIVE_CNT    43  /* checkActiveVdbeCnt */
#define FUZZ_MODE_VDBE_ADD_FUNCTION_CALL   44  /* sqlite3VdbeAddFunctionCall */
#define FUZZ_MODE_VDBE_ADD_OP4             45  /* sqlite3VdbeAddOp4 */
#define FUZZ_MODE_VDBE_ADD_OP4_DUP8        46  /* sqlite3VdbeAddOp4Dup8 */

/* Test scenarios for VDBE auxiliary operations */
#define VDBE_AUX_SCENARIO_NORMAL        0x01  /* Normal operation */
#define VDBE_AUX_SCENARIO_COMPLEX       0x02  /* Complex SQL statements */
#define VDBE_AUX_SCENARIO_MULTI_STMT    0x03  /* Multiple statements */
#define VDBE_AUX_SCENARIO_FUNCTIONS     0x04  /* Function calls */
#define VDBE_AUX_SCENARIO_OPCODES       0x05  /* Various opcodes */
#define VDBE_AUX_SCENARIO_MEMORY        0x06  /* Memory pressure */
#define VDBE_AUX_SCENARIO_CORRUPTION    0x07  /* Corruption testing */
#define VDBE_AUX_SCENARIO_BOUNDARY      0x08  /* Boundary conditions */

/* Common VDBE opcodes for testing */
#define VDBE_OP_NOOP         0
#define VDBE_OP_EXPLAIN      1
#define VDBE_OP_FUNCTION     62
#define VDBE_OP_INT64        63
#define VDBE_OP_BLOB         126
#define VDBE_OP_STRING8      144

/* Input packet for checkActiveVdbeCnt fuzzing */
typedef struct VdbeCheckActiveCntPacket {
  uint8_t scenario;          /* Test scenario selector */
  uint8_t vdbeCount;         /* Number of VDBEs to create */
  uint8_t activeCount;       /* Expected active count */
  uint8_t readCount;         /* Expected read count */
  uint8_t writeCount;        /* Expected write count */
  uint32_t corruption_flags; /* Corruption pattern */
  uint8_t testData[16];      /* Test parameters */
} VdbeCheckActiveCntPacket;

/* Input packet for sqlite3VdbeAddFunctionCall fuzzing */
typedef struct VdbeAddFunctionCallPacket {
  uint8_t scenario;          /* Test scenario selector */
  uint8_t argCount;          /* Function argument count */
  uint16_t constantMask;     /* Constant argument mask */
  uint16_t firstArg;         /* First argument register */
  uint16_t resultReg;        /* Result register */
  uint32_t funcFlags;        /* Function flags */
  int32_t auxData;           /* Auxiliary data index */
  uint32_t corruption_flags; /* Corruption pattern */
  uint8_t testData[12];      /* Test parameters */
} VdbeAddFunctionCallPacket;

/* Input packet for sqlite3VdbeAddOp4 fuzzing */
typedef struct VdbeAddOp4Packet {
  uint8_t scenario;          /* Test scenario selector */
  uint8_t opcode;            /* VDBE opcode */
  int16_t p1;                /* P1 operand */
  int16_t p2;                /* P2 operand */
  int16_t p3;                /* P3 operand */
  uint8_t p4Type;            /* P4 parameter type */
  uint16_t stringLength;     /* String length for P4 */
  uint32_t corruption_flags; /* Corruption pattern */
  uint8_t testData[16];      /* Test string data */
} VdbeAddOp4Packet;

/* Input packet for sqlite3VdbeAddOp4Dup8 fuzzing */
typedef struct VdbeAddOp4Dup8Packet {
  uint8_t scenario;          /* Test scenario selector */
  uint8_t opcode;            /* VDBE opcode */
  int16_t p1;                /* P1 operand */
  int16_t p2;                /* P2 operand */
  int16_t p3;                /* P3 operand */
  uint8_t p4Type;            /* P4 parameter type */
  uint64_t data8;            /* 8-byte data for duplication */
  uint32_t corruption_flags; /* Corruption pattern */
  uint8_t testData[8];       /* Additional test parameters */
} VdbeAddOp4Dup8Packet;

/* Function declarations for VDBE auxiliary fuzzing */
int fuzz_vdbe_check_active_cnt(FuzzCtx *pCtx, const VdbeCheckActiveCntPacket *pPacket);
int fuzz_vdbe_add_function_call(FuzzCtx *pCtx, const VdbeAddFunctionCallPacket *pPacket);
int fuzz_vdbe_add_op4(FuzzCtx *pCtx, const VdbeAddOp4Packet *pPacket);
int fuzz_vdbe_add_op4_dup8(FuzzCtx *pCtx, const VdbeAddOp4Dup8Packet *pPacket);

#endif /* VDBE_AUXILIARY_HARNESS_H */