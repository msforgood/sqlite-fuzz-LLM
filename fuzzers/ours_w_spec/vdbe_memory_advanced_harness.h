/*
** VDBE Memory Advanced Functions Harness Header
** Target functions: sqlite3VdbeMemSetZeroBlob, sqlite3VdbeMemShallowCopy, sqlite3VdbeMemStringify, sqlite3VdbeMemValidStrRep
** Specification-based fuzzing for VDBE memory operations
*/
#ifndef VDBE_MEMORY_ADVANCED_HARNESS_H
#define VDBE_MEMORY_ADVANCED_HARNESS_H

#include "fuzz.h"

/* VDBE Memory fuzzing test scenarios */
#define MEMORY_SCENARIO_NORMAL          0x01  /* Normal operation */
#define MEMORY_SCENARIO_ZERO_SIZE       0x02  /* Zero or small size operations */
#define MEMORY_SCENARIO_LARGE_ALLOC     0x03  /* Large allocation scenarios */
#define MEMORY_SCENARIO_MEMORY_PRESSURE 0x04  /* Memory pressure conditions */
#define MEMORY_SCENARIO_ENCODING_EDGE   0x05  /* Character encoding edge cases */
#define MEMORY_SCENARIO_FLAG_EDGE       0x06  /* Memory flag edge cases */
#define MEMORY_SCENARIO_CORRUPTION      0x07  /* Corruption simulation */
#define MEMORY_SCENARIO_BOUNDARY        0x08  /* Boundary condition testing */

/* Memory flag constants */
#ifndef MEM_Null
#define MEM_Null      0x0001   /* Value is NULL */
#define MEM_Str       0x0002   /* Value is a string */
#define MEM_Int       0x0004   /* Value is an integer */
#define MEM_Real      0x0008   /* Value is a real number */
#define MEM_Blob      0x0010   /* Value is a BLOB */
#define MEM_AffMask   0x001f   /* Mask of affinity bits */
#define MEM_FromBind  0x0020   /* Value originates from sqlite3_bind_xxx() */
#define MEM_Undefined 0x0080   /* Value is undefined */
#define MEM_Cleared   0x0100   /* NULL set by OP_Null, not from data */
#define MEM_TypeMask  0x81ff   /* Combined type mask */
#define MEM_Term      0x0200   /* String is zero terminated */
#define MEM_Dyn       0x0400   /* Need to call Mem.xDel() on Mem.z */
#define MEM_Static    0x0800   /* Mem.z points to a static string */
#define MEM_Ephem     0x1000   /* Mem.z points to an ephemeral string */
#define MEM_Agg       0x2000   /* Mem.z points to an agg function context */
#define MEM_Zero      0x4000   /* Mem.i contains count of 0s appended to blob */
#define MEM_IntReal   0x8000   /* MEM_Int that stringifies as MEM_Real */
#endif

/* Text encoding constants */
#define SQLITE_UTF8     1
#define SQLITE_UTF16LE  2
#define SQLITE_UTF16BE  3
#define SQLITE_UTF16    4

/* Input packet for sqlite3VdbeMemSetZeroBlob fuzzing */
typedef struct MemSetZeroBlobPacket {
  uint8_t scenario;              /* Test scenario selector */
  uint8_t size_mode;             /* Size determination mode */
  uint16_t flags;                /* Memory flags to set */
  uint32_t blob_size;            /* Zero blob size */
  uint32_t corruption_flags;     /* Corruption pattern */
  uint8_t testData[16];          /* Additional test parameters */
} MemSetZeroBlobPacket;

/* Input packet for sqlite3VdbeMemShallowCopy fuzzing */
typedef struct MemShallowCopyPacket {
  uint8_t scenario;              /* Test scenario selector */
  uint8_t src_type;              /* Source memory type */
  uint16_t src_flags;            /* Source memory flags */
  uint16_t dst_flags;            /* Destination memory flags */
  uint8_t copy_type;             /* Copy type (MEM_Ephem/MEM_Static) */
  uint32_t data_size;            /* Size of data to copy */
  uint32_t corruption_flags;     /* Corruption pattern */
  uint8_t testData[20];          /* Test content data */
} MemShallowCopyPacket;

/* Input packet for sqlite3VdbeMemStringify fuzzing */
typedef struct MemStringifyPacket {
  uint8_t scenario;              /* Test scenario selector */
  uint8_t encoding;              /* Text encoding type */
  uint8_t force_flag;            /* Force conversion flag */
  uint8_t value_type;            /* Numeric value type */
  uint16_t mem_flags;            /* Memory flags */
  uint32_t int_value;            /* Integer value for conversion */
  uint32_t corruption_flags;     /* Corruption pattern */
  double real_value;             /* Real value for conversion */
  uint8_t testData[12];          /* Additional test data */
} MemStringifyPacket;

/* Input packet for sqlite3VdbeMemValidStrRep fuzzing */
typedef struct MemValidStrRepPacket {
  uint8_t scenario;              /* Test scenario selector */
  uint8_t encoding;              /* String encoding */
  uint16_t str_flags;            /* String-related flags */
  uint16_t str_length;           /* String length */
  uint8_t termination;           /* Termination pattern */
  uint32_t malloc_size;          /* Malloc size simulation */
  uint32_t corruption_flags;     /* Corruption pattern */
  uint8_t stringData[24];        /* String content data */
} MemValidStrRepPacket;

/* Function declarations for VDBE memory advanced fuzzing */
void fuzz_vdbe_mem_set_zero_blob(FuzzCtx *pCtx, const MemSetZeroBlobPacket *pPacket);
void fuzz_vdbe_mem_shallow_copy(FuzzCtx *pCtx, const MemShallowCopyPacket *pPacket);
void fuzz_vdbe_mem_stringify(FuzzCtx *pCtx, const MemStringifyPacket *pPacket);
void fuzz_vdbe_mem_valid_str_rep(FuzzCtx *pCtx, const MemValidStrRepPacket *pPacket);

#endif /* VDBE_MEMORY_ADVANCED_HARNESS_H */