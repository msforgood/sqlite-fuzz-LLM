/*
** VDBE Record Functions Harness Header
** Target functions: vdbeRecordCompareDebug, vdbeRecordCompareString, vdbeRecordCompareInt, vdbeRecordDecodeInt
** Specification-based fuzzing for VDBE record operations
*/
#ifndef VDBE_RECORD_HARNESS_H
#define VDBE_RECORD_HARNESS_H

#include "fuzz.h"

/* VDBE Record fuzzing test scenarios */
#define RECORD_SCENARIO_NORMAL          0x01  /* Normal operation */
#define RECORD_SCENARIO_EMPTY_RECORD    0x02  /* Empty record edge cases */
#define RECORD_SCENARIO_LARGE_RECORD    0x03  /* Large record handling */
#define RECORD_SCENARIO_INVALID_SERIAL  0x04  /* Invalid serial types */
#define RECORD_SCENARIO_ENCODING_EDGE   0x05  /* Character encoding edge cases */
#define RECORD_SCENARIO_CORRUPTION      0x06  /* Corruption simulation */
#define RECORD_SCENARIO_MEMORY_PRESSURE 0x07  /* Memory pressure conditions */
#define RECORD_SCENARIO_COLLATION_HEAVY 0x08  /* Heavy collation scenarios */

/* Serial type constants for SQLite records */
#define SERIAL_TYPE_NULL       0
#define SERIAL_TYPE_INT8       1
#define SERIAL_TYPE_INT16      2
#define SERIAL_TYPE_INT24      3
#define SERIAL_TYPE_INT32      4
#define SERIAL_TYPE_INT48      5
#define SERIAL_TYPE_INT64      6
#define SERIAL_TYPE_FLOAT64    7
#define SERIAL_TYPE_ZERO       8
#define SERIAL_TYPE_ONE        9
#define SERIAL_TYPE_BLOB_EVEN  10
#define SERIAL_TYPE_BLOB_ODD   11
#define SERIAL_TYPE_STRING     12  /* Base for string types */

/* Memory flags for VDBE Mem structure */
#define MEM_Null      0x0001   /* Value is NULL (or uninitialized) */
#define MEM_Str       0x0002   /* Value is a string */
#define MEM_Int       0x0004   /* Value is an integer */
#define MEM_Real      0x0008   /* Value is a real number */
#define MEM_Blob      0x0010   /* Value is a BLOB */
#define MEM_AffMask   0x001f   /* Mask of affinity bits */
#define MEM_FromBind  0x0020   /* Value originates from sqlite3_bind_xxx() */
#define MEM_Undefined 0x0080   /* Value is undefined */
#define MEM_Cleared   0x0100   /* NULL set by OP_Null, not from data */
#define MEM_TypeMask  0x81ff   /* Combined MEM_Null, MEM_Str, MEM_Int, MEM_Real, MEM_Blob, MEM_Undefined */
#define MEM_Term      0x0200   /* String in Mem structure is zero terminated */
#define MEM_Dyn       0x0400   /* Need to call Mem.xDel() on Mem.z */
#define MEM_Static    0x0800   /* Mem.z points to a static string */
#define MEM_Ephem     0x1000   /* Mem.z points to an ephemeral string */
#define MEM_Agg       0x2000   /* Mem.z points to an agg function context */
#define MEM_Zero      0x4000   /* Mem.i contains count of 0s appended to blob */

/* Input packet for vdbeRecordCompareDebug fuzzing */
typedef struct RecordCompareDebugPacket {
  uint8_t scenario;              /* Test scenario selector */
  uint8_t desiredResult;         /* Expected comparison result (-1, 0, 1) */
  uint16_t nKey1;                /* Size of key1 data */
  uint16_t nFields;              /* Number of fields in unpacked record */
  uint8_t encoding;              /* Text encoding type */
  uint8_t fieldTypes[8];         /* Serial types for fields */
  uint32_t corruption_flags;     /* Corruption pattern */
  uint8_t keyData[32];           /* Key record data */
} RecordCompareDebugPacket;

/* Input packet for vdbeRecordCompareString fuzzing */
typedef struct RecordCompareStringPacket {
  uint8_t scenario;              /* Test scenario selector */
  uint8_t serialType;            /* String serial type */
  uint16_t nKey1;                /* Size of key1 data */
  uint16_t stringLength;         /* String length */
  uint8_t encoding;              /* Text encoding type */
  uint8_t collationFlags;        /* Collation sequence flags */
  uint32_t memFlags;             /* Memory flags for string */
  uint32_t corruption_flags;     /* Corruption pattern */
  uint8_t stringData[24];        /* String content data */
} RecordCompareStringPacket;

/* Input packet for vdbeRecordCompareInt fuzzing */
typedef struct RecordCompareIntPacket {
  uint8_t scenario;              /* Test scenario selector */
  uint8_t serialType;            /* Integer serial type (1-9, not 7) */
  uint16_t nKey1;                /* Size of key1 data */
  uint8_t headerByte;            /* Record header byte */
  uint8_t integerSize;           /* Integer size in bytes */
  uint16_t memFlags;             /* Memory flags for integer */
  uint32_t corruption_flags;     /* Corruption pattern */
  uint8_t intData[16];           /* Integer data bytes */
} RecordCompareIntPacket;

/* Input packet for vdbeRecordDecodeInt fuzzing */
typedef struct RecordDecodeIntPacket {
  uint8_t scenario;              /* Test scenario selector */
  uint8_t serialType;            /* Serial type for integer */
  uint8_t dataSize;              /* Size of integer data */
  uint8_t signTest;              /* Sign bit test pattern */
  uint32_t corruption_flags;     /* Corruption pattern */
  uint8_t testData[16];          /* Integer test data */
} RecordDecodeIntPacket;

/* Function declarations for VDBE record fuzzing */
void fuzz_vdbe_record_compare_debug(FuzzCtx *pCtx, const RecordCompareDebugPacket *pPacket);
void fuzz_vdbe_record_compare_string(FuzzCtx *pCtx, const RecordCompareStringPacket *pPacket);
void fuzz_vdbe_record_compare_int(FuzzCtx *pCtx, const RecordCompareIntPacket *pPacket);
void fuzz_vdbe_record_decode_int(FuzzCtx *pCtx, const RecordDecodeIntPacket *pPacket);

#endif /* VDBE_RECORD_HARNESS_H */