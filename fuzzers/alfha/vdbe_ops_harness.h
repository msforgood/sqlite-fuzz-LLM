/*
** VDBE Operations Harness Header
** Target: sqlite3VdbeDeleteAuxData, sqlite3VdbeSetNumCols, sqlite3VdbeMemMakeWriteable, sqlite3_value_free
** Specification-based fuzzing implementation
*/

#ifndef VDBE_OPS_HARNESS_H
#define VDBE_OPS_HARNESS_H

#include "fuzz.h"

/* Fuzzing mode values for VDBE operations */
#define FUZZ_MODE_DELETE_AUXDATA  0x14  /* Target sqlite3VdbeDeleteAuxData specifically */
#define FUZZ_MODE_SET_NUMCOLS     0x15  /* Target sqlite3VdbeSetNumCols specifically */
#define FUZZ_MODE_MEM_WRITEABLE   0x16  /* Target sqlite3VdbeMemMakeWriteable specifically */
#define FUZZ_MODE_VALUE_FREE      0x17  /* Target sqlite3_value_free specifically */

/* Input packet structure for sqlite3VdbeDeleteAuxData fuzzing */
typedef struct DeleteAuxDataPacket {
  uint8_t mode;              /* Fuzzing mode selector */
  uint8_t deletionMode;      /* Deletion mode (single/mask/all) */
  uint16_t opIndex;          /* Operation index */
  uint32_t maskValue;        /* Mask for selective deletion */
  uint32_t auxDataCount;     /* Number of aux data items to create */
  uint32_t corruptionSeed;   /* Corruption injection seed */
  uint8_t testData[16];      /* Additional test parameters */
} DeleteAuxDataPacket;

/* Input packet structure for sqlite3VdbeSetNumCols fuzzing */
typedef struct SetNumColsPacket {
  uint8_t mode;              /* Fuzzing mode selector */
  uint8_t encoding;          /* Column encoding type */
  uint16_t numCols;          /* Number of columns to set */
  uint32_t namePattern;      /* Column name generation pattern */
  uint32_t typePattern;      /* Column type pattern */
  uint32_t memoryLimit;      /* Memory allocation limit */
  uint8_t testData[16];      /* Additional test parameters */
} SetNumColsPacket;

/* Input packet structure for sqlite3VdbeMemMakeWriteable fuzzing */
typedef struct MemWriteablePacket {
  uint8_t mode;              /* Fuzzing mode selector */
  uint8_t memFlags;          /* Initial memory flags */
  uint16_t memSize;          /* Memory size to allocate */
  uint32_t contentPattern;   /* Content pattern for memory */
  uint32_t preserveFlag;     /* Whether to preserve content */
  uint32_t corruptionMask;   /* Corruption pattern mask */
  uint8_t testData[16];      /* Additional test parameters */
} MemWriteablePacket;

/* Input packet structure for sqlite3_value_free fuzzing */
typedef struct ValueFreePacket {
  uint8_t mode;              /* Fuzzing mode selector */
  uint8_t valueType;         /* Type of value to create and free */
  uint16_t valueSize;        /* Size of value data */
  uint32_t allocPattern;     /* Allocation pattern */
  uint32_t destructorTest;   /* Destructor testing flags */
  uint32_t freeScenario;     /* Free scenario selector */
  uint8_t testData[16];      /* Additional test parameters */
} ValueFreePacket;

/* Function declarations */
int fuzz_delete_auxdata(const uint8_t *data, size_t size);
int fuzz_set_numcols(const uint8_t *data, size_t size);
int fuzz_mem_writeable(const uint8_t *data, size_t size);
int fuzz_value_free(const uint8_t *data, size_t size);

#endif /* VDBE_OPS_HARNESS_H */