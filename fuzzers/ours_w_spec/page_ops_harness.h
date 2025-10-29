/*
** Page Operations Harness Header
** Target: freePage, clearDatabasePage, defragmentPage, sqlite3BtreeCloseCursor
** Specification-based fuzzing implementation
*/

#ifndef PAGE_OPS_HARNESS_H
#define PAGE_OPS_HARNESS_H

#include "fuzz.h"

/* Fuzzing mode values for page operations */
#define FUZZ_MODE_FREE_PAGE      0x10  /* Target freePage specifically */
#define FUZZ_MODE_CLEAR_PAGE     0x11  /* Target clearDatabasePage specifically */
#define FUZZ_MODE_DEFRAG_PAGE    0x12  /* Target defragmentPage specifically */
#define FUZZ_MODE_CLOSE_CURSOR   0x13  /* Target sqlite3BtreeCloseCursor specifically */

/* Input packet structure for freePage fuzzing */
typedef struct FreePagePacket {
  uint8_t mode;              /* Fuzzing mode selector */
  uint8_t errorScenario;     /* Error injection scenario */
  uint16_t pageType;         /* Page type for test setup */
  uint32_t targetPgno;       /* Page number to free */
  uint32_t cellCount;        /* Number of cells to create before free */
  uint32_t corruptionMask;   /* Corruption pattern mask */
  uint8_t testData[16];      /* Additional test parameters */
} FreePagePacket;

/* Input packet structure for clearDatabasePage fuzzing */
typedef struct ClearPagePacket {
  uint8_t mode;              /* Fuzzing mode selector */
  uint8_t freeFlag;          /* Free flag parameter */
  uint16_t pageType;         /* Page type to clear */
  uint32_t targetPgno;       /* Page number to clear */
  uint32_t cellData;         /* Initial cell data pattern */
  uint32_t corruptionOffset; /* Offset for corruption injection */
  uint8_t testData[16];      /* Additional test parameters */
} ClearPagePacket;

/* Input packet structure for defragmentPage fuzzing */
typedef struct DefragPagePacket {
  uint8_t mode;              /* Fuzzing mode selector */
  uint8_t fragmentation;     /* Fragmentation level to create */
  uint16_t cursorHint;       /* Cursor hint parameter */
  uint32_t targetPgno;       /* Page number to defragment */
  uint32_t cellPattern;      /* Cell insertion pattern */
  uint32_t freeSpaceTarget;  /* Target free space amount */
  uint8_t testData[16];      /* Additional test parameters */
} DefragPagePacket;

/* Input packet structure for sqlite3BtreeCloseCursor fuzzing */
typedef struct CloseCursorPacket {
  uint8_t mode;              /* Fuzzing mode selector */
  uint8_t cursorState;       /* Initial cursor state */
  uint16_t keyType;          /* Key type for cursor setup */
  uint32_t rootPage;         /* Root page for cursor */
  uint32_t seekPosition;     /* Position to seek before close */
  uint32_t overflowPages;    /* Number of overflow pages to create */
  uint8_t testData[16];      /* Additional test parameters */
} CloseCursorPacket;

/* Function declarations */
int fuzz_free_page(const uint8_t *data, size_t size);
int fuzz_clear_database_page(const uint8_t *data, size_t size);
int fuzz_defragment_page(const uint8_t *data, size_t size);
int fuzz_close_cursor(const uint8_t *data, size_t size);

#endif /* PAGE_OPS_HARNESS_H */