/*
** Table/Cursor Management Harness Header
** Targets: btreeCreateTable, btreeDropTable, btreeCursor, btreeCursorWithLock
** Enhanced coverage for B-Tree table and cursor operations
*/
#ifndef TABLECURSOR_HARNESS_H
#define TABLECURSOR_HARNESS_H

#include "fuzz.h"

/* Table/Cursor management test scenarios */
#define TABLECURSOR_SCENARIO_NORMAL          0x01  /* Normal table/cursor operations */
#define TABLECURSOR_SCENARIO_LIFECYCLE       0x02  /* Complete table lifecycle */
#define TABLECURSOR_SCENARIO_CONCURRENT      0x03  /* Multiple cursors and tables */
#define TABLECURSOR_SCENARIO_LOCKING         0x04  /* Shared cache locking */
#define TABLECURSOR_SCENARIO_AUTOVACUUM      0x05  /* Auto-vacuum interactions */
#define TABLECURSOR_SCENARIO_CORRUPTION      0x06  /* Error and corruption handling */
#define TABLECURSOR_SCENARIO_STRESS          0x07  /* High load scenarios */
#define TABLECURSOR_SCENARIO_COMPREHENSIVE   0x08  /* All scenarios combined */

/* Table creation flags */
#define CREATE_TABLE_INTKEY      0x01  /* BTREE_INTKEY */
#define CREATE_TABLE_LEAFDATA    0x02  /* BTREE_LEAFDATA */
#define CREATE_TABLE_ZERODATA    0x04  /* BTREE_ZERODATA */

/* Cursor access patterns */
#define CURSOR_READ_ONLY         0x00
#define CURSOR_WRITE             0x01  /* BTREE_WRCSR */
#define CURSOR_FORDELETE         0x02  /* BTREE_FORDELETE */

/* Input packet structure for table/cursor management fuzzing */
typedef struct TableCursorPacket {
  uint8_t scenario;          /* Test scenario selector */
  uint8_t tableCount;        /* Number of tables to create */
  uint8_t cursorCount;       /* Number of cursors per table */
  uint8_t createFlags;       /* Table creation flags */
  uint16_t operationCount;   /* Number of operations to perform */
  uint16_t pageSize;         /* Page size selector */
  uint32_t tableIds[8];      /* Table IDs for operations */
  uint8_t cursorFlags[8];    /* Cursor flags for each operation */
  uint32_t corruptionMask;   /* Corruption pattern mask */
  uint8_t testData[32];      /* Additional test parameters */
} TableCursorPacket;

/* Function declarations for table/cursor management fuzzing */
void fuzz_table_cursor_management(FuzzCtx *pCtx, const TableCursorPacket *pPacket);
int setup_tablecursor_database(FuzzCtx *pCtx, const TableCursorPacket *pPacket);
int test_table_lifecycle(FuzzCtx *pCtx, const TableCursorPacket *pPacket);
int test_cursor_operations(FuzzCtx *pCtx, const TableCursorPacket *pPacket);
int test_concurrent_access(FuzzCtx *pCtx, const TableCursorPacket *pPacket);
int test_locking_scenarios(FuzzCtx *pCtx, const TableCursorPacket *pPacket);
int test_autovacuum_interactions(FuzzCtx *pCtx, const TableCursorPacket *pPacket);
int test_error_conditions(FuzzCtx *pCtx, const TableCursorPacket *pPacket);
int stress_test_operations(FuzzCtx *pCtx, const TableCursorPacket *pPacket);

#endif /* TABLECURSOR_HARNESS_H */