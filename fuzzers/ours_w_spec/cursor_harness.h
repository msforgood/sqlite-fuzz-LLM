/*
** Cursor Harness Header
** Target: btreeCursor function (btree.c:4661)
** Focus: B-Tree cursor creation and management
*/
#ifndef CURSOR_HARNESS_H
#define CURSOR_HARNESS_H

#include "fuzz.h"

/* Cursor test scenarios */
#define CURSOR_SCENARIO_BASIC     0x01
#define CURSOR_SCENARIO_READONLY  0x02
#define CURSOR_SCENARIO_WRITE     0x03
#define CURSOR_SCENARIO_FORDELETE 0x04
#define CURSOR_SCENARIO_KEYINFO   0x05
#define CURSOR_SCENARIO_STRESS    0x06

/* Function declarations */
void fuzz_cursor_operations(FuzzCtx *pCtx, const CursorPacket *pPacket);

#endif /* CURSOR_HARNESS_H */