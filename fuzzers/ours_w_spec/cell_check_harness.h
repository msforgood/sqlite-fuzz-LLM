/*
** Cell Size Check Harness Header
** Target: btreeCellSizeCheck function (btree.c:2173)
** Focus: Cell integrity validation and corruption detection
*/
#ifndef CELL_CHECK_HARNESS_H
#define CELL_CHECK_HARNESS_H

#include "fuzz.h"

/* Cell check test scenarios */
#define CELL_SCENARIO_VALID      0x01
#define CELL_SCENARIO_OVERLAP    0x02
#define CELL_SCENARIO_OVERRUN    0x03
#define CELL_SCENARIO_UNDERRUN   0x04
#define CELL_SCENARIO_CORRUPT    0x05

/* Function declarations */
void fuzz_cell_size_check(FuzzCtx *pCtx, const CellCheckPacket *pPacket);

#endif /* CELL_CHECK_HARNESS_H */