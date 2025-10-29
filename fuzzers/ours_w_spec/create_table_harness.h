/*
** Create Table Harness Header
** Target: btreeCreateTable function (btree.c:10015)
** Focus: Table creation and page allocation
*/
#ifndef CREATE_TABLE_HARNESS_H
#define CREATE_TABLE_HARNESS_H

#include "fuzz.h"

/* Create table test scenarios */
#define CREATE_SCENARIO_BASIC    0x01
#define CREATE_SCENARIO_INTKEY   0x02
#define CREATE_SCENARIO_INDEX    0x03
#define CREATE_SCENARIO_STRESS   0x04
#define CREATE_SCENARIO_FULL     0x05

/* Function declarations */
void fuzz_create_table(FuzzCtx *pCtx, const CreateTablePacket *pPacket);

#endif /* CREATE_TABLE_HARNESS_H */