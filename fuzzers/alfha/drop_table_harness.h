/*
** Drop Table Harness Header
** Target: btreeDropTable function (btree.c:10289)
** Focus: Table deletion and page management
*/
#ifndef DROP_TABLE_HARNESS_H
#define DROP_TABLE_HARNESS_H

#include "fuzz.h"

/* Drop table test scenarios */
#define DROP_SCENARIO_BASIC     0x01
#define DROP_SCENARIO_MULTIPLE  0x02
#define DROP_SCENARIO_INDEXED   0x03
#define DROP_SCENARIO_LARGE     0x04
#define DROP_SCENARIO_PARTIAL   0x05
#define DROP_SCENARIO_CASCADE   0x06

/* Function declarations */
void fuzz_drop_table_operations(FuzzCtx *pCtx, const DropTablePacket *pPacket);

#endif /* DROP_TABLE_HARNESS_H */