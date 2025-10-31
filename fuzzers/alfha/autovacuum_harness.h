/*
** Auto-Vacuum Commit Fuzzing Harness Header
** Target: autoVacuumCommit function (btree.c)
*/
#ifndef AUTOVACUUM_HARNESS_H
#define AUTOVACUUM_HARNESS_H

#include "fuzz.h"

/* Auto-vacuum harness function declarations */
void generate_autovacuum_sql(char *zSql, size_t sqlSize, const AutoVacuumPacket *pPacket);
int setup_autovacuum_environment(FuzzCtx *pCtx, const AutoVacuumPacket *pPacket);
int test_autovacuum_scenarios(FuzzCtx *pCtx, const AutoVacuumPacket *pPacket);
int test_incremental_vacuum(FuzzCtx *pCtx, const AutoVacuumPacket *pPacket);
int test_autovac_corruption(FuzzCtx *pCtx, const AutoVacuumPacket *pPacket);
int test_custom_autovac_callback(FuzzCtx *pCtx, const AutoVacuumPacket *pPacket);
int custom_autovac_callback(void *pArg, const char *zDbName, unsigned int nPage, unsigned int nFree, unsigned int nPageSize);
int fuzz_autovacuum_commit(FuzzCtx *pCtx, const AutoVacuumPacket *pPacket);

#endif /* AUTOVACUUM_HARNESS_H */