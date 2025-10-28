/*
** Auto-Vacuum Commit Fuzzing Harness
** Target: autoVacuumCommit function (btree.c)
** Focus: Auto-vacuum commit scenarios with deep coverage optimization
*/
#include "fuzz.h"

/* Generate auto-vacuum focused SQL commands based on fuzzing packet */
void generate_autovacuum_sql(char *zSql, size_t sqlSize, const AutoVacuumPacket *pPacket) {
  const char *templates[] = {
    /* Basic table operations that trigger auto-vacuum scenarios */
    "CREATE TABLE IF NOT EXISTS vacuum_test%u(id INTEGER PRIMARY KEY, data BLOB);",
    "INSERT INTO vacuum_test%u VALUES(NULL, randomblob(%u));",
    "DELETE FROM vacuum_test%u WHERE id %% %u = 0;",
    
    /* Auto-vacuum control commands */
    "PRAGMA auto_vacuum = %u;",
    "PRAGMA incremental_vacuum(%u);",
    "VACUUM;",
    
    /* Page management operations */
    "PRAGMA page_count;",
    "PRAGMA freelist_count;",
    "PRAGMA max_page_count = %u;",
    
    /* Transaction operations affecting vacuum */
    "BEGIN IMMEDIATE;",
    "SAVEPOINT autovac_%u;",
    "ROLLBACK TO autovac_%u;",
    "COMMIT;",
    
    /* Index operations that affect page allocation */
    "CREATE INDEX IF NOT EXISTS idx_vacuum_%u ON vacuum_test%u(data);",
    "DROP INDEX IF EXISTS idx_vacuum_%u;",
  };
  
  int templateIdx = pPacket->corruptionSeed % (sizeof(templates)/sizeof(templates[0]));
  uint32_t param1 = pPacket->dbPages % 100;
  uint32_t param2 = (pPacket->freePages % 1000) + 1;
  uint32_t param3 = pPacket->scenario % 10;
  
  snprintf(zSql, sqlSize, templates[templateIdx], param1, param2, param1, param3, param2, param2, param1 * 100, param1, param1, param1, param1, param1);
}

/* Setup auto-vacuum environment for targeted testing */
int setup_autovacuum_environment(FuzzCtx *pCtx, const AutoVacuumPacket *pPacket) {
  char *zErrMsg = 0;
  char zSql[512];
  int rc;
  
  /* Configure page size based on packet */
  uint32_t pageSize;
  switch(pPacket->pageSize % 7) {
    case 0: pageSize = 512; break;
    case 1: pageSize = 1024; break; 
    case 2: pageSize = 2048; break;
    case 3: pageSize = 4096; break;
    case 4: pageSize = 8192; break;
    case 5: pageSize = 16384; break;
    default: pageSize = 32768; break;
  }
  
  snprintf(zSql, sizeof(zSql), "PRAGMA page_size = %u;", pageSize);
  rc = sqlite3_exec(pCtx->db, zSql, 0, 0, &zErrMsg);
  sqlite3_free(zErrMsg);
  
  /* Configure auto-vacuum mode */
  const char *vacModes[] = {"NONE", "FULL", "INCREMENTAL"};
  snprintf(zSql, sizeof(zSql), "PRAGMA auto_vacuum = %s;", 
           vacModes[pPacket->vacuumMode % 3]);
  rc = sqlite3_exec(pCtx->db, zSql, 0, 0, &zErrMsg);
  if( rc ) {
    printf("Auto-vacuum mode setup error: %s\n", zErrMsg);
  }
  sqlite3_free(zErrMsg);
  
  /* Create initial table structure */
  snprintf(zSql, sizeof(zSql),
    "CREATE TABLE IF NOT EXISTS autovac_main("
    "id INTEGER PRIMARY KEY, "
    "payload BLOB, "
    "metadata TEXT DEFAULT 'autovac_test_%u'"
    ");", pPacket->dbPages % 1000);
  
  rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
  sqlite3_free(zErrMsg);
  
  return SQLITE_OK;
}

/* Test auto-vacuum scenarios that exercise autoVacuumCommit */
int test_autovacuum_scenarios(FuzzCtx *pCtx, const AutoVacuumPacket *pPacket) {
  char zSql[1024];
  char *zErrMsg = 0;
  int rc;
  uint32_t iterations = (pPacket->dbPages % 100) + 1;
  uint32_t i;
  
  /* Fill database to target size */
  for(i = 0; i < iterations; i++) {
    uint32_t blobSize = (pPacket->testData[i % 24] % 2000) + 100;
    snprintf(zSql, sizeof(zSql),
      "INSERT INTO autovac_main(payload) VALUES(randomblob(%u));", blobSize);
    
    rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
    if( rc && rc != SQLITE_INTERRUPT ) break;
    sqlite3_free(zErrMsg);
    zErrMsg = 0;
  }
  
  /* Create fragmentation by deleting pages */
  uint32_t deletePattern = (pPacket->freePages % 9) + 1;
  snprintf(zSql, sizeof(zSql),
    "DELETE FROM autovac_main WHERE id %% %u = 0;", deletePattern);
  rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
  sqlite3_free(zErrMsg);
  
  /* Trigger auto-vacuum through transaction commit */
  rc = sqlite3_exec(pCtx->db, "BEGIN IMMEDIATE;", 0, 0, &zErrMsg);
  sqlite3_free(zErrMsg);
  
  /* More insertions to trigger reallocation */
  for(i = 0; i < iterations/4; i++) {
    uint32_t blobSize = (pPacket->testData[(i+12) % 24] % 1000) + 50;
    snprintf(zSql, sizeof(zSql),
      "INSERT INTO autovac_main(payload) VALUES(randomblob(%u));", blobSize);
    
    rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
    if( rc && rc != SQLITE_INTERRUPT ) break;
    sqlite3_free(zErrMsg);
    zErrMsg = 0;
  }
  
  /* Commit to trigger autoVacuumCommit */
  rc = sqlite3_exec(pCtx->db, "COMMIT;", exec_handler, (void*)pCtx, &zErrMsg);
  sqlite3_free(zErrMsg);
  
  return SQLITE_OK;
}

/* Test incremental vacuum scenarios */
int test_incremental_vacuum(FuzzCtx *pCtx, const AutoVacuumPacket *pPacket) {
  char zSql[512];
  char *zErrMsg = 0;
  int rc;
  
  /* Set incremental vacuum mode */
  rc = sqlite3_exec(pCtx->db, "PRAGMA auto_vacuum = INCREMENTAL;", 0, 0, &zErrMsg);
  sqlite3_free(zErrMsg);
  
  /* Create and populate test data */
  uint32_t records = (pPacket->dbPages % 50) + 10;
  uint32_t i;
  for(i = 0; i < records; i++) {
    uint32_t size = (pPacket->testData[i % 24] % 5000) + 500;
    snprintf(zSql, sizeof(zSql),
      "INSERT INTO autovac_main(payload) VALUES(randomblob(%u));", size);
    rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
    sqlite3_free(zErrMsg);
    if( rc && rc != SQLITE_INTERRUPT ) break;
  }
  
  /* Delete half the records */
  snprintf(zSql, sizeof(zSql), "DELETE FROM autovac_main WHERE id %% 2 = 0;");
  rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
  sqlite3_free(zErrMsg);
  
  /* Perform incremental vacuum with varying page counts */
  uint32_t vacPages = (pPacket->freePages % 20) + 1;
  snprintf(zSql, sizeof(zSql), "PRAGMA incremental_vacuum(%u);", vacPages);
  rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
  sqlite3_free(zErrMsg);
  
  return SQLITE_OK;
}

/* Test corruption scenarios in auto-vacuum */
int test_autovac_corruption(FuzzCtx *pCtx, const AutoVacuumPacket *pPacket) {
  char zSql[512];
  char *zErrMsg = 0;
  
  /* Enable strict mode for better corruption detection */
  sqlite3_exec(pCtx->db, "PRAGMA cell_size_check = ON;", 0, 0, &zErrMsg);
  sqlite3_free(zErrMsg);
  
  /* Test integrity with auto-vacuum enabled */
  uint32_t checkLimit = (pPacket->corruptionSeed % 100) + 1;
  snprintf(zSql, sizeof(zSql), "PRAGMA integrity_check(%u);", checkLimit);
  sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
  sqlite3_free(zErrMsg);
  
  /* Quick check for pointer map validation */
  sqlite3_exec(pCtx->db, "PRAGMA quick_check;", exec_handler, (void*)pCtx, &zErrMsg);
  sqlite3_free(zErrMsg);
  
  /* Check freelist consistency */
  sqlite3_exec(pCtx->db, "PRAGMA freelist_count;", exec_handler, (void*)pCtx, &zErrMsg);
  sqlite3_free(zErrMsg);
  
  return SQLITE_OK;
}

/* Custom auto-vacuum callback simulation */
int custom_autovac_callback(void *pArg, const char *zDbName, unsigned int nPage, unsigned int nFree, unsigned int nPageSize) {
  AutoVacuumPacket *pPacket = (AutoVacuumPacket*)pArg;
  if( !pPacket ) return 0;
  
  /* Simulate different callback behaviors based on packet data */
  uint32_t behavior = pPacket->customVacFunc % 5;
  switch(behavior) {
    case 0: return 0;              /* No vacuum */
    case 1: return nFree;          /* Vacuum all free pages */
    case 2: return nFree / 2;      /* Vacuum half */
    case 3: return (nFree * 3) / 4; /* Vacuum 75% */
    default: return (pPacket->freePages % nFree) + 1; /* Custom amount */
  }
}

/* Test custom auto-vacuum callback functionality */
int test_custom_autovac_callback(FuzzCtx *pCtx, const AutoVacuumPacket *pPacket) {
  char zSql[256];
  char *zErrMsg = 0;
  int rc;
  
  /* Note: This simulates the effect of custom callbacks through SQL operations */
  /* since we can't directly set the xAutovacPages callback in fuzzing context */
  
  /* Create scenario that would trigger custom callback logic */
  uint32_t targetPages = (pPacket->dbPages % 100) + 10;
  uint32_t i;
  for(i = 0; i < targetPages; i++) {
    snprintf(zSql, sizeof(zSql),
      "INSERT INTO autovac_main(payload) VALUES(randomblob(%u));",
      (pPacket->testData[i % 24] % 1000) + 200);
    rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
    sqlite3_free(zErrMsg);
    if( rc && rc != SQLITE_INTERRUPT ) break;
  }
  
  /* Delete pattern based on custom vacuum behavior */
  uint32_t deleteRatio = custom_autovac_callback((void*)pPacket, "main", targetPages, targetPages/3, 4096);
  if( deleteRatio > 0 ) {
    uint32_t modulus = (targetPages / deleteRatio) + 1;
    snprintf(zSql, sizeof(zSql), "DELETE FROM autovac_main WHERE id %% %u = 0;", modulus);
    rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
    sqlite3_free(zErrMsg);
  }
  
  return SQLITE_OK;
}

/* Enhanced auto-vacuum commit fuzzing */
int fuzz_autovacuum_commit(FuzzCtx *pCtx, const AutoVacuumPacket *pPacket) {
  int rc = SQLITE_OK;
  
  /* Setup auto-vacuum environment */
  setup_autovacuum_environment(pCtx, pPacket);
  
  /* Execute different test scenarios based on packet */
  uint32_t scenario = pPacket->scenario % 8;
  switch(scenario) {
    case 0:
      /* Basic auto-vacuum scenarios */
      test_autovacuum_scenarios(pCtx, pPacket);
      break;
      
    case 1:
      /* Incremental vacuum testing */
      test_incremental_vacuum(pCtx, pPacket);
      break;
      
    case 2:
      /* Corruption detection during vacuum */
      test_autovac_corruption(pCtx, pPacket);
      test_autovacuum_scenarios(pCtx, pPacket);
      break;
      
    case 3:
      /* Custom callback simulation */
      test_custom_autovac_callback(pCtx, pPacket);
      break;
      
    case 4:
      /* Combined incremental + corruption */
      test_incremental_vacuum(pCtx, pPacket);
      test_autovac_corruption(pCtx, pPacket);
      break;
      
    case 5:
      /* Full auto-vacuum with custom patterns */
      test_autovacuum_scenarios(pCtx, pPacket);
      test_custom_autovac_callback(pCtx, pPacket);
      break;
      
    case 6:
      /* Stress testing with all scenarios */
      test_autovacuum_scenarios(pCtx, pPacket);
      test_incremental_vacuum(pCtx, pPacket);
      test_autovac_corruption(pCtx, pPacket);
      break;
      
    default:
      /* Comprehensive testing */
      test_autovacuum_scenarios(pCtx, pPacket);
      test_incremental_vacuum(pCtx, pPacket);
      test_custom_autovac_callback(pCtx, pPacket);
      test_autovac_corruption(pCtx, pPacket);
      break;
  }
  
  return rc;
}