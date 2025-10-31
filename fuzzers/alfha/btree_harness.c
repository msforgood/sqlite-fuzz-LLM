/*
** B-Tree Allocation Fuzzing Harness
** Target: allocateBtreePage function (btree.c:6475)
** Focus: B-Tree page allocation with deep coverage optimization
*/
#include "fuzz.h"

/* Generate B-Tree focused SQL commands based on fuzzing packet */
void generate_btree_sql(char *zSql, size_t sqlSize, const BtreeAllocPacket *pPacket) {
  const char *templates[] = {
    /* Basic table operations that trigger page allocation */
    "CREATE TABLE IF NOT EXISTS test%u(id INTEGER PRIMARY KEY, data BLOB);",
    "INSERT INTO test%u VALUES(NULL, randomblob(%u));",
    "CREATE INDEX IF NOT EXISTS idx%u ON test%u(data);",
    
    /* Operations that stress freelist management */
    "DELETE FROM test%u WHERE id %% %u = 0;",
    "VACUUM;",
    "PRAGMA incremental_vacuum(%u);",
    
    /* Auto-vacuum operations */
    "PRAGMA auto_vacuum = %u;",
    "PRAGMA freelist_count;",
    "PRAGMA page_count;",
    
    /* Transactions that affect page allocation */
    "BEGIN IMMEDIATE;",
    "SAVEPOINT sp%u;",
    "ROLLBACK TO sp%u;",
    "COMMIT;",
  };
  
  int templateIdx = pPacket->corruptionMask % (sizeof(templates)/sizeof(templates[0]));
  uint32_t param1 = pPacket->nearbyPgno % 100;
  uint32_t param2 = (pPacket->memoryPressure % 1000) + 1;
  
  snprintf(zSql, sqlSize, templates[templateIdx], param1, param2, param1, param1, param2, param2, param1 % 3, param1, param1);
}

/* Setup B-Tree environment for targeted testing */
int setup_btree_environment(FuzzCtx *pCtx, const BtreeAllocPacket *pPacket) {
  char *zErrMsg = 0;
  char zSql[512];
  int rc;
  
  /* Configure database for B-Tree testing */
  if( pPacket->flags & 0x01 ) {
    rc = sqlite3_exec(pCtx->db, "PRAGMA auto_vacuum = FULL;", 0, 0, &zErrMsg);
    if( rc ) {
      printf("Auto-vacuum setup error: %s\n", zErrMsg);
    }
    sqlite3_free(zErrMsg);
  }
  
  if( pPacket->flags & 0x02 ) {
    rc = sqlite3_exec(pCtx->db, "PRAGMA journal_mode = WAL;", 0, 0, &zErrMsg);
    sqlite3_free(zErrMsg);
  }
  
  /* Create initial table structure to populate B-Tree */
  snprintf(zSql, sizeof(zSql), 
    "CREATE TABLE IF NOT EXISTS btree_test("
    "id INTEGER PRIMARY KEY, "
    "data BLOB, "
    "extra TEXT DEFAULT 'padding_%u'"
    ");", pPacket->nearbyPgno % 1000);
  
  rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
  sqlite3_free(zErrMsg);
  
  return SQLITE_OK;
}

/* Test freelist scenarios that exercise allocateBtreePage */
int test_freelist_scenarios(FuzzCtx *pCtx, const BtreeAllocPacket *pPacket) {
  char zSql[1024];
  char *zErrMsg = 0;
  int rc;
  uint32_t iterations = (pPacket->memoryPressure % 50) + 1;
  uint32_t i;
  
  /* Fill pages then delete to create freelist */
  for(i = 0; i < iterations; i++) {
    snprintf(zSql, sizeof(zSql),
      "INSERT INTO btree_test(data) VALUES(randomblob(%u));",
      (pPacket->payload[i % 32] % 1000) + 100);
    
    rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
    if( rc && rc != SQLITE_INTERRUPT ) break;
    sqlite3_free(zErrMsg);
    zErrMsg = 0;
  }
  
  /* Delete pattern to fragment freelist */
  uint32_t deletePattern = pPacket->corruptionMask % 7 + 1;
  snprintf(zSql, sizeof(zSql),
    "DELETE FROM btree_test WHERE id %% %u = 0;", deletePattern);
  
  rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
  sqlite3_free(zErrMsg);
  
  /* Force reallocation from freelist */
  for(i = 0; i < iterations/2; i++) {
    snprintf(zSql, sizeof(zSql),
      "INSERT INTO btree_test(data) VALUES(randomblob(%u));",
      (pPacket->payload[(i+16) % 32] % 500) + 50);
    
    rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
    if( rc && rc != SQLITE_INTERRUPT ) break;
    sqlite3_free(zErrMsg);
    zErrMsg = 0;
  }
  
  return SQLITE_OK;
}

/* Test memory stress conditions affecting page allocation */
int test_memory_stress(FuzzCtx *pCtx, const BtreeAllocPacket *pPacket) {
  char zSql[512];
  char *zErrMsg = 0;
  int rc;
  
  /* Set lower memory limit based on packet */
  uint32_t memLimit = (pPacket->memoryPressure % 10000000) + 1000000; /* 1-10MB */
  sqlite3_hard_heap_limit64(memLimit);
  
  /* Try to allocate large amounts of data */
  uint32_t blobSize = (pPacket->nearbyPgno % 50000) + 1000;
  snprintf(zSql, sizeof(zSql),
    "INSERT INTO btree_test(data) VALUES(randomblob(%u));", blobSize);
  
  rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
  sqlite3_free(zErrMsg);
  
  /* Reset to original limit */
  sqlite3_hard_heap_limit64(20000000);
  
  return SQLITE_OK;
}

/* Test corruption detection in page allocation */
int test_corruption_detection(FuzzCtx *pCtx, const BtreeAllocPacket *pPacket) {
  char zSql[256];
  char *zErrMsg = 0;
  
  /* Trigger integrity check which exercises page allocation validation */
  snprintf(zSql, sizeof(zSql), "PRAGMA integrity_check(%u);", 
           (pPacket->corruptionMask % 100) + 1);
  
  sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
  sqlite3_free(zErrMsg);
  
  /* Quick check that also validates B-Tree structure */
  sqlite3_exec(pCtx->db, "PRAGMA quick_check;", exec_handler, (void*)pCtx, &zErrMsg);
  sqlite3_free(zErrMsg);
  
  return SQLITE_OK;
}

/* Enhanced B-Tree allocation fuzzing */
int fuzz_btree_allocation(FuzzCtx *pCtx, const BtreeAllocPacket *pPacket) {
  int rc = SQLITE_OK;
  
  /* Setup environment based on fuzzing mode */
  setup_btree_environment(pCtx, pPacket);
  
  switch(pCtx->fuzzMode) {
    case FUZZ_MODE_BTREE_ALLOC:
      /* Direct B-Tree allocation scenarios */
      test_freelist_scenarios(pCtx, pPacket);
      break;
      
    case FUZZ_MODE_FREELIST_FULL:
      /* Comprehensive freelist testing */
      test_freelist_scenarios(pCtx, pPacket);
      test_corruption_detection(pCtx, pPacket);
      break;
      
    case FUZZ_MODE_MEMORY_STRESS:
      /* Memory pressure testing */
      test_memory_stress(pCtx, pPacket);
      test_freelist_scenarios(pCtx, pPacket);
      break;
      
    case FUZZ_MODE_CORRUPTION:
      /* Corruption detection testing */
      test_corruption_detection(pCtx, pPacket);
      break;
      
    default:
      /* Multi-mode comprehensive testing */
      test_freelist_scenarios(pCtx, pPacket);
      test_memory_stress(pCtx, pPacket);
      test_corruption_detection(pCtx, pPacket);
      break;
  }
  
  return rc;
}