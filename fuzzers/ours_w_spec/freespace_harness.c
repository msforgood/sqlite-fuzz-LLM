/*
** FreeSpace Computation Fuzzing Harness
** Target: btreeComputeFreeSpace function (btree.c:2091)
** Focus: B-Tree free space calculation with corruption detection
*/
#include "fuzz.h"
#include "freespace_harness.h"

/* Setup database with specific page configurations for free space testing */
int setup_freespace_database(FuzzCtx *pCtx, const FreeSpacePacket *pPacket) {
  char zSql[1024];
  char *zErrMsg = 0;
  int rc;
  
  /* Configure page size based on packet */
  uint32_t pageSize;
  switch(pPacket->pageSize % 8) {
    case 0: pageSize = 512; break;
    case 1: pageSize = 1024; break;
    case 2: pageSize = 2048; break;
    case 3: pageSize = 4096; break;
    case 4: pageSize = 8192; break;
    case 5: pageSize = 16384; break;
    case 6: pageSize = 32768; break;
    default: pageSize = 65536; break;
  }
  
  snprintf(zSql, sizeof(zSql), "PRAGMA page_size = %u;", pageSize);
  rc = sqlite3_exec(pCtx->db, zSql, 0, 0, &zErrMsg);
  sqlite3_free(zErrMsg);
  
  /* Create table structure based on page type */
  const char *tableType = (pPacket->pageType % 2 == 0) ? "TABLE" : "INDEX";
  if (pPacket->pageType % 4 < 2) {
    /* Table pages */
    snprintf(zSql, sizeof(zSql),
      "CREATE TABLE IF NOT EXISTS freespace_test("
      "id INTEGER PRIMARY KEY, "
      "data BLOB, "
      "metadata TEXT"
      ");");
  } else {
    /* Index pages */
    snprintf(zSql, sizeof(zSql),
      "CREATE TABLE IF NOT EXISTS freespace_test("
      "id INTEGER PRIMARY KEY, "
      "data BLOB, "
      "metadata TEXT"
      "); "
      "CREATE INDEX IF NOT EXISTS idx_freespace ON freespace_test(data, metadata);");
  }
  
  rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
  sqlite3_free(zErrMsg);
  
  return SQLITE_OK;
}

/* Create specific page layouts to trigger free space computation scenarios */
int create_test_page_layout(FuzzCtx *pCtx, const FreeSpacePacket *pPacket) {
  char zSql[2048];
  char *zErrMsg = 0;
  int rc;
  uint32_t i;
  
  /* Fill page with cells of varying sizes */
  uint32_t cellCount = (pPacket->cellCount % 100) + 1;
  for(i = 0; i < cellCount; i++) {
    uint32_t dataSize = (pPacket->cellSizes[i % 16] % 2000) + 10;
    uint32_t metadataLen = (pPacket->testData[i % 16] % 200) + 5;
    
    snprintf(zSql, sizeof(zSql),
      "INSERT INTO freespace_test(data, metadata) VALUES("
      "randomblob(%u), "
      "printf('meta_%%0%ud', %u)"
      ");", dataSize, metadataLen, i);
    
    rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
    if (rc && rc != SQLITE_INTERRUPT) break;
    sqlite3_free(zErrMsg);
    zErrMsg = 0;
  }
  
  return SQLITE_OK;
}

/* Test boundary conditions for free space calculation */
int test_boundary_conditions(FuzzCtx *pCtx, const FreeSpacePacket *pPacket) {
  char zSql[512];
  char *zErrMsg = 0;
  int rc;
  
  /* Test edge cases with specific data patterns */
  uint32_t scenario = pPacket->scenario % 8;
  
  switch(scenario) {
    case 0:
      /* Nearly full page */
      for(int i = 0; i < 20; i++) {
        snprintf(zSql, sizeof(zSql),
          "INSERT INTO freespace_test(data) VALUES(randomblob(%u));",
          (pPacket->testData[i % 16] % 1000) + 3000);
        rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
        sqlite3_free(zErrMsg);
      }
      break;
      
    case 1:
      /* Nearly empty page with minimal data */
      snprintf(zSql, sizeof(zSql),
        "INSERT INTO freespace_test(data) VALUES(randomblob(%u));",
        (pPacket->testData[0] % 50) + 1);
      rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
      sqlite3_free(zErrMsg);
      break;
      
    case 2:
      /* Maximum cell count with minimal data */
      for(int i = 0; i < 100; i++) {
        snprintf(zSql, sizeof(zSql),
          "INSERT INTO freespace_test(data) VALUES(randomblob(1));");
        rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
        sqlite3_free(zErrMsg);
      }
      break;
      
    default:
      /* Mixed size cells */
      for(int i = 0; i < 10; i++) {
        uint32_t size = (i % 2 == 0) ? 10 : 2000;
        snprintf(zSql, sizeof(zSql),
          "INSERT INTO freespace_test(data) VALUES(randomblob(%u));", size);
        rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
        sqlite3_free(zErrMsg);
      }
      break;
  }
  
  return SQLITE_OK;
}

/* Test fragmentation scenarios */
int test_fragmentation_scenarios(FuzzCtx *pCtx, const FreeSpacePacket *pPacket) {
  char zSql[512];
  char *zErrMsg = 0;
  int rc;
  
  /* Create fragmentation by inserting and deleting data */
  uint32_t iterations = (pPacket->freeblockCount % 50) + 10;
  uint32_t i;
  
  /* First, fill the page */
  for(i = 0; i < iterations; i++) {
    uint32_t blobSize = (pPacket->cellSizes[i % 16] % 1500) + 100;
    snprintf(zSql, sizeof(zSql),
      "INSERT INTO freespace_test(data) VALUES(randomblob(%u));", blobSize);
    rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
    sqlite3_free(zErrMsg);
    if (rc && rc != SQLITE_INTERRUPT) break;
  }
  
  /* Create fragmentation pattern */
  uint32_t deletePattern = (pPacket->corruptionMask % 7) + 2;
  snprintf(zSql, sizeof(zSql),
    "DELETE FROM freespace_test WHERE rowid %% %u = 0;", deletePattern);
  rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
  sqlite3_free(zErrMsg);
  
  /* Insert smaller records to create more fragmentation */
  for(i = 0; i < iterations/3; i++) {
    uint32_t blobSize = (pPacket->testData[i % 16] % 200) + 10;
    snprintf(zSql, sizeof(zSql),
      "INSERT INTO freespace_test(data) VALUES(randomblob(%u));", blobSize);
    rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
    sqlite3_free(zErrMsg);
  }
  
  return SQLITE_OK;
}

/* Validate free space calculation through PRAGMA commands */
int validate_freespace_calculation(FuzzCtx *pCtx, const FreeSpacePacket *pPacket) {
  char *zErrMsg = 0;
  
  /* Check page information */
  sqlite3_exec(pCtx->db, "PRAGMA page_count;", exec_handler, (void*)pCtx, &zErrMsg);
  sqlite3_free(zErrMsg);
  
  sqlite3_exec(pCtx->db, "PRAGMA freelist_count;", exec_handler, (void*)pCtx, &zErrMsg);
  sqlite3_free(zErrMsg);
  
  /* Trigger integrity check which internally calls btreeComputeFreeSpace */
  uint32_t checkLimit = (pPacket->corruptionMask % 50) + 1;
  char zSql[256];
  snprintf(zSql, sizeof(zSql), "PRAGMA integrity_check(%u);", checkLimit);
  sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
  sqlite3_free(zErrMsg);
  
  /* Quick check for rapid validation */
  sqlite3_exec(pCtx->db, "PRAGMA quick_check;", exec_handler, (void*)pCtx, &zErrMsg);
  sqlite3_free(zErrMsg);
  
  return SQLITE_OK;
}

/* Inject corruption patterns to test error detection */
int inject_freeblock_corruption(FuzzCtx *pCtx, const FreeSpacePacket *pPacket) {
  char zSql[512];
  char *zErrMsg = 0;
  
  /* Enable cell size checking for better corruption detection */
  sqlite3_exec(pCtx->db, "PRAGMA cell_size_check = ON;", 0, 0, &zErrMsg);
  sqlite3_free(zErrMsg);
  
  /* Create conditions that stress free space calculation */
  uint32_t corruptType = pPacket->corruptionMask % 5;
  
  switch(corruptType) {
    case 0:
      /* Extreme fragmentation */
      for(int i = 0; i < 50; i++) {
        snprintf(zSql, sizeof(zSql),
          "INSERT INTO freespace_test(data) VALUES(randomblob(%u));",
          (pPacket->testData[i % 16] % 100) + 10);
        sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
        sqlite3_free(zErrMsg);
      }
      sqlite3_exec(pCtx->db, "DELETE FROM freespace_test WHERE rowid % 3 = 0;", 
                   exec_handler, (void*)pCtx, &zErrMsg);
      sqlite3_free(zErrMsg);
      break;
      
    case 1:
      /* Large varying cell sizes */
      for(int i = 0; i < 10; i++) {
        uint32_t size = (i % 2 == 0) ? 5000 : 5;
        snprintf(zSql, sizeof(zSql),
          "INSERT INTO freespace_test(data) VALUES(randomblob(%u));", size);
        sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
        sqlite3_free(zErrMsg);
      }
      break;
      
    case 2:
      /* Update operations to trigger reallocation */
      sqlite3_exec(pCtx->db, "INSERT INTO freespace_test(data) VALUES(randomblob(100));",
                   exec_handler, (void*)pCtx, &zErrMsg);
      sqlite3_free(zErrMsg);
      for(int i = 0; i < 10; i++) {
        uint32_t newSize = (pPacket->cellSizes[i % 16] % 3000) + 500;
        snprintf(zSql, sizeof(zSql),
          "UPDATE freespace_test SET data = randomblob(%u) WHERE rowid = 1;", newSize);
        sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
        sqlite3_free(zErrMsg);
      }
      break;
      
    default:
      /* Transaction rollback scenarios */
      sqlite3_exec(pCtx->db, "BEGIN;", 0, 0, &zErrMsg);
      sqlite3_free(zErrMsg);
      for(int i = 0; i < 20; i++) {
        snprintf(zSql, sizeof(zSql),
          "INSERT INTO freespace_test(data) VALUES(randomblob(%u));",
          (pPacket->testData[i % 16] % 2000) + 100);
        sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
        sqlite3_free(zErrMsg);
      }
      sqlite3_exec(pCtx->db, "ROLLBACK;", 0, 0, &zErrMsg);
      sqlite3_free(zErrMsg);
      break;
  }
  
  return SQLITE_OK;
}

/* Enhanced free space computation fuzzing */
void fuzz_freespace_computation(FuzzCtx *pCtx, const FreeSpacePacket *pPacket) {
  /* Setup database environment */
  setup_freespace_database(pCtx, pPacket);
  
  /* Execute different test scenarios based on packet */
  uint32_t scenario = pPacket->scenario % 8;
  switch(scenario) {
    case FREESPACE_SCENARIO_NORMAL:
      /* Normal operation scenarios */
      create_test_page_layout(pCtx, pPacket);
      validate_freespace_calculation(pCtx, pPacket);
      break;
      
    case FREESPACE_SCENARIO_CORRUPTION:
      /* Corruption injection and detection */
      inject_freeblock_corruption(pCtx, pPacket);
      validate_freespace_calculation(pCtx, pPacket);
      break;
      
    case FREESPACE_SCENARIO_BOUNDARY:
      /* Boundary condition testing */
      test_boundary_conditions(pCtx, pPacket);
      validate_freespace_calculation(pCtx, pPacket);
      break;
      
    case FREESPACE_SCENARIO_FRAGMENTED:
      /* Fragmentation scenarios */
      test_fragmentation_scenarios(pCtx, pPacket);
      validate_freespace_calculation(pCtx, pPacket);
      break;
      
    case FREESPACE_SCENARIO_OVERLAP:
      /* Overlapping freeblock testing through extreme operations */
      create_test_page_layout(pCtx, pPacket);
      test_fragmentation_scenarios(pCtx, pPacket);
      inject_freeblock_corruption(pCtx, pPacket);
      break;
      
    case FREESPACE_SCENARIO_EMPTY:
      /* Empty page scenarios */
      validate_freespace_calculation(pCtx, pPacket);
      break;
      
    case FREESPACE_SCENARIO_FULL:
      /* Full page scenarios */
      test_boundary_conditions(pCtx, pPacket);
      test_fragmentation_scenarios(pCtx, pPacket);
      break;
      
    default:
      /* Comprehensive testing */
      create_test_page_layout(pCtx, pPacket);
      test_boundary_conditions(pCtx, pPacket);
      test_fragmentation_scenarios(pCtx, pPacket);
      inject_freeblock_corruption(pCtx, pPacket);
      validate_freespace_calculation(pCtx, pPacket);
      break;
  }
}