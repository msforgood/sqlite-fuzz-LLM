/*
** Page Management Fuzzing Harness
** Targets: btreeClearHasContent, btreeGetHasContent, btreeInitPage
** Focus: B-Tree page management with bitvec operations and corruption detection
*/
#include "fuzz.h"
#include "pagemanagement_harness.h"

/* Setup database with configurations for page management testing */
int setup_page_management_db(FuzzCtx *pCtx, const PageMgmtPacket *pPacket) {
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
  
  /* Enable various integrity checking modes */
  sqlite3_exec(pCtx->db, "PRAGMA cell_size_check = ON;", 0, 0, &zErrMsg);
  sqlite3_free(zErrMsg);
  
  /* Create base table structure */
  snprintf(zSql, sizeof(zSql),
    "CREATE TABLE IF NOT EXISTS pagemgmt_test("
    "id INTEGER PRIMARY KEY, "
    "data BLOB, "
    "metadata TEXT, "
    "counter INTEGER DEFAULT 0"
    ");");
  
  rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
  sqlite3_free(zErrMsg);
  
  return SQLITE_OK;
}

/* Test page initialization scenarios */
int test_page_initialization(FuzzCtx *pCtx, const PageMgmtPacket *pPacket) {
  char zSql[2048];
  char *zErrMsg = 0;
  int rc;
  uint32_t i;
  
  /* Create multiple tables to trigger page initialization */
  uint32_t tableCount = (pPacket->pageCount % 20) + 1;
  for(i = 0; i < tableCount; i++) {
    uint32_t pageType = pPacket->pageTypes[i % 8] % 4;
    
    /* Different table structures based on page type preference */
    switch(pageType) {
      case 0:
        /* Simple table (leaf pages) */
        snprintf(zSql, sizeof(zSql),
          "CREATE TABLE IF NOT EXISTS init_table_%u("
          "id INTEGER PRIMARY KEY, "
          "data BLOB"
          ");", i);
        break;
        
      case 1:
        /* Index table (interior pages) */
        snprintf(zSql, sizeof(zSql),
          "CREATE TABLE IF NOT EXISTS init_table_%u("
          "id INTEGER PRIMARY KEY, "
          "data BLOB, "
          "indexed_col TEXT"
          "); "
          "CREATE INDEX IF NOT EXISTS idx_%u ON init_table_%u(indexed_col);", 
          i, i, i);
        break;
        
      case 2:
        /* Large row table (overflow pages) */
        snprintf(zSql, sizeof(zSql),
          "CREATE TABLE IF NOT EXISTS init_table_%u("
          "id INTEGER PRIMARY KEY, "
          "large_data BLOB, "
          "metadata TEXT"
          ");", i);
        break;
        
      default:
        /* Mixed structure */
        snprintf(zSql, sizeof(zSql),
          "CREATE TABLE IF NOT EXISTS init_table_%u("
          "id INTEGER PRIMARY KEY, "
          "data BLOB, "
          "flag INTEGER, "
          "metadata TEXT"
          ");", i);
        break;
    }
    
    rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
    sqlite3_free(zErrMsg);
    if (rc && rc != SQLITE_INTERRUPT) break;
  }
  
  return SQLITE_OK;
}

/* Test bitvec operations through page content tracking */
int test_bitvec_operations(FuzzCtx *pCtx, const PageMgmtPacket *pPacket) {
  char zSql[1024];
  char *zErrMsg = 0;
  int rc;
  uint32_t i;
  
  /* Fill database to create bitvec usage scenarios */
  uint32_t insertCount = (pPacket->bitvecSize % 1000) + 100;
  for(i = 0; i < insertCount; i++) {
    uint32_t dataSize = (pPacket->testData[i % 16] % 5000) + 100;
    uint32_t tableNum = i % 5;  /* Spread across multiple tables */
    
    snprintf(zSql, sizeof(zSql),
      "INSERT INTO pagemgmt_test(data, metadata, counter) VALUES("
      "randomblob(%u), "
      "'bitvec_test_%u', "
      "%u"
      ");", dataSize, tableNum, i);
    
    rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
    sqlite3_free(zErrMsg);
    if (rc && rc != SQLITE_INTERRUPT) break;
  }
  
  /* Transaction operations to trigger bitvec clearing */
  for(i = 0; i < 5; i++) {
    rc = sqlite3_exec(pCtx->db, "BEGIN IMMEDIATE;", 0, 0, &zErrMsg);
    sqlite3_free(zErrMsg);
    
    /* Modify data within transaction */
    uint32_t updateCount = (pPacket->pageNumbers[i % 8] % 50) + 10;
    snprintf(zSql, sizeof(zSql),
      "UPDATE pagemgmt_test SET counter = counter + 1 WHERE id %% %u = 0;",
      updateCount);
    rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
    sqlite3_free(zErrMsg);
    
    /* Commit to trigger btreeClearHasContent */
    rc = sqlite3_exec(pCtx->db, "COMMIT;", 0, 0, &zErrMsg);
    sqlite3_free(zErrMsg);
  }
  
  return SQLITE_OK;
}

/* Test content tracking operations */
int test_content_tracking(FuzzCtx *pCtx, const PageMgmtPacket *pPacket) {
  char zSql[512];
  char *zErrMsg = 0;
  int rc;
  uint32_t i;
  
  /* Create scenarios that exercise content tracking */
  uint32_t operations = pPacket->operations % 16;
  
  for(i = 0; i < 10; i++) {
    switch(operations % 4) {
      case 0:
        /* Insert operations */
        snprintf(zSql, sizeof(zSql),
          "INSERT INTO pagemgmt_test(data) VALUES(randomblob(%u));",
          (pPacket->testData[i % 16] % 2000) + 100);
        break;
        
      case 1:
        /* Update operations */
        snprintf(zSql, sizeof(zSql),
          "UPDATE pagemgmt_test SET data = randomblob(%u) WHERE id = %u;",
          (pPacket->testData[i % 16] % 3000) + 500, i + 1);
        break;
        
      case 2:
        /* Delete operations */
        snprintf(zSql, sizeof(zSql),
          "DELETE FROM pagemgmt_test WHERE id %% %u = 0;",
          (pPacket->pageNumbers[i % 8] % 10) + 2);
        break;
        
      default:
        /* Vacuum operations */
        strcpy(zSql, "VACUUM;");
        break;
    }
    
    rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
    sqlite3_free(zErrMsg);
    operations++;
  }
  
  return SQLITE_OK;
}

/* Test transaction lifecycle with page management */
int test_transaction_lifecycle(FuzzCtx *pCtx, const PageMgmtPacket *pPacket) {
  char zSql[512];
  char *zErrMsg = 0;
  int rc;
  uint32_t i;
  
  /* Test various transaction patterns */
  uint32_t txnCount = (pPacket->pageCount % 10) + 1;
  
  for(i = 0; i < txnCount; i++) {
    /* Begin transaction */
    rc = sqlite3_exec(pCtx->db, "BEGIN;", 0, 0, &zErrMsg);
    sqlite3_free(zErrMsg);
    
    /* Savepoint operations */
    snprintf(zSql, sizeof(zSql), "SAVEPOINT sp_%u;", i);
    rc = sqlite3_exec(pCtx->db, zSql, 0, 0, &zErrMsg);
    sqlite3_free(zErrMsg);
    
    /* Data modifications */
    uint32_t modCount = (pPacket->testData[i % 16] % 20) + 5;
    uint32_t j;
    for(j = 0; j < modCount; j++) {
      snprintf(zSql, sizeof(zSql),
        "INSERT INTO pagemgmt_test(data, metadata) VALUES("
        "randomblob(%u), 'txn_%u_%u');",
        (pPacket->pageNumbers[j % 8] % 1000) + 50, i, j);
      rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
      sqlite3_free(zErrMsg);
    }
    
    /* Randomly rollback to savepoint or commit */
    if (pPacket->corruptionMask & (1u << (i % 32))) {
      snprintf(zSql, sizeof(zSql), "ROLLBACK TO sp_%u;", i);
      rc = sqlite3_exec(pCtx->db, zSql, 0, 0, &zErrMsg);
      sqlite3_free(zErrMsg);
    }
    
    /* Commit transaction (triggers btreeClearHasContent) */
    rc = sqlite3_exec(pCtx->db, "COMMIT;", 0, 0, &zErrMsg);
    sqlite3_free(zErrMsg);
  }
  
  return SQLITE_OK;
}

/* Test page corruption detection */
int test_page_corruption_detection(FuzzCtx *pCtx, const PageMgmtPacket *pPacket) {
  char zSql[512];
  char *zErrMsg = 0;
  
  /* Create conditions that stress page initialization */
  uint32_t corruptType = pPacket->corruptionMask % 5;
  
  switch(corruptType) {
    case 0:
      /* Large data that may cause page splits */
      for(int i = 0; i < 10; i++) {
        snprintf(zSql, sizeof(zSql),
          "INSERT INTO pagemgmt_test(data) VALUES(randomblob(%u));",
          (pPacket->testData[i % 16] % 10000) + 5000);
        sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
        sqlite3_free(zErrMsg);
      }
      break;
      
    case 1:
      /* Many small records */
      for(int i = 0; i < 1000; i++) {
        snprintf(zSql, sizeof(zSql),
          "INSERT INTO pagemgmt_test(data) VALUES(randomblob(%u));",
          (pPacket->testData[i % 16] % 100) + 1);
        sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
        sqlite3_free(zErrMsg);
      }
      break;
      
    case 2:
      /* Index creation on existing data */
      sqlite3_exec(pCtx->db, 
        "CREATE INDEX IF NOT EXISTS idx_corrupt ON pagemgmt_test(metadata);",
        exec_handler, (void*)pCtx, &zErrMsg);
      sqlite3_free(zErrMsg);
      break;
      
    default:
      /* Mixed operations */
      for(int i = 0; i < 50; i++) {
        if (i % 2 == 0) {
          snprintf(zSql, sizeof(zSql),
            "INSERT INTO pagemgmt_test(data) VALUES(randomblob(%u));",
            (pPacket->pageNumbers[i % 8] % 3000) + 100);
        } else {
          snprintf(zSql, sizeof(zSql),
            "DELETE FROM pagemgmt_test WHERE id = %u;", i);
        }
        sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
        sqlite3_free(zErrMsg);
      }
      break;
  }
  
  /* Integrity checks to trigger page initialization */
  sqlite3_exec(pCtx->db, "PRAGMA integrity_check(10);", 
               exec_handler, (void*)pCtx, &zErrMsg);
  sqlite3_free(zErrMsg);
  
  sqlite3_exec(pCtx->db, "PRAGMA quick_check;", 
               exec_handler, (void*)pCtx, &zErrMsg);
  sqlite3_free(zErrMsg);
  
  return SQLITE_OK;
}

/* Test mixed page types */
int test_mixed_page_types(FuzzCtx *pCtx, const PageMgmtPacket *pPacket) {
  char zSql[1024];
  char *zErrMsg = 0;
  int rc;
  
  /* Create tables and indexes to generate different page types */
  uint32_t structureCount = (pPacket->pageCount % 8) + 1;
  uint32_t i;
  
  for(i = 0; i < structureCount; i++) {
    /* Create table */
    snprintf(zSql, sizeof(zSql),
      "CREATE TABLE IF NOT EXISTS mixed_%u("
      "id INTEGER PRIMARY KEY, "
      "col1 BLOB, "
      "col2 TEXT, "
      "col3 INTEGER"
      ");", i);
    rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
    sqlite3_free(zErrMsg);
    
    /* Create indexes to force interior pages */
    snprintf(zSql, sizeof(zSql),
      "CREATE INDEX IF NOT EXISTS idx_mixed_%u_1 ON mixed_%u(col2); "
      "CREATE INDEX IF NOT EXISTS idx_mixed_%u_2 ON mixed_%u(col3, col2);",
      i, i, i, i);
    rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
    sqlite3_free(zErrMsg);
    
    /* Populate with data to create page hierarchy */
    uint32_t recordCount = (pPacket->pageNumbers[i % 8] % 200) + 50;
    uint32_t j;
    for(j = 0; j < recordCount; j++) {
      uint32_t blobSize = (pPacket->testData[j % 16] % 2000) + 100;
      snprintf(zSql, sizeof(zSql),
        "INSERT INTO mixed_%u(col1, col2, col3) VALUES("
        "randomblob(%u), "
        "'index_test_%u_%u', "
        "%u"
        ");", i, blobSize, i, j, j);
      
      rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
      sqlite3_free(zErrMsg);
      if (rc && rc != SQLITE_INTERRUPT) break;
    }
  }
  
  return SQLITE_OK;
}

/* Enhanced page management fuzzing */
void fuzz_page_management(FuzzCtx *pCtx, const PageMgmtPacket *pPacket) {
  /* Setup database environment */
  setup_page_management_db(pCtx, pPacket);
  
  /* Execute different test scenarios based on packet */
  uint32_t scenario = pPacket->scenario % 8;
  switch(scenario) {
    case PAGEMGMT_SCENARIO_NORMAL:
      /* Normal page operations */
      test_page_initialization(pCtx, pPacket);
      test_content_tracking(pCtx, pPacket);
      break;
      
    case PAGEMGMT_SCENARIO_BITVEC_STRESS:
      /* Bitvec stress testing */
      test_bitvec_operations(pCtx, pPacket);
      test_transaction_lifecycle(pCtx, pPacket);
      break;
      
    case PAGEMGMT_SCENARIO_CORRUPTION:
      /* Corruption detection */
      test_page_corruption_detection(pCtx, pPacket);
      test_page_initialization(pCtx, pPacket);
      break;
      
    case PAGEMGMT_SCENARIO_TRANSACTION:
      /* Transaction lifecycle */
      test_transaction_lifecycle(pCtx, pPacket);
      test_bitvec_operations(pCtx, pPacket);
      break;
      
    case PAGEMGMT_SCENARIO_MIXED_PAGES:
      /* Mixed page types */
      test_mixed_page_types(pCtx, pPacket);
      test_content_tracking(pCtx, pPacket);
      break;
      
    case PAGEMGMT_SCENARIO_BOUNDARY:
      /* Boundary conditions */
      test_page_corruption_detection(pCtx, pPacket);
      test_mixed_page_types(pCtx, pPacket);
      break;
      
    case PAGEMGMT_SCENARIO_CONCURRENT:
      /* Concurrent-like patterns */
      test_transaction_lifecycle(pCtx, pPacket);
      test_page_initialization(pCtx, pPacket);
      test_content_tracking(pCtx, pPacket);
      break;
      
    default:
      /* Comprehensive testing */
      test_page_initialization(pCtx, pPacket);
      test_bitvec_operations(pCtx, pPacket);
      test_content_tracking(pCtx, pPacket);
      test_transaction_lifecycle(pCtx, pPacket);
      test_page_corruption_detection(pCtx, pPacket);
      test_mixed_page_types(pCtx, pPacket);
      break;
  }
}