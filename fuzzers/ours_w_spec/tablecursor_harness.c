/*
** Table/Cursor Management Fuzzing Harness
** Targets: btreeCreateTable, btreeDropTable, btreeCursor, btreeCursorWithLock
** Focus: B-Tree table and cursor operations with comprehensive coverage
*/
#include "fuzz.h"
#include "tablecursor_harness.h"

/* Setup database with configurations for table/cursor testing */
int setup_tablecursor_database(FuzzCtx *pCtx, const TableCursorPacket *pPacket) {
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
  
  /* Configure auto-vacuum based on test data */
  const char *vacModes[] = {"NONE", "FULL", "INCREMENTAL"};
  snprintf(zSql, sizeof(zSql), "PRAGMA auto_vacuum = %s;", 
           vacModes[pPacket->testData[0] % 3]);
  rc = sqlite3_exec(pCtx->db, zSql, 0, 0, &zErrMsg);
  sqlite3_free(zErrMsg);
  
  /* Enable shared cache if testing locking */
  if (pPacket->scenario == TABLECURSOR_SCENARIO_LOCKING) {
    sqlite3_exec(pCtx->db, "PRAGMA cache_size = 1000;", 0, 0, &zErrMsg);
    sqlite3_free(zErrMsg);
  }
  
  /* Create base table for operations */
  snprintf(zSql, sizeof(zSql),
    "CREATE TABLE IF NOT EXISTS tablecursor_base("
    "id INTEGER PRIMARY KEY, "
    "data BLOB, "
    "metadata TEXT"
    ");");
  
  rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
  sqlite3_free(zErrMsg);
  
  return SQLITE_OK;
}

/* Test complete table lifecycle operations */
int test_table_lifecycle(FuzzCtx *pCtx, const TableCursorPacket *pPacket) {
  char zSql[2048];
  char *zErrMsg = 0;
  int rc;
  uint32_t i;
  
  /* Create multiple tables with different characteristics */
  uint32_t tableCount = (pPacket->tableCount % 10) + 1;
  for(i = 0; i < tableCount; i++) {
    uint32_t tableId = (pPacket->tableIds[i % 8] % 1000) + 100;
    uint8_t createFlags = pPacket->createFlags;
    
    /* Determine table type based on flags */
    if (createFlags & CREATE_TABLE_INTKEY) {
      /* Regular table with rowid */
      snprintf(zSql, sizeof(zSql),
        "CREATE TABLE IF NOT EXISTS lifecycle_table_%u("
        "id INTEGER PRIMARY KEY, "
        "data BLOB, "
        "value INTEGER"
        ");", tableId);
    } else if (createFlags & CREATE_TABLE_ZERODATA) {
      /* Index-like table */
      snprintf(zSql, sizeof(zSql),
        "CREATE TABLE IF NOT EXISTS lifecycle_table_%u("
        "key TEXT PRIMARY KEY"
        ") WITHOUT ROWID;", tableId);
    } else {
      /* Mixed structure */
      snprintf(zSql, sizeof(zSql),
        "CREATE TABLE IF NOT EXISTS lifecycle_table_%u("
        "id INTEGER, "
        "data BLOB, "
        "metadata TEXT, "
        "PRIMARY KEY(id, metadata)"
        ");", tableId);
    }
    
    rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
    sqlite3_free(zErrMsg);
    if (rc && rc != SQLITE_INTERRUPT) break;
    
    /* Populate table with test data */
    uint32_t recordCount = (pPacket->testData[i % 32] % 100) + 10;
    uint32_t j;
    for(j = 0; j < recordCount; j++) {
      uint32_t dataSize = (pPacket->testData[(i+j) % 32] % 2000) + 100;
      
      if (createFlags & CREATE_TABLE_ZERODATA) {
        snprintf(zSql, sizeof(zSql),
          "INSERT OR IGNORE INTO lifecycle_table_%u(key) VALUES('key_%u_%u');",
          tableId, i, j);
      } else {
        snprintf(zSql, sizeof(zSql),
          "INSERT INTO lifecycle_table_%u(data, value, metadata) VALUES("
          "randomblob(%u), %u, 'meta_%u_%u');",
          tableId, dataSize, j, i, j);
      }
      
      rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
      sqlite3_free(zErrMsg);
      if (rc && rc != SQLITE_INTERRUPT) break;
    }
  }
  
  /* Drop some tables to test cleanup */
  for(i = 0; i < tableCount/2; i++) {
    uint32_t tableId = (pPacket->tableIds[i % 8] % 1000) + 100;
    snprintf(zSql, sizeof(zSql), "DROP TABLE IF EXISTS lifecycle_table_%u;", tableId);
    rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
    sqlite3_free(zErrMsg);
  }
  
  return SQLITE_OK;
}

/* Test cursor operations with various access patterns */
int test_cursor_operations(FuzzCtx *pCtx, const TableCursorPacket *pPacket) {
  char zSql[1024];
  char *zErrMsg = 0;
  int rc;
  uint32_t i;
  
  /* Create test tables for cursor operations */
  uint32_t tableCount = (pPacket->tableCount % 5) + 1;
  for(i = 0; i < tableCount; i++) {
    uint32_t tableId = (pPacket->tableIds[i % 8] % 100) + 200;
    
    snprintf(zSql, sizeof(zSql),
      "CREATE TABLE IF NOT EXISTS cursor_table_%u("
      "id INTEGER PRIMARY KEY, "
      "data BLOB, "
      "indexed_col TEXT"
      ");", tableId);
    rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
    sqlite3_free(zErrMsg);
    
    /* Create index to test index cursors */
    snprintf(zSql, sizeof(zSql),
      "CREATE INDEX IF NOT EXISTS idx_cursor_%u ON cursor_table_%u(indexed_col);",
      tableId, tableId);
    rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
    sqlite3_free(zErrMsg);
  }
  
  /* Perform various cursor operations */
  uint32_t operationCount = (pPacket->operationCount % 50) + 10;
  for(i = 0; i < operationCount; i++) {
    uint32_t tableId = (pPacket->tableIds[i % 8] % 100) + 200;
    uint8_t cursorFlag = pPacket->cursorFlags[i % 8];
    uint32_t dataSize = (pPacket->testData[i % 32] % 3000) + 100;
    
    switch(cursorFlag % 4) {
      case 0:
        /* Read operations */
        snprintf(zSql, sizeof(zSql),
          "SELECT count(*) FROM cursor_table_%u WHERE data IS NOT NULL;", tableId);
        break;
        
      case 1:
        /* Insert operations (write cursor) */
        snprintf(zSql, sizeof(zSql),
          "INSERT INTO cursor_table_%u(data, indexed_col) VALUES("
          "randomblob(%u), 'index_val_%u');",
          tableId, dataSize, i);
        break;
        
      case 2:
        /* Update operations (write cursor) */
        snprintf(zSql, sizeof(zSql),
          "UPDATE cursor_table_%u SET data = randomblob(%u) WHERE id = %u;",
          tableId, dataSize, i % 10 + 1);
        break;
        
      default:
        /* Delete operations (cursor for delete) */
        snprintf(zSql, sizeof(zSql),
          "DELETE FROM cursor_table_%u WHERE id %% %u = 0;",
          tableId, (i % 5) + 2);
        break;
    }
    
    rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
    sqlite3_free(zErrMsg);
    if (rc && rc != SQLITE_INTERRUPT) break;
  }
  
  return SQLITE_OK;
}

/* Test concurrent access patterns */
int test_concurrent_access(FuzzCtx *pCtx, const TableCursorPacket *pPacket) {
  char zSql[1024];
  char *zErrMsg = 0;
  int rc;
  uint32_t i;
  
  /* Create multiple tables for concurrent testing */
  uint32_t tableCount = (pPacket->tableCount % 8) + 2;
  for(i = 0; i < tableCount; i++) {
    uint32_t tableId = (pPacket->tableIds[i % 8] % 100) + 300;
    
    snprintf(zSql, sizeof(zSql),
      "CREATE TABLE IF NOT EXISTS concurrent_table_%u("
      "id INTEGER PRIMARY KEY, "
      "shared_data BLOB, "
      "thread_id INTEGER"
      ");", tableId);
    rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
    sqlite3_free(zErrMsg);
  }
  
  /* Simulate concurrent operations with transaction patterns */
  uint32_t cursorCount = (pPacket->cursorCount % 10) + 1;
  for(i = 0; i < cursorCount; i++) {
    uint32_t tableId = (pPacket->tableIds[i % 8] % 100) + 300;
    
    /* Begin transaction */
    rc = sqlite3_exec(pCtx->db, "BEGIN IMMEDIATE;", 0, 0, &zErrMsg);
    sqlite3_free(zErrMsg);
    
    /* Multiple operations within transaction */
    uint32_t opsInTxn = (pPacket->testData[i % 32] % 10) + 1;
    uint32_t j;
    for(j = 0; j < opsInTxn; j++) {
      uint32_t dataSize = (pPacket->testData[(i+j) % 32] % 1500) + 100;
      
      snprintf(zSql, sizeof(zSql),
        "INSERT INTO concurrent_table_%u(shared_data, thread_id) VALUES("
        "randomblob(%u), %u);",
        tableId, dataSize, i);
      rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
      sqlite3_free(zErrMsg);
      
      /* Read from other tables */
      uint32_t readTableId = (pPacket->tableIds[(i+j+1) % 8] % 100) + 300;
      snprintf(zSql, sizeof(zSql),
        "SELECT count(*) FROM concurrent_table_%u WHERE thread_id != %u;",
        readTableId, i);
      rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
      sqlite3_free(zErrMsg);
    }
    
    /* Commit transaction */
    rc = sqlite3_exec(pCtx->db, "COMMIT;", 0, 0, &zErrMsg);
    sqlite3_free(zErrMsg);
  }
  
  return SQLITE_OK;
}

/* Test locking scenarios for shared cache */
int test_locking_scenarios(FuzzCtx *pCtx, const TableCursorPacket *pPacket) {
  char zSql[1024];
  char *zErrMsg = 0;
  int rc;
  uint32_t i;
  
  /* Create tables with different locking patterns */
  uint32_t tableCount = (pPacket->tableCount % 6) + 1;
  for(i = 0; i < tableCount; i++) {
    uint32_t tableId = (pPacket->tableIds[i % 8] % 100) + 400;
    
    snprintf(zSql, sizeof(zSql),
      "CREATE TABLE IF NOT EXISTS lock_table_%u("
      "id INTEGER PRIMARY KEY, "
      "lock_data BLOB, "
      "priority INTEGER"
      ");", tableId);
    rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
    sqlite3_free(zErrMsg);
  }
  
  /* Test various locking scenarios */
  uint32_t lockOperations = (pPacket->operationCount % 30) + 5;
  for(i = 0; i < lockOperations; i++) {
    uint32_t tableId = (pPacket->tableIds[i % 8] % 100) + 400;
    uint8_t lockType = pPacket->cursorFlags[i % 8];
    
    switch(lockType % 3) {
      case 0:
        /* Read lock scenario */
        snprintf(zSql, sizeof(zSql),
          "SELECT * FROM lock_table_%u WHERE priority = %u;",
          tableId, i % 10);
        break;
        
      case 1:
        /* Write lock scenario */
        snprintf(zSql, sizeof(zSql),
          "INSERT INTO lock_table_%u(lock_data, priority) VALUES("
          "randomblob(%u), %u);",
          tableId, (pPacket->testData[i % 32] % 1000) + 100, i % 10);
        break;
        
      default:
        /* Exclusive lock scenario */
        snprintf(zSql, sizeof(zSql),
          "UPDATE lock_table_%u SET priority = %u WHERE id = %u;",
          tableId, (i + 1) % 10, (i % 5) + 1);
        break;
    }
    
    rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
    sqlite3_free(zErrMsg);
  }
  
  return SQLITE_OK;
}

/* Test auto-vacuum interactions with table operations */
int test_autovacuum_interactions(FuzzCtx *pCtx, const TableCursorPacket *pPacket) {
  char zSql[1024];
  char *zErrMsg = 0;
  int rc;
  uint32_t i;
  
  /* Create tables that will trigger auto-vacuum */
  uint32_t tableCount = (pPacket->tableCount % 5) + 1;
  for(i = 0; i < tableCount; i++) {
    uint32_t tableId = (pPacket->tableIds[i % 8] % 100) + 500;
    
    snprintf(zSql, sizeof(zSql),
      "CREATE TABLE IF NOT EXISTS autovac_table_%u("
      "id INTEGER PRIMARY KEY, "
      "large_data BLOB"
      ");", tableId);
    rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
    sqlite3_free(zErrMsg);
    
    /* Fill table with large data to create fragmentation */
    uint32_t recordCount = (pPacket->testData[i % 32] % 50) + 20;
    uint32_t j;
    for(j = 0; j < recordCount; j++) {
      uint32_t dataSize = (pPacket->testData[(i+j) % 32] % 8000) + 2000;
      
      snprintf(zSql, sizeof(zSql),
        "INSERT INTO autovac_table_%u(large_data) VALUES(randomblob(%u));",
        tableId, dataSize);
      rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
      sqlite3_free(zErrMsg);
      if (rc && rc != SQLITE_INTERRUPT) break;
    }
    
    /* Delete some records to create holes */
    snprintf(zSql, sizeof(zSql),
      "DELETE FROM autovac_table_%u WHERE id %% %u = 0;",
      tableId, (i % 4) + 2);
    rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
    sqlite3_free(zErrMsg);
  }
  
  /* Drop and recreate tables to trigger auto-vacuum */
  for(i = 0; i < tableCount/2; i++) {
    uint32_t tableId = (pPacket->tableIds[i % 8] % 100) + 500;
    
    snprintf(zSql, sizeof(zSql), "DROP TABLE IF EXISTS autovac_table_%u;", tableId);
    rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
    sqlite3_free(zErrMsg);
    
    snprintf(zSql, sizeof(zSql),
      "CREATE TABLE autovac_table_%u(id INTEGER PRIMARY KEY, new_data BLOB);",
      tableId);
    rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
    sqlite3_free(zErrMsg);
  }
  
  return SQLITE_OK;
}

/* Test error conditions and corruption handling */
int test_error_conditions(FuzzCtx *pCtx, const TableCursorPacket *pPacket) {
  char zSql[1024];
  char *zErrMsg = 0;
  int rc;
  
  /* Enable integrity checking */
  sqlite3_exec(pCtx->db, "PRAGMA cell_size_check = ON;", 0, 0, &zErrMsg);
  sqlite3_free(zErrMsg);
  
  /* Test various error scenarios */
  uint32_t errorTests = (pPacket->corruptionMask % 10) + 1;
  uint32_t i;
  for(i = 0; i < errorTests; i++) {
    switch(i % 5) {
      case 0:
        /* Invalid table name */
        snprintf(zSql, sizeof(zSql), "CREATE TABLE IF NOT EXISTS \"invalid table %u\"(id INTEGER);", i);
        break;
        
      case 1:
        /* Large number of columns */
        snprintf(zSql, sizeof(zSql),
          "CREATE TABLE IF NOT EXISTS many_cols_%u("
          "c1 INT, c2 INT, c3 INT, c4 INT, c5 INT, c6 INT, c7 INT, c8 INT, "
          "c9 INT, c10 INT, c11 INT, c12 INT, c13 INT, c14 INT, c15 INT"
          ");", i);
        break;
        
      case 2:
        /* Attempt to drop non-existent table */
        snprintf(zSql, sizeof(zSql), "DROP TABLE nonexistent_table_%u;", i);
        break;
        
      case 3:
        /* Create table with same name */
        snprintf(zSql, sizeof(zSql), "CREATE TABLE error_table_%u(id INTEGER);", i % 3);
        break;
        
      default:
        /* Complex constraint scenario */
        snprintf(zSql, sizeof(zSql),
          "CREATE TABLE IF NOT EXISTS constraint_table_%u("
          "id INTEGER PRIMARY KEY, "
          "data BLOB UNIQUE, "
          "CHECK(length(data) > 0)"
          ");", i);
        break;
    }
    
    rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
    sqlite3_free(zErrMsg);
  }
  
  /* Run integrity check */
  sqlite3_exec(pCtx->db, "PRAGMA integrity_check(5);", 
               exec_handler, (void*)pCtx, &zErrMsg);
  sqlite3_free(zErrMsg);
  
  return SQLITE_OK;
}

/* Stress test with high load scenarios */
int stress_test_operations(FuzzCtx *pCtx, const TableCursorPacket *pPacket) {
  char zSql[1024];
  char *zErrMsg = 0;
  int rc;
  uint32_t i;
  
  /* Create multiple tables for stress testing */
  uint32_t stressTableCount = (pPacket->tableCount % 20) + 10;
  for(i = 0; i < stressTableCount; i++) {
    uint32_t tableId = (pPacket->tableIds[i % 8] % 1000) + 600;
    
    snprintf(zSql, sizeof(zSql),
      "CREATE TABLE IF NOT EXISTS stress_table_%u("
      "id INTEGER PRIMARY KEY, "
      "data BLOB"
      ");", tableId);
    rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
    sqlite3_free(zErrMsg);
    if (rc && rc != SQLITE_INTERRUPT) break;
  }
  
  /* High-frequency operations */
  uint32_t highFreqOps = (pPacket->operationCount % 200) + 100;
  for(i = 0; i < highFreqOps; i++) {
    uint32_t tableId = (pPacket->tableIds[i % 8] % 1000) + 600;
    uint32_t operation = pPacket->testData[i % 32] % 4;
    
    switch(operation) {
      case 0:
        snprintf(zSql, sizeof(zSql),
          "INSERT INTO stress_table_%u(data) VALUES(randomblob(%u));",
          tableId, (i % 1000) + 100);
        break;
      case 1:
        snprintf(zSql, sizeof(zSql),
          "SELECT count(*) FROM stress_table_%u;", tableId);
        break;
      case 2:
        snprintf(zSql, sizeof(zSql),
          "UPDATE stress_table_%u SET data = randomblob(%u) WHERE id = %u;",
          tableId, (i % 500) + 50, (i % 10) + 1);
        break;
      default:
        snprintf(zSql, sizeof(zSql),
          "DELETE FROM stress_table_%u WHERE id = %u;", tableId, i % 50 + 1);
        break;
    }
    
    rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
    sqlite3_free(zErrMsg);
    if (rc && rc != SQLITE_INTERRUPT) break;
  }
  
  return SQLITE_OK;
}

/* Enhanced table/cursor management fuzzing */
void fuzz_table_cursor_management(FuzzCtx *pCtx, const TableCursorPacket *pPacket) {
  /* Setup database environment */
  setup_tablecursor_database(pCtx, pPacket);
  
  /* Execute different test scenarios based on packet */
  uint32_t scenario = pPacket->scenario % 8;
  switch(scenario) {
    case TABLECURSOR_SCENARIO_NORMAL:
      /* Normal operations */
      test_table_lifecycle(pCtx, pPacket);
      test_cursor_operations(pCtx, pPacket);
      break;
      
    case TABLECURSOR_SCENARIO_LIFECYCLE:
      /* Complete lifecycle testing */
      test_table_lifecycle(pCtx, pPacket);
      break;
      
    case TABLECURSOR_SCENARIO_CONCURRENT:
      /* Concurrent access patterns */
      test_concurrent_access(pCtx, pPacket);
      test_cursor_operations(pCtx, pPacket);
      break;
      
    case TABLECURSOR_SCENARIO_LOCKING:
      /* Locking scenarios */
      test_locking_scenarios(pCtx, pPacket);
      test_concurrent_access(pCtx, pPacket);
      break;
      
    case TABLECURSOR_SCENARIO_AUTOVACUUM:
      /* Auto-vacuum interactions */
      test_autovacuum_interactions(pCtx, pPacket);
      test_table_lifecycle(pCtx, pPacket);
      break;
      
    case TABLECURSOR_SCENARIO_CORRUPTION:
      /* Error and corruption handling */
      test_error_conditions(pCtx, pPacket);
      test_cursor_operations(pCtx, pPacket);
      break;
      
    case TABLECURSOR_SCENARIO_STRESS:
      /* Stress testing */
      stress_test_operations(pCtx, pPacket);
      break;
      
    default:
      /* Comprehensive testing */
      test_table_lifecycle(pCtx, pPacket);
      test_cursor_operations(pCtx, pPacket);
      test_concurrent_access(pCtx, pPacket);
      test_locking_scenarios(pCtx, pPacket);
      test_autovacuum_interactions(pCtx, pPacket);
      test_error_conditions(pCtx, pPacket);
      break;
  }
}