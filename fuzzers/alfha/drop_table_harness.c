/*
** Drop Table Harness Implementation
** Target: btreeDropTable function (btree.c:10289)
** Function Code: btree_006
*/
#include "drop_table_harness.h"

void fuzz_drop_table_operations(FuzzCtx *pCtx, const DropTablePacket *pPacket) {
  if (!pCtx || !pPacket) return;
  
  /* Validate packet bounds */
  if (pPacket->scenario > 10) return;
  if (pPacket->tableRoot < 2) return;
  
  if (!pCtx->db) return;
  
  sqlite3_exec(pCtx->db, "BEGIN;", NULL, NULL, NULL);
  
  /* Test different drop table scenarios */
  switch (pPacket->scenario & 0x0F) {
    case DROP_SCENARIO_BASIC:
      /* Basic table drop */
      {
        char sql[256];
        snprintf(sql, sizeof(sql), "CREATE TABLE IF NOT EXISTS drop_basic_%u (id INTEGER, data TEXT);", 
                pPacket->tableRoot & 0xFFFF);
        sqlite3_exec(pCtx->db, sql, NULL, NULL, NULL);
        
        /* Add some data */
        snprintf(sql, sizeof(sql), "INSERT INTO drop_basic_%u VALUES(1, 'test');", 
                pPacket->tableRoot & 0xFFFF);
        sqlite3_exec(pCtx->db, sql, NULL, NULL, NULL);
        
        /* Drop the table */
        snprintf(sql, sizeof(sql), "DROP TABLE IF EXISTS drop_basic_%u;", 
                pPacket->tableRoot & 0xFFFF);
        sqlite3_exec(pCtx->db, sql, NULL, NULL, NULL);
      }
      break;
      
    case DROP_SCENARIO_MULTIPLE:
      /* Multiple table drops */
      {
        int tableCount = (pPacket->dropMode & 0x0F) + 1;
        for (int i = 0; i < tableCount; i++) {
          char sql[512];
          uint32_t tableId = (pPacket->tableRoot + i) & 0xFFFF;
          
          /* Create table */
          snprintf(sql, sizeof(sql), "CREATE TABLE IF NOT EXISTS multi_drop_%u (col1, col2, col3);", tableId);
          sqlite3_exec(pCtx->db, sql, NULL, NULL, NULL);
          
          /* Insert data based on test data */
          for (int j = 0; j < (pPacket->testData[i % 20] & 0x0F); j++) {
            snprintf(sql, sizeof(sql), "INSERT INTO multi_drop_%u VALUES(%d, 'data_%d', %d);", 
                    tableId, j, j, pPacket->testData[j % 20]);
            sqlite3_exec(pCtx->db, sql, NULL, NULL, NULL);
          }
        }
        
        /* Drop tables in reverse order */
        for (int i = tableCount - 1; i >= 0; i--) {
          char sql[256];
          uint32_t tableId = (pPacket->tableRoot + i) & 0xFFFF;
          snprintf(sql, sizeof(sql), "DROP TABLE IF EXISTS multi_drop_%u;", tableId);
          sqlite3_exec(pCtx->db, sql, NULL, NULL, NULL);
        }
      }
      break;
      
    case DROP_SCENARIO_INDEXED:
      /* Drop table with indexes */
      {
        char sql[512];
        uint32_t tableId = pPacket->tableRoot & 0xFFFF;
        
        /* Create table with indexes */
        snprintf(sql, sizeof(sql), "CREATE TABLE IF NOT EXISTS indexed_drop_%u (a INTEGER, b TEXT, c REAL);", tableId);
        sqlite3_exec(pCtx->db, sql, NULL, NULL, NULL);
        
        snprintf(sql, sizeof(sql), "CREATE INDEX IF NOT EXISTS idx_a_%u ON indexed_drop_%u(a);", tableId, tableId);
        sqlite3_exec(pCtx->db, sql, NULL, NULL, NULL);
        
        snprintf(sql, sizeof(sql), "CREATE INDEX IF NOT EXISTS idx_b_%u ON indexed_drop_%u(b);", tableId, tableId);
        sqlite3_exec(pCtx->db, sql, NULL, NULL, NULL);
        
        snprintf(sql, sizeof(sql), "CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_%u ON indexed_drop_%u(a, b);", tableId, tableId);
        sqlite3_exec(pCtx->db, sql, NULL, NULL, NULL);
        
        /* Insert data */
        for (int i = 0; i < 10; i++) {
          char *text = sqlite3_mprintf("text_%d_%02x", i, pPacket->testData[i % 20]);
          if (text) {
            snprintf(sql, sizeof(sql), "INSERT OR IGNORE INTO indexed_drop_%u VALUES(%d, '%s', %f);", 
                    tableId, i, text, (double)i * 1.5);
            sqlite3_exec(pCtx->db, sql, NULL, NULL, NULL);
            sqlite3_free(text);
          }
        }
        
        /* Drop table (indexes should be dropped automatically) */
        snprintf(sql, sizeof(sql), "DROP TABLE IF EXISTS indexed_drop_%u;", tableId);
        sqlite3_exec(pCtx->db, sql, NULL, NULL, NULL);
      }
      break;
      
    case DROP_SCENARIO_LARGE:
      /* Drop table with large amounts of data */
      {
        char sql[512];
        uint32_t tableId = pPacket->tableRoot & 0xFFFF;
        
        snprintf(sql, sizeof(sql), "CREATE TABLE IF NOT EXISTS large_drop_%u (id INTEGER PRIMARY KEY, data BLOB);", tableId);
        sqlite3_exec(pCtx->db, sql, NULL, NULL, NULL);
        
        /* Insert larger data */
        int dataSize = (pPacket->expectedMoved & 0xFF) + 100;
        if (dataSize > 10000) dataSize = 10000; /* Limit size */
        
        for (int i = 0; i < (pPacket->dropMode & 0x1F); i++) {
          char *largeData = sqlite3_mprintf("%*c", dataSize, 'X');
          if (largeData) {
            snprintf(sql, sizeof(sql), "INSERT INTO large_drop_%u(data) VALUES('%s');", tableId, largeData);
            sqlite3_exec(pCtx->db, sql, NULL, NULL, NULL);
            sqlite3_free(largeData);
          }
        }
        
        /* Drop the large table */
        snprintf(sql, sizeof(sql), "DROP TABLE IF EXISTS large_drop_%u;", tableId);
        sqlite3_exec(pCtx->db, sql, NULL, NULL, NULL);
      }
      break;
      
    case DROP_SCENARIO_PARTIAL:
      /* Partial drop scenarios with rollback */
      {
        char sql[256];
        uint32_t tableId = pPacket->tableRoot & 0xFFFF;
        
        sqlite3_exec(pCtx->db, "SAVEPOINT drop_test;", NULL, NULL, NULL);
        
        snprintf(sql, sizeof(sql), "CREATE TABLE IF NOT EXISTS partial_drop_%u (x, y, z);", tableId);
        sqlite3_exec(pCtx->db, sql, NULL, NULL, NULL);
        
        snprintf(sql, sizeof(sql), "INSERT INTO partial_drop_%u VALUES(1, 2, 3);", tableId);
        sqlite3_exec(pCtx->db, sql, NULL, NULL, NULL);
        
        if (pPacket->testData[0] & 0x80) {
          /* Rollback instead of drop */
          sqlite3_exec(pCtx->db, "ROLLBACK TO drop_test;", NULL, NULL, NULL);
        } else {
          /* Complete the drop */
          snprintf(sql, sizeof(sql), "DROP TABLE partial_drop_%u;", tableId);
          sqlite3_exec(pCtx->db, sql, NULL, NULL, NULL);
          sqlite3_exec(pCtx->db, "RELEASE drop_test;", NULL, NULL, NULL);
        }
      }
      break;
      
    case DROP_SCENARIO_CASCADE:
      /* Drop with foreign key constraints (if enabled) */
      {
        char sql[512];
        uint32_t parentId = pPacket->tableRoot & 0xFFFF;
        uint32_t childId = (pPacket->tableRoot + 1) & 0xFFFF;
        
        /* Create parent table */
        snprintf(sql, sizeof(sql), "CREATE TABLE IF NOT EXISTS parent_%u (id INTEGER PRIMARY KEY, name TEXT);", parentId);
        sqlite3_exec(pCtx->db, sql, NULL, NULL, NULL);
        
        /* Create child table with foreign key */
        snprintf(sql, sizeof(sql), "CREATE TABLE IF NOT EXISTS child_%u (id INTEGER, parent_id INTEGER, FOREIGN KEY(parent_id) REFERENCES parent_%u(id));", childId, parentId);
        sqlite3_exec(pCtx->db, sql, NULL, NULL, NULL);
        
        /* Insert data */
        snprintf(sql, sizeof(sql), "INSERT INTO parent_%u VALUES(1, 'parent');", parentId);
        sqlite3_exec(pCtx->db, sql, NULL, NULL, NULL);
        
        snprintf(sql, sizeof(sql), "INSERT INTO child_%u VALUES(1, 1);", childId);
        sqlite3_exec(pCtx->db, sql, NULL, NULL, NULL);
        
        /* Try to drop parent (may fail due to foreign key) */
        snprintf(sql, sizeof(sql), "DROP TABLE IF EXISTS parent_%u;", parentId);
        sqlite3_exec(pCtx->db, sql, NULL, NULL, NULL);
        
        /* Drop child first, then parent */
        snprintf(sql, sizeof(sql), "DROP TABLE IF EXISTS child_%u;", childId);
        sqlite3_exec(pCtx->db, sql, NULL, NULL, NULL);
        
        snprintf(sql, sizeof(sql), "DROP TABLE IF EXISTS parent_%u;", parentId);
        sqlite3_exec(pCtx->db, sql, NULL, NULL, NULL);
      }
      break;
      
    default:
      /* Complex mixed scenario */
      {
        char sql[512];
        
        /* Create multiple tables with various characteristics */
        sqlite3_exec(pCtx->db, "CREATE TABLE IF NOT EXISTS temp_table_1(a, b);", NULL, NULL, NULL);
        sqlite3_exec(pCtx->db, "CREATE TABLE IF NOT EXISTS temp_table_2(x INTEGER PRIMARY KEY, y TEXT);", NULL, NULL, NULL);
        sqlite3_exec(pCtx->db, "CREATE TABLE IF NOT EXISTS temp_table_3(data BLOB);", NULL, NULL, NULL);
        
        /* Populate with test data */
        for (int i = 0; i < 5; i++) {
          snprintf(sql, sizeof(sql), "INSERT INTO temp_table_1 VALUES(%d, '%02x');", i, pPacket->testData[i % 20]);
          sqlite3_exec(pCtx->db, sql, NULL, NULL, NULL);
          
          snprintf(sql, sizeof(sql), "INSERT INTO temp_table_2(y) VALUES('data_%d');", i);
          sqlite3_exec(pCtx->db, sql, NULL, NULL, NULL);
        }
        
        /* Create view */
        sqlite3_exec(pCtx->db, "CREATE VIEW IF NOT EXISTS test_view AS SELECT * FROM temp_table_1 JOIN temp_table_2;", NULL, NULL, NULL);
        
        /* Drop in sequence */
        sqlite3_exec(pCtx->db, "DROP VIEW IF EXISTS test_view;", NULL, NULL, NULL);
        sqlite3_exec(pCtx->db, "DROP TABLE IF EXISTS temp_table_3;", NULL, NULL, NULL);
        sqlite3_exec(pCtx->db, "DROP TABLE IF EXISTS temp_table_2;", NULL, NULL, NULL);
        sqlite3_exec(pCtx->db, "DROP TABLE IF EXISTS temp_table_1;", NULL, NULL, NULL);
      }
      break;
  }
  
  /* Compaction after drops if requested */
  if (pPacket->compactAfter) {
    sqlite3_exec(pCtx->db, "VACUUM;", NULL, NULL, NULL);
  }
  
  /* Memory pressure testing */
  if (pPacket->testData[19] & 0x40) {
    sqlite3_soft_heap_limit64(pPacket->testData[18] * 1024);
    sqlite3_exec(pCtx->db, "CREATE TABLE IF NOT EXISTS pressure_drop AS SELECT 1;", NULL, NULL, NULL);
    sqlite3_exec(pCtx->db, "DROP TABLE IF EXISTS pressure_drop;", NULL, NULL, NULL);
    sqlite3_soft_heap_limit64(0);
  }
  
  sqlite3_exec(pCtx->db, "COMMIT;", NULL, NULL, NULL);
}