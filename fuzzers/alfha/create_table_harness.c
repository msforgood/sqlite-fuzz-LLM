/*
** Create Table Harness Implementation
** Target: btreeCreateTable function (btree.c:10015)
** Function Code: btree_004
*/
#include "create_table_harness.h"

void fuzz_create_table(FuzzCtx *pCtx, const CreateTablePacket *pPacket) {
  if (!pCtx || !pPacket) return;
  
  /* Validate packet bounds */
  if (pPacket->scenario > 10) return;
  if (pPacket->initialPages > 1000) return;
  
  /* Initialize transaction for table creation */
  if (!pCtx->db) return;
  
  sqlite3_exec(pCtx->db, "BEGIN;", NULL, NULL, NULL);
  
  /* Test different table creation scenarios */
  switch (pPacket->scenario & 0x0F) {
    case CREATE_SCENARIO_BASIC:
      /* Basic table creation */
      {
        char sql[256];
        snprintf(sql, sizeof(sql), "CREATE TABLE IF NOT EXISTS test_table_%u (id INTEGER PRIMARY KEY, data TEXT);", 
                pPacket->tableId & 0xFFFF);
        sqlite3_exec(pCtx->db, sql, NULL, NULL, NULL);
      }
      break;
      
    case CREATE_SCENARIO_INTKEY:
      /* Integer key table */
      {
        char sql[256];
        snprintf(sql, sizeof(sql), "CREATE TABLE IF NOT EXISTS intkey_table_%u (key INTEGER, value BLOB);", 
                pPacket->tableId & 0xFFFF);
        sqlite3_exec(pCtx->db, sql, NULL, NULL, NULL);
      }
      break;
      
    case CREATE_SCENARIO_INDEX:
      /* Table with indexes */
      {
        char sql[512];
        snprintf(sql, sizeof(sql), "CREATE TABLE IF NOT EXISTS indexed_table_%u (a INTEGER, b TEXT, c REAL);", 
                pPacket->tableId & 0xFFFF);
        sqlite3_exec(pCtx->db, sql, NULL, NULL, NULL);
        
        snprintf(sql, sizeof(sql), "CREATE INDEX IF NOT EXISTS idx_%u_a ON indexed_table_%u(a);", 
                pPacket->tableId & 0xFFFF, pPacket->tableId & 0xFFFF);
        sqlite3_exec(pCtx->db, sql, NULL, NULL, NULL);
        
        snprintf(sql, sizeof(sql), "CREATE INDEX IF NOT EXISTS idx_%u_b ON indexed_table_%u(b);", 
                pPacket->tableId & 0xFFFF, pPacket->tableId & 0xFFFF);
        sqlite3_exec(pCtx->db, sql, NULL, NULL, NULL);
      }
      break;
      
    case CREATE_SCENARIO_STRESS:
      /* Multiple table creation stress test */
      {
        int count = (pPacket->createFlags & 0x0F) + 1;
        for (int i = 0; i < count; i++) {
          char sql[256];
          snprintf(sql, sizeof(sql), "CREATE TABLE IF NOT EXISTS stress_table_%d_%u (col1, col2, col3);", 
                  i, pPacket->tableId & 0xFFFF);
          sqlite3_exec(pCtx->db, sql, NULL, NULL, NULL);
        }
      }
      break;
      
    case CREATE_SCENARIO_FULL:
      /* Test under full/near-full conditions */
      {
        /* Fill database to simulate full condition */
        sqlite3_exec(pCtx->db, "CREATE TABLE IF NOT EXISTS filler AS SELECT randomblob(1000) as data;", NULL, NULL, NULL);
        
        /* Try to create table under pressure */
        char sql[256];
        snprintf(sql, sizeof(sql), "CREATE TABLE IF NOT EXISTS full_test_%u (emergency TEXT);", 
                pPacket->tableId & 0xFFFF);
        sqlite3_exec(pCtx->db, sql, NULL, NULL, NULL);
      }
      break;
      
    default:
      /* Complex schema creation */
      {
        char sql[1024];
        snprintf(sql, sizeof(sql), 
                "CREATE TABLE IF NOT EXISTS complex_%u ("
                "id INTEGER PRIMARY KEY, "
                "name TEXT NOT NULL, "
                "value REAL, "
                "data BLOB, "
                "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
                ");", pPacket->tableId & 0xFFFF);
        sqlite3_exec(pCtx->db, sql, NULL, NULL, NULL);
        
        /* Add constraints and triggers */
        snprintf(sql, sizeof(sql), 
                "CREATE UNIQUE INDEX IF NOT EXISTS unique_%u ON complex_%u(name);", 
                pPacket->tableId & 0xFFFF, pPacket->tableId & 0xFFFF);
        sqlite3_exec(pCtx->db, sql, NULL, NULL, NULL);
      }
      break;
  }
  
  /* Test with different page types and flags */
  if (pPacket->createFlags & 0x10) {
    /* WITHOUT ROWID table */
    char sql[256];
    snprintf(sql, sizeof(sql), "CREATE TABLE IF NOT EXISTS without_rowid_%u (key TEXT PRIMARY KEY, val) WITHOUT ROWID;", 
            pPacket->tableId & 0xFFFF);
    sqlite3_exec(pCtx->db, sql, NULL, NULL, NULL);
  }
  
  /* Test virtual table creation if supported */
  if (pPacket->createFlags & 0x20) {
    sqlite3_exec(pCtx->db, "CREATE VIRTUAL TABLE IF NOT EXISTS fts_test USING fts5(content);", NULL, NULL, NULL);
  }
  
  /* Insert test data to trigger page allocations */
  if (pPacket->testData[0] & 0x80) {
    int insertCount = (pPacket->testData[1] & 0x1F) + 1;
    for (int i = 0; i < insertCount; i++) {
      char sql[512];
      char *testStr = sqlite3_mprintf("test_data_%d_%02x", i, pPacket->testData[i % 20]);
      if (testStr) {
        snprintf(sql, sizeof(sql), "INSERT OR IGNORE INTO test_table_%u VALUES(%d, '%s');", 
                pPacket->tableId & 0xFFFF, i, testStr);
        sqlite3_exec(pCtx->db, sql, NULL, NULL, NULL);
        sqlite3_free(testStr);
      }
    }
  }
  
  /* Memory pressure testing */
  if (pPacket->testData[19] & 0x40) {
    sqlite3_soft_heap_limit64(pPacket->testData[18] * 1024);
    char sql[256];
    snprintf(sql, sizeof(sql), "CREATE TABLE IF NOT EXISTS pressure_table_%u AS SELECT * FROM test_table_%u;", 
            (pPacket->tableId + 1) & 0xFFFF, pPacket->tableId & 0xFFFF);
    sqlite3_exec(pCtx->db, sql, NULL, NULL, NULL);
    sqlite3_soft_heap_limit64(0);
  }
  
  sqlite3_exec(pCtx->db, "COMMIT;", NULL, NULL, NULL);
}