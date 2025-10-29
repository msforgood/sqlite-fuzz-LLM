/*
** Cell Size Check Harness Implementation
** Target: btreeCellSizeCheck function (btree.c:2173)
** Function Code: btree_003
*/
#include "cell_check_harness.h"

void fuzz_cell_size_check(FuzzCtx *pCtx, const CellCheckPacket *pPacket) {
  if (!pCtx || !pPacket) return;
  
  /* Validate packet bounds */
  if (pPacket->pageType > 3) return;
  if (pPacket->cellCount > 1000) return;
  if (pPacket->pageSize < 512 || pPacket->pageSize > 65536) return;
  
  /* Test different page scenarios that trigger cell size checking */
  switch (pPacket->corruption & 0x0F) {
    case CELL_SCENARIO_VALID:
      /* Valid cell structure test */
      if (pCtx->db) {
        sqlite3_exec(pCtx->db, "CREATE TABLE IF NOT EXISTS t1(a PRIMARY KEY, b);", NULL, NULL, NULL);
        sqlite3_exec(pCtx->db, "INSERT INTO t1 VALUES(1, 'test');", NULL, NULL, NULL);
        sqlite3_exec(pCtx->db, "SELECT * FROM t1;", NULL, NULL, NULL);
      }
      break;
      
    case CELL_SCENARIO_OVERLAP:
      /* Cell overlap detection test */
      if (pCtx->db) {
        sqlite3_exec(pCtx->db, "CREATE TABLE IF NOT EXISTS t2(x);", NULL, NULL, NULL);
        /* Insert data to create various cell sizes */
        for (int i = 0; i < (pPacket->cellCount & 0x0F); i++) {
          char sql[128];
          int len = (pPacket->cellData[i % 20] & 0x1F) + 1;
          char *data = sqlite3_mprintf("%*c", len, 'A' + (i % 26));
          if (data) {
            snprintf(sql, sizeof(sql), "INSERT INTO t2 VALUES('%s');", data);
            sqlite3_exec(pCtx->db, sql, NULL, NULL, NULL);
            sqlite3_free(data);
          }
        }
        sqlite3_exec(pCtx->db, "PRAGMA integrity_check;", NULL, NULL, NULL);
      }
      break;
      
    case CELL_SCENARIO_OVERRUN:
      /* Cell overrun test */
      if (pCtx->db) {
        sqlite3_exec(pCtx->db, "CREATE TABLE IF NOT EXISTS t3(big TEXT);", NULL, NULL, NULL);
        /* Create large cell content */
        int size = (pPacket->corruptOffset & 0xFFFF) + 100;
        if (size > 10000) size = 10000; /* Limit size */
        char *bigData = sqlite3_mprintf("%*c", size, 'X');
        if (bigData) {
          char *sql = sqlite3_mprintf("INSERT INTO t3 VALUES('%s');", bigData);
          if (sql) {
            sqlite3_exec(pCtx->db, sql, NULL, NULL, NULL);
            sqlite3_free(sql);
          }
          sqlite3_free(bigData);
        }
      }
      break;
      
    case CELL_SCENARIO_UNDERRUN:
      /* Minimal cell size test */
      if (pCtx->db) {
        sqlite3_exec(pCtx->db, "CREATE TABLE IF NOT EXISTS t4(tiny);", NULL, NULL, NULL);
        sqlite3_exec(pCtx->db, "INSERT INTO t4 VALUES(NULL);", NULL, NULL, NULL);
        sqlite3_exec(pCtx->db, "INSERT INTO t4 VALUES('');", NULL, NULL, NULL);
        sqlite3_exec(pCtx->db, "INSERT INTO t4 VALUES(0);", NULL, NULL, NULL);
      }
      break;
      
    case CELL_SCENARIO_CORRUPT:
      /* Corruption detection stress test */
      if (pCtx->db) {
        /* Force database operations that exercise cell validation */
        sqlite3_exec(pCtx->db, "CREATE TABLE IF NOT EXISTS corrupt_test(id, data);", NULL, NULL, NULL);
        
        /* Insert pattern based on test data */
        for (int i = 0; i < 10; i++) {
          char sql[256];
          uint8_t pattern = pPacket->cellData[i % 20];
          snprintf(sql, sizeof(sql), "INSERT INTO corrupt_test VALUES(%d, %d);", 
                  i, pattern);
          sqlite3_exec(pCtx->db, sql, NULL, NULL, NULL);
        }
        
        /* Force page reorganization */
        sqlite3_exec(pCtx->db, "DELETE FROM corrupt_test WHERE id % 2 = 0;", NULL, NULL, NULL);
        sqlite3_exec(pCtx->db, "VACUUM;", NULL, NULL, NULL);
      }
      break;
      
    default:
      /* Mixed scenario test */
      if (pCtx->db) {
        sqlite3_exec(pCtx->db, "CREATE TABLE IF NOT EXISTS mixed(a, b, c);", NULL, NULL, NULL);
        
        /* Create mixed cell types and sizes */
        sqlite3_exec(pCtx->db, "INSERT INTO mixed VALUES(1, 'short', NULL);", NULL, NULL, NULL);
        sqlite3_exec(pCtx->db, "INSERT INTO mixed VALUES(2, 'medium_length_text', 12345);", NULL, NULL, NULL);
        
        /* Create index to exercise different page types */
        sqlite3_exec(pCtx->db, "CREATE INDEX IF NOT EXISTS idx_mixed ON mixed(a);", NULL, NULL, NULL);
        sqlite3_exec(pCtx->db, "SELECT * FROM mixed ORDER BY a;", NULL, NULL, NULL);
      }
      break;
  }
  
  /* Page size variation testing */
  if (pPacket->pageSize != 4096 && pCtx->db) {
    char pragma[64];
    snprintf(pragma, sizeof(pragma), "PRAGMA page_size=%u;", pPacket->pageSize);
    sqlite3_exec(pCtx->db, pragma, NULL, NULL, NULL);
    sqlite3_exec(pCtx->db, "VACUUM;", NULL, NULL, NULL);
  }
  
  /* Memory pressure testing */
  if (pPacket->cellData[19] & 0x80) {
    sqlite3_soft_heap_limit64(pPacket->cellData[18] * 1024);
    if (pCtx->db) {
      sqlite3_exec(pCtx->db, "CREATE TABLE IF NOT EXISTS pressure_test AS SELECT * FROM mixed;", NULL, NULL, NULL);
    }
    sqlite3_soft_heap_limit64(0);
  }
}