/*
** Cursor Harness Implementation
** Target: btreeCursor function (btree.c:4661)
** Function Code: btree_005
*/
#include "cursor_harness.h"

void fuzz_cursor_operations(FuzzCtx *pCtx, const CursorPacket *pPacket) {
  if (!pCtx || !pPacket) return;
  
  /* Validate packet bounds */
  if (pPacket->wrFlag > 2) return;
  if (pPacket->scenario > 10) return;
  if (pPacket->tableRoot < 2) return;
  
  /* Test different cursor scenarios */
  switch (pPacket->scenario & 0x0F) {
    case CURSOR_SCENARIO_BASIC:
      /* Basic cursor creation */
      if (pCtx->db) {
        sqlite3_exec(pCtx->db, "CREATE TABLE IF NOT EXISTS cursor_test(id INTEGER PRIMARY KEY, data TEXT);", NULL, NULL, NULL);
        sqlite3_exec(pCtx->db, "INSERT INTO cursor_test VALUES(1, 'test');", NULL, NULL, NULL);
        sqlite3_exec(pCtx->db, "SELECT * FROM cursor_test;", NULL, NULL, NULL);
      }
      break;
      
    case CURSOR_SCENARIO_READONLY:
      /* Read-only cursor operations */
      if (pCtx->db) {
        sqlite3_exec(pCtx->db, "CREATE TABLE IF NOT EXISTS readonly_test(a, b, c);", NULL, NULL, NULL);
        for (int i = 0; i < (pPacket->keyFields & 0x0F); i++) {
          char sql[256];
          snprintf(sql, sizeof(sql), "INSERT INTO readonly_test VALUES(%d, 'data_%d', %d);", 
                  i, i, pPacket->keyData[i % 20]);
          sqlite3_exec(pCtx->db, sql, NULL, NULL, NULL);
        }
        sqlite3_exec(pCtx->db, "SELECT COUNT(*) FROM readonly_test;", NULL, NULL, NULL);
      }
      break;
      
    case CURSOR_SCENARIO_WRITE:
      /* Write cursor operations */
      if (pCtx->db) {
        sqlite3_exec(pCtx->db, "CREATE TABLE IF NOT EXISTS write_test(key INTEGER, value BLOB);", NULL, NULL, NULL);
        
        /* Perform various write operations */
        for (int i = 0; i < (pPacket->keyFields & 0x1F); i++) {
          char sql[512];
          uint8_t pattern = pPacket->keyData[i % 20];
          char *data = sqlite3_mprintf("%*c", (pattern & 0x3F) + 1, 'A' + (i % 26));
          if (data) {
            snprintf(sql, sizeof(sql), "INSERT OR REPLACE INTO write_test VALUES(%d, '%s');", 
                    i + pPacket->tableRoot, data);
            sqlite3_exec(pCtx->db, sql, NULL, NULL, NULL);
            sqlite3_free(data);
          }
        }
        
        /* Test updates */
        sqlite3_exec(pCtx->db, "UPDATE write_test SET value = 'updated' WHERE key % 2 = 0;", NULL, NULL, NULL);
      }
      break;
      
    case CURSOR_SCENARIO_FORDELETE:
      /* Cursor for deletion operations */
      if (pCtx->db) {
        sqlite3_exec(pCtx->db, "CREATE TABLE IF NOT EXISTS delete_test(id, data);", NULL, NULL, NULL);
        
        /* Insert test data */
        for (int i = 0; i < 20; i++) {
          char sql[256];
          snprintf(sql, sizeof(sql), "INSERT INTO delete_test VALUES(%d, 'item_%d');", i, i);
          sqlite3_exec(pCtx->db, sql, NULL, NULL, NULL);
        }
        
        /* Selective deletion based on packet data */
        for (int i = 0; i < (pPacket->keyFields & 0x0F); i++) {
          char sql[256];
          int deleteId = pPacket->keyData[i % 20] % 20;
          snprintf(sql, sizeof(sql), "DELETE FROM delete_test WHERE id = %d;", deleteId);
          sqlite3_exec(pCtx->db, sql, NULL, NULL, NULL);
        }
      }
      break;
      
    case CURSOR_SCENARIO_KEYINFO:
      /* Complex key info cursor operations */
      if (pCtx->db) {
        sqlite3_exec(pCtx->db, "CREATE TABLE IF NOT EXISTS keyinfo_test(a INTEGER, b TEXT, c REAL);", NULL, NULL, NULL);
        
        /* Create index to exercise key info */
        sqlite3_exec(pCtx->db, "CREATE INDEX IF NOT EXISTS idx_keyinfo ON keyinfo_test(b, c);", NULL, NULL, NULL);
        
        /* Insert diverse data */
        for (int i = 0; i < (pPacket->keyFields & 0x1F); i++) {
          char sql[512];
          uint8_t pattern = pPacket->keyData[i % 20];
          char *text = sqlite3_mprintf("key_%02x_%d", pattern, i);
          double real_val = (double)(pattern * i) / 100.0;
          
          if (text) {
            snprintf(sql, sizeof(sql), "INSERT INTO keyinfo_test VALUES(%d, '%s', %f);", 
                    i, text, real_val);
            sqlite3_exec(pCtx->db, sql, NULL, NULL, NULL);
            sqlite3_free(text);
          }
        }
        
        /* Complex queries using index */
        sqlite3_exec(pCtx->db, "SELECT * FROM keyinfo_test ORDER BY b, c;", NULL, NULL, NULL);
        sqlite3_exec(pCtx->db, "SELECT * FROM keyinfo_test WHERE b LIKE 'key_%' ORDER BY c DESC;", NULL, NULL, NULL);
      }
      break;
      
    case CURSOR_SCENARIO_STRESS:
      /* Stress test with multiple cursors */
      if (pCtx->db) {
        /* Create multiple tables */
        for (int t = 0; t < (pPacket->keyType & 0x07) + 1; t++) {
          char sql[256];
          snprintf(sql, sizeof(sql), "CREATE TABLE IF NOT EXISTS stress_table_%d(id, data);", t);
          sqlite3_exec(pCtx->db, sql, NULL, NULL, NULL);
        }
        
        /* Interleaved operations across tables */
        for (int op = 0; op < (pPacket->keyFields & 0x3F); op++) {
          int table_id = op % ((pPacket->keyType & 0x07) + 1);
          char sql[512];
          
          if (op % 3 == 0) {
            /* Insert */
            snprintf(sql, sizeof(sql), "INSERT INTO stress_table_%d VALUES(%d, 'data_%d');", 
                    table_id, op, pPacket->keyData[op % 20]);
          } else if (op % 3 == 1) {
            /* Select */
            snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM stress_table_%d;", table_id);
          } else {
            /* Update/Delete */
            snprintf(sql, sizeof(sql), "UPDATE stress_table_%d SET data = 'updated_%d' WHERE id %% 4 = %d;", 
                    table_id, op, op % 4);
          }
          
          sqlite3_exec(pCtx->db, sql, NULL, NULL, NULL);
        }
      }
      break;
      
    default:
      /* Multi-scenario test */
      if (pCtx->db) {
        sqlite3_exec(pCtx->db, "CREATE TABLE IF NOT EXISTS multi_test(pk INTEGER PRIMARY KEY, col1, col2, col3);", NULL, NULL, NULL);
        
        /* Mixed operations */
        sqlite3_exec(pCtx->db, "INSERT INTO multi_test VALUES(1, 'a', 'b', 'c');", NULL, NULL, NULL);
        sqlite3_exec(pCtx->db, "INSERT INTO multi_test VALUES(2, 'x', 'y', 'z');", NULL, NULL, NULL);
        sqlite3_exec(pCtx->db, "SELECT * FROM multi_test WHERE pk = 1;", NULL, NULL, NULL);
        sqlite3_exec(pCtx->db, "UPDATE multi_test SET col1 = 'updated' WHERE pk = 2;", NULL, NULL, NULL);
        sqlite3_exec(pCtx->db, "DELETE FROM multi_test WHERE pk = 1;", NULL, NULL, NULL);
      }
      break;
  }
  
  /* Page size variation testing */
  if (pPacket->keyData[19] & 0x40) {
    char pragma[64];
    uint32_t pageSize = 512 << (pPacket->keyType & 0x07);  /* 512, 1024, 2048, 4096, etc. */
    if (pageSize <= 65536) {
      snprintf(pragma, sizeof(pragma), "PRAGMA page_size=%u;", pageSize);
      sqlite3_exec(pCtx->db, pragma, NULL, NULL, NULL);
      sqlite3_exec(pCtx->db, "VACUUM;", NULL, NULL, NULL);
    }
  }
  
  /* Memory pressure testing */
  if (pPacket->keyData[18] & 0x80) {
    sqlite3_soft_heap_limit64(pPacket->keyData[17] * 1024);
    if (pCtx->db) {
      sqlite3_exec(pCtx->db, "CREATE TABLE IF NOT EXISTS pressure_cursor AS SELECT * FROM multi_test;", NULL, NULL, NULL);
    }
    sqlite3_soft_heap_limit64(0);
  }
}