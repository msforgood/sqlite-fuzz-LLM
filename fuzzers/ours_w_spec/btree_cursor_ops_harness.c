/*
** B-Tree Cursor Operations Harness Implementation
** Target functions: btreeMoveto, btreeOverwriteCell, btreeOverwriteContent
** Specification-based fuzzing for B-Tree cursor and content operations
*/
#include "btree_cursor_ops_harness.h"

/* Helper function to create test data structure */
static void setup_test_table(sqlite3 *db, const char *tableName, int withIndex) {
  char *zSql;
  
  /* Create test table */
  zSql = sqlite3_mprintf("CREATE TABLE IF NOT EXISTS %s ("
                        "id INTEGER PRIMARY KEY, "
                        "data BLOB, "
                        "text_val TEXT, "
                        "real_val REAL)", tableName);
  if( zSql ) {
    sqlite3_exec(db, zSql, 0, 0, 0);
    sqlite3_free(zSql);
  }
  
  if( withIndex ) {
    /* Create index for cursor positioning tests */
    zSql = sqlite3_mprintf("CREATE INDEX IF NOT EXISTS idx_%s_data ON %s(data)", 
                          tableName, tableName);
    if( zSql ) {
      sqlite3_exec(db, zSql, 0, 0, 0);
      sqlite3_free(zSql);
    }
  }
  
  /* Insert some test data */
  zSql = sqlite3_mprintf("INSERT OR IGNORE INTO %s VALUES "
                        "(1, X'deadbeef', 'test1', 1.23), "
                        "(2, X'cafebabe', 'test2', 4.56), "
                        "(3, X'feedface', 'test3', 7.89)", tableName);
  if( zSql ) {
    sqlite3_exec(db, zSql, 0, 0, 0);
    sqlite3_free(zSql);
  }
}

/*
** Fuzz btreeMoveto function (btree.c:860)
** FC: btree_moveto_001
*/
void fuzz_btree_moveto(FuzzCtx *pCtx, const MovetoPacket *pPacket) {
  if( !pCtx || !pCtx->db || !pPacket ) return;
  
  /* Validate packet constraints from spec */
  if( pPacket->nKey > 2147483647 ) return;  /* Max key size */
  if( pPacket->bias < 253 || pPacket->bias > 255 ) return;  /* Bias range -1,0,1 mapped to 253,254,255 */
  
  int rc;
  sqlite3_stmt *pStmt = NULL;
  const char *tableName = "moveto_test";
  
  /* Setup test environment */
  setup_test_table(pCtx->db, tableName, 1);
  
  /* Scenario-based testing */
  uint8_t scenario = pPacket->scenario % 8;
  
  switch( scenario ) {
    case 0: /* Integer key search on table */
      rc = sqlite3_prepare_v2(pCtx->db, "SELECT * FROM moveto_test WHERE id = ?", -1, &pStmt, 0);
      if( rc == SQLITE_OK && pStmt ) {
        sqlite3_bind_int64(pStmt, 1, (sqlite3_int64)(pPacket->nKey % 1000));
        sqlite3_step(pStmt);
      }
      break;
      
    case 1: /* BLOB key search on index */
      rc = sqlite3_prepare_v2(pCtx->db, "SELECT * FROM moveto_test WHERE data = ?", -1, &pStmt, 0);
      if( rc == SQLITE_OK && pStmt ) {
        sqlite3_bind_blob(pStmt, 1, pPacket->keyData, 
                         (pPacket->nKey % 16) + 1, SQLITE_STATIC);
        sqlite3_step(pStmt);
      }
      break;
      
    case 2: /* Text key search */
      rc = sqlite3_prepare_v2(pCtx->db, "SELECT * FROM moveto_test WHERE text_val = ?", -1, &pStmt, 0);
      if( rc == SQLITE_OK && pStmt ) {
        char textKey[17];
        memcpy(textKey, pPacket->keyData, 16);
        textKey[16] = '\0';
        sqlite3_bind_text(pStmt, 1, textKey, -1, SQLITE_STATIC);
        sqlite3_step(pStmt);
      }
      break;
      
    case 3: /* Range search with bias */
      rc = sqlite3_prepare_v2(pCtx->db, "SELECT * FROM moveto_test WHERE id > ? ORDER BY id", -1, &pStmt, 0);
      if( rc == SQLITE_OK && pStmt ) {
        sqlite3_bind_int(pStmt, 1, (int)(pPacket->nKey % 10));
        sqlite3_step(pStmt);
      }
      break;
      
    case 4: /* Cursor positioning on empty range */
      rc = sqlite3_prepare_v2(pCtx->db, "SELECT * FROM moveto_test WHERE id > 999999", -1, &pStmt, 0);
      if( rc == SQLITE_OK && pStmt ) {
        sqlite3_step(pStmt);
      }
      break;
      
    case 5: /* NULL key handling */
      rc = sqlite3_prepare_v2(pCtx->db, "SELECT * FROM moveto_test WHERE data IS NULL", -1, &pStmt, 0);
      if( rc == SQLITE_OK && pStmt ) {
        sqlite3_step(pStmt);
      }
      break;
      
    case 6: /* Complex index search */
      rc = sqlite3_prepare_v2(pCtx->db, "SELECT * FROM moveto_test WHERE data BETWEEN ? AND ?", -1, &pStmt, 0);
      if( rc == SQLITE_OK && pStmt ) {
        sqlite3_bind_blob(pStmt, 1, pPacket->keyData, 8, SQLITE_STATIC);
        sqlite3_bind_blob(pStmt, 2, pPacket->keyData + 8, 8, SQLITE_STATIC);
        sqlite3_step(pStmt);
      }
      break;
      
    case 7: /* Corrupted key scenario */
      if( pPacket->cursorState & 1 ) {
        /* Simulate corrupted UnpackedRecord scenario */
        rc = sqlite3_prepare_v2(pCtx->db, "SELECT * FROM moveto_test WHERE data = X'FF'", -1, &pStmt, 0);
        if( rc == SQLITE_OK && pStmt ) {
          sqlite3_step(pStmt);
        }
      }
      break;
  }
  
  if( pStmt ) {
    sqlite3_finalize(pStmt);
  }
}

/*
** Fuzz btreeOverwriteCell function (btree.c:9320)  
** FC: btree_overwrite_cell_001
*/
void fuzz_btree_overwrite_cell(FuzzCtx *pCtx, const OverwriteCellPacket *pPacket) {
  if( !pCtx || !pCtx->db || !pPacket ) return;
  
  /* Validate packet constraints */
  if( pPacket->nData > 1000000000 ) return;  /* Max data size */
  if( pPacket->localSize > 65536 ) return;   /* Max local size */
  
  int rc;
  sqlite3_stmt *pStmt = NULL;
  const char *tableName = "overwrite_cell_test";
  
  /* Setup test environment */
  setup_test_table(pCtx->db, tableName, 0);
  
  /* Scenario-based cell overwrite testing */
  uint8_t scenario = pPacket->scenario % 6;
  
  switch( scenario ) {
    case 0: /* Small data overwrite (local only) */
      rc = sqlite3_prepare_v2(pCtx->db, "UPDATE overwrite_cell_test SET data = ? WHERE id = 1", -1, &pStmt, 0);
      if( rc == SQLITE_OK && pStmt ) {
        /* Create small payload that fits in local storage */
        uint8_t smallData[12];
        memcpy(smallData, pPacket->payloadData, 12);
        sqlite3_bind_blob(pStmt, 1, smallData, 12, SQLITE_STATIC);
        sqlite3_step(pStmt);
      }
      break;
      
    case 1: /* Large data overwrite (with overflow) */
      rc = sqlite3_prepare_v2(pCtx->db, "UPDATE overwrite_cell_test SET data = ? WHERE id = 2", -1, &pStmt, 0);
      if( rc == SQLITE_OK && pStmt ) {
        /* Create large payload that requires overflow pages */
        size_t largeSize = (pPacket->nData % 8192) + 1024;
        uint8_t *largeData = sqlite3_malloc64(largeSize);
        if( largeData ) {
          memset(largeData, pPacket->payloadData[0], largeSize);
          sqlite3_bind_blob(pStmt, 1, largeData, (int)largeSize, sqlite3_free);
          sqlite3_step(pStmt);
        }
      }
      break;
      
    case 2: /* Text content overwrite */
      rc = sqlite3_prepare_v2(pCtx->db, "UPDATE overwrite_cell_test SET text_val = ? WHERE id = 1", -1, &pStmt, 0);
      if( rc == SQLITE_OK && pStmt ) {
        char textData[256];
        size_t textLen = (pPacket->nData % 200) + 1;
        memset(textData, pPacket->payloadData[1] % 95 + 32, textLen);  /* Printable ASCII */
        textData[textLen] = '\0';
        sqlite3_bind_text(pStmt, 1, textData, -1, SQLITE_STATIC);
        sqlite3_step(pStmt);
      }
      break;
      
    case 3: /* Zero-length data */
      rc = sqlite3_prepare_v2(pCtx->db, "UPDATE overwrite_cell_test SET data = ? WHERE id = 3", -1, &pStmt, 0);
      if( rc == SQLITE_OK && pStmt ) {
        sqlite3_bind_blob(pStmt, 1, "", 0, SQLITE_STATIC);
        sqlite3_step(pStmt);
      }
      break;
      
    case 4: /* NULL overwrite */
      rc = sqlite3_prepare_v2(pCtx->db, "UPDATE overwrite_cell_test SET data = NULL WHERE id = 1", -1, &pStmt, 0);
      if( rc == SQLITE_OK && pStmt ) {
        sqlite3_step(pStmt);
      }
      break;
      
    case 5: /* Mixed content overwrite */
      if( pPacket->nZero > 0 && pPacket->nZero < 1000 ) {
        rc = sqlite3_prepare_v2(pCtx->db, "UPDATE overwrite_cell_test SET data = ? WHERE id = 2", -1, &pStmt, 0);
        if( rc == SQLITE_OK && pStmt ) {
          /* Create data with zero padding */
          size_t totalSize = 12 + (pPacket->nZero % 100);
          uint8_t *mixedData = sqlite3_malloc64(totalSize);
          if( mixedData ) {
            memcpy(mixedData, pPacket->payloadData, 12);
            memset(mixedData + 12, 0, totalSize - 12);
            sqlite3_bind_blob(pStmt, 1, mixedData, (int)totalSize, sqlite3_free);
            sqlite3_step(pStmt);
          }
        }
      }
      break;
  }
  
  if( pStmt ) {
    sqlite3_finalize(pStmt);
  }
}

/*
** Fuzz btreeOverwriteContent function (btree.c:9225)
** FC: btree_overwrite_content_001  
*/
void fuzz_btree_overwrite_content(FuzzCtx *pCtx, const OverwriteContentPacket *pPacket) {
  if( !pCtx || !pCtx->db || !pPacket ) return;
  
  /* Validate packet constraints */
  if( pPacket->iOffset > 65536 ) return;  /* Max offset */
  if( pPacket->iAmt > 65536 ) return;     /* Max amount */
  
  int rc;
  sqlite3_stmt *pStmt = NULL;
  const char *tableName = "overwrite_content_test";
  
  /* Setup test environment */
  setup_test_table(pCtx->db, tableName, 0);
  
  /* Scenario-based content overwrite testing */
  uint8_t scenario = pPacket->scenario % 5;
  
  switch( scenario ) {
    case 0: /* Direct data overwrite */
      rc = sqlite3_prepare_v2(pCtx->db, "UPDATE overwrite_content_test SET data = ? WHERE id = 1", -1, &pStmt, 0);
      if( rc == SQLITE_OK && pStmt ) {
        /* Create content based on write mode */
        size_t contentSize = (pPacket->iAmt % 1024) + 16;
        uint8_t *content = sqlite3_malloc64(contentSize);
        if( content ) {
          if( pPacket->writeMode == 0 ) {
            /* DATA mode - copy pattern */
            for( size_t i = 0; i < contentSize; i++ ) {
              content[i] = pPacket->contentData[i % 16];
            }
          } else if( pPacket->writeMode == 1 ) {
            /* ZERO mode - zero fill */
            memset(content, 0, contentSize);
          } else {
            /* MIXED mode - pattern + zeros */
            size_t dataLen = contentSize / 2;
            for( size_t i = 0; i < dataLen; i++ ) {
              content[i] = pPacket->contentData[i % 16];
            }
            memset(content + dataLen, 0, contentSize - dataLen);
          }
          sqlite3_bind_blob(pStmt, 1, content, (int)contentSize, sqlite3_free);
          sqlite3_step(pStmt);
        }
      }
      break;
      
    case 1: /* Partial content update */
      rc = sqlite3_prepare_v2(pCtx->db, "UPDATE overwrite_content_test SET text_val = ? WHERE id = 2", -1, &pStmt, 0);
      if( rc == SQLITE_OK && pStmt ) {
        char textContent[512];
        size_t textLen = (pPacket->iAmt % 400) + 1;
        
        /* Fill based on alignment test */
        char fillChar = (pPacket->alignment % 95) + 32;  /* Printable ASCII */
        memset(textContent, fillChar, textLen);
        textContent[textLen] = '\0';
        
        sqlite3_bind_text(pStmt, 1, textContent, -1, SQLITE_STATIC);
        sqlite3_step(pStmt);
      }
      break;
      
    case 2: /* Zero-offset overwrite */
      rc = sqlite3_prepare_v2(pCtx->db, "UPDATE overwrite_content_test SET data = ? WHERE id = 3", -1, &pStmt, 0);
      if( rc == SQLITE_OK && pStmt ) {
        sqlite3_bind_blob(pStmt, 1, pPacket->contentData, 16, SQLITE_STATIC);
        sqlite3_step(pStmt);
      }
      break;
      
    case 3: /* Boundary condition testing */
      if( pPacket->iAmt > 0 && pPacket->iAmt <= 16 ) {
        rc = sqlite3_prepare_v2(pCtx->db, "UPDATE overwrite_content_test SET data = ? WHERE id = 1", -1, &pStmt, 0);
        if( rc == SQLITE_OK && pStmt ) {
          sqlite3_bind_blob(pStmt, 1, pPacket->contentData, pPacket->iAmt, SQLITE_STATIC);
          sqlite3_step(pStmt);
        }
      }
      break;
      
    case 4: /* Memory alignment edge case */
      if( pPacket->alignment % 8 == 0 ) {  /* 8-byte alignment test */
        rc = sqlite3_prepare_v2(pCtx->db, "UPDATE overwrite_content_test SET real_val = ? WHERE id = 2", -1, &pStmt, 0);
        if( rc == SQLITE_OK && pStmt ) {
          double realVal;
          memcpy(&realVal, pPacket->contentData, sizeof(double));
          sqlite3_bind_double(pStmt, 1, realVal);
          sqlite3_step(pStmt);
        }
      }
      break;
  }
  
  if( pStmt ) {
    sqlite3_finalize(pStmt);
  }
}