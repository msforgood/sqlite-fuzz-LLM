/*
** VDBE Auxiliary Extended Functions Harness Implementation
** Target functions: columnMallocFailure, freeP4, vdbeAssertFieldCountWithinLimits
** Specification-based fuzzing for VDBE auxiliary operations
*/
#include "vdbe_auxiliary_extended_harness.h"

/* Helper function to setup test environment with statements */
static void setup_test_statements(sqlite3 *db, int count) {
  char *zSql;
  sqlite3_stmt *pStmt;
  int i;
  
  /* Create test table */
  sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS vdbe_test ("
                   "id INTEGER PRIMARY KEY, "
                   "data TEXT, "
                   "value REAL)", 0, 0, 0);
  
  /* Prepare multiple statements */
  for( i = 0; i < count && i < 10; i++ ) {
    zSql = sqlite3_mprintf("SELECT * FROM vdbe_test WHERE id = %d", i);
    if( zSql ) {
      sqlite3_prepare_v2(db, zSql, -1, &pStmt, 0);
      sqlite3_free(zSql);
      if( pStmt ) {
        sqlite3_finalize(pStmt);
      }
    }
  }
}

/*
** Fuzz columnMallocFailure function (vdbeapi.c:1343)
** FC: vdbe_column_malloc_failure_001
*/
void fuzz_column_malloc_failure(FuzzCtx *pCtx, const ColumnMallocFailurePacket *pPacket) {
  if( !pCtx || !pCtx->db || !pPacket ) return;
  
  /* Validate packet constraints */
  if( pPacket->mallocSize > 100000000 ) return;  /* Reasonable malloc size limit */
  
  int rc;
  sqlite3_stmt *pStmt = NULL;
  
  /* Setup test environment */
  setup_test_statements(pCtx->db, 3);
  
  /* Scenario-based testing */
  uint8_t scenario = pPacket->scenario % 6;
  
  switch( scenario ) {
    case 0: /* Text column with encoding conversion */
      rc = sqlite3_prepare_v2(pCtx->db, "SELECT 'test' || ?", -1, &pStmt, 0);
      if( rc == SQLITE_OK && pStmt ) {
        /* Create large text to potentially trigger malloc failure */
        size_t textSize = (pPacket->mallocSize % 10000) + 100;
        char *largeText = sqlite3_malloc64(textSize);
        if( largeText ) {
          memset(largeText, 'A' + (pPacket->testData[0] % 26), textSize - 1);
          largeText[textSize - 1] = '\0';
          sqlite3_bind_text(pStmt, 1, largeText, -1, sqlite3_free);
          sqlite3_step(pStmt);
          /* Try to access column with potential encoding conversion */
          sqlite3_column_text(pStmt, 0);
        }
      }
      break;
      
    case 1: /* BLOB column access */
      rc = sqlite3_prepare_v2(pCtx->db, "SELECT randomblob(?)", -1, &pStmt, 0);
      if( rc == SQLITE_OK && pStmt ) {
        sqlite3_bind_int(pStmt, 1, (pPacket->mallocSize % 1000) + 10);
        sqlite3_step(pStmt);
        sqlite3_column_blob(pStmt, 0);
        sqlite3_column_bytes(pStmt, 0);
      }
      break;
      
    case 2: /* Multiple column access */
      rc = sqlite3_prepare_v2(pCtx->db, "SELECT ?, ?, ?", -1, &pStmt, 0);
      if( rc == SQLITE_OK && pStmt ) {
        sqlite3_bind_text(pStmt, 1, "test1", -1, SQLITE_STATIC);
        sqlite3_bind_text(pStmt, 2, "test2", -1, SQLITE_STATIC);
        sqlite3_bind_text(pStmt, 3, "test3", -1, SQLITE_STATIC);
        sqlite3_step(pStmt);
        
        /* Access columns in different encodings */
        sqlite3_column_text(pStmt, 0);
        sqlite3_column_text16(pStmt, 1);
        sqlite3_column_text(pStmt, 2);
      }
      break;
      
    case 3: /* Column access with UTF-16 conversion */
      rc = sqlite3_prepare_v2(pCtx->db, "SELECT ? || 'suffix'", -1, &pStmt, 0);
      if( rc == SQLITE_OK && pStmt ) {
        /* Bind text that may require encoding conversion */
        char *testText = sqlite3_mprintf("prefix_%.*s", 
                                        (int)(pPacket->mallocSize % 100),
                                        pPacket->testData);
        if( testText ) {
          sqlite3_bind_text(pStmt, 1, testText, -1, sqlite3_free);
          sqlite3_step(pStmt);
          sqlite3_column_text16(pStmt, 0);  /* Force UTF-16 conversion */
        }
      }
      break;
      
    case 4: /* Statement error state simulation */
      rc = sqlite3_prepare_v2(pCtx->db, "SELECT 1/0", -1, &pStmt, 0); /* Division by zero */
      if( rc == SQLITE_OK && pStmt ) {
        sqlite3_step(pStmt);
        /* Try to access column after error */
        sqlite3_column_int(pStmt, 0);
      }
      break;
      
    case 5: /* Large result set */
      rc = sqlite3_prepare_v2(pCtx->db, "SELECT hex(randomblob(?))", -1, &pStmt, 0);
      if( rc == SQLITE_OK && pStmt ) {
        sqlite3_bind_int(pStmt, 1, (pPacket->mallocSize % 500) + 50);
        sqlite3_step(pStmt);
        sqlite3_column_text(pStmt, 0);
        sqlite3_column_bytes(pStmt, 0);
      }
      break;
  }
  
  if( pStmt ) {
    sqlite3_finalize(pStmt);
  }
}

/*
** Fuzz freeP4 function (vdbeaux.c:1377)
** FC: vdbe_free_p4_001
*/
void fuzz_free_p4(FuzzCtx *pCtx, const FreeP4Packet *pPacket) {
  if( !pCtx || !pCtx->db || !pPacket ) return;
  
  /* Validate packet constraints */
  if( pPacket->allocSize > 1048576 ) return;  /* 1MB limit */
  
  int rc;
  sqlite3_stmt *pStmt = NULL;
  
  /* Setup test environment */
  setup_test_statements(pCtx->db, 2);
  
  /* Scenario-based P4 parameter testing */
  uint8_t scenario = pPacket->scenario % 7;
  
  switch( scenario ) {
    case 0: /* String parameter (P4_DYNAMIC) */
      rc = sqlite3_prepare_v2(pCtx->db, "SELECT ?", -1, &pStmt, 0);
      if( rc == SQLITE_OK && pStmt ) {
        size_t strSize = (pPacket->allocSize % 1000) + 10;
        char *dynamicStr = sqlite3_malloc64(strSize);
        if( dynamicStr ) {
          memset(dynamicStr, 'X' + (pPacket->p4Data[0] % 10), strSize - 1);
          dynamicStr[strSize - 1] = '\0';
          sqlite3_bind_text(pStmt, 1, dynamicStr, -1, sqlite3_free);
          sqlite3_step(pStmt);
        }
      }
      break;
      
    case 1: /* Integer array parameter (P4_INTARRAY) */
      rc = sqlite3_prepare_v2(pCtx->db, "SELECT * FROM vdbe_test WHERE id IN (?,?,?)", -1, &pStmt, 0);
      if( rc == SQLITE_OK && pStmt ) {
        sqlite3_bind_int(pStmt, 1, pPacket->p4Data[0]);
        sqlite3_bind_int(pStmt, 2, pPacket->p4Data[1]);
        sqlite3_bind_int(pStmt, 3, pPacket->p4Data[2]);
        sqlite3_step(pStmt);
      }
      break;
      
    case 2: /* Real number parameter (P4_REAL) */
      rc = sqlite3_prepare_v2(pCtx->db, "SELECT ? * 2.0", -1, &pStmt, 0);
      if( rc == SQLITE_OK && pStmt ) {
        double realVal;
        memcpy(&realVal, pPacket->p4Data, sizeof(double));
        sqlite3_bind_double(pStmt, 1, realVal);
        sqlite3_step(pStmt);
      }
      break;
      
    case 3: /* 64-bit integer parameter (P4_INT64) */
      rc = sqlite3_prepare_v2(pCtx->db, "SELECT ? + 1000000", -1, &pStmt, 0);
      if( rc == SQLITE_OK && pStmt ) {
        sqlite3_int64 int64Val;
        memcpy(&int64Val, pPacket->p4Data, sizeof(sqlite3_int64));
        sqlite3_bind_int64(pStmt, 1, int64Val);
        sqlite3_step(pStmt);
      }
      break;
      
    case 4: /* Multiple parameters for complex expression */
      rc = sqlite3_prepare_v2(pCtx->db, "SELECT ? || ? || ?", -1, &pStmt, 0);
      if( rc == SQLITE_OK && pStmt ) {
        sqlite3_bind_text(pStmt, 1, "prefix_", -1, SQLITE_STATIC);
        char *middleStr = sqlite3_mprintf("%.*s", 8, pPacket->p4Data);
        if( middleStr ) {
          sqlite3_bind_text(pStmt, 2, middleStr, -1, sqlite3_free);
        }
        sqlite3_bind_text(pStmt, 3, "_suffix", -1, SQLITE_STATIC);
        sqlite3_step(pStmt);
      }
      break;
      
    case 5: /* BLOB parameter */
      rc = sqlite3_prepare_v2(pCtx->db, "SELECT length(?)", -1, &pStmt, 0);
      if( rc == SQLITE_OK && pStmt ) {
        size_t blobSize = (pPacket->allocSize % 100) + 16;
        void *blobData = sqlite3_malloc64(blobSize);
        if( blobData ) {
          memcpy(blobData, pPacket->p4Data, 16);
          sqlite3_bind_blob(pStmt, 1, blobData, (int)blobSize, sqlite3_free);
          sqlite3_step(pStmt);
        }
      }
      break;
      
    case 6: /* NULL parameter handling */
      rc = sqlite3_prepare_v2(pCtx->db, "SELECT coalesce(?, 'default')", -1, &pStmt, 0);
      if( rc == SQLITE_OK && pStmt ) {
        sqlite3_bind_null(pStmt, 1);
        sqlite3_step(pStmt);
      }
      break;
  }
  
  if( pStmt ) {
    sqlite3_finalize(pStmt);
  }
}

/*
** Fuzz vdbeAssertFieldCountWithinLimits function (vdbeaux.c:4416)
** FC: vdbe_assert_field_count_001
*/
void fuzz_assert_field_count(FuzzCtx *pCtx, const AssertFieldCountPacket *pPacket) {
  if( !pCtx || !pCtx->db || !pPacket ) return;
  
  /* Validate packet constraints */
  if( pPacket->keySize > 65536 ) return;      /* Reasonable key size limit */
  if( pPacket->headerSize > 1000 ) return;    /* Header size limit */
  if( pPacket->fieldCount > 100 ) return;     /* Field count limit */
  
  int rc;
  sqlite3_stmt *pStmt = NULL;
  
  /* Setup test environment */
  sqlite3_exec(pCtx->db, "CREATE TABLE IF NOT EXISTS field_test ("
                         "id INTEGER PRIMARY KEY, "
                         "f1 TEXT, f2 TEXT, f3 TEXT, f4 TEXT, f5 TEXT)", 0, 0, 0);
  
  /* Insert test data */
  sqlite3_exec(pCtx->db, "INSERT OR IGNORE INTO field_test VALUES "
                         "(1, 'a', 'b', 'c', 'd', 'e'), "
                         "(2, 'x', 'y', 'z', 'w', 'v')", 0, 0, 0);
  
  /* Scenario-based field count testing */
  uint8_t scenario = pPacket->scenario % 5;
  
  switch( scenario ) {
    case 0: /* Multi-field record access */
      rc = sqlite3_prepare_v2(pCtx->db, "SELECT * FROM field_test", -1, &pStmt, 0);
      if( rc == SQLITE_OK && pStmt ) {
        while( sqlite3_step(pStmt) == SQLITE_ROW ) {
          int colCount = sqlite3_column_count(pStmt);
          int i;
          for( i = 0; i < colCount && i < pPacket->fieldCount; i++ ) {
            sqlite3_column_text(pStmt, i);
          }
        }
      }
      break;
      
    case 1: /* Index key comparison */
      sqlite3_exec(pCtx->db, "CREATE INDEX IF NOT EXISTS idx_field_test ON field_test(f1, f2)", 0, 0, 0);
      rc = sqlite3_prepare_v2(pCtx->db, "SELECT * FROM field_test WHERE f1 = ? AND f2 = ?", -1, &pStmt, 0);
      if( rc == SQLITE_OK && pStmt ) {
        char searchKey[17];
        memcpy(searchKey, pPacket->recordData, 16);
        searchKey[16] = '\0';
        sqlite3_bind_text(pStmt, 1, searchKey, 8, SQLITE_STATIC);
        sqlite3_bind_text(pStmt, 2, searchKey + 8, 8, SQLITE_STATIC);
        sqlite3_step(pStmt);
      }
      break;
      
    case 2: /* Variable field count query */
      rc = sqlite3_prepare_v2(pCtx->db, "SELECT f1, f2, f3 FROM field_test ORDER BY id", -1, &pStmt, 0);
      if( rc == SQLITE_OK && pStmt ) {
        sqlite3_step(pStmt);
        /* Access specific number of fields based on packet */
        int fieldAccess = pPacket->fieldCount % 4;
        int i;
        for( i = 0; i < fieldAccess; i++ ) {
          sqlite3_column_text(pStmt, i);
        }
      }
      break;
      
    case 3: /* Complex record with different types */
      rc = sqlite3_prepare_v2(pCtx->db, "SELECT ?, ?, ?, ?, ?", -1, &pStmt, 0);
      if( rc == SQLITE_OK && pStmt ) {
        sqlite3_bind_int(pStmt, 1, pPacket->recordData[0]);
        sqlite3_bind_double(pStmt, 2, 3.14159);
        sqlite3_bind_text(pStmt, 3, "text_field", -1, SQLITE_STATIC);
        sqlite3_bind_blob(pStmt, 4, pPacket->recordData + 8, 8, SQLITE_STATIC);
        sqlite3_bind_null(pStmt, 5);
        sqlite3_step(pStmt);
        
        /* Access fields in order */
        int colCount = sqlite3_column_count(pStmt);
        int i;
        for( i = 0; i < colCount; i++ ) {
          switch( sqlite3_column_type(pStmt, i) ) {
            case SQLITE_INTEGER:
              sqlite3_column_int64(pStmt, i);
              break;
            case SQLITE_FLOAT:
              sqlite3_column_double(pStmt, i);
              break;
            case SQLITE_TEXT:
              sqlite3_column_text(pStmt, i);
              break;
            case SQLITE_BLOB:
              sqlite3_column_blob(pStmt, i);
              break;
            case SQLITE_NULL:
              break;
          }
        }
      }
      break;
      
    case 4: /* Large field count edge case */
      if( pPacket->fieldCount > 10 ) {
        /* Create dynamic query with many fields */
        char *dynamicQuery = sqlite3_mprintf("SELECT %s FROM field_test", 
                                            "f1,f2,f3,f4,f5,f1,f2,f3,f4,f5");
        if( dynamicQuery ) {
          rc = sqlite3_prepare_v2(pCtx->db, dynamicQuery, -1, &pStmt, 0);
          sqlite3_free(dynamicQuery);
          if( rc == SQLITE_OK && pStmt ) {
            sqlite3_step(pStmt);
            /* Access limited fields to avoid overflow */
            int accessCount = pPacket->fieldCount % 10;
            int i;
            for( i = 0; i < accessCount; i++ ) {
              sqlite3_column_text(pStmt, i);
            }
          }
        }
      }
      break;
  }
  
  if( pStmt ) {
    sqlite3_finalize(pStmt);
  }
}