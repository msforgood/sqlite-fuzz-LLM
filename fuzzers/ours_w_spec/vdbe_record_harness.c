/*
** VDBE Record Functions Harness Implementation
** Target functions: vdbeRecordCompareDebug, vdbeRecordCompareString, vdbeRecordCompareInt, vdbeRecordDecodeInt
** Comprehensive fuzzing for VDBE record operations through indirect testing
*/

#include "vdbe_record_harness.h"
#include <string.h>

static sqlite3 *setup_record_test_database(void) {
  sqlite3 *db = NULL;
  int rc = sqlite3_open(":memory:", &db);
  if( rc != SQLITE_OK ) {
    if( db ) sqlite3_close(db);
    return NULL;
  }
  
  sqlite3_exec(db, "CREATE TABLE test_records (id INTEGER, data TEXT, value REAL)", NULL, NULL, NULL);
  sqlite3_exec(db, "CREATE INDEX idx_test ON test_records(data, value)", NULL, NULL, NULL);
  return db;
}

static void cleanup_record_test_database(sqlite3 *db) {
  if( db ) {
    sqlite3_close(db);
  }
}

void fuzz_vdbe_record_compare_debug(FuzzCtx *pCtx, const RecordCompareDebugPacket *pPacket) {
  if( !pCtx || !pPacket ) return;
  
  if( pPacket->nKey1 > 1000 || pPacket->nFields > 20 ) return;
  
  sqlite3 *db = setup_record_test_database();
  if( !db ) return;
  
  uint8_t scenario = pPacket->scenario % 8;
  
  /* Test VDBE record comparison through complex query operations */
  switch( scenario ) {
    case RECORD_SCENARIO_NORMAL: {
      sqlite3_stmt *stmt;
      char *sql = sqlite3_mprintf(
        "WITH test_data(a,b) AS (VALUES (?,?)) "
        "SELECT * FROM test_data ORDER BY a, b"
      );
      
      if( sql && sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK ) {
        sqlite3_bind_blob(stmt, 1, pPacket->keyData, pPacket->nKey1 < 32 ? pPacket->nKey1 : 32, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 2, pPacket->desiredResult);
        
        while( sqlite3_step(stmt) == SQLITE_ROW ) {
          /* Force record operations internally */
          const void *blob = sqlite3_column_blob(stmt, 0);
          int bytes = sqlite3_column_bytes(stmt, 0);
          (void)blob; (void)bytes;
        }
        sqlite3_finalize(stmt);
      }
      sqlite3_free(sql);
      break;
    }
    
    case RECORD_SCENARIO_LARGE_RECORD: {
      /* Test with complex multi-column sorting to trigger record comparison */
      sqlite3_stmt *stmt;
      if( sqlite3_prepare_v2(db, 
        "INSERT INTO test_records (id, data, value) VALUES (?, ?, ?)", 
        -1, &stmt, NULL) == SQLITE_OK ) {
        
        for( int i = 0; i < pPacket->nFields && i < 10; i++ ) {
          sqlite3_bind_int(stmt, 1, i);
          sqlite3_bind_blob(stmt, 2, &pPacket->keyData[i % 32], 4, SQLITE_STATIC);
          sqlite3_bind_double(stmt, 3, i * 3.14);
          sqlite3_step(stmt);
          sqlite3_reset(stmt);
        }
        sqlite3_finalize(stmt);
      }
      
      /* Trigger complex sorting to exercise record comparison */
      if( sqlite3_prepare_v2(db, 
        "SELECT * FROM test_records ORDER BY data, value DESC, id", 
        -1, &stmt, NULL) == SQLITE_OK ) {
        while( sqlite3_step(stmt) == SQLITE_ROW ) {
          /* Process results to ensure comparison logic is exercised */
        }
        sqlite3_finalize(stmt);
      }
      break;
    }
    
    default: {
      /* Test with index operations that trigger record comparisons */
      sqlite3_stmt *stmt;
      if( sqlite3_prepare_v2(db, 
        "SELECT * FROM test_records WHERE data BETWEEN ? AND ? ORDER BY data", 
        -1, &stmt, NULL) == SQLITE_OK ) {
        
        sqlite3_bind_blob(stmt, 1, pPacket->keyData, 8, SQLITE_STATIC);
        sqlite3_bind_blob(stmt, 2, &pPacket->keyData[8], 8, SQLITE_STATIC);
        
        while( sqlite3_step(stmt) == SQLITE_ROW ) {
          /* Index seek operations exercise record comparison */
        }
        sqlite3_finalize(stmt);
      }
      break;
    }
  }
  
  cleanup_record_test_database(db);
}

void fuzz_vdbe_record_compare_string(FuzzCtx *pCtx, const RecordCompareStringPacket *pPacket) {
  if( !pCtx || !pPacket ) return;
  
  if( pPacket->nKey1 > 1000 || pPacket->stringLength > 500 ) return;
  
  sqlite3 *db = setup_record_test_database();
  if( !db ) return;
  
  uint8_t scenario = pPacket->scenario % 8;
  
  /* Test VDBE string record comparison through string operations */
  switch( scenario ) {
    case RECORD_SCENARIO_NORMAL: {
      sqlite3_stmt *stmt;
      char test_string[64];
      int copy_len = pPacket->stringLength < 24 ? pPacket->stringLength : 24;
      memcpy(test_string, pPacket->stringData, copy_len);
      test_string[copy_len] = '\0';
      
      /* Test string comparison with different collations */
      char *sql = sqlite3_mprintf(
        "SELECT * FROM (VALUES (?), ('test'), ('')) ORDER BY 1 COLLATE NOCASE"
      );
      
      if( sql && sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK ) {
        sqlite3_bind_text(stmt, 1, test_string, copy_len, SQLITE_STATIC);
        while( sqlite3_step(stmt) == SQLITE_ROW ) {
          /* String comparison logic is exercised internally */
        }
        sqlite3_finalize(stmt);
      }
      sqlite3_free(sql);
      break;
    }
    
    case RECORD_SCENARIO_ENCODING_EDGE: {
      /* Test different text encodings */
      sqlite3_stmt *stmt;
      char test_data[32];
      memcpy(test_data, pPacket->stringData, 24);
      test_data[24] = '\0';
      
      if( sqlite3_prepare_v2(db, 
        "SELECT ?, UPPER(?), LOWER(?) ORDER BY 1", 
        -1, &stmt, NULL) == SQLITE_OK ) {
        
        sqlite3_bind_text(stmt, 1, test_data, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, test_data, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, test_data, -1, SQLITE_STATIC);
        
        while( sqlite3_step(stmt) == SQLITE_ROW ) {
          /* String processing exercises record comparison */
        }
        sqlite3_finalize(stmt);
      }
      break;
    }
    
    default: {
      /* Test string pattern matching */
      sqlite3_stmt *stmt;
      char pattern[32];
      memcpy(pattern, pPacket->stringData, 16);
      pattern[16] = '%';
      pattern[17] = '\0';
      
      if( sqlite3_prepare_v2(db, 
        "SELECT data FROM test_records WHERE data LIKE ? ORDER BY data", 
        -1, &stmt, NULL) == SQLITE_OK ) {
        
        sqlite3_bind_text(stmt, 1, pattern, -1, SQLITE_STATIC);
        while( sqlite3_step(stmt) == SQLITE_ROW ) {
          /* Pattern matching uses string record comparison */
        }
        sqlite3_finalize(stmt);
      }
      break;
    }
  }
  
  cleanup_record_test_database(db);
}

void fuzz_vdbe_record_compare_int(FuzzCtx *pCtx, const RecordCompareIntPacket *pPacket) {
  if( !pCtx || !pPacket ) return;
  
  if( pPacket->nKey1 > 512 ) return;
  if( pPacket->serialType == 7 || pPacket->serialType > 9 ) return;
  
  sqlite3 *db = setup_record_test_database();
  if( !db ) return;
  
  uint8_t scenario = pPacket->scenario % 8;
  
  /* Test VDBE integer record comparison through integer operations */
  switch( scenario ) {
    case RECORD_SCENARIO_NORMAL: {
      sqlite3_stmt *stmt;
      
      /* Construct integer value from test data */
      long long test_value = 0;
      int data_len = pPacket->integerSize;
      if( data_len > 8 ) data_len = 8;
      
      for( int i = 0; i < data_len && i < 16; i++ ) {
        test_value = (test_value << 8) | pPacket->intData[i];
      }
      
      /* Test integer comparison with ordering */
      char *sql = sqlite3_mprintf(
        "SELECT * FROM (VALUES (?), (0), (1), (-1)) ORDER BY 1"
      );
      
      if( sql && sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK ) {
        sqlite3_bind_int64(stmt, 1, test_value);
        while( sqlite3_step(stmt) == SQLITE_ROW ) {
          /* Integer comparison logic is exercised */
        }
        sqlite3_finalize(stmt);
      }
      sqlite3_free(sql);
      break;
    }
    
    case RECORD_SCENARIO_LARGE_RECORD: {
      /* Test with large integer ranges */
      sqlite3_stmt *stmt;
      if( sqlite3_prepare_v2(db, 
        "INSERT INTO test_records (id, value) VALUES (?, ?)", 
        -1, &stmt, NULL) == SQLITE_OK ) {
        
        for( int i = 0; i < 5; i++ ) {
          long long val = 0;
          for( int j = 0; j < 8 && (i*8 + j) < 16; j++ ) {
            val = (val << 8) | pPacket->intData[i*8 + j];
          }
          
          sqlite3_bind_int(stmt, 1, i);
          sqlite3_bind_int64(stmt, 2, val);
          sqlite3_step(stmt);
          sqlite3_reset(stmt);
        }
        sqlite3_finalize(stmt);
      }
      
      /* Trigger integer record comparison through sorting */
      if( sqlite3_prepare_v2(db, 
        "SELECT * FROM test_records ORDER BY value, id", 
        -1, &stmt, NULL) == SQLITE_OK ) {
        while( sqlite3_step(stmt) == SQLITE_ROW ) {
          /* Integer sorting exercises record comparison */
        }
        sqlite3_finalize(stmt);
      }
      break;
    }
    
    default: {
      /* Test integer range queries */
      sqlite3_stmt *stmt;
      long long min_val = (long long)pPacket->intData[0] - 100;
      long long max_val = (long long)pPacket->intData[1] + 100;
      
      if( sqlite3_prepare_v2(db, 
        "SELECT COUNT(*) FROM test_records WHERE id BETWEEN ? AND ?", 
        -1, &stmt, NULL) == SQLITE_OK ) {
        
        sqlite3_bind_int64(stmt, 1, min_val);
        sqlite3_bind_int64(stmt, 2, max_val);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
      }
      break;
    }
  }
  
  cleanup_record_test_database(db);
}

void fuzz_vdbe_record_decode_int(FuzzCtx *pCtx, const RecordDecodeIntPacket *pPacket) {
  if( !pCtx || !pPacket ) return;
  
  if( pPacket->serialType == 7 || pPacket->serialType > 9 ) return;
  if( pPacket->dataSize > 16 ) return;
  
  sqlite3 *db = setup_record_test_database();
  if( !db ) return;
  
  uint8_t scenario = pPacket->scenario % 8;
  
  /* Test VDBE integer decoding through various integer operations */
  switch( scenario ) {
    case RECORD_SCENARIO_NORMAL: {
      sqlite3_stmt *stmt;
      
      /* Construct test integer from packet data */
      long long test_int = 0;
      for( int i = 0; i < pPacket->dataSize && i < 8; i++ ) {
        test_int = (test_int << 8) | pPacket->testData[i];
      }
      
      /* Test integer value handling */
      if( sqlite3_prepare_v2(db, 
        "SELECT ?, ABS(?), ? * 2, ? + 1", 
        -1, &stmt, NULL) == SQLITE_OK ) {
        
        sqlite3_bind_int64(stmt, 1, test_int);
        sqlite3_bind_int64(stmt, 2, test_int);
        sqlite3_bind_int64(stmt, 3, test_int);
        sqlite3_bind_int64(stmt, 4, test_int);
        
        if( sqlite3_step(stmt) == SQLITE_ROW ) {
          /* Integer decoding is exercised internally */
          for( int i = 0; i < 4; i++ ) {
            sqlite3_column_int64(stmt, i);
          }
        }
        sqlite3_finalize(stmt);
      }
      break;
    }
    
    case RECORD_SCENARIO_INVALID_SERIAL: {
      /* Test with various integer sizes and patterns */
      sqlite3_stmt *stmt;
      
      for( int size = 1; size <= 8; size *= 2 ) {
        long long val = 0;
        for( int i = 0; i < size && i < pPacket->dataSize; i++ ) {
          val = (val << 8) | pPacket->testData[i];
        }
        
        /* Test different ways of using the integer */
        if( sqlite3_prepare_v2(db, 
          "SELECT CASE WHEN ? > 0 THEN 'positive' ELSE 'negative' END", 
          -1, &stmt, NULL) == SQLITE_OK ) {
          
          sqlite3_bind_int64(stmt, 1, val);
          sqlite3_step(stmt);
          sqlite3_finalize(stmt);
        }
      }
      break;
    }
    
    default: {
      /* Test integer arithmetic that requires decoding */
      sqlite3_stmt *stmt;
      
      long long base_val = 0;
      for( int i = 0; i < 4 && i < pPacket->dataSize; i++ ) {
        base_val = (base_val << 8) | pPacket->testData[i];
      }
      
      if( sqlite3_prepare_v2(db, 
        "SELECT (? << 1) + (? >> 1) - (? & 0xFF)", 
        -1, &stmt, NULL) == SQLITE_OK ) {
        
        sqlite3_bind_int64(stmt, 1, base_val);
        sqlite3_bind_int64(stmt, 2, base_val);
        sqlite3_bind_int64(stmt, 3, base_val);
        
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
      }
      break;
    }
  }
  
  cleanup_record_test_database(db);
}