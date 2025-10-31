/*
** VDBE Memory Advanced Functions Harness Implementation
** Target functions: sqlite3VdbeMemSetZeroBlob, sqlite3VdbeMemShallowCopy, sqlite3VdbeMemStringify, sqlite3VdbeMemValidStrRep
** Comprehensive fuzzing for VDBE memory operations
*/

#include "vdbe_memory_advanced_harness.h"
#include <string.h>

static sqlite3 *setup_memory_test_database(void) {
  sqlite3 *db = NULL;
  int rc = sqlite3_open(":memory:", &db);
  if( rc != SQLITE_OK ) {
    if( db ) sqlite3_close(db);
    return NULL;
  }
  
  sqlite3_exec(db, "CREATE TABLE test_memory (id INTEGER, data BLOB, value TEXT)", NULL, NULL, NULL);
  return db;
}

static void cleanup_memory_test_database(sqlite3 *db) {
  if( db ) {
    sqlite3_close(db);
  }
}

void fuzz_vdbe_mem_set_zero_blob(FuzzCtx *pCtx, const MemSetZeroBlobPacket *pPacket) {
  if( !pCtx || !pPacket ) return;
  
  if( pPacket->blob_size > 1000000 ) return;
  
  sqlite3 *db = setup_memory_test_database();
  if( !db ) return;
  
  uint8_t scenario = pPacket->scenario % 8;
  
  switch( scenario ) {
    case MEMORY_SCENARIO_NORMAL: {
      sqlite3_stmt *stmt;
      if( sqlite3_prepare_v2(db, "SELECT zeroblob(?)", -1, &stmt, NULL) == SQLITE_OK ) {
        int blob_size = pPacket->blob_size % 10000;
        sqlite3_bind_int(stmt, 1, blob_size);
        
        if( sqlite3_step(stmt) == SQLITE_ROW ) {
          const void *blob = sqlite3_column_blob(stmt, 0);
          int size = sqlite3_column_bytes(stmt, 0);
          
          /* Verify zero blob properties */
          if( blob && size == blob_size ) {
            const char *data = (const char*)blob;
            for( int i = 0; i < size && i < 100; i++ ) {
              if( data[i] != 0 ) break;
            }
          }
        }
        sqlite3_finalize(stmt);
      }
      break;
    }
    
    case MEMORY_SCENARIO_ZERO_SIZE: {
      sqlite3_stmt *stmt;
      if( sqlite3_prepare_v2(db, "SELECT zeroblob(0), zeroblob(1)", -1, &stmt, NULL) == SQLITE_OK ) {
        if( sqlite3_step(stmt) == SQLITE_ROW ) {
          sqlite3_column_blob(stmt, 0);
          sqlite3_column_blob(stmt, 1);
          sqlite3_column_bytes(stmt, 0);
          sqlite3_column_bytes(stmt, 1);
        }
        sqlite3_finalize(stmt);
      }
      break;
    }
    
    case MEMORY_SCENARIO_LARGE_ALLOC: {
      sqlite3_stmt *stmt;
      if( sqlite3_prepare_v2(db, "INSERT INTO test_memory (data) VALUES (?)", -1, &stmt, NULL) == SQLITE_OK ) {
        int large_size = (pPacket->blob_size % 50000) + 1000;
        
        char *large_blob = sqlite3_malloc(large_size);
        if( large_blob ) {
          memset(large_blob, 0, large_size);
          
          /* Add some pattern to test data integrity */
          for( int i = 0; i < large_size && i < 16; i++ ) {
            large_blob[i] = pPacket->testData[i];
          }
          
          sqlite3_bind_blob(stmt, 1, large_blob, large_size, sqlite3_free);
          sqlite3_step(stmt);
        }
        sqlite3_finalize(stmt);
      }
      break;
    }
    
    case MEMORY_SCENARIO_MEMORY_PRESSURE: {
      /* Test multiple allocations to create memory pressure */
      sqlite3_stmt *stmt;
      if( sqlite3_prepare_v2(db, "SELECT zeroblob(?), zeroblob(?), zeroblob(?)", -1, &stmt, NULL) == SQLITE_OK ) {
        int size1 = (pPacket->blob_size % 1000) + 100;
        int size2 = (pPacket->testData[0] % 1000) + 100;
        int size3 = (pPacket->testData[1] % 1000) + 100;
        
        sqlite3_bind_int(stmt, 1, size1);
        sqlite3_bind_int(stmt, 2, size2);
        sqlite3_bind_int(stmt, 3, size3);
        
        if( sqlite3_step(stmt) == SQLITE_ROW ) {
          for( int i = 0; i < 3; i++ ) {
            sqlite3_column_blob(stmt, i);
            sqlite3_column_bytes(stmt, i);
          }
        }
        sqlite3_finalize(stmt);
      }
      break;
    }
    
    default: {
      /* Test boundary conditions */
      sqlite3_stmt *stmt;
      if( sqlite3_prepare_v2(db, "SELECT length(zeroblob(?))", -1, &stmt, NULL) == SQLITE_OK ) {
        int test_size = scenario * 100 + (pPacket->blob_size % 1000);
        sqlite3_bind_int(stmt, 1, test_size);
        
        if( sqlite3_step(stmt) == SQLITE_ROW ) {
          int result_len = sqlite3_column_int(stmt, 0);
          (void)result_len;
        }
        sqlite3_finalize(stmt);
      }
      break;
    }
  }
  
  cleanup_memory_test_database(db);
}

void fuzz_vdbe_mem_shallow_copy(FuzzCtx *pCtx, const MemShallowCopyPacket *pPacket) {
  if( !pCtx || !pPacket ) return;
  
  if( pPacket->data_size > 10000 ) return;
  
  sqlite3 *db = setup_memory_test_database();
  if( !db ) return;
  
  uint8_t scenario = pPacket->scenario % 8;
  
  switch( scenario ) {
    case MEMORY_SCENARIO_NORMAL: {
      sqlite3_stmt *stmt;
      if( sqlite3_prepare_v2(db, "SELECT ?, ?", -1, &stmt, NULL) == SQLITE_OK ) {
        /* Test copying different data types */
        switch( pPacket->src_type % 4 ) {
          case 0: /* Integer */
            sqlite3_bind_int64(stmt, 1, *(int64_t*)pPacket->testData);
            sqlite3_bind_int64(stmt, 2, *(int64_t*)&pPacket->testData[8]);
            break;
          case 1: /* Real */
            sqlite3_bind_double(stmt, 1, 3.14159);
            sqlite3_bind_double(stmt, 2, 2.71828);
            break;
          case 2: /* Text */
            {
              char text[32];
              memcpy(text, pPacket->testData, 20);
              text[20] = '\0';
              sqlite3_bind_text(stmt, 1, text, -1, SQLITE_TRANSIENT);
              sqlite3_bind_text(stmt, 2, "copy_test", -1, SQLITE_STATIC);
            }
            break;
          case 3: /* Blob */
            sqlite3_bind_blob(stmt, 1, pPacket->testData, 16, SQLITE_STATIC);
            sqlite3_bind_blob(stmt, 2, &pPacket->testData[4], 12, SQLITE_STATIC);
            break;
        }
        
        if( sqlite3_step(stmt) == SQLITE_ROW ) {
          /* Access both columns to trigger potential copying */
          for( int i = 0; i < 2; i++ ) {
            int type = sqlite3_column_type(stmt, i);
            switch( type ) {
              case SQLITE_INTEGER:
                sqlite3_column_int64(stmt, i);
                break;
              case SQLITE_FLOAT:
                sqlite3_column_double(stmt, i);
                break;
              case SQLITE_TEXT:
                sqlite3_column_text(stmt, i);
                sqlite3_column_bytes(stmt, i);
                break;
              case SQLITE_BLOB:
                sqlite3_column_blob(stmt, i);
                sqlite3_column_bytes(stmt, i);
                break;
            }
          }
        }
        sqlite3_finalize(stmt);
      }
      break;
    }
    
    case MEMORY_SCENARIO_FLAG_EDGE: {
      /* Test different memory management scenarios */
      sqlite3_stmt *stmt;
      if( sqlite3_prepare_v2(db, 
        "WITH RECURSIVE test(n) AS (VALUES(1) UNION SELECT n+1 FROM test WHERE n<?) "
        "SELECT n, ? FROM test", -1, &stmt, NULL) == SQLITE_OK ) {
        
        int count = (pPacket->testData[0] % 10) + 1;
        sqlite3_bind_int(stmt, 1, count);
        
        char test_string[64];
        memcpy(test_string, pPacket->testData, 20);
        test_string[20] = '\0';
        sqlite3_bind_text(stmt, 2, test_string, -1, SQLITE_TRANSIENT);
        
        while( sqlite3_step(stmt) == SQLITE_ROW ) {
          sqlite3_column_int(stmt, 0);
          sqlite3_column_text(stmt, 1);
        }
        sqlite3_finalize(stmt);
      }
      break;
    }
    
    case MEMORY_SCENARIO_ENCODING_EDGE: {
      /* Test different text encodings */
      sqlite3_stmt *stmt;
      if( sqlite3_prepare_v2(db, "SELECT UPPER(?), LOWER(?), LENGTH(?)", -1, &stmt, NULL) == SQLITE_OK ) {
        char utf8_text[24];
        memcpy(utf8_text, pPacket->testData, 20);
        utf8_text[20] = '\0';
        
        sqlite3_bind_text(stmt, 1, utf8_text, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, utf8_text, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, utf8_text, -1, SQLITE_STATIC);
        
        if( sqlite3_step(stmt) == SQLITE_ROW ) {
          for( int i = 0; i < 3; i++ ) {
            sqlite3_column_text(stmt, i);
            sqlite3_column_bytes(stmt, i);
          }
        }
        sqlite3_finalize(stmt);
      }
      break;
    }
    
    default: {
      /* Test bulk copying operations */
      sqlite3_stmt *stmt;
      if( sqlite3_prepare_v2(db, 
        "INSERT INTO test_memory (id, data, value) SELECT ?, ?, ?", 
        -1, &stmt, NULL) == SQLITE_OK ) {
        
        for( int i = 0; i < 5; i++ ) {
          sqlite3_bind_int(stmt, 1, i);
          sqlite3_bind_blob(stmt, 2, &pPacket->testData[i % 16], 8, SQLITE_STATIC);
          
          char value[32];
          snprintf(value, sizeof(value), "copy_test_%d_%02x", i, pPacket->testData[i % 20]);
          sqlite3_bind_text(stmt, 3, value, -1, SQLITE_TRANSIENT);
          
          sqlite3_step(stmt);
          sqlite3_reset(stmt);
        }
        sqlite3_finalize(stmt);
      }
      break;
    }
  }
  
  cleanup_memory_test_database(db);
}

void fuzz_vdbe_mem_stringify(FuzzCtx *pCtx, const MemStringifyPacket *pPacket) {
  if( !pCtx || !pPacket ) return;
  
  sqlite3 *db = setup_memory_test_database();
  if( !db ) return;
  
  uint8_t scenario = pPacket->scenario % 8;
  
  switch( scenario ) {
    case MEMORY_SCENARIO_NORMAL: {
      sqlite3_stmt *stmt;
      if( sqlite3_prepare_v2(db, "SELECT CAST(? AS TEXT), CAST(? AS TEXT)", -1, &stmt, NULL) == SQLITE_OK ) {
        /* Test integer to string conversion */
        int64_t int_val = pPacket->int_value;
        double real_val = pPacket->real_value;
        
        sqlite3_bind_int64(stmt, 1, int_val);
        sqlite3_bind_double(stmt, 2, real_val);
        
        if( sqlite3_step(stmt) == SQLITE_ROW ) {
          const char *str1 = (const char*)sqlite3_column_text(stmt, 0);
          const char *str2 = (const char*)sqlite3_column_text(stmt, 1);
          
          if( str1 ) {
            int len1 = sqlite3_column_bytes(stmt, 0);
            (void)len1;
          }
          if( str2 ) {
            int len2 = sqlite3_column_bytes(stmt, 1);
            (void)len2;
          }
        }
        sqlite3_finalize(stmt);
      }
      break;
    }
    
    case MEMORY_SCENARIO_ENCODING_EDGE: {
      /* Test string conversion with different encodings */
      sqlite3_stmt *stmt;
      if( sqlite3_prepare_v2(db, 
        "SELECT printf('%d', ?), printf('%.6f', ?), hex(?)", 
        -1, &stmt, NULL) == SQLITE_OK ) {
        
        sqlite3_bind_int64(stmt, 1, pPacket->int_value);
        sqlite3_bind_double(stmt, 2, pPacket->real_value);
        sqlite3_bind_int64(stmt, 3, pPacket->int_value);
        
        if( sqlite3_step(stmt) == SQLITE_ROW ) {
          for( int i = 0; i < 3; i++ ) {
            sqlite3_column_text(stmt, i);
            sqlite3_column_bytes(stmt, i);
          }
        }
        sqlite3_finalize(stmt);
      }
      break;
    }
    
    case MEMORY_SCENARIO_BOUNDARY: {
      /* Test boundary values */
      sqlite3_stmt *stmt;
      if( sqlite3_prepare_v2(db, 
        "SELECT CAST(? AS TEXT), CAST(? AS TEXT), CAST(? AS TEXT)", 
        -1, &stmt, NULL) == SQLITE_OK ) {
        
        /* Test extreme values */
        sqlite3_bind_int64(stmt, 1, 9223372036854775807LL);  /* MAX_INT64 */
        sqlite3_bind_int64(stmt, 2, -9223372036854775807LL - 1); /* MIN_INT64 */
        sqlite3_bind_double(stmt, 3, 1.7976931348623157e+308); /* Large double */
        
        if( sqlite3_step(stmt) == SQLITE_ROW ) {
          for( int i = 0; i < 3; i++ ) {
            sqlite3_column_text(stmt, i);
          }
        }
        sqlite3_finalize(stmt);
      }
      break;
    }
    
    default: {
      /* Test arithmetic operations that require stringification */
      sqlite3_stmt *stmt;
      if( sqlite3_prepare_v2(db, 
        "SELECT (? + 0) || '', (? * 1.0) || '', (? / 1) || ''", 
        -1, &stmt, NULL) == SQLITE_OK ) {
        
        int test_val = (int)pPacket->int_value % 10000;
        sqlite3_bind_int(stmt, 1, test_val);
        sqlite3_bind_double(stmt, 2, pPacket->real_value);
        sqlite3_bind_int(stmt, 3, test_val + 1);
        
        if( sqlite3_step(stmt) == SQLITE_ROW ) {
          for( int i = 0; i < 3; i++ ) {
            sqlite3_column_text(stmt, i);
          }
        }
        sqlite3_finalize(stmt);
      }
      break;
    }
  }
  
  cleanup_memory_test_database(db);
}

void fuzz_vdbe_mem_valid_str_rep(FuzzCtx *pCtx, const MemValidStrRepPacket *pPacket) {
  if( !pCtx || !pPacket ) return;
  
  if( pPacket->str_length > 1000 ) return;
  
  sqlite3 *db = setup_memory_test_database();
  if( !db ) return;
  
  uint8_t scenario = pPacket->scenario % 8;
  
  switch( scenario ) {
    case MEMORY_SCENARIO_NORMAL: {
      sqlite3_stmt *stmt;
      char test_string[64];
      int copy_len = pPacket->str_length < 24 ? pPacket->str_length : 24;
      memcpy(test_string, pPacket->stringData, copy_len);
      test_string[copy_len] = '\0';
      
      if( sqlite3_prepare_v2(db, "SELECT length(?), ?", -1, &stmt, NULL) == SQLITE_OK ) {
        sqlite3_bind_text(stmt, 1, test_string, copy_len, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, test_string, copy_len, SQLITE_TRANSIENT);
        
        if( sqlite3_step(stmt) == SQLITE_ROW ) {
          int len = sqlite3_column_int(stmt, 0);
          const char *str = (const char*)sqlite3_column_text(stmt, 1);
          
          if( str && len >= 0 ) {
            /* Verify string properties */
            int actual_len = strlen(str);
            (void)actual_len;
          }
        }
        sqlite3_finalize(stmt);
      }
      break;
    }
    
    case MEMORY_SCENARIO_ENCODING_EDGE: {
      /* Test different string encodings and validations */
      sqlite3_stmt *stmt;
      char utf8_string[32];
      memcpy(utf8_string, pPacket->stringData, 24);
      utf8_string[24] = '\0';
      
      if( sqlite3_prepare_v2(db, 
        "SELECT typeof(?), length(?), ?", 
        -1, &stmt, NULL) == SQLITE_OK ) {
        
        sqlite3_bind_text(stmt, 1, utf8_string, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, utf8_string, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, utf8_string, -1, SQLITE_STATIC);
        
        if( sqlite3_step(stmt) == SQLITE_ROW ) {
          sqlite3_column_text(stmt, 0);  /* typeof */
          sqlite3_column_int(stmt, 1);   /* length */
          sqlite3_column_text(stmt, 2);  /* value */
        }
        sqlite3_finalize(stmt);
      }
      break;
    }
    
    case MEMORY_SCENARIO_BOUNDARY: {
      /* Test boundary string conditions */
      sqlite3_stmt *stmt;
      if( sqlite3_prepare_v2(db, 
        "SELECT ?, substr(?, 1, ?), substr(?, ?, ?)", 
        -1, &stmt, NULL) == SQLITE_OK ) {
        
        char boundary_string[16];
        memcpy(boundary_string, pPacket->stringData, 12);
        boundary_string[12] = '\0';
        
        sqlite3_bind_text(stmt, 1, boundary_string, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, boundary_string, -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 3, pPacket->str_length % 10);
        sqlite3_bind_text(stmt, 4, boundary_string, -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 5, (pPacket->stringData[0] % 5) + 1);
        sqlite3_bind_int(stmt, 6, (pPacket->stringData[1] % 5) + 1);
        
        if( sqlite3_step(stmt) == SQLITE_ROW ) {
          for( int i = 0; i < 3; i++ ) {
            sqlite3_column_text(stmt, i);
            sqlite3_column_bytes(stmt, i);
          }
        }
        sqlite3_finalize(stmt);
      }
      break;
    }
    
    default: {
      /* Test string validation with patterns */
      sqlite3_stmt *stmt;
      if( sqlite3_prepare_v2(db, 
        "SELECT ? LIKE '%' || ? || '%', instr(?, ?), replace(?, ?, ?)", 
        -1, &stmt, NULL) == SQLITE_OK ) {
        
        char pattern[8];
        memcpy(pattern, pPacket->stringData, 4);
        pattern[4] = '\0';
        
        char search[8];
        memcpy(search, &pPacket->stringData[4], 4);
        search[4] = '\0';
        
        char replace[8];
        memcpy(replace, &pPacket->stringData[8], 4);
        replace[4] = '\0';
        
        char text[16];
        memcpy(text, &pPacket->stringData[12], 8);
        text[8] = '\0';
        
        sqlite3_bind_text(stmt, 1, text, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, pattern, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, text, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 4, search, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 5, text, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 6, search, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 7, replace, -1, SQLITE_STATIC);
        
        if( sqlite3_step(stmt) == SQLITE_ROW ) {
          sqlite3_column_int(stmt, 0);   /* LIKE result */
          sqlite3_column_int(stmt, 1);   /* instr result */
          sqlite3_column_text(stmt, 2);  /* replace result */
        }
        sqlite3_finalize(stmt);
      }
      break;
    }
  }
  
  cleanup_memory_test_database(db);
}