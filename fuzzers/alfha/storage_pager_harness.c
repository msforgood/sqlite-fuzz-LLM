/*
** Storage Pager Functions Harness Implementation
** Target functions: assert_pager_state, checkPage, pageInJournal, pagerFixMaplimit
** Specification-based fuzzing for storage pager operations
*/

#include "storage_pager_harness.h"

/* Helper function to setup test database with specific configurations */
static sqlite3* setup_test_database(uint32_t pageSize, uint8_t walEnabled) {
  sqlite3 *db = NULL;
  int rc = sqlite3_open(":memory:", &db);
  if( rc != SQLITE_OK ) return NULL;
  
  /* Set page size */
  char *pageSizeSql = sqlite3_mprintf("PRAGMA page_size=%u", pageSize);
  sqlite3_exec(db, pageSizeSql, NULL, NULL, NULL);
  sqlite3_free(pageSizeSql);
  
  /* Enable WAL if requested */
  if( walEnabled ) {
    sqlite3_exec(db, "PRAGMA journal_mode=WAL", NULL, NULL, NULL);
  }
  
  /* Create basic test table */
  sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS test_pages ("
                   "id INTEGER PRIMARY KEY, "
                   "data TEXT, "
                   "blob_data BLOB)", NULL, NULL, NULL);
  
  return db;
}

/*
** Fuzz assert_pager_state function (pager.c:1089)
** FC: storage_assert_pager_state_001
*/
void fuzz_assert_pager_state(FuzzCtx *pCtx, const AssertPagerStatePacket *pPacket) {
  if( !pCtx || !pPacket ) return;
  
  /* Validate packet constraints */
  if( pPacket->dbSize > 1073741824 ) return;      /* 1GB limit */
  if( pPacket->cacheSpill > 1000000 ) return;     /* Cache limit */
  
  /* Determine page size */
  uint32_t pageSize = 4096;
  switch( pPacket->testData[0] % 8 ) {
    case 0: pageSize = 512; break;
    case 1: pageSize = 1024; break;
    case 2: pageSize = 2048; break;
    case 3: pageSize = 4096; break;
    case 4: pageSize = 8192; break;
    case 5: pageSize = 16384; break;
    case 6: pageSize = 32768; break;
    case 7: pageSize = 65536; break;
  }
  
  sqlite3 *db = setup_test_database(pageSize, pPacket->walEnabled);
  if( !db ) return;
  
  /* Scenario-based testing */
  uint8_t scenario = pPacket->scenario % 6;
  
  switch( scenario ) {
    case 0: /* Normal pager state transitions */
      sqlite3_exec(db, "INSERT INTO test_pages VALUES (1, 'state_test', NULL)", NULL, NULL, NULL);
      sqlite3_exec(db, "BEGIN TRANSACTION", NULL, NULL, NULL);
      sqlite3_exec(db, "INSERT INTO test_pages VALUES (2, 'txn_test', NULL)", NULL, NULL, NULL);
      sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
      break;
      
    case 1: /* WAL mode state validation */
      if( pPacket->walEnabled ) {
        sqlite3_exec(db, "INSERT INTO test_pages VALUES (1, 'wal_test', NULL)", NULL, NULL, NULL);
        sqlite3_exec(db, "PRAGMA wal_checkpoint", NULL, NULL, NULL);
      }
      break;
      
    case 2: /* Lock level transitions */
      sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL);
      char *insertSql = sqlite3_mprintf("INSERT INTO test_pages VALUES (%u, '%.*s', NULL)", 
                                       pPacket->changeCounter % 1000, 8, pPacket->testData);
      sqlite3_exec(db, insertSql, NULL, NULL, NULL);
      sqlite3_free(insertSql);
      sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
      break;
      
    case 3: /* Cache pressure scenarios */
      char *cacheSql = sqlite3_mprintf("PRAGMA cache_size=%d", 
                                      (int)(pPacket->cacheSpill % 1000) + 10);
      sqlite3_exec(db, cacheSql, NULL, NULL, NULL);
      sqlite3_free(cacheSql);
      
      for( int i = 0; i < 20; i++ ) {
        char *sql = sqlite3_mprintf("INSERT INTO test_pages VALUES (%d, 'cache_%d', NULL)", 
                                   i, i);
        sqlite3_exec(db, sql, NULL, NULL, NULL);
        sqlite3_free(sql);
      }
      break;
      
    case 4: /* Database size scenarios */
      for( int i = 0; i < (pPacket->dbSize % 100) + 5; i++ ) {
        char *sql = sqlite3_mprintf("INSERT INTO test_pages VALUES (%d, 'size_test_%.*s', NULL)", 
                                   i, 8, pPacket->testData);
        sqlite3_exec(db, sql, NULL, NULL, NULL);
        sqlite3_free(sql);
      }
      sqlite3_exec(db, "VACUUM", NULL, NULL, NULL);
      break;
      
    case 5: /* Corruption detection state */
      sqlite3_exec(db, "INSERT INTO test_pages VALUES (1, 'corrupt_test', NULL)", NULL, NULL, NULL);
      if( pPacket->corruption_flags & 0x1 ) {
        sqlite3_exec(db, "PRAGMA integrity_check", NULL, NULL, NULL);
      }
      break;
  }
  
  sqlite3_close(db);
}

/*
** Fuzz checkPage function (pager.c:4567)
** FC: storage_check_page_001
*/
void fuzz_check_page(FuzzCtx *pCtx, const CheckPagePacket *pPacket) {
  if( !pCtx || !pPacket ) return;
  
  /* Validate packet constraints */
  if( pPacket->pgno == 0 || pPacket->pgno > 1073741823 ) return;
  if( pPacket->pageSize < 512 || pPacket->pageSize > 65536 ) return;
  if( pPacket->headerOffset >= pPacket->pageSize ) return;
  
  /* Normalize page size to valid SQLite values */
  uint32_t pageSize = 4096;
  if( pPacket->pageSize <= 512 ) pageSize = 512;
  else if( pPacket->pageSize <= 1024 ) pageSize = 1024;
  else if( pPacket->pageSize <= 2048 ) pageSize = 2048;
  else if( pPacket->pageSize <= 4096 ) pageSize = 4096;
  else if( pPacket->pageSize <= 8192 ) pageSize = 8192;
  else if( pPacket->pageSize <= 16384 ) pageSize = 16384;
  else if( pPacket->pageSize <= 32768 ) pageSize = 32768;
  else pageSize = 65536;
  
  sqlite3 *db = setup_test_database(pageSize, 0);
  if( !db ) return;
  
  /* Scenario-based page checking */
  uint8_t scenario = pPacket->scenario % 7;
  
  switch( scenario ) {
    case 0: /* Normal page validation */
      sqlite3_exec(db, "CREATE INDEX idx_test ON test_pages(data)", NULL, NULL, NULL);
      for( int i = 0; i < 10; i++ ) {
        char *sql = sqlite3_mprintf("INSERT INTO test_pages VALUES (%d, 'page_%.*s_%d', NULL)", 
                                   i, 8, pPacket->pageData, i);
        sqlite3_exec(db, sql, NULL, NULL, NULL);
        sqlite3_free(sql);
      }
      break;
      
    case 1: /* B-Tree page types */
      switch( pPacket->pageType % 4 ) {
        case 0: /* Table leaf page */
          sqlite3_exec(db, "INSERT INTO test_pages VALUES (1, 'leaf_test', NULL)", NULL, NULL, NULL);
          break;
        case 1: /* Table interior page */
          for( int i = 0; i < 100; i++ ) {
            char *sql = sqlite3_mprintf("INSERT INTO test_pages VALUES (%d, 'interior_%d', NULL)", i, i);
            sqlite3_exec(db, sql, NULL, NULL, NULL);
            sqlite3_free(sql);
          }
          break;
        case 2: /* Index leaf page */
          sqlite3_exec(db, "CREATE INDEX idx_page_test ON test_pages(data)", NULL, NULL, NULL);
          sqlite3_exec(db, "INSERT INTO test_pages VALUES (1, 'index_leaf', NULL)", NULL, NULL, NULL);
          break;
        case 3: /* Index interior page */
          sqlite3_exec(db, "CREATE INDEX idx_large ON test_pages(id, data)", NULL, NULL, NULL);
          for( int i = 0; i < 50; i++ ) {
            char *sql = sqlite3_mprintf("INSERT INTO test_pages VALUES (%d, 'idx_int_%d', NULL)", i, i);
            sqlite3_exec(db, sql, NULL, NULL, NULL);
            sqlite3_free(sql);
          }
          break;
      }
      break;
      
    case 2: /* Page header validation */
      sqlite3_exec(db, "INSERT INTO test_pages VALUES (1, 'header_test', NULL)", NULL, NULL, NULL);
      char *headerSql = sqlite3_mprintf("INSERT INTO test_pages VALUES (%u, '%.*s', NULL)", 
                                       pPacket->headerOffset % 1000, 12, pPacket->pageData);
      sqlite3_exec(db, headerSql, NULL, NULL, NULL);
      sqlite3_free(headerSql);
      break;
      
    case 3: /* Checksum validation */
      for( int i = 0; i < 5; i++ ) {
        char *sql = sqlite3_mprintf("INSERT INTO test_pages VALUES (%d, 'chksum_%u_%.*s', NULL)", 
                                   i, pPacket->checksum % 10000, 8, pPacket->pageData);
        sqlite3_exec(db, sql, NULL, NULL, NULL);
        sqlite3_free(sql);
      }
      sqlite3_exec(db, "PRAGMA integrity_check", NULL, NULL, NULL);
      break;
      
    case 4: /* Cell validation */
      sqlite3_stmt *stmt;
      if( sqlite3_prepare_v2(db, "INSERT INTO test_pages VALUES (?, ?, ?)", -1, &stmt, NULL) == SQLITE_OK ) {
        sqlite3_bind_int(stmt, 1, pPacket->pgno % 1000);
        sqlite3_bind_text(stmt, 2, "cell_test", -1, SQLITE_STATIC);
        sqlite3_bind_blob(stmt, 3, pPacket->pageData, 16, SQLITE_STATIC);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
      }
      break;
      
    case 5: /* Overflow page validation */
      if( sqlite3_prepare_v2(db, "INSERT INTO test_pages VALUES (?, ?, ?)", -1, &stmt, NULL) == SQLITE_OK ) {
        sqlite3_bind_int(stmt, 1, 1);
        sqlite3_bind_text(stmt, 2, "overflow_test", -1, SQLITE_STATIC);
        
        /* Create large blob to trigger overflow */
        size_t blobSize = (pageSize / 2) + 100;
        char *largeBlob = sqlite3_malloc64(blobSize);
        if( largeBlob ) {
          memset(largeBlob, 'O' + (pPacket->pageData[0] % 10), blobSize);
          sqlite3_bind_blob(stmt, 3, largeBlob, (int)blobSize, sqlite3_free);
          sqlite3_step(stmt);
        }
        sqlite3_finalize(stmt);
      }
      break;
      
    case 6: /* Corruption scenarios */
      sqlite3_exec(db, "INSERT INTO test_pages VALUES (1, 'corrupt_check', NULL)", NULL, NULL, NULL);
      if( pPacket->corruptionType & 0x1 ) {
        sqlite3_exec(db, "PRAGMA integrity_check", NULL, NULL, NULL);
      }
      if( pPacket->corruptionType & 0x2 ) {
        sqlite3_exec(db, "PRAGMA quick_check", NULL, NULL, NULL);
      }
      break;
  }
  
  sqlite3_close(db);
}

/*
** Fuzz pageInJournal function (pager.c:3456)
** FC: storage_page_in_journal_001
*/
void fuzz_page_in_journal(FuzzCtx *pCtx, const PageInJournalPacket *pPacket) {
  if( !pCtx || !pPacket ) return;
  
  /* Validate packet constraints */
  if( pPacket->pgno == 0 || pPacket->pgno > 1073741823 ) return;
  if( pPacket->journalSize > 1073741824 ) return;    /* 1GB limit */
  if( pPacket->pageSize < 512 || pPacket->pageSize > 65536 ) return;
  
  /* Normalize page size */
  uint32_t pageSize = 4096;
  if( pPacket->pageSize <= 1024 ) pageSize = 1024;
  else if( pPacket->pageSize <= 2048 ) pageSize = 2048;
  else if( pPacket->pageSize <= 8192 ) pageSize = 8192;
  else if( pPacket->pageSize <= 16384 ) pageSize = 16384;
  else if( pPacket->pageSize <= 32768 ) pageSize = 32768;
  else if( pPacket->pageSize <= 65536 ) pageSize = 65536;
  
  sqlite3 *db = setup_test_database(pageSize, pPacket->walEnabled);
  if( !db ) return;
  
  /* Configure journal mode based on packet */
  const char *journalModes[] = {"DELETE", "TRUNCATE", "PERSIST", "MEMORY", "WAL", "OFF"};
  const char *selectedMode = journalModes[pPacket->journalMode % 6];
  
  char *journalSql = sqlite3_mprintf("PRAGMA journal_mode=%s", selectedMode);
  sqlite3_exec(db, journalSql, NULL, NULL, NULL);
  sqlite3_free(journalSql);
  
  /* Configure synchronization */
  char *syncSql = sqlite3_mprintf("PRAGMA synchronous=%d", pPacket->syncFlags % 4);
  sqlite3_exec(db, syncSql, NULL, NULL, NULL);
  sqlite3_free(syncSql);
  
  /* Scenario-based journal testing */
  uint8_t scenario = pPacket->scenario % 6;
  
  switch( scenario ) {
    case 0: /* Normal journal operations */
      sqlite3_exec(db, "BEGIN TRANSACTION", NULL, NULL, NULL);
      for( int i = 0; i < 5; i++ ) {
        char *sql = sqlite3_mprintf("INSERT INTO test_pages VALUES (%d, 'journal_%.*s_%d', NULL)", 
                                   i, 8, pPacket->journalData, i);
        sqlite3_exec(db, sql, NULL, NULL, NULL);
        sqlite3_free(sql);
      }
      sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
      break;
      
    case 1: /* Journal rollback scenarios */
      sqlite3_exec(db, "INSERT INTO test_pages VALUES (1, 'before_rollback', NULL)", NULL, NULL, NULL);
      sqlite3_exec(db, "BEGIN TRANSACTION", NULL, NULL, NULL);
      sqlite3_exec(db, "INSERT INTO test_pages VALUES (2, 'will_rollback', NULL)", NULL, NULL, NULL);
      sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
      break;
      
    case 2: /* Journal size scenarios */
      sqlite3_exec(db, "BEGIN TRANSACTION", NULL, NULL, NULL);
      int insertCount = (pPacket->journalSize % 100) + 10;
      for( int i = 0; i < insertCount; i++ ) {
        char *sql = sqlite3_mprintf("INSERT INTO test_pages VALUES (%d, 'size_test_%d', NULL)", 
                                   i, i);
        sqlite3_exec(db, sql, NULL, NULL, NULL);
        sqlite3_free(sql);
      }
      sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
      break;
      
    case 3: /* WAL mode journal interaction */
      if( pPacket->walEnabled ) {
        sqlite3_exec(db, "INSERT INTO test_pages VALUES (1, 'wal_journal', NULL)", NULL, NULL, NULL);
        sqlite3_exec(db, "PRAGMA wal_checkpoint(PASSIVE)", NULL, NULL, NULL);
        
        for( int i = 0; i < 10; i++ ) {
          char *sql = sqlite3_mprintf("INSERT INTO test_pages VALUES (%d, 'wal_%.*s_%d', NULL)", 
                                     i + 2, 6, pPacket->journalData, i);
          sqlite3_exec(db, sql, NULL, NULL, NULL);
          sqlite3_free(sql);
        }
        sqlite3_exec(db, "PRAGMA wal_checkpoint(FULL)", NULL, NULL, NULL);
      }
      break;
      
    case 4: /* Journal offset and page tracking */
      sqlite3_exec(db, "BEGIN TRANSACTION", NULL, NULL, NULL);
      char *offsetSql = sqlite3_mprintf("INSERT INTO test_pages VALUES (%u, 'offset_%.*s', NULL)", 
                                       pPacket->journalOffset % 1000, 10, pPacket->journalData);
      sqlite3_exec(db, offsetSql, NULL, NULL, NULL);
      sqlite3_free(offsetSql);
      
      /* Update existing pages to trigger journal writes */
      sqlite3_exec(db, "UPDATE test_pages SET data = data || '_updated' WHERE id = 1", NULL, NULL, NULL);
      sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
      break;
      
    case 5: /* Journal corruption scenarios */
      sqlite3_exec(db, "INSERT INTO test_pages VALUES (1, 'corrupt_journal', NULL)", NULL, NULL, NULL);
      sqlite3_exec(db, "BEGIN TRANSACTION", NULL, NULL, NULL);
      sqlite3_exec(db, "INSERT INTO test_pages VALUES (2, 'journal_test', NULL)", NULL, NULL, NULL);
      
      /* Simulate integrity check during journal operations */
      if( strcmp(selectedMode, "WAL") != 0 ) {
        sqlite3_exec(db, "PRAGMA integrity_check", NULL, NULL, NULL);
      }
      sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
      break;
  }
  
  sqlite3_close(db);
}

/*
** Fuzz pagerFixMaplimit function (pager.c:2789)
** FC: storage_pager_fix_maplimit_001
*/
void fuzz_pager_fix_maplimit(FuzzCtx *pCtx, const PagerFixMaplimitPacket *pPacket) {
  if( !pCtx || !pPacket ) return;
  
  /* Validate packet constraints */
  if( pPacket->dbSize > 1073741824 ) return;       /* 1GB limit */
  if( pPacket->mmapSize > 268435456 ) return;      /* 256MB limit */
  if( pPacket->pageSize < 512 || pPacket->pageSize > 65536 ) return;
  if( pPacket->cacheSize > 1000000 ) return;       /* Cache limit */
  
  /* Normalize page size */
  uint32_t pageSize = 4096;
  if( pPacket->pageSize <= 1024 ) pageSize = 1024;
  else if( pPacket->pageSize <= 2048 ) pageSize = 2048;
  else if( pPacket->pageSize <= 8192 ) pageSize = 8192;
  else if( pPacket->pageSize <= 16384 ) pageSize = 16384;
  else if( pPacket->pageSize <= 32768 ) pageSize = 32768;
  else if( pPacket->pageSize <= 65536 ) pageSize = 65536;
  
  sqlite3 *db = setup_test_database(pageSize, 0);
  if( !db ) return;
  
  /* Configure memory mapping if enabled */
  if( pPacket->mmapEnabled ) {
    char *mmapSql = sqlite3_mprintf("PRAGMA mmap_size=%u", pPacket->mmapSize);
    sqlite3_exec(db, mmapSql, NULL, NULL, NULL);
    sqlite3_free(mmapSql);
  }
  
  /* Configure cache size */
  char *cacheSql = sqlite3_mprintf("PRAGMA cache_size=%d", 
                                  (int)(pPacket->cacheSize % 10000) + 100);
  sqlite3_exec(db, cacheSql, NULL, NULL, NULL);
  sqlite3_free(cacheSql);
  
  /* Configure sector size simulation */
  uint32_t sectorSize = 512;
  switch( pPacket->sectorSize % 4 ) {
    case 0: sectorSize = 512; break;
    case 1: sectorSize = 1024; break;
    case 2: sectorSize = 2048; break;
    case 3: sectorSize = 4096; break;
  }
  
  /* Scenario-based mmap limit testing */
  uint8_t scenario = pPacket->scenario % 6;
  
  switch( scenario ) {
    case 0: /* Normal mmap operations */
      for( int i = 0; i < 20; i++ ) {
        char *sql = sqlite3_mprintf("INSERT INTO test_pages VALUES (%d, 'mmap_%.*s_%d', NULL)", 
                                   i, 8, pPacket->testData, i);
        sqlite3_exec(db, sql, NULL, NULL, NULL);
        sqlite3_free(sql);
      }
      break;
      
    case 1: /* Large database scenarios */
      int insertCount = (pPacket->dbSize % 1000) + 100;
      for( int i = 0; i < insertCount; i++ ) {
        char *sql = sqlite3_mprintf("INSERT INTO test_pages VALUES (%d, 'large_db_%d', NULL)", 
                                   i, i);
        sqlite3_exec(db, sql, NULL, NULL, NULL);
        sqlite3_free(sql);
      }
      sqlite3_exec(db, "VACUUM", NULL, NULL, NULL);
      break;
      
    case 2: /* Memory pressure scenarios */
      sqlite3_stmt *stmt;
      if( sqlite3_prepare_v2(db, "INSERT INTO test_pages VALUES (?, ?, ?)", -1, &stmt, NULL) == SQLITE_OK ) {
        for( int i = 0; i < 10; i++ ) {
          sqlite3_bind_int(stmt, 1, i);
          sqlite3_bind_text(stmt, 2, "memory_test", -1, SQLITE_STATIC);
          
          /* Create variable-sized blobs */
          size_t blobSize = (pPacket->testData[i % 12] % 100) + 50;
          char *testBlob = sqlite3_malloc64(blobSize);
          if( testBlob ) {
            memset(testBlob, 'M' + (i % 10), blobSize);
            sqlite3_bind_blob(stmt, 3, testBlob, (int)blobSize, sqlite3_free);
            sqlite3_step(stmt);
            sqlite3_reset(stmt);
          }
        }
        sqlite3_finalize(stmt);
      }
      break;
      
    case 3: /* Lock level impact on mmap */
      sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL);
      char *lockSql = sqlite3_mprintf("INSERT INTO test_pages VALUES (1, 'lock_mmap_%.*s', NULL)", 
                                     10, pPacket->testData);
      sqlite3_exec(db, lockSql, NULL, NULL, NULL);
      sqlite3_free(lockSql);
      sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
      break;
      
    case 4: /* Sector size alignment */
      char *sectorSql = sqlite3_mprintf("INSERT INTO test_pages VALUES (1, 'sector_%u_%.*s', NULL)", 
                                       sectorSize, 8, pPacket->testData);
      sqlite3_exec(db, sectorSql, NULL, NULL, NULL);
      sqlite3_free(sectorSql);
      
      /* Force page writes to test alignment */
      for( int i = 0; i < 5; i++ ) {
        char *sql = sqlite3_mprintf("INSERT INTO test_pages VALUES (%d, 'align_%d', NULL)", 
                                   i + 2, i);
        sqlite3_exec(db, sql, NULL, NULL, NULL);
        sqlite3_free(sql);
      }
      break;
      
    case 5: /* Mmap limit boundary conditions */
      if( pPacket->mmapEnabled ) {
        /* Test near mmap size limit */
        int targetInserts = (pPacket->mmapSize / pageSize) / 10; /* Conservative estimate */
        if( targetInserts > 1000 ) targetInserts = 1000; /* Safety limit */
        
        for( int i = 0; i < targetInserts; i++ ) {
          char *sql = sqlite3_mprintf("INSERT INTO test_pages VALUES (%d, 'boundary_%.*s', NULL)", 
                                     i, 6, pPacket->testData);
          sqlite3_exec(db, sql, NULL, NULL, NULL);
          sqlite3_free(sql);
        }
      }
      break;
  }
  
  /* Test integrity after mmap operations */
  sqlite3_exec(db, "PRAGMA integrity_check", NULL, NULL, NULL);
  
  sqlite3_close(db);
}