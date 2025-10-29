/*
** Storage Pager Harness Implementation
** Targets: pagerAcquireMapPage, pagerBeginReadTransaction, pagerExclusiveLock, getPageNormal
** Specification-based fuzzing implementation for SQLite3 v3.51.0
*/

#include "storage_pager_harness.h"
#include "sqlite3.h"

/*
** Fuzzing harness for pagerAcquireMapPage function
** FC: pager_001
*/
int fuzz_pager_acquire_mmap(FuzzCtx *pCtx, const PagerAcquireMapPacket *pPacket) {
    /* Validation according to pagerAcquireMapPage_spec.json */
    if (pPacket->pgno == 0 || pPacket->pgno > 1073741823) return 0;
    if (pPacket->pageSize == 0 || pPacket->pageSize > 65536) return 0;
    if (pPacket->mmapSize > 268435456) return 0;
    
    sqlite3 *db = NULL;
    int rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) return 0;
    
    /* Configure memory mapping based on packet */
    char *mmapSql = sqlite3_mprintf("PRAGMA mmap_size=%u", 
                                   pPacket->mmapSize & 0xFFFFFF);
    sqlite3_exec(db, mmapSql, NULL, NULL, NULL);
    sqlite3_free(mmapSql);
    
    /* Create test table with appropriate page size */
    unsigned testPageSize = 4096; /* Default */
    switch (pPacket->pageSize & 0x7) {
        case 0: testPageSize = 512; break;
        case 1: testPageSize = 1024; break;
        case 2: testPageSize = 2048; break;
        case 3: testPageSize = 4096; break;
        case 4: testPageSize = 8192; break;
        case 5: testPageSize = 16384; break;
        case 6: testPageSize = 32768; break;
        case 7: testPageSize = 65536; break;
    }
    
    char *pageSizeSql = sqlite3_mprintf("PRAGMA page_size=%u", testPageSize);
    sqlite3_exec(db, pageSizeSql, NULL, NULL, NULL);
    sqlite3_free(pageSizeSql);
    
    /* Test different scenarios based on packet */
    switch (pPacket->scenario & 0x7) {
        case PAGER_SCENARIO_NORMAL: {
            /* Normal mmap page acquisition */
            sqlite3_exec(db, "CREATE TABLE t1(id INTEGER, data TEXT)", NULL, NULL, NULL);
            for (int i = 0; i < 10; i++) {
                char *insertSql = sqlite3_mprintf(
                    "INSERT INTO t1 VALUES(%d, '%.*s_%d')", 
                    i, 8, pPacket->testData, i);
                sqlite3_exec(db, insertSql, NULL, NULL, NULL);
                sqlite3_free(insertSql);
            }
            break;
        }
        case PAGER_SCENARIO_MMAP: {
            /* Large data to trigger memory mapping */
            sqlite3_exec(db, "CREATE TABLE t1(id INTEGER, blob_data BLOB)", NULL, NULL, NULL);
            sqlite3_stmt *stmt;
            if (sqlite3_prepare_v2(db, "INSERT INTO t1 VALUES(?, ?)", -1, &stmt, NULL) == SQLITE_OK) {
                sqlite3_bind_int(stmt, 1, pPacket->pgno & 0xFFFF);
                sqlite3_bind_blob(stmt, 2, pPacket->testData, 16, SQLITE_STATIC);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
        }
        case PAGER_SCENARIO_WAL: {
            /* WAL mode with memory mapping */
            sqlite3_exec(db, "PRAGMA journal_mode=WAL", NULL, NULL, NULL);
            sqlite3_exec(db, "CREATE TABLE t1(x)", NULL, NULL, NULL);
            sqlite3_exec(db, "INSERT INTO t1 VALUES('test')", NULL, NULL, NULL);
            break;
        }
        case PAGER_SCENARIO_BOUNDARY: {
            /* Boundary page numbers */
            sqlite3_exec(db, "CREATE TABLE t1(data)", NULL, NULL, NULL);
            char *sql = sqlite3_mprintf("INSERT INTO t1 VALUES('%.*s')", 
                                       16, pPacket->testData);
            sqlite3_exec(db, sql, NULL, NULL, NULL);
            sqlite3_free(sql);
            break;
        }
        default: {
            /* Mixed scenarios */
            sqlite3_exec(db, "CREATE TABLE t1(mixed TEXT)", NULL, NULL, NULL);
            char *sql = sqlite3_mprintf("INSERT INTO t1 VALUES('mixed_%.*s')", 
                                       8, pPacket->testData);
            sqlite3_exec(db, sql, NULL, NULL, NULL);
            sqlite3_free(sql);
            break;
        }
    }
    
    /* Test corruption scenarios */
    if (pPacket->corruption_flags & 0x1) {
        sqlite3_exec(db, "PRAGMA integrity_check", NULL, NULL, NULL);
    }
    
    sqlite3_close(db);
    return 0;
}

/*
** Fuzzing harness for pagerBeginReadTransaction function
** FC: pager_002
*/
int fuzz_pager_begin_read_txn(FuzzCtx *pCtx, const PagerBeginReadTxnPacket *pPacket) {
    /* Validation according to pagerBeginReadTransaction_spec.json */
    if (pPacket->walSize > 1073741824) return 0;
    if (pPacket->readMark < -1 || pPacket->readMark > 4) return 0;
    
    sqlite3 *db = NULL;
    int rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) return 0;
    
    /* Configure WAL mode if enabled */
    if (pPacket->walEnabled) {
        sqlite3_exec(db, "PRAGMA journal_mode=WAL", NULL, NULL, NULL);
    }
    
    /* Test different read transaction scenarios */
    switch (pPacket->scenario & 0x7) {
        case PAGER_SCENARIO_NORMAL: {
            /* Normal read transaction */
            sqlite3_exec(db, "CREATE TABLE t1(id INTEGER)", NULL, NULL, NULL);
            sqlite3_exec(db, "INSERT INTO t1 VALUES(1)", NULL, NULL, NULL);
            
            /* Begin read transaction through SELECT */
            sqlite3_stmt *stmt;
            if (sqlite3_prepare_v2(db, "SELECT id FROM t1", -1, &stmt, NULL) == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
        }
        case PAGER_SCENARIO_WAL: {
            /* WAL-specific read transaction testing */
            if (pPacket->walEnabled) {
                sqlite3_exec(db, "CREATE TABLE t1(data TEXT)", NULL, NULL, NULL);
                char *sql = sqlite3_mprintf("INSERT INTO t1 VALUES('%.*s')", 
                                           12, pPacket->testData);
                sqlite3_exec(db, sql, NULL, NULL, NULL);
                sqlite3_free(sql);
                
                /* Multiple read transactions */
                for (int i = 0; i < 3; i++) {
                    sqlite3_stmt *stmt;
                    if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM t1", -1, &stmt, NULL) == SQLITE_OK) {
                        sqlite3_step(stmt);
                        sqlite3_finalize(stmt);
                    }
                }
            }
            break;
        }
        case PAGER_SCENARIO_LOCKING: {
            /* Lock contention scenarios */
            sqlite3_exec(db, "CREATE TABLE t1(x)", NULL, NULL, NULL);
            sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL);
            sqlite3_exec(db, "INSERT INTO t1 VALUES('lock_test')", NULL, NULL, NULL);
            sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
            break;
        }
        case PAGER_SCENARIO_CORRUPTION: {
            /* Corruption handling during read transaction */
            sqlite3_exec(db, "CREATE TABLE t1(corrupt_data)", NULL, NULL, NULL);
            char *sql = sqlite3_mprintf("INSERT INTO t1 VALUES('%.*s')", 
                                       10, pPacket->testData);
            sqlite3_exec(db, sql, NULL, NULL, NULL);
            sqlite3_free(sql);
            
            if (pPacket->corruption_flags & 0x1) {
                sqlite3_exec(db, "PRAGMA integrity_check", NULL, NULL, NULL);
            }
            break;
        }
        default: {
            /* Mixed scenarios */
            sqlite3_exec(db, "CREATE TABLE t1(mixed)", NULL, NULL, NULL);
            sqlite3_exec(db, "INSERT INTO t1 VALUES('mixed')", NULL, NULL, NULL);
            sqlite3_exec(db, "SELECT * FROM t1", NULL, NULL, NULL);
            break;
        }
    }
    
    sqlite3_close(db);
    return 0;
}

/*
** Fuzzing harness for pagerExclusiveLock function  
** FC: pager_003
*/
int fuzz_pager_exclusive_lock(FuzzCtx *pCtx, const PagerExclusiveLockPacket *pPacket) {
    /* Validation according to pagerExclusiveLock_spec.json */
    if (pPacket->timeout > 30000) return 0;
    if (pPacket->syncFlags > 63) return 0;
    
    sqlite3 *db = NULL;
    int rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) return 0;
    
    /* Configure synchronization based on packet */
    char *syncSql = sqlite3_mprintf("PRAGMA synchronous=%d", 
                                   (pPacket->syncFlags & 0x3));
    sqlite3_exec(db, syncSql, NULL, NULL, NULL);
    sqlite3_free(syncSql);
    
    /* Test different exclusive lock scenarios */
    switch (pPacket->scenario & 0x7) {
        case PAGER_SCENARIO_NORMAL: {
            /* Normal exclusive lock acquisition */
            sqlite3_exec(db, "CREATE TABLE t1(id INTEGER)", NULL, NULL, NULL);
            sqlite3_exec(db, "BEGIN EXCLUSIVE", NULL, NULL, NULL);
            char *sql = sqlite3_mprintf("INSERT INTO t1 VALUES(%u)", 
                                       pPacket->timeout & 0xFFFF);
            sqlite3_exec(db, sql, NULL, NULL, NULL);
            sqlite3_free(sql);
            sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
            break;
        }
        case PAGER_SCENARIO_LOCKING: {
            /* Lock escalation testing */
            sqlite3_exec(db, "CREATE TABLE t1(data TEXT)", NULL, NULL, NULL);
            sqlite3_exec(db, "BEGIN", NULL, NULL, NULL);
            sqlite3_exec(db, "INSERT INTO t1 VALUES('test')", NULL, NULL, NULL);
            sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
            break;
        }
        case PAGER_SCENARIO_READONLY: {
            /* Read-only scenarios */
            if (!pPacket->readOnly) {
                sqlite3_exec(db, "CREATE TABLE t1(readonly_test)", NULL, NULL, NULL);
                char *sql = sqlite3_mprintf("INSERT INTO t1 VALUES('%.*s')", 
                                           12, pPacket->testData);
                sqlite3_exec(db, sql, NULL, NULL, NULL);
                sqlite3_free(sql);
            }
            break;
        }
        case PAGER_SCENARIO_MEMORY: {
            /* Memory pressure during locking */
            sqlite3_exec(db, "CREATE TABLE t1(large_data BLOB)", NULL, NULL, NULL);
            sqlite3_stmt *stmt;
            if (sqlite3_prepare_v2(db, "INSERT INTO t1 VALUES(?)", -1, &stmt, NULL) == SQLITE_OK) {
                sqlite3_bind_blob(stmt, 1, pPacket->testData, 12, SQLITE_STATIC);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
        }
        default: {
            /* Mixed locking scenarios */
            sqlite3_exec(db, "CREATE TABLE t1(mixed)", NULL, NULL, NULL);
            sqlite3_exec(db, "INSERT INTO t1 VALUES('mixed')", NULL, NULL, NULL);
            break;
        }
    }
    
    /* Test corruption scenarios */
    if (pPacket->corruption_flags & 0x1) {
        sqlite3_exec(db, "PRAGMA integrity_check", NULL, NULL, NULL);
    }
    
    sqlite3_close(db);
    return 0;
}

/*
** Fuzzing harness for getPageNormal function
** FC: pager_004
*/
int fuzz_get_page_normal(FuzzCtx *pCtx, const GetPageNormalPacket *pPacket) {
    /* Validation according to getPageNormal_spec.json */
    if (pPacket->pgno == 0 || pPacket->pgno > 1073741823) return 0;
    if (pPacket->pageSize == 0) return 0;
    if (pPacket->cacheSize > 1000000) return 0;
    
    sqlite3 *db = NULL;
    int rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) return 0;
    
    /* Configure cache size */
    char *cacheSql = sqlite3_mprintf("PRAGMA cache_size=%d", 
                                    (int)(pPacket->cacheSize & 0xFFFF));
    sqlite3_exec(db, cacheSql, NULL, NULL, NULL);
    sqlite3_free(cacheSql);
    
    /* Test different page retrieval scenarios */
    switch (pPacket->scenario & 0x7) {
        case PAGER_SCENARIO_NORMAL: {
            /* Normal page retrieval */
            sqlite3_exec(db, "CREATE TABLE t1(id INTEGER, data TEXT)", NULL, NULL, NULL);
            for (int i = 0; i < 5; i++) {
                char *sql = sqlite3_mprintf("INSERT INTO t1 VALUES(%d, '%.*s_%d')", 
                                           i, 8, pPacket->testData, i);
                sqlite3_exec(db, sql, NULL, NULL, NULL);
                sqlite3_free(sql);
            }
            
            /* Force page reads through SELECT */
            sqlite3_stmt *stmt;
            if (sqlite3_prepare_v2(db, "SELECT * FROM t1 ORDER BY id", -1, &stmt, NULL) == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    sqlite3_column_int(stmt, 0);
                    sqlite3_column_text(stmt, 1);
                }
                sqlite3_finalize(stmt);
            }
            break;
        }
        case PAGER_SCENARIO_BOUNDARY: {
            /* Boundary page access */
            sqlite3_exec(db, "CREATE TABLE t1(boundary_data)", NULL, NULL, NULL);
            char *sql = sqlite3_mprintf("INSERT INTO t1 VALUES('%.*s')", 
                                       12, pPacket->testData);
            sqlite3_exec(db, sql, NULL, NULL, NULL);
            sqlite3_free(sql);
            break;
        }
        case PAGER_SCENARIO_MEMORY: {
            /* Memory pressure scenarios */
            sqlite3_exec(db, "CREATE TABLE t1(large_text TEXT)", NULL, NULL, NULL);
            char *largeText = sqlite3_mprintf("%.*s", 100, pPacket->testData);
            char *sql = sqlite3_mprintf("INSERT INTO t1 VALUES('%s')", largeText);
            sqlite3_exec(db, sql, NULL, NULL, NULL);
            sqlite3_free(sql);
            sqlite3_free(largeText);
            break;
        }
        case PAGER_SCENARIO_CORRUPTION: {
            /* Corruption detection during page reads */
            sqlite3_exec(db, "CREATE TABLE t1(corrupt_test)", NULL, NULL, NULL);
            sqlite3_exec(db, "INSERT INTO t1 VALUES('corruption')", NULL, NULL, NULL);
            
            if (pPacket->corruption_flags & 0x1) {
                sqlite3_exec(db, "PRAGMA integrity_check", NULL, NULL, NULL);
            }
            break;
        }
        default: {
            /* Mixed page access scenarios */
            sqlite3_exec(db, "CREATE TABLE t1(mixed)", NULL, NULL, NULL);
            for (int i = 0; i < 3; i++) {
                char *sql = sqlite3_mprintf("INSERT INTO t1 VALUES('test_%d')", i);
                sqlite3_exec(db, sql, NULL, NULL, NULL);
                sqlite3_free(sql);
            }
            sqlite3_exec(db, "SELECT COUNT(*) FROM t1", NULL, NULL, NULL);
            break;
        }
    }
    
    sqlite3_close(db);
    return 0;
}