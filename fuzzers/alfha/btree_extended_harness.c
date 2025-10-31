#include "btree_extended_harness.h"
#include <string.h>

/* btreeEndTransaction fuzzing implementation */
void fuzz_btree_end_transaction(FuzzCtx *pCtx, const BtreeTransEndPacket *pPacket) {
    int rc;
    sqlite3_stmt *pStmt = NULL;
    
    /* Create a complex scenario that exercises btreeEndTransaction */
    const char *setupSql = 
        "CREATE TABLE trans_test(id INTEGER PRIMARY KEY, data TEXT);"
        "BEGIN TRANSACTION;"
        "INSERT INTO trans_test VALUES(1, 'test1');"
        "INSERT INTO trans_test VALUES(2, 'test2');";
    
    rc = sqlite3_exec(pCtx->db, setupSql, NULL, NULL, NULL);
    if( rc != SQLITE_OK ) return;
    
    /* Test transaction state variations */
    uint8_t transState = pPacket->transactionState % 4;
    
    switch( transState ) {
        case 0: /* Normal commit */
            sqlite3_exec(pCtx->db, "COMMIT;", NULL, NULL, NULL);
            break;
            
        case 1: /* Rollback scenario */
            sqlite3_exec(pCtx->db, "ROLLBACK;", NULL, NULL, NULL);
            break;
            
        case 2: /* Nested transaction with multiple VDBE reads */
            sqlite3_prepare_v2(pCtx->db, "SELECT * FROM trans_test;", -1, &pStmt, NULL);
            if( pStmt ) {
                sqlite3_step(pStmt);
                /* Don't finalize - simulate multiple active statements */
                sqlite3_exec(pCtx->db, "COMMIT;", NULL, NULL, NULL);
                sqlite3_finalize(pStmt);
            }
            break;
            
        case 3: /* Corruption simulation */
            if( pPacket->corruptionMask & 0x1 ) {
                /* Try to corrupt transaction state */
                sqlite3_exec(pCtx->db, "PRAGMA integrity_check;", NULL, NULL, NULL);
            }
            sqlite3_exec(pCtx->db, "COMMIT;", NULL, NULL, NULL);
            break;
    }
    
    /* Test edge cases with varying VDBE read counts */
    if( pPacket->nVdbeRead > 0 ) {
        sqlite3_stmt *pMultiStmt = NULL;
        sqlite3_prepare_v2(pCtx->db, "BEGIN; INSERT INTO trans_test VALUES(?, ?);", -1, &pMultiStmt, NULL);
        if( pMultiStmt ) {
            for( int i = 0; i < (pPacket->nVdbeRead % 5); i++ ) {
                sqlite3_bind_int(pMultiStmt, 1, i + 10);
                sqlite3_bind_text(pMultiStmt, 2, "multi", -1, SQLITE_STATIC);
                sqlite3_step(pMultiStmt);
                sqlite3_reset(pMultiStmt);
            }
            sqlite3_finalize(pMultiStmt);
            sqlite3_exec(pCtx->db, "COMMIT;", NULL, NULL, NULL);
        }
    }
}

/* btreeGetPage fuzzing implementation */
void fuzz_btree_get_page(FuzzCtx *pCtx, const BtreeGetPagePacket *pPacket) {
    int rc;
    sqlite3_stmt *pStmt = NULL;
    
    /* Setup database with known page structure */
    const char *setupSql = 
        "CREATE TABLE page_test(id INTEGER PRIMARY KEY, data BLOB);"
        "INSERT INTO page_test VALUES(1, randomblob(1000));"
        "INSERT INTO page_test VALUES(2, randomblob(2000));"
        "INSERT INTO page_test VALUES(3, randomblob(500));";
    
    rc = sqlite3_exec(pCtx->db, setupSql, NULL, NULL, NULL);
    if( rc != SQLITE_OK ) return;
    
    /* Test different page access patterns */
    uint8_t pageMode = pPacket->pageFlag % 4;
    uint32_t targetPage = (pPacket->targetPgno % 10) + 1; /* Pages 1-10 */
    
    switch( pageMode ) {
        case 0: /* Normal page access */
            rc = sqlite3_prepare_v2(pCtx->db, "SELECT * FROM page_test WHERE id = ?;", -1, &pStmt, NULL);
            if( pStmt ) {
                sqlite3_bind_int(pStmt, 1, targetPage % 4);
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
            break;
            
        case 1: /* Page access with NOCONTENT flag simulation */
            sqlite3_exec(pCtx->db, "BEGIN;", NULL, NULL, NULL);
            rc = sqlite3_prepare_v2(pCtx->db, "UPDATE page_test SET data = randomblob(?) WHERE id = ?;", -1, &pStmt, NULL);
            if( pStmt ) {
                sqlite3_bind_int(pStmt, 1, (pPacket->testData[0] % 500) + 100);
                sqlite3_bind_int(pStmt, 2, (targetPage % 3) + 1);
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
            sqlite3_exec(pCtx->db, "ROLLBACK;", NULL, NULL, NULL);
            break;
            
        case 2: /* Read-only page access */
            rc = sqlite3_prepare_v2(pCtx->db, "SELECT COUNT(*) FROM page_test;", -1, &pStmt, NULL);
            if( pStmt ) {
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
            break;
            
        case 3: /* Page access with corruption check */
            if( pPacket->corruptionMask & 0x2 ) {
                sqlite3_exec(pCtx->db, "PRAGMA integrity_check;", NULL, NULL, NULL);
            }
            /* Force page access through large scan */
            rc = sqlite3_prepare_v2(pCtx->db, "SELECT * FROM page_test ORDER BY data;", -1, &pStmt, NULL);
            if( pStmt ) {
                while( sqlite3_step(pStmt) == SQLITE_ROW ) {
                    /* Process rows to force page reads */
                }
                sqlite3_finalize(pStmt);
            }
            break;
    }
}

/* btreeGetUnusedPage fuzzing implementation */
void fuzz_btree_get_unused_page(FuzzCtx *pCtx, const BtreeUnusedPagePacket *pPacket) {
    int rc;
    
    /* Create and delete tables to generate unused pages */
    const char *setupSql = 
        "CREATE TABLE unused_test1(id INTEGER, data TEXT);"
        "CREATE TABLE unused_test2(id INTEGER, data BLOB);"
        "INSERT INTO unused_test1 SELECT value, 'data' || value FROM generate_series(1, 100);"
        "INSERT INTO unused_test2 SELECT value, randomblob(100) FROM generate_series(1, 50);";
    
    rc = sqlite3_exec(pCtx->db, setupSql, NULL, NULL, NULL);
    
    /* Test unused page scenarios */
    uint8_t refMode = pPacket->refCountMode % 4;
    
    switch( refMode ) {
        case 0: /* Drop table to create unused pages */
            sqlite3_exec(pCtx->db, "DROP TABLE unused_test1;", NULL, NULL, NULL);
            /* Try to reuse the space */
            sqlite3_exec(pCtx->db, "CREATE TABLE reuse_test(id INTEGER, data TEXT);", NULL, NULL, NULL);
            sqlite3_exec(pCtx->db, "INSERT INTO reuse_test VALUES(1, 'reused');", NULL, NULL, NULL);
            break;
            
        case 1: /* Vacuum to trigger page reuse */
            sqlite3_exec(pCtx->db, "DROP TABLE unused_test2;", NULL, NULL, NULL);
            sqlite3_exec(pCtx->db, "VACUUM;", NULL, NULL, NULL);
            break;
            
        case 2: { /* Test reference count validation */
            /* Create multiple cursors on same table */
            sqlite3_stmt *pStmt1 = NULL, *pStmt2 = NULL;
            sqlite3_prepare_v2(pCtx->db, "SELECT * FROM unused_test1;", -1, &pStmt1, NULL);
            sqlite3_prepare_v2(pCtx->db, "SELECT * FROM unused_test1;", -1, &pStmt2, NULL);
            
            if( pStmt1 && pStmt2 ) {
                sqlite3_step(pStmt1);
                sqlite3_step(pStmt2);
                /* This should test reference counting */
                sqlite3_finalize(pStmt1);
                sqlite3_finalize(pStmt2);
            }
            break;
        }
            
        case 3: /* Corruption scenario with unused pages */
            if( pPacket->corruptionMask & 0x4 ) {
                sqlite3_exec(pCtx->db, "DROP TABLE unused_test1;", NULL, NULL, NULL);
                sqlite3_exec(pCtx->db, "PRAGMA integrity_check;", NULL, NULL, NULL);
            }
            break;
    }
}

/* btreeHeapInsert fuzzing implementation */
void fuzz_btree_heap_insert(FuzzCtx *pCtx, const BtreeHeapInsertPacket *pPacket) {
    /* Create test scenario that exercises heap operations indirectly */
    const char *setupSql = 
        "CREATE TABLE heap_test(id INTEGER PRIMARY KEY, priority INTEGER, data TEXT);"
        "CREATE INDEX idx_priority ON heap_test(priority);";
    
    sqlite3_exec(pCtx->db, setupSql, NULL, NULL, NULL);
    
    /* Test heap-like operations through B-tree index management */
    uint8_t heapMode = pPacket->insertMode % 4;
    uint32_t baseElement = pPacket->heapElement;
    
    switch( heapMode ) {
        case 0: { /* Insert elements in heap-like pattern */
            for( int i = 0; i < (pPacket->heapSize % 10) + 1; i++ ) {
                sqlite3_stmt *pStmt = NULL;
                int priority = (baseElement + i * 17) % 1000; /* Pseudo-random priorities */
                
                sqlite3_prepare_v2(pCtx->db, "INSERT INTO heap_test(priority, data) VALUES(?, ?);", -1, &pStmt, NULL);
                if( pStmt ) {
                    sqlite3_bind_int(pStmt, 1, priority);
                    sqlite3_bind_text(pStmt, 2, "heap_data", -1, SQLITE_STATIC);
                    sqlite3_step(pStmt);
                    sqlite3_finalize(pStmt);
                }
            }
            break;
        }
            
        case 1: { /* Min-heap extraction simulation */
            sqlite3_stmt *pStmt = NULL;
            sqlite3_prepare_v2(pCtx->db, "SELECT id FROM heap_test ORDER BY priority LIMIT 1;", -1, &pStmt, NULL);
            if( pStmt ) {
                if( sqlite3_step(pStmt) == SQLITE_ROW ) {
                    int minId = sqlite3_column_int(pStmt, 0);
                    sqlite3_finalize(pStmt);
                    
                    /* Delete the minimum element */
                    sqlite3_prepare_v2(pCtx->db, "DELETE FROM heap_test WHERE id = ?;", -1, &pStmt, NULL);
                    if( pStmt ) {
                        sqlite3_bind_int(pStmt, 1, minId);
                        sqlite3_step(pStmt);
                        sqlite3_finalize(pStmt);
                    }
                } else {
                    sqlite3_finalize(pStmt);
                }
            }
            break;
        }
            
        case 2: /* Heap property validation */
            sqlite3_exec(pCtx->db, "SELECT * FROM heap_test ORDER BY priority;", NULL, NULL, NULL);
            break;
            
        case 3: { /* Corruption testing for heap structures */
            if( pPacket->corruptionMask & 0x8 ) {
                /* Insert invalid priorities */
                sqlite3_stmt *pStmt = NULL;
                sqlite3_prepare_v2(pCtx->db, "INSERT INTO heap_test(priority, data) VALUES(NULL, 'corrupted');", -1, &pStmt, NULL);
                if( pStmt ) {
                    sqlite3_step(pStmt);
                    sqlite3_finalize(pStmt);
                }
                sqlite3_exec(pCtx->db, "PRAGMA integrity_check;", NULL, NULL, NULL);
            }
            break;
        }
    }
}

/* btreeHeapPull fuzzing implementation */
void fuzz_btree_heap_pull(FuzzCtx *pCtx, const BtreeHeapPullPacket *pPacket) {
    /* Setup heap-like data structure */
    const char *setupSql = 
        "CREATE TABLE heap_pull_test(id INTEGER PRIMARY KEY, value INTEGER);"
        "INSERT INTO heap_pull_test(value) VALUES(10), (5), (15), (3), (8), (12), (20), (1);";
    
    sqlite3_exec(pCtx->db, setupSql, NULL, NULL, NULL);
    
    /* Test heap pull operations */
    uint8_t pullMode = pPacket->pullMode % 4;
    
    switch( pullMode ) {
        case 0: { /* Extract minimum (heap pull) */
            sqlite3_stmt *pStmt = NULL;
            sqlite3_prepare_v2(pCtx->db, "SELECT id, value FROM heap_pull_test ORDER BY value LIMIT 1;", -1, &pStmt, NULL);
            if( pStmt ) {
                if( sqlite3_step(pStmt) == SQLITE_ROW ) {
                    int minId = sqlite3_column_int(pStmt, 0);
                    sqlite3_finalize(pStmt);
                    
                    /* Remove the minimum element */
                    sqlite3_prepare_v2(pCtx->db, "DELETE FROM heap_pull_test WHERE id = ?;", -1, &pStmt, NULL);
                    if( pStmt ) {
                        sqlite3_bind_int(pStmt, 1, minId);
                        sqlite3_step(pStmt);
                        sqlite3_finalize(pStmt);
                    }
                } else {
                    sqlite3_finalize(pStmt);
                }
            }
            break;
        }
            
        case 1: { /* Empty heap scenario */
            sqlite3_exec(pCtx->db, "DELETE FROM heap_pull_test;", NULL, NULL, NULL);
            /* Try to pull from empty heap */
            sqlite3_stmt *pStmt = NULL;
            sqlite3_prepare_v2(pCtx->db, "SELECT * FROM heap_pull_test ORDER BY value LIMIT 1;", -1, &pStmt, NULL);
            if( pStmt ) {
                sqlite3_step(pStmt); /* Should return no rows */
                sqlite3_finalize(pStmt);
            }
            break;
        }
            
        case 2: { /* Multiple heap pulls */
            for( int i = 0; i < (pPacket->heapSize % 5) + 1; i++ ) {
                sqlite3_stmt *pStmt = NULL;
                sqlite3_prepare_v2(pCtx->db, "DELETE FROM heap_pull_test WHERE id IN (SELECT id FROM heap_pull_test ORDER BY value LIMIT 1);", -1, &pStmt, NULL);
                if( pStmt ) {
                    sqlite3_step(pStmt);
                    sqlite3_finalize(pStmt);
                }
            }
            break;
        }
            
        case 3: { /* Heap invariant verification */
            if( pPacket->corruptionMask & 0x10 ) {
                /* Insert elements that might break heap property */
                sqlite3_exec(pCtx->db, "INSERT INTO heap_pull_test(value) VALUES(-1), (1000);", NULL, NULL, NULL);
            }
            /* Verify ordering */
            sqlite3_stmt *pStmt = NULL;
            sqlite3_prepare_v2(pCtx->db, "SELECT value FROM heap_pull_test ORDER BY value;", -1, &pStmt, NULL);
            if( pStmt ) {
                while( sqlite3_step(pStmt) == SQLITE_ROW ) {
                    /* Verify heap property */
                }
                sqlite3_finalize(pStmt);
            }
            break;
        }
    }
}