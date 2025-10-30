/*
** B-Tree Transaction Management Functions Harness Implementation
** Target functions: sqlite3BtreeBeginTrans, sqlite3BtreeClearCursor, btreeReleaseAllCursorPages, querySharedCacheTableLock
** High complexity B-Tree transaction and cursor management functions
*/

#include <time.h>
#include "btree_trans_mgmt_harness.h"

/* Fuzzing harness for sqlite3BtreeBeginTrans */
int fuzz_btree_begin_trans(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < sizeof(BtreeBeginTransPacket)) return 0;
    
    const BtreeBeginTransPacket *packet = (const BtreeBeginTransPacket*)data;
    
    if (!ctx->db) return 0;
    
    /* Test scenarios for B-Tree transaction begin */
    switch (packet->scenario % 8) {
        case 0: {
            /* Test read transaction begin */
            sqlite3_stmt *pStmt = NULL;
            int rc = sqlite3_prepare_v2(ctx->db, "CREATE TABLE IF NOT EXISTS trans_test (id INTEGER)", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
            
            rc = sqlite3_prepare_v2(ctx->db, "SELECT * FROM trans_test", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
            break;
        }
        case 1: {
            /* Test write transaction begin */
            sqlite3_stmt *pStmt = NULL;
            int rc = sqlite3_prepare_v2(ctx->db, "CREATE TABLE IF NOT EXISTS write_test (data BLOB)", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
            
            rc = sqlite3_prepare_v2(ctx->db, "INSERT INTO write_test VALUES (?)", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                char testData[64];
                snprintf(testData, sizeof(testData), "data_%u_%u", packet->transactionType, packet->testData[0]);
                sqlite3_bind_text(pStmt, 1, testData, -1, SQLITE_TRANSIENT);
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
            break;
        }
        case 2: {
            /* Test transaction with schema version check */
            sqlite3_stmt *pStmt = NULL;
            int rc = sqlite3_prepare_v2(ctx->db, "PRAGMA schema_version", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                if (sqlite3_step(pStmt) == SQLITE_ROW) {
                    sqlite3_column_int(pStmt, 0);
                }
                sqlite3_finalize(pStmt);
            }
            
            rc = sqlite3_prepare_v2(ctx->db, "CREATE TABLE IF NOT EXISTS schema_test (v INTEGER)", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
            break;
        }
        case 3: {
            /* Test nested transaction scenarios */
            int rc = sqlite3_exec(ctx->db, "BEGIN IMMEDIATE", NULL, NULL, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_stmt *pStmt = NULL;
                rc = sqlite3_prepare_v2(ctx->db, "CREATE TABLE IF NOT EXISTS nested_test (nested_id INTEGER)", -1, &pStmt, NULL);
                if (rc == SQLITE_OK && pStmt) {
                    sqlite3_step(pStmt);
                    sqlite3_finalize(pStmt);
                }
                sqlite3_exec(ctx->db, "COMMIT", NULL, NULL, NULL);
            }
            break;
        }
        case 4: {
            /* Test transaction rollback scenario */
            int rc = sqlite3_exec(ctx->db, "BEGIN", NULL, NULL, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_stmt *pStmt = NULL;
                rc = sqlite3_prepare_v2(ctx->db, "CREATE TABLE IF NOT EXISTS rollback_test (rb_data TEXT)", -1, &pStmt, NULL);
                if (rc == SQLITE_OK && pStmt) {
                    sqlite3_step(pStmt);
                    sqlite3_finalize(pStmt);
                }
                
                if (packet->flags & 1) {
                    sqlite3_exec(ctx->db, "ROLLBACK", NULL, NULL, NULL);
                } else {
                    sqlite3_exec(ctx->db, "COMMIT", NULL, NULL, NULL);
                }
            }
            break;
        }
        case 5: {
            /* Test savepoint operations */
            int rc = sqlite3_exec(ctx->db, "SAVEPOINT sp1", NULL, NULL, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_stmt *pStmt = NULL;
                rc = sqlite3_prepare_v2(ctx->db, "CREATE TABLE IF NOT EXISTS savepoint_test (sp_value INTEGER)", -1, &pStmt, NULL);
                if (rc == SQLITE_OK && pStmt) {
                    sqlite3_step(pStmt);
                    sqlite3_finalize(pStmt);
                }
                
                if (packet->flags & 2) {
                    sqlite3_exec(ctx->db, "ROLLBACK TO sp1", NULL, NULL, NULL);
                } else {
                    sqlite3_exec(ctx->db, "RELEASE sp1", NULL, NULL, NULL);
                }
            }
            break;
        }
        case 6: {
            /* Test concurrent transaction scenario */
            sqlite3_stmt *pStmt = NULL;
            int rc = sqlite3_prepare_v2(ctx->db, "CREATE TABLE IF NOT EXISTS concurrent_test (thread_id INTEGER)", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
            
            rc = sqlite3_prepare_v2(ctx->db, "INSERT INTO concurrent_test VALUES (?)", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                sqlite3_bind_int(pStmt, 1, packet->testData[1] % 1000);
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
            break;
        }
        case 7: {
            /* Test transaction with large operations */
            sqlite3_stmt *pStmt = NULL;
            int rc = sqlite3_prepare_v2(ctx->db, "CREATE TABLE IF NOT EXISTS large_test (large_data BLOB)", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
            
            rc = sqlite3_prepare_v2(ctx->db, "INSERT INTO large_test VALUES (?)", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                size_t blobSize = (packet->testData[2] % 8192) + 1;
                char *largeData = sqlite3_malloc((int)blobSize);
                if (largeData) {
                    memset(largeData, 0xAB, blobSize);
                    sqlite3_bind_blob(pStmt, 1, largeData, (int)blobSize, sqlite3_free);
                    sqlite3_step(pStmt);
                }
                sqlite3_finalize(pStmt);
            }
            break;
        }
    }
    
    return SQLITE_OK;
}

/* Fuzzing harness for sqlite3BtreeClearCursor */
int fuzz_btree_clear_cursor(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < sizeof(BtreeClearCursorPacket)) return 0;
    
    const BtreeClearCursorPacket *packet = (const BtreeClearCursorPacket*)data;
    
    if (!ctx->db) return 0;
    
    /* Test scenarios for B-Tree cursor clearing */
    switch (packet->scenario % 6) {
        case 0: {
            /* Test cursor clear with table scan */
            sqlite3_stmt *pStmt = NULL;
            int rc = sqlite3_prepare_v2(ctx->db, "CREATE TABLE IF NOT EXISTS cursor_test (cursor_id INTEGER, cursor_data TEXT)", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
            
            rc = sqlite3_prepare_v2(ctx->db, "INSERT INTO cursor_test VALUES (?, ?)", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                for (int i = 0; i < (packet->testData[0] % 10) + 1; i++) {
                    sqlite3_bind_int(pStmt, 1, i);
                    char dataStr[64];
                    snprintf(dataStr, sizeof(dataStr), "cursor_data_%d_%u", i, packet->testData[1]);
                    sqlite3_bind_text(pStmt, 2, dataStr, -1, SQLITE_TRANSIENT);
                    sqlite3_step(pStmt);
                    sqlite3_reset(pStmt);
                }
                sqlite3_finalize(pStmt);
            }
            
            rc = sqlite3_prepare_v2(ctx->db, "SELECT * FROM cursor_test ORDER BY cursor_id", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                while (sqlite3_step(pStmt) == SQLITE_ROW) {
                    sqlite3_column_int(pStmt, 0);
                    sqlite3_column_text(pStmt, 1);
                }
                sqlite3_finalize(pStmt);
            }
            break;
        }
        case 1: {
            /* Test cursor clear with index operations */
            sqlite3_stmt *pStmt = NULL;
            int rc = sqlite3_prepare_v2(ctx->db, 
                "CREATE TABLE IF NOT EXISTS indexed_test (id INTEGER PRIMARY KEY, value TEXT)", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
            
            rc = sqlite3_prepare_v2(ctx->db, "CREATE INDEX IF NOT EXISTS idx_value ON indexed_test(value)", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
            
            rc = sqlite3_prepare_v2(ctx->db, "SELECT * FROM indexed_test WHERE value = ?", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                char searchValue[32];
                snprintf(searchValue, sizeof(searchValue), "search_%u", packet->testData[2] % 100);
                sqlite3_bind_text(pStmt, 1, searchValue, -1, SQLITE_TRANSIENT);
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
            break;
        }
        case 2: {
            /* Test cursor clear with blob operations */
            sqlite3_stmt *pStmt = NULL;
            int rc = sqlite3_prepare_v2(ctx->db, "CREATE TABLE IF NOT EXISTS blob_cursor_test (blob_data BLOB)", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
            
            rc = sqlite3_prepare_v2(ctx->db, "INSERT INTO blob_cursor_test VALUES (?)", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                size_t blobSize = (packet->keySize % 1024) + 1;
                char *blobData = sqlite3_malloc((int)blobSize);
                if (blobData) {
                    for (size_t i = 0; i < blobSize; i++) {
                        blobData[i] = (char)((packet->testData[3] + i) & 0xFF);
                    }
                    sqlite3_bind_blob(pStmt, 1, blobData, (int)blobSize, sqlite3_free);
                    sqlite3_step(pStmt);
                }
                sqlite3_finalize(pStmt);
            }
            break;
        }
        case 3: {
            /* Test cursor clear with virtual table operations */
            sqlite3_stmt *pStmt = NULL;
            int rc = sqlite3_prepare_v2(ctx->db, "CREATE TABLE IF NOT EXISTS virtual_like_test (vl_id INTEGER, vl_content TEXT)", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
            
            rc = sqlite3_prepare_v2(ctx->db, "SELECT * FROM virtual_like_test WHERE vl_content LIKE ?", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                char pattern[32];
                snprintf(pattern, sizeof(pattern), "%%%u%%", packet->cursorState);
                sqlite3_bind_text(pStmt, 1, pattern, -1, SQLITE_TRANSIENT);
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
            break;
        }
        case 4: {
            /* Test cursor clear with transaction boundaries */
            int rc = sqlite3_exec(ctx->db, "BEGIN", NULL, NULL, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_stmt *pStmt = NULL;
                rc = sqlite3_prepare_v2(ctx->db, "CREATE TABLE IF NOT EXISTS trans_cursor_test (tc_value INTEGER)", -1, &pStmt, NULL);
                if (rc == SQLITE_OK && pStmt) {
                    sqlite3_step(pStmt);
                    sqlite3_finalize(pStmt);
                }
                
                rc = sqlite3_prepare_v2(ctx->db, "SELECT COUNT(*) FROM trans_cursor_test", -1, &pStmt, NULL);
                if (rc == SQLITE_OK && pStmt) {
                    sqlite3_step(pStmt);
                    sqlite3_finalize(pStmt);
                }
                
                sqlite3_exec(ctx->db, "COMMIT", NULL, NULL, NULL);
            }
            break;
        }
        case 5: {
            /* Test cursor clear with join operations */
            sqlite3_stmt *pStmt = NULL;
            int rc = sqlite3_prepare_v2(ctx->db,
                "CREATE TABLE IF NOT EXISTS join_a (ja_id INTEGER, ja_value TEXT); "
                "CREATE TABLE IF NOT EXISTS join_b (jb_id INTEGER, jb_ref INTEGER)", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
            
            rc = sqlite3_prepare_v2(ctx->db, 
                "SELECT ja.ja_value, jb.jb_id FROM join_a ja LEFT JOIN join_b jb ON ja.ja_id = jb.jb_ref LIMIT 10", 
                -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                while (sqlite3_step(pStmt) == SQLITE_ROW) {
                    sqlite3_column_text(pStmt, 0);
                    sqlite3_column_int(pStmt, 1);
                }
                sqlite3_finalize(pStmt);
            }
            break;
        }
    }
    
    return SQLITE_OK;
}

/* Fuzzing harness for btreeReleaseAllCursorPages */
int fuzz_btree_release_all_pages(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < sizeof(BtreeReleaseAllPagesPacket)) return 0;
    
    const BtreeReleaseAllPagesPacket *packet = (const BtreeReleaseAllPagesPacket*)data;
    
    if (!ctx->db) return 0;
    
    /* Test scenarios for B-Tree page release */
    switch (packet->scenario % 6) {
        case 0: {
            /* Test page release with large table scan */
            sqlite3_stmt *pStmt = NULL;
            int rc = sqlite3_prepare_v2(ctx->db, "CREATE TABLE IF NOT EXISTS large_page_test (lp_id INTEGER, lp_data BLOB)", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
            
            rc = sqlite3_prepare_v2(ctx->db, "INSERT INTO large_page_test VALUES (?, ?)", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                int insertCount = (packet->pageCount % 50) + 1;
                for (int i = 0; i < insertCount; i++) {
                    sqlite3_bind_int(pStmt, 1, i);
                    
                    size_t dataSize = (packet->testData[0] % 512) + 64;
                    char *pageData = sqlite3_malloc((int)dataSize);
                    if (pageData) {
                        memset(pageData, 0xCD, dataSize);
                        sqlite3_bind_blob(pStmt, 2, pageData, (int)dataSize, sqlite3_free);
                        sqlite3_step(pStmt);
                        sqlite3_reset(pStmt);
                    }
                }
                sqlite3_finalize(pStmt);
            }
            
            rc = sqlite3_prepare_v2(ctx->db, "SELECT COUNT(*) FROM large_page_test", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
            break;
        }
        case 1: {
            /* Test page release with cursor positioning */
            sqlite3_stmt *pStmt = NULL;
            int rc = sqlite3_prepare_v2(ctx->db, "CREATE TABLE IF NOT EXISTS cursor_pos_test (cp_key INTEGER PRIMARY KEY, cp_value TEXT)", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
            
            rc = sqlite3_prepare_v2(ctx->db, "SELECT * FROM cursor_pos_test WHERE cp_key BETWEEN ? AND ? ORDER BY cp_key", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                int startKey = packet->testData[1] % 1000;
                int endKey = startKey + (packet->pageIndexes[0] % 100);
                sqlite3_bind_int(pStmt, 1, startKey);
                sqlite3_bind_int(pStmt, 2, endKey);
                
                while (sqlite3_step(pStmt) == SQLITE_ROW) {
                    sqlite3_column_int(pStmt, 0);
                    sqlite3_column_text(pStmt, 1);
                }
                sqlite3_finalize(pStmt);
            }
            break;
        }
        case 2: {
            /* Test page release with memory pressure */
            sqlite3_stmt *pStmt = NULL;
            int rc = sqlite3_prepare_v2(ctx->db, "CREATE TABLE IF NOT EXISTS memory_pressure_test (mp_data BLOB)", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
            
            rc = sqlite3_prepare_v2(ctx->db, "INSERT INTO memory_pressure_test VALUES (?)", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                for (int i = 0; i < (packet->pageCount % 20) + 1; i++) {
                    size_t blobSize = (packet->pageIndexes[i % 8] % 2048) + 256;
                    char *memData = sqlite3_malloc((int)blobSize);
                    if (memData) {
                        for (size_t j = 0; j < blobSize; j++) {
                            memData[j] = (char)((i + j + packet->testData[0]) & 0xFF);
                        }
                        sqlite3_bind_blob(pStmt, 1, memData, (int)blobSize, sqlite3_free);
                        sqlite3_step(pStmt);
                        sqlite3_reset(pStmt);
                    }
                }
                sqlite3_finalize(pStmt);
            }
            break;
        }
        case 3: {
            /* Test page release with index traversal */
            sqlite3_stmt *pStmt = NULL;
            int rc = sqlite3_prepare_v2(ctx->db, 
                "CREATE TABLE IF NOT EXISTS index_traverse_test (it_id INTEGER, it_category TEXT, it_score INTEGER)", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
            
            rc = sqlite3_prepare_v2(ctx->db, "CREATE INDEX IF NOT EXISTS idx_category_score ON index_traverse_test(it_category, it_score)", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
            
            rc = sqlite3_prepare_v2(ctx->db, "SELECT * FROM index_traverse_test WHERE it_category = ? ORDER BY it_score DESC LIMIT 50", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                char category[32];
                snprintf(category, sizeof(category), "cat_%u", packet->cursorIndex % 10);
                sqlite3_bind_text(pStmt, 1, category, -1, SQLITE_TRANSIENT);
                
                while (sqlite3_step(pStmt) == SQLITE_ROW) {
                    sqlite3_column_int(pStmt, 0);
                    sqlite3_column_text(pStmt, 1);
                    sqlite3_column_int(pStmt, 2);
                }
                sqlite3_finalize(pStmt);
            }
            break;
        }
        case 4: {
            /* Test page release with rollback operations */
            int rc = sqlite3_exec(ctx->db, "SAVEPOINT page_release_sp", NULL, NULL, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_stmt *pStmt = NULL;
                rc = sqlite3_prepare_v2(ctx->db, "CREATE TABLE IF NOT EXISTS rollback_page_test (rp_data BLOB)", -1, &pStmt, NULL);
                if (rc == SQLITE_OK && pStmt) {
                    sqlite3_step(pStmt);
                    sqlite3_finalize(pStmt);
                }
                
                rc = sqlite3_prepare_v2(ctx->db, "INSERT INTO rollback_page_test VALUES (?)", -1, &pStmt, NULL);
                if (rc == SQLITE_OK && pStmt) {
                    for (int i = 0; i < (packet->pageCount % 15) + 1; i++) {
                        size_t dataSize = (packet->pageIndexes[i % 8] % 1024) + 128;
                        char *rollbackData = sqlite3_malloc((int)dataSize);
                        if (rollbackData) {
                            memset(rollbackData, 0xEF, dataSize);
                            sqlite3_bind_blob(pStmt, 1, rollbackData, (int)dataSize, sqlite3_free);
                            sqlite3_step(pStmt);
                            sqlite3_reset(pStmt);
                        }
                    }
                    sqlite3_finalize(pStmt);
                }
                
                if (packet->flags & 1) {
                    sqlite3_exec(ctx->db, "ROLLBACK TO page_release_sp", NULL, NULL, NULL);
                } else {
                    sqlite3_exec(ctx->db, "RELEASE page_release_sp", NULL, NULL, NULL);
                }
            }
            break;
        }
        case 5: {
            /* Test page release with vacuum operations */
            sqlite3_stmt *pStmt = NULL;
            int rc = sqlite3_prepare_v2(ctx->db, "CREATE TABLE IF NOT EXISTS vacuum_page_test (vp_id INTEGER, vp_content TEXT)", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
            
            rc = sqlite3_prepare_v2(ctx->db, "INSERT INTO vacuum_page_test VALUES (?, ?)", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                for (int i = 0; i < (packet->pageCount % 25) + 1; i++) {
                    sqlite3_bind_int(pStmt, 1, i);
                    
                    char content[256];
                    snprintf(content, sizeof(content), "vacuum_content_%d_%u_%u", 
                            i, packet->testData[0], packet->testData[1]);
                    sqlite3_bind_text(pStmt, 2, content, -1, SQLITE_TRANSIENT);
                    sqlite3_step(pStmt);
                    sqlite3_reset(pStmt);
                }
                sqlite3_finalize(pStmt);
            }
            
            if (packet->releaseType % 4 == 0) {
                sqlite3_exec(ctx->db, "PRAGMA incremental_vacuum(10)", NULL, NULL, NULL);
            }
            break;
        }
    }
    
    return SQLITE_OK;
}

/* Fuzzing harness for querySharedCacheTableLock */
int fuzz_query_shared_cache_lock(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < sizeof(QuerySharedCacheLockPacket)) return 0;
    
    const QuerySharedCacheLockPacket *packet = (const QuerySharedCacheLockPacket*)data;
    
    if (!ctx->db) return 0;
    
    /* Test scenarios for shared cache table lock queries */
    switch (packet->scenario % 8) {
        case 0: {
            /* Test basic table lock query */
            sqlite3_stmt *pStmt = NULL;
            int rc = sqlite3_prepare_v2(ctx->db, "CREATE TABLE IF NOT EXISTS lock_test (lock_id INTEGER, lock_data TEXT)", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
            
            rc = sqlite3_prepare_v2(ctx->db, "SELECT * FROM lock_test WHERE lock_id = ?", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                sqlite3_bind_int(pStmt, 1, packet->tableNumber % 1000);
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
            break;
        }
        case 1: {
            /* Test concurrent read operations */
            sqlite3_stmt *pStmt = NULL;
            int rc = sqlite3_prepare_v2(ctx->db, "CREATE TABLE IF NOT EXISTS concurrent_read_test (cr_value INTEGER)", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
            
            for (int i = 0; i < (packet->testData[0] % 5) + 1; i++) {
                rc = sqlite3_prepare_v2(ctx->db, "SELECT COUNT(*) FROM concurrent_read_test", -1, &pStmt, NULL);
                if (rc == SQLITE_OK && pStmt) {
                    sqlite3_step(pStmt);
                    sqlite3_finalize(pStmt);
                }
            }
            break;
        }
        case 2: {
            /* Test write lock contention */
            sqlite3_stmt *pStmt = NULL;
            int rc = sqlite3_prepare_v2(ctx->db, "CREATE TABLE IF NOT EXISTS write_lock_test (wl_id INTEGER, wl_timestamp INTEGER)", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
            
            rc = sqlite3_prepare_v2(ctx->db, "INSERT INTO write_lock_test VALUES (?, ?)", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                sqlite3_bind_int(pStmt, 1, packet->testData[1] % 10000);
                sqlite3_bind_int(pStmt, 2, (int)time(NULL));
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
            
            rc = sqlite3_prepare_v2(ctx->db, "UPDATE write_lock_test SET wl_timestamp = ? WHERE wl_id = ?", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                sqlite3_bind_int(pStmt, 1, (int)time(NULL) + 1);
                sqlite3_bind_int(pStmt, 2, packet->testData[2] % 10000);
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
            break;
        }
        case 3: {
            /* Test schema modification locks */
            sqlite3_stmt *pStmt = NULL;
            char tableName[64];
            snprintf(tableName, sizeof(tableName), "schema_mod_test_%u", packet->dbIndex % 10);
            
            char createSql[256];
            snprintf(createSql, sizeof(createSql), 
                    "CREATE TABLE IF NOT EXISTS %s (sm_id INTEGER, sm_value TEXT)", tableName);
            
            int rc = sqlite3_prepare_v2(ctx->db, createSql, -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
            
            if (packet->lockType % 2 == 0) {
                char alterSql[256];
                snprintf(alterSql, sizeof(alterSql), 
                        "ALTER TABLE %s ADD COLUMN sm_extra INTEGER DEFAULT 0", tableName);
                sqlite3_prepare_v2(ctx->db, alterSql, -1, &pStmt, NULL);
                if (pStmt) {
                    sqlite3_step(pStmt);
                    sqlite3_finalize(pStmt);
                }
            }
            break;
        }
        case 4: {
            /* Test transaction isolation levels */
            int rc = sqlite3_exec(ctx->db, "BEGIN IMMEDIATE", NULL, NULL, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_stmt *pStmt = NULL;
                rc = sqlite3_prepare_v2(ctx->db, "CREATE TABLE IF NOT EXISTS isolation_test (iso_level INTEGER)", -1, &pStmt, NULL);
                if (rc == SQLITE_OK && pStmt) {
                    sqlite3_step(pStmt);
                    sqlite3_finalize(pStmt);
                }
                
                rc = sqlite3_prepare_v2(ctx->db, "SELECT * FROM isolation_test", -1, &pStmt, NULL);
                if (rc == SQLITE_OK && pStmt) {
                    while (sqlite3_step(pStmt) == SQLITE_ROW) {
                        sqlite3_column_int(pStmt, 0);
                    }
                    sqlite3_finalize(pStmt);
                }
                
                sqlite3_exec(ctx->db, "COMMIT", NULL, NULL, NULL);
            }
            break;
        }
        case 5: {
            /* Test deadlock detection scenarios */
            sqlite3_stmt *pStmt = NULL;
            int rc = sqlite3_prepare_v2(ctx->db, 
                "CREATE TABLE IF NOT EXISTS deadlock_test_a (dla_id INTEGER);"
                "CREATE TABLE IF NOT EXISTS deadlock_test_b (dlb_id INTEGER)", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
            
            rc = sqlite3_prepare_v2(ctx->db, "INSERT INTO deadlock_test_a VALUES (?)", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                sqlite3_bind_int(pStmt, 1, packet->testData[0] % 100);
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
            
            rc = sqlite3_prepare_v2(ctx->db, "INSERT INTO deadlock_test_b VALUES (?)", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                sqlite3_bind_int(pStmt, 1, packet->testData[1] % 100);
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
            break;
        }
        case 6: {
            /* Test lock timeout scenarios */
            sqlite3_stmt *pStmt = NULL;
            int rc = sqlite3_prepare_v2(ctx->db, "CREATE TABLE IF NOT EXISTS timeout_test (to_value INTEGER)", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
            
            rc = sqlite3_prepare_v2(ctx->db, "PRAGMA busy_timeout = ?", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                sqlite3_bind_int(pStmt, 1, packet->lockTimeout % 1000);
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
            
            rc = sqlite3_prepare_v2(ctx->db, "SELECT * FROM timeout_test", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
            break;
        }
        case 7: {
            /* Test shared cache consistency */
            sqlite3_stmt *pStmt = NULL;
            int rc = sqlite3_prepare_v2(ctx->db, "CREATE TABLE IF NOT EXISTS consistency_test (cons_checksum INTEGER)", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
            
            rc = sqlite3_prepare_v2(ctx->db, "INSERT INTO consistency_test VALUES (?)", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                uint32_t checksum = packet->testData[0] ^ packet->testData[1] ^ packet->testData[2];
                sqlite3_bind_int(pStmt, 1, (int)checksum);
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
            
            rc = sqlite3_prepare_v2(ctx->db, "SELECT SUM(cons_checksum) FROM consistency_test", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
            break;
        }
    }
    
    return SQLITE_OK;
}