/*
** B-Tree Advanced Operations Functions Harness Implementation
** Target functions: btreeParseCellPtr, cursorOnLastPage, sqlite3BtreeCursorHasMoved, 
**                   sqlite3BtreeInsert, sqlite3BtreeIndexMoveto, clearAllSharedCacheTableLocks
*/
#include <time.h>
#include "btree_advanced_ops_harness.h"

/* Helper function to create test page with cell data */
static void* createTestPage(FuzzCtx *ctx, uint8_t pageType, uint16_t cellOffset, uint16_t cellSize, const uint8_t *cellData) {
    if (!ctx || !ctx->db) return NULL;
    
    /* Create a temporary table to get a real page structure */
    char *sql = sqlite3_mprintf("CREATE TEMP TABLE test_page_%d (id INTEGER, data TEXT)", 
                               (int)(time(NULL) % 10000));
    if (!sql) return NULL;
    
    sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
    sqlite3_free(sql);
    
    /* Insert some data to ensure page allocation */
    sql = sqlite3_mprintf("INSERT INTO test_page_%d VALUES (1, 'test_data')", 
                         (int)(time(NULL) % 10000));
    if (sql) {
        sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
        sqlite3_free(sql);
    }
    
    return NULL; /* Simplified for fuzzing context */
}

/* Fuzz btreeParseCellPtr function - Critical cell parsing */
int fuzz_btree_parse_cell_ptr(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < sizeof(BtreeParseCellPacket)) return 0;
    
    const BtreeParseCellPacket *packet = (const BtreeParseCellPacket*)data;
    
    /* Validation checks */
    if (packet->cellOffset > 65535) return 0;
    if (packet->cellSize > 65535) return 0;
    if (packet->payloadSize > 1000000000) return 0;
    if (packet->keySize < 0 || packet->keySize > 2147483647) return 0;
    
    uint8_t scenario = packet->flags % 8;
    
    switch(scenario) {
        case 0: { /* Table leaf cell parsing */
            char *sql = "CREATE TABLE test_parse (id INTEGER PRIMARY KEY, data TEXT)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            char *insertSql = sqlite3_mprintf("INSERT INTO test_parse VALUES (%lld, '%.*s')",
                                            packet->keySize % 1000000,
                                            (int)(sizeof(packet->cellData)), packet->cellData);
            if (insertSql) {
                sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                sqlite3_free(insertSql);
            }
            break;
        }
        
        case 1: { /* Index leaf cell parsing */
            char *sql = "CREATE TABLE test_idx (id INTEGER, name TEXT); CREATE INDEX idx_name ON test_idx(name)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            char *insertSql = sqlite3_mprintf("INSERT INTO test_idx VALUES (%u, '%.*s')",
                                            packet->cellOffset,
                                            (int)(packet->cellSize % 32), packet->cellData);
            if (insertSql) {
                sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                sqlite3_free(insertSql);
            }
            break;
        }
        
        case 2: { /* Interior cell parsing */
            char *sql = "CREATE TABLE test_interior (id INTEGER PRIMARY KEY, data TEXT)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            /* Insert multiple rows to force interior pages */
            for (int i = 0; i < (packet->nLocal % 50) + 10; i++) {
                char *insertSql = sqlite3_mprintf("INSERT INTO test_interior VALUES (%d, '%.*s_%d')",
                                                i, (int)(packet->cellSize % 16), packet->cellData, i);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
            }
            break;
        }
        
        case 3: { /* Overflow cell parsing */
            char *sql = "CREATE TABLE test_overflow (id INTEGER, large_data TEXT)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            /* Create large data to trigger overflow */
            char *largeSql = sqlite3_mprintf("INSERT INTO test_overflow VALUES (%u, '%.*s')",
                                           packet->payloadSize % 1000,
                                           (int)sizeof(packet->cellData), packet->cellData);
            if (largeSql) {
                sqlite3_exec(ctx->db, largeSql, NULL, NULL, NULL);
                sqlite3_free(largeSql);
            }
            break;
        }
        
        case 4: { /* Variable length key parsing */
            char *sql = "CREATE TABLE test_varkey (key BLOB PRIMARY KEY, value TEXT)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            sqlite3_stmt *stmt;
            if (sqlite3_prepare_v2(ctx->db, "INSERT INTO test_varkey VALUES (?, ?)", -1, &stmt, NULL) == SQLITE_OK) {
                sqlite3_bind_blob(stmt, 1, packet->cellData, packet->cellSize % 64, SQLITE_STATIC);
                sqlite3_bind_text(stmt, 2, (char*)packet->cellData, packet->nLocal % 32, SQLITE_STATIC);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 5: { /* Zero-length key parsing */
            char *sql = "CREATE TABLE test_zerokey (id INTEGER, empty_key TEXT)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            char *insertSql = sqlite3_mprintf("INSERT INTO test_zerokey VALUES (%u, '')", 
                                            packet->cellOffset);
            if (insertSql) {
                sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                sqlite3_free(insertSql);
            }
            break;
        }
        
        case 6: { /* Corrupted cell data simulation */
            char *sql = "CREATE TABLE test_corrupt (id INTEGER, data BLOB)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            sqlite3_stmt *stmt;
            if (sqlite3_prepare_v2(ctx->db, "INSERT INTO test_corrupt VALUES (?, ?)", -1, &stmt, NULL) == SQLITE_OK) {
                sqlite3_bind_int(stmt, 1, packet->keySize % 1000);
                sqlite3_bind_blob(stmt, 2, packet->cellData, sizeof(packet->cellData), SQLITE_STATIC);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 7: { /* Page boundary cell parsing */
            char *sql = "CREATE TABLE test_boundary (id INTEGER, boundary_data TEXT)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            char *insertSql = sqlite3_mprintf("INSERT INTO test_boundary VALUES (%u, '%.*s')",
                                            packet->cellOffset,
                                            (int)(packet->cellSize % sizeof(packet->cellData)), packet->cellData);
            if (insertSql) {
                sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                sqlite3_free(insertSql);
            }
            break;
        }
    }
    
    return 1;
}

/* Fuzz cursorOnLastPage function - Critical cursor navigation */
int fuzz_cursor_on_last_page(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < sizeof(CursorLastPagePacket)) return 0;
    
    const CursorLastPagePacket *packet = (const CursorLastPagePacket*)data;
    
    /* Validation checks */
    if (packet->pageDepth > 20) return 0;
    if (packet->currentPage == 0) return 0;
    if (packet->rootPage == 0) return 0;
    
    uint8_t scenario = packet->scenario % 8;
    
    switch(scenario) {
        case 0: { /* Simple table cursor at last page */
            char *sql = "CREATE TABLE test_last (id INTEGER PRIMARY KEY, data TEXT)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            for (int i = 1; i <= (packet->pageDepth % 10) + 5; i++) {
                char *insertSql = sqlite3_mprintf("INSERT INTO test_last VALUES (%d, 'data_%d')", i, i);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
            }
            
            /* Navigate to last */
            sqlite3_stmt *stmt;
            if (sqlite3_prepare_v2(ctx->db, "SELECT * FROM test_last ORDER BY id DESC LIMIT 1", -1, &stmt, NULL) == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 1: { /* Index cursor at last page */
            char *sql = "CREATE TABLE test_idx_last (id INTEGER, name TEXT); CREATE INDEX idx_last ON test_idx_last(name)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            for (int i = 0; i < (packet->currentPage % 20) + 10; i++) {
                char *insertSql = sqlite3_mprintf("INSERT INTO test_idx_last VALUES (%d, 'name_%04d')", i, i);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
            }
            
            sqlite3_stmt *stmt;
            if (sqlite3_prepare_v2(ctx->db, "SELECT * FROM test_idx_last WHERE name >= 'name_9999' ORDER BY name", -1, &stmt, NULL) == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 2: { /* Multi-level tree navigation */
            char *sql = "CREATE TABLE test_multilevel (id INTEGER PRIMARY KEY, data TEXT)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            /* Insert enough data to create multiple levels */
            int insertCount = (packet->rootPage % 500) + 100;
            for (int i = 1; i <= insertCount; i++) {
                char *insertSql = sqlite3_mprintf("INSERT INTO test_multilevel VALUES (%d, 'multilevel_data_%d')", i, i);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
            }
            
            /* Navigate to absolute last */
            sqlite3_stmt *stmt;
            if (sqlite3_prepare_v2(ctx->db, "SELECT MAX(id) FROM test_multilevel", -1, &stmt, NULL) == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 3: { /* Cursor after deletion */
            char *sql = "CREATE TABLE test_delete_last (id INTEGER PRIMARY KEY, data TEXT)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            for (int i = 1; i <= 50; i++) {
                char *insertSql = sqlite3_mprintf("INSERT INTO test_delete_last VALUES (%d, 'data_%d')", i, i);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
            }
            
            /* Delete some records and check cursor position */
            char *deleteSql = sqlite3_mprintf("DELETE FROM test_delete_last WHERE id > %u", packet->currentPage % 45);
            if (deleteSql) {
                sqlite3_exec(ctx->db, deleteSql, NULL, NULL, NULL);
                sqlite3_free(deleteSql);
            }
            
            sqlite3_stmt *stmt;
            if (sqlite3_prepare_v2(ctx->db, "SELECT * FROM test_delete_last ORDER BY id DESC", -1, &stmt, NULL) == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    /* Navigate through remaining records */
                }
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 4: { /* Empty table cursor */
            char *sql = "CREATE TABLE test_empty_last (id INTEGER PRIMARY KEY, data TEXT)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            sqlite3_stmt *stmt;
            if (sqlite3_prepare_v2(ctx->db, "SELECT * FROM test_empty_last ORDER BY id DESC", -1, &stmt, NULL) == SQLITE_OK) {
                sqlite3_step(stmt); /* Should return SQLITE_DONE */
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 5: { /* Single record table */
            char *sql = "CREATE TABLE test_single_last (id INTEGER PRIMARY KEY, data TEXT)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            char *insertSql = sqlite3_mprintf("INSERT INTO test_single_last VALUES (%u, 'single_record')", packet->rootPage % 1000);
            if (insertSql) {
                sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                sqlite3_free(insertSql);
            }
            
            sqlite3_stmt *stmt;
            if (sqlite3_prepare_v2(ctx->db, "SELECT * FROM test_single_last", -1, &stmt, NULL) == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 6: { /* Reverse iteration to last */
            char *sql = "CREATE TABLE test_reverse_last (id INTEGER PRIMARY KEY DESC, data TEXT)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            for (int i = 1; i <= (packet->pageDepth % 20) + 10; i++) {
                char *insertSql = sqlite3_mprintf("INSERT INTO test_reverse_last VALUES (%d, 'reverse_%d')", i, i);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
            }
            
            sqlite3_stmt *stmt;
            if (sqlite3_prepare_v2(ctx->db, "SELECT * FROM test_reverse_last ORDER BY id", -1, &stmt, NULL) == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    /* Iterate to last */
                }
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 7: { /* Concurrent access simulation */
            char *sql = "CREATE TABLE test_concurrent_last (id INTEGER PRIMARY KEY, data TEXT, timestamp INTEGER)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            for (int i = 0; i < (packet->currentPage % 30) + 15; i++) {
                char *insertSql = sqlite3_mprintf("INSERT INTO test_concurrent_last VALUES (%d, 'concurrent_%d', %u)", 
                                                i, i, packet->testData[i % 4]);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
            }
            
            sqlite3_stmt *stmt;
            if (sqlite3_prepare_v2(ctx->db, "SELECT * FROM test_concurrent_last ORDER BY timestamp DESC LIMIT 1", -1, &stmt, NULL) == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
        }
    }
    
    return 1;
}

/* Fuzz sqlite3BtreeCursorHasMoved function - Critical cursor state validation */
int fuzz_sqlite3_btree_cursor_has_moved(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < sizeof(CursorMovedPacket)) return 0;
    
    const CursorMovedPacket *packet = (const CursorMovedPacket*)data;
    
    /* Validation checks */
    if (packet->pageNumber == 0) return 0;
    if (packet->cursorState > 3) return 0;
    
    uint8_t scenario = packet->scenario % 10;
    
    switch(scenario) {
        case 0: { /* Basic cursor movement detection */
            char *sql = "CREATE TABLE test_moved (id INTEGER PRIMARY KEY, data TEXT)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            for (int i = 1; i <= 20; i++) {
                char *insertSql = sqlite3_mprintf("INSERT INTO test_moved VALUES (%d, 'data_%d')", i, i);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
            }
            
            sqlite3_stmt *stmt;
            if (sqlite3_prepare_v2(ctx->db, "SELECT * FROM test_moved WHERE id = ?", -1, &stmt, NULL) == SQLITE_OK) {
                sqlite3_bind_int(stmt, 1, packet->cellIndex % 20 + 1);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 1: { /* Cursor movement after update */
            char *sql = "CREATE TABLE test_update_moved (id INTEGER PRIMARY KEY, data TEXT, version INTEGER)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            for (int i = 1; i <= 15; i++) {
                char *insertSql = sqlite3_mprintf("INSERT INTO test_update_moved VALUES (%d, 'data_%d', 1)", i, i);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
            }
            
            /* Update some records */
            char *updateSql = sqlite3_mprintf("UPDATE test_update_moved SET version = %u WHERE id <= %u", 
                                            packet->validationData[0] % 100, packet->cellIndex % 10 + 1);
            if (updateSql) {
                sqlite3_exec(ctx->db, updateSql, NULL, NULL, NULL);
                sqlite3_free(updateSql);
            }
            
            sqlite3_stmt *stmt;
            if (sqlite3_prepare_v2(ctx->db, "SELECT * FROM test_update_moved WHERE version > 1", -1, &stmt, NULL) == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    /* Check cursor state */
                }
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 2: { /* Cursor movement after delete */
            char *sql = "CREATE TABLE test_delete_moved (id INTEGER PRIMARY KEY, data TEXT)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            for (int i = 1; i <= 25; i++) {
                char *insertSql = sqlite3_mprintf("INSERT INTO test_delete_moved VALUES (%d, 'delete_data_%d')", i, i);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
            }
            
            char *deleteSql = sqlite3_mprintf("DELETE FROM test_delete_moved WHERE id BETWEEN %u AND %u", 
                                            packet->cellIndex % 20 + 1, packet->cellIndex % 20 + 5);
            if (deleteSql) {
                sqlite3_exec(ctx->db, deleteSql, NULL, NULL, NULL);
                sqlite3_free(deleteSql);
            }
            
            sqlite3_stmt *stmt;
            if (sqlite3_prepare_v2(ctx->db, "SELECT COUNT(*) FROM test_delete_moved", -1, &stmt, NULL) == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 3: { /* Index cursor movement */
            char *sql = "CREATE TABLE test_idx_moved (id INTEGER, name TEXT, value INTEGER); CREATE INDEX idx_moved ON test_idx_moved(name)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            for (int i = 0; i < 20; i++) {
                char *insertSql = sqlite3_mprintf("INSERT INTO test_idx_moved VALUES (%d, 'name_%04d', %u)", 
                                                i, i, packet->validationData[i % 3]);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
            }
            
            sqlite3_stmt *stmt;
            char *selectSql = sqlite3_mprintf("SELECT * FROM test_idx_moved WHERE name = 'name_%04d'", packet->cellIndex % 20);
            if (selectSql && sqlite3_prepare_v2(ctx->db, selectSql, -1, &stmt, NULL) == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
                sqlite3_free(selectSql);
            }
            break;
        }
        
        case 4: { /* Transaction cursor state */
            char *sql = "CREATE TABLE test_txn_moved (id INTEGER PRIMARY KEY, data TEXT)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            sqlite3_exec(ctx->db, "BEGIN TRANSACTION", NULL, NULL, NULL);
            
            for (int i = 1; i <= 10; i++) {
                char *insertSql = sqlite3_mprintf("INSERT INTO test_txn_moved VALUES (%d, 'txn_data_%d')", i, i);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
            }
            
            if (packet->eState % 2 == 0) {
                sqlite3_exec(ctx->db, "COMMIT", NULL, NULL, NULL);
            } else {
                sqlite3_exec(ctx->db, "ROLLBACK", NULL, NULL, NULL);
            }
            
            sqlite3_stmt *stmt;
            if (sqlite3_prepare_v2(ctx->db, "SELECT COUNT(*) FROM test_txn_moved", -1, &stmt, NULL) == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 5: { /* Savepoint cursor state */
            char *sql = "CREATE TABLE test_sp_moved (id INTEGER PRIMARY KEY, data TEXT)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            for (int i = 1; i <= 8; i++) {
                char *insertSql = sqlite3_mprintf("INSERT INTO test_sp_moved VALUES (%d, 'sp_data_%d')", i, i);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
            }
            
            char *spSql = sqlite3_mprintf("SAVEPOINT sp_%u", packet->pageNumber % 1000);
            if (spSql) {
                sqlite3_exec(ctx->db, spSql, NULL, NULL, NULL);
                sqlite3_free(spSql);
            }
            
            char *updateSql = sqlite3_mprintf("UPDATE test_sp_moved SET data = 'updated_%u' WHERE id = %u", 
                                            packet->validationData[0], packet->cellIndex % 8 + 1);
            if (updateSql) {
                sqlite3_exec(ctx->db, updateSql, NULL, NULL, NULL);
                sqlite3_free(updateSql);
            }
            
            if (packet->skipNext % 2 == 0) {
                char *releaseSql = sqlite3_mprintf("RELEASE sp_%u", packet->pageNumber % 1000);
                if (releaseSql) {
                    sqlite3_exec(ctx->db, releaseSql, NULL, NULL, NULL);
                    sqlite3_free(releaseSql);
                }
            } else {
                char *rollbackSql = sqlite3_mprintf("ROLLBACK TO sp_%u", packet->pageNumber % 1000);
                if (rollbackSql) {
                    sqlite3_exec(ctx->db, rollbackSql, NULL, NULL, NULL);
                    sqlite3_free(rollbackSql);
                }
            }
            break;
        }
        
        default: { /* Multi-table cursor interaction */
            char *sql = "CREATE TABLE test_multi1 (id INTEGER PRIMARY KEY, data TEXT); "
                       "CREATE TABLE test_multi2 (id INTEGER PRIMARY KEY, ref_id INTEGER, value TEXT)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            for (int i = 1; i <= 10; i++) {
                char *insertSql = sqlite3_mprintf("INSERT INTO test_multi1 VALUES (%d, 'multi1_data_%d')", i, i);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
                
                insertSql = sqlite3_mprintf("INSERT INTO test_multi2 VALUES (%d, %d, 'multi2_value_%d')", 
                                          i + 100, i, i);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
            }
            
            sqlite3_stmt *stmt;
            if (sqlite3_prepare_v2(ctx->db, "SELECT m1.*, m2.value FROM test_multi1 m1 JOIN test_multi2 m2 ON m1.id = m2.ref_id", -1, &stmt, NULL) == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    /* Joined cursor navigation */
                }
                sqlite3_finalize(stmt);
            }
            break;
        }
    }
    
    return 1;
}

/* Fuzz sqlite3BtreeInsert function - Critical insertion operation */
int fuzz_sqlite3_btree_insert(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < sizeof(BtreeInsertPacket)) return 0;
    
    const BtreeInsertPacket *packet = (const BtreeInsertPacket*)data;
    
    /* Validation checks */
    if (packet->keySize < 0 || packet->keySize > 2147483647) return 0;
    if (packet->dataSize > 1000000000) return 0;
    
    uint8_t scenario = packet->scenario % 12;
    
    switch(scenario) {
        case 0: { /* Basic integer key insertion */
            char *sql = "CREATE TABLE test_insert (id INTEGER PRIMARY KEY, data TEXT)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            char *insertSql = sqlite3_mprintf("INSERT INTO test_insert VALUES (%lld, '%.*s')",
                                            packet->keySize % 1000000,
                                            (int)(packet->dataSize % sizeof(packet->valueData)), packet->valueData);
            if (insertSql) {
                sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                sqlite3_free(insertSql);
            }
            break;
        }
        
        case 1: { /* Large data insertion */
            char *sql = "CREATE TABLE test_large_insert (id INTEGER, large_data TEXT)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            /* Create large data string */
            size_t largeSize = (packet->dataSize % 1000) + 100;
            char *largeData = sqlite3_malloc(largeSize + 1);
            if (largeData) {
                memset(largeData, 'A', largeSize);
                largeData[largeSize] = '\0';
                
                char *insertSql = sqlite3_mprintf("INSERT INTO test_large_insert VALUES (%lld, '%s')",
                                                packet->keySize % 1000, largeData);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
                sqlite3_free(largeData);
            }
            break;
        }
        
        case 2: { /* Blob insertion */
            char *sql = "CREATE TABLE test_blob_insert (id INTEGER PRIMARY KEY, blob_data BLOB)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            sqlite3_stmt *stmt;
            if (sqlite3_prepare_v2(ctx->db, "INSERT INTO test_blob_insert VALUES (?, ?)", -1, &stmt, NULL) == SQLITE_OK) {
                sqlite3_bind_int64(stmt, 1, packet->keySize % 1000000);
                sqlite3_bind_blob(stmt, 2, packet->valueData, sizeof(packet->valueData), SQLITE_STATIC);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 3: { /* Duplicate key insertion */
            char *sql = "CREATE TABLE test_dup_insert (id INTEGER PRIMARY KEY, data TEXT)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            int keyValue = packet->keySize % 100;
            char *insertSql = sqlite3_mprintf("INSERT OR REPLACE INTO test_dup_insert VALUES (%d, '%.*s')",
                                            keyValue, (int)(packet->dataSize % sizeof(packet->valueData)), packet->valueData);
            if (insertSql) {
                sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                sqlite3_free(insertSql);
            }
            
            /* Try to insert duplicate */
            insertSql = sqlite3_mprintf("INSERT OR IGNORE INTO test_dup_insert VALUES (%d, 'duplicate_data')", keyValue);
            if (insertSql) {
                sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                sqlite3_free(insertSql);
            }
            break;
        }
        
        case 4: { /* Index insertion */
            char *sql = "CREATE TABLE test_idx_insert (id INTEGER, name TEXT, value INTEGER); "
                       "CREATE INDEX idx_insert_name ON test_idx_insert(name)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            char *insertSql = sqlite3_mprintf("INSERT INTO test_idx_insert VALUES (%lld, '%.*s', %u)",
                                            packet->keySize % 1000,
                                            (int)(packet->dataSize % sizeof(packet->keyData)), packet->keyData,
                                            packet->testParams[0]);
            if (insertSql) {
                sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                sqlite3_free(insertSql);
            }
            break;
        }
        
        case 5: { /* Multi-column insertion */
            char *sql = "CREATE TABLE test_multi_insert (id INTEGER, col1 TEXT, col2 INTEGER, col3 REAL, col4 BLOB)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            sqlite3_stmt *stmt;
            if (sqlite3_prepare_v2(ctx->db, "INSERT INTO test_multi_insert VALUES (?, ?, ?, ?, ?)", -1, &stmt, NULL) == SQLITE_OK) {
                sqlite3_bind_int64(stmt, 1, packet->keySize % 1000000);
                sqlite3_bind_text(stmt, 2, (char*)packet->keyData, packet->dataSize % sizeof(packet->keyData), SQLITE_STATIC);
                sqlite3_bind_int(stmt, 3, packet->testParams[1]);
                sqlite3_bind_double(stmt, 4, (double)packet->testParams[2] / 1000.0);
                sqlite3_bind_blob(stmt, 5, packet->valueData, sizeof(packet->valueData), SQLITE_STATIC);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 6: { /* Batch insertion */
            char *sql = "CREATE TABLE test_batch_insert (id INTEGER PRIMARY KEY, batch_data TEXT)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            sqlite3_exec(ctx->db, "BEGIN TRANSACTION", NULL, NULL, NULL);
            
            int batchSize = (packet->spaceCheck % 50) + 10;
            for (int i = 0; i < batchSize; i++) {
                char *insertSql = sqlite3_mprintf("INSERT INTO test_batch_insert VALUES (%lld, 'batch_%d_%.*s')",
                                                (packet->keySize % 1000000) + i,
                                                i, (int)(packet->dataSize % 16), packet->valueData);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
            }
            
            sqlite3_exec(ctx->db, "COMMIT", NULL, NULL, NULL);
            break;
        }
        
        case 7: { /* Insertion with constraints */
            char *sql = "CREATE TABLE test_constraint_insert (id INTEGER PRIMARY KEY CHECK(id > 0), "
                       "data TEXT NOT NULL, value INTEGER DEFAULT 42)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            char *insertSql = sqlite3_mprintf("INSERT INTO test_constraint_insert (id, data) VALUES (%lld, '%.*s')",
                                            (packet->keySize % 1000000) + 1,
                                            (int)(packet->dataSize % sizeof(packet->valueData)), packet->valueData);
            if (insertSql) {
                sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                sqlite3_free(insertSql);
            }
            break;
        }
        
        case 8: { /* Insertion with foreign key */
            char *sql = "PRAGMA foreign_keys=ON; "
                       "CREATE TABLE parent_insert (id INTEGER PRIMARY KEY, name TEXT); "
                       "CREATE TABLE child_insert (id INTEGER PRIMARY KEY, parent_id INTEGER, "
                       "data TEXT, FOREIGN KEY(parent_id) REFERENCES parent_insert(id))";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            /* Insert parent first */
            int parentId = packet->keySize % 1000 + 1;
            char *parentSql = sqlite3_mprintf("INSERT INTO parent_insert VALUES (%d, 'parent_%.*s')",
                                            parentId, (int)(packet->dataSize % sizeof(packet->keyData)), packet->keyData);
            if (parentSql) {
                sqlite3_exec(ctx->db, parentSql, NULL, NULL, NULL);
                sqlite3_free(parentSql);
            }
            
            /* Insert child */
            char *childSql = sqlite3_mprintf("INSERT INTO child_insert VALUES (%u, %d, '%.*s')",
                                           packet->testParams[0] % 1000, parentId,
                                           (int)(packet->dataSize % sizeof(packet->valueData)), packet->valueData);
            if (childSql) {
                sqlite3_exec(ctx->db, childSql, NULL, NULL, NULL);
                sqlite3_free(childSql);
            }
            break;
        }
        
        case 9: { /* Insertion with triggers */
            char *sql = "CREATE TABLE test_trigger_insert (id INTEGER PRIMARY KEY, data TEXT, updated_at INTEGER); "
                       "CREATE TRIGGER update_timestamp AFTER INSERT ON test_trigger_insert "
                       "BEGIN UPDATE test_trigger_insert SET updated_at = strftime('%s', 'now') WHERE id = NEW.id; END";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            char *insertSql = sqlite3_mprintf("INSERT INTO test_trigger_insert (id, data) VALUES (%lld, '%.*s')",
                                            packet->keySize % 1000000,
                                            (int)(packet->dataSize % sizeof(packet->valueData)), packet->valueData);
            if (insertSql) {
                sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                sqlite3_free(insertSql);
            }
            break;
        }
        
        case 10: { /* Insertion with virtual table simulation */
            char *sql = "CREATE TABLE test_virtual_insert (id INTEGER PRIMARY KEY, search_data TEXT)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            char *insertSql = sqlite3_mprintf("INSERT INTO test_virtual_insert VALUES (%lld, '%.*s search terms')",
                                            packet->keySize % 1000000,
                                            (int)(packet->dataSize % sizeof(packet->valueData)), packet->valueData);
            if (insertSql) {
                sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                sqlite3_free(insertSql);
            }
            break;
        }
        
        case 11: { /* Insertion with page splitting */
            char *sql = "CREATE TABLE test_split_insert (id INTEGER PRIMARY KEY, large_text TEXT)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            /* Insert data that will likely cause page splits */
            int insertCount = (packet->spaceCheck % 100) + 50;
            for (int i = 0; i < insertCount; i++) {
                char *largeSql = sqlite3_mprintf("INSERT INTO test_split_insert VALUES (%lld, '%.*s_split_data_%d')",
                                               (packet->keySize % 1000000) + i,
                                               (int)(packet->dataSize % sizeof(packet->valueData)), packet->valueData, i);
                if (largeSql) {
                    sqlite3_exec(ctx->db, largeSql, NULL, NULL, NULL);
                    sqlite3_free(largeSql);
                }
            }
            break;
        }
    }
    
    return 1;
}

/* Fuzz sqlite3BtreeIndexMoveto function - Critical index navigation */
int fuzz_sqlite3_btree_index_moveto(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < sizeof(BtreeIndexMovetoPacket)) return 0;
    
    const BtreeIndexMovetoPacket *packet = (const BtreeIndexMovetoPacket*)data;
    
    /* Validation checks */
    if (packet->keyFields == 0 || packet->keyFields > 255) return 0;
    if (packet->keyLength > 1048576) return 0;
    
    uint8_t scenario = packet->scenario % 10;
    
    switch(scenario) {
        case 0: { /* Simple index seek */
            char *sql = "CREATE TABLE test_idx_seek (id INTEGER, name TEXT, value INTEGER); "
                       "CREATE INDEX idx_seek_name ON test_idx_seek(name)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            /* Insert test data */
            for (int i = 0; i < 20; i++) {
                char *insertSql = sqlite3_mprintf("INSERT INTO test_idx_seek VALUES (%d, 'name_%04d', %u)", 
                                                i, i, packet->searchParams[i % 6]);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
            }
            
            /* Search using index */
            char *searchSql = sqlite3_mprintf("SELECT * FROM test_idx_seek WHERE name = 'name_%04d'", 
                                            packet->keyFields % 20);
            if (searchSql) {
                sqlite3_stmt *stmt;
                if (sqlite3_prepare_v2(ctx->db, searchSql, -1, &stmt, NULL) == SQLITE_OK) {
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
                sqlite3_free(searchSql);
            }
            break;
        }
        
        case 1: { /* Multi-column index seek */
            char *sql = "CREATE TABLE test_multi_idx (id INTEGER, col1 TEXT, col2 INTEGER, col3 REAL); "
                       "CREATE INDEX idx_multi ON test_multi_idx(col1, col2, col3)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            for (int i = 0; i < 25; i++) {
                char *insertSql = sqlite3_mprintf("INSERT INTO test_multi_idx VALUES (%d, '%.*s_%d', %u, %f)", 
                                                i, 
                                                (int)(packet->keyLength % sizeof(packet->keyData)), packet->keyData,
                                                i, packet->searchParams[i % 6], 
                                                (double)packet->searchParams[(i+1) % 6] / 1000.0);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
            }
            
            char *searchSql = sqlite3_mprintf("SELECT * FROM test_multi_idx WHERE col1 = '%.*s_%d' AND col2 = %u",
                                            (int)(packet->keyLength % sizeof(packet->keyData)), packet->keyData,
                                            packet->keyFields % 25, packet->searchParams[0]);
            if (searchSql) {
                sqlite3_stmt *stmt;
                if (sqlite3_prepare_v2(ctx->db, searchSql, -1, &stmt, NULL) == SQLITE_OK) {
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
                sqlite3_free(searchSql);
            }
            break;
        }
        
        case 2: { /* Range index seek */
            char *sql = "CREATE TABLE test_range_idx (id INTEGER, score INTEGER, name TEXT); "
                       "CREATE INDEX idx_range_score ON test_range_idx(score)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            for (int i = 0; i < 30; i++) {
                char *insertSql = sqlite3_mprintf("INSERT INTO test_range_idx VALUES (%d, %u, 'name_%d')", 
                                                i, (packet->searchParams[i % 6] % 1000), i);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
            }
            
            int minScore = packet->searchParams[0] % 500;
            int maxScore = minScore + (packet->searchParams[1] % 300);
            char *rangeSql = sqlite3_mprintf("SELECT * FROM test_range_idx WHERE score BETWEEN %d AND %d ORDER BY score", 
                                           minScore, maxScore);
            if (rangeSql) {
                sqlite3_stmt *stmt;
                if (sqlite3_prepare_v2(ctx->db, rangeSql, -1, &stmt, NULL) == SQLITE_OK) {
                    while (sqlite3_step(stmt) == SQLITE_ROW) {
                        /* Range scan */
                    }
                    sqlite3_finalize(stmt);
                }
                sqlite3_free(rangeSql);
            }
            break;
        }
        
        case 3: { /* Unique index seek */
            char *sql = "CREATE TABLE test_unique_idx (id INTEGER PRIMARY KEY, email TEXT UNIQUE, name TEXT); "
                       "CREATE UNIQUE INDEX idx_unique_email ON test_unique_idx(email)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            for (int i = 0; i < 15; i++) {
                char *insertSql = sqlite3_mprintf("INSERT INTO test_unique_idx VALUES (%d, 'user%d@%.*s.com', 'User%d')", 
                                                i, i, (int)(packet->keyLength % 8), packet->keyData, i);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
            }
            
            char *searchSql = sqlite3_mprintf("SELECT * FROM test_unique_idx WHERE email = 'user%u@%.*s.com'", 
                                            packet->keyFields % 15, (int)(packet->keyLength % 8), packet->keyData);
            if (searchSql) {
                sqlite3_stmt *stmt;
                if (sqlite3_prepare_v2(ctx->db, searchSql, -1, &stmt, NULL) == SQLITE_OK) {
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
                sqlite3_free(searchSql);
            }
            break;
        }
        
        case 4: { /* Partial index seek */
            char *sql = "CREATE TABLE test_partial_idx (id INTEGER, status TEXT, data TEXT); "
                       "CREATE INDEX idx_partial_active ON test_partial_idx(id) WHERE status = 'active'";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            for (int i = 0; i < 20; i++) {
                char *status = (i % 3 == 0) ? "active" : "inactive";
                char *insertSql = sqlite3_mprintf("INSERT INTO test_partial_idx VALUES (%d, '%s', '%.*s_%d')", 
                                                i, status, (int)(packet->keyLength % sizeof(packet->keyData)), packet->keyData, i);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
            }
            
            char *searchSql = sqlite3_mprintf("SELECT * FROM test_partial_idx WHERE status = 'active' AND id = %u", 
                                            packet->keyFields % 20);
            if (searchSql) {
                sqlite3_stmt *stmt;
                if (sqlite3_prepare_v2(ctx->db, searchSql, -1, &stmt, NULL) == SQLITE_OK) {
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
                sqlite3_free(searchSql);
            }
            break;
        }
        
        case 5: { /* Expression index seek */
            char *sql = "CREATE TABLE test_expr_idx (id INTEGER, name TEXT, value INTEGER); "
                       "CREATE INDEX idx_expr_upper ON test_expr_idx(UPPER(name))";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            for (int i = 0; i < 18; i++) {
                char *insertSql = sqlite3_mprintf("INSERT INTO test_expr_idx VALUES (%d, '%.*s_%d', %u)", 
                                                i, (int)(packet->keyLength % sizeof(packet->keyData)), packet->keyData, i,
                                                packet->searchParams[i % 6]);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
            }
            
            char *searchSql = sqlite3_mprintf("SELECT * FROM test_expr_idx WHERE UPPER(name) = UPPER('%.*s_%u')", 
                                            (int)(packet->keyLength % sizeof(packet->keyData)), packet->keyData,
                                            packet->keyFields % 18);
            if (searchSql) {
                sqlite3_stmt *stmt;
                if (sqlite3_prepare_v2(ctx->db, searchSql, -1, &stmt, NULL) == SQLITE_OK) {
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
                sqlite3_free(searchSql);
            }
            break;
        }
        
        case 6: { /* Covering index seek */
            char *sql = "CREATE TABLE test_covering_idx (id INTEGER, name TEXT, value INTEGER, description TEXT); "
                       "CREATE INDEX idx_covering ON test_covering_idx(name, value, description)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            for (int i = 0; i < 22; i++) {
                char *insertSql = sqlite3_mprintf("INSERT INTO test_covering_idx VALUES (%d, '%.*s_%d', %u, 'desc_%d')", 
                                                i, (int)(packet->keyLength % sizeof(packet->keyData)), packet->keyData, i,
                                                packet->searchParams[i % 6], i);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
            }
            
            char *searchSql = sqlite3_mprintf("SELECT name, value, description FROM test_covering_idx WHERE name = '%.*s_%u'", 
                                            (int)(packet->keyLength % sizeof(packet->keyData)), packet->keyData,
                                            packet->keyFields % 22);
            if (searchSql) {
                sqlite3_stmt *stmt;
                if (sqlite3_prepare_v2(ctx->db, searchSql, -1, &stmt, NULL) == SQLITE_OK) {
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
                sqlite3_free(searchSql);
            }
            break;
        }
        
        case 7: { /* Descending index seek */
            char *sql = "CREATE TABLE test_desc_idx (id INTEGER, timestamp INTEGER, data TEXT); "
                       "CREATE INDEX idx_desc_timestamp ON test_desc_idx(timestamp DESC)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            for (int i = 0; i < 25; i++) {
                char *insertSql = sqlite3_mprintf("INSERT INTO test_desc_idx VALUES (%d, %u, '%.*s_%d')", 
                                                i, packet->searchParams[i % 6] + i * 1000,
                                                (int)(packet->keyLength % sizeof(packet->keyData)), packet->keyData, i);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
            }
            
            char *searchSql = sqlite3_mprintf("SELECT * FROM test_desc_idx WHERE timestamp <= %u ORDER BY timestamp DESC LIMIT 5", 
                                            packet->searchParams[0] + 10000);
            if (searchSql) {
                sqlite3_stmt *stmt;
                if (sqlite3_prepare_v2(ctx->db, searchSql, -1, &stmt, NULL) == SQLITE_OK) {
                    while (sqlite3_step(stmt) == SQLITE_ROW) {
                        /* Descending order scan */
                    }
                    sqlite3_finalize(stmt);
                }
                sqlite3_free(searchSql);
            }
            break;
        }
        
        case 8: { /* Collation index seek */
            char *sql = "CREATE TABLE test_collate_idx (id INTEGER, name TEXT COLLATE NOCASE, value INTEGER); "
                       "CREATE INDEX idx_collate_name ON test_collate_idx(name COLLATE NOCASE)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            for (int i = 0; i < 16; i++) {
                char *name = (i % 2 == 0) ? sqlite3_mprintf("%.*s_%d", (int)(packet->keyLength % sizeof(packet->keyData)), packet->keyData, i)
                                          : sqlite3_mprintf("%.*s_%d", (int)(packet->keyLength % sizeof(packet->keyData)), packet->keyData, i);
                if (name) {
                    char *insertSql = sqlite3_mprintf("INSERT INTO test_collate_idx VALUES (%d, '%s', %u)", 
                                                    i, name, packet->searchParams[i % 6]);
                    if (insertSql) {
                        sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                        sqlite3_free(insertSql);
                    }
                    sqlite3_free(name);
                }
            }
            
            char *searchSql = sqlite3_mprintf("SELECT * FROM test_collate_idx WHERE name = '%.*s_%u' COLLATE NOCASE", 
                                            (int)(packet->keyLength % sizeof(packet->keyData)), packet->keyData,
                                            packet->keyFields % 16);
            if (searchSql) {
                sqlite3_stmt *stmt;
                if (sqlite3_prepare_v2(ctx->db, searchSql, -1, &stmt, NULL) == SQLITE_OK) {
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
                sqlite3_free(searchSql);
            }
            break;
        }
        
        case 9: { /* Complex seek with subquery */
            char *sql = "CREATE TABLE test_complex_idx (id INTEGER, category TEXT, score INTEGER, name TEXT); "
                       "CREATE INDEX idx_complex_cat_score ON test_complex_idx(category, score DESC)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            for (int i = 0; i < 30; i++) {
                char *category = (i % 3 == 0) ? "A" : (i % 3 == 1) ? "B" : "C";
                char *insertSql = sqlite3_mprintf("INSERT INTO test_complex_idx VALUES (%d, '%s', %u, '%.*s_%d')", 
                                                i, category, packet->searchParams[i % 6],
                                                (int)(packet->keyLength % sizeof(packet->keyData)), packet->keyData, i);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
            }
            
            char *category = (packet->keyFields % 3 == 0) ? "A" : (packet->keyFields % 3 == 1) ? "B" : "C";
            char *searchSql = sqlite3_mprintf("SELECT * FROM test_complex_idx WHERE category = '%s' AND score > "
                                            "(SELECT AVG(score) FROM test_complex_idx WHERE category = '%s') ORDER BY score DESC", 
                                            category, category);
            if (searchSql) {
                sqlite3_stmt *stmt;
                if (sqlite3_prepare_v2(ctx->db, searchSql, -1, &stmt, NULL) == SQLITE_OK) {
                    while (sqlite3_step(stmt) == SQLITE_ROW) {
                        /* Complex subquery with index */
                    }
                    sqlite3_finalize(stmt);
                }
                sqlite3_free(searchSql);
            }
            break;
        }
    }
    
    return 1;
}

/* Fuzz clearAllSharedCacheTableLocks function - Critical lock management */
int fuzz_clear_all_shared_cache_locks(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < sizeof(SharedCacheClearPacket)) return 0;
    
    const SharedCacheClearPacket *packet = (const SharedCacheClearPacket*)data;
    
    /* Validation checks */
    if (packet->lockCount > 8) return 0;
    if (packet->tableCount > 8) return 0;
    
    uint8_t scenario = packet->scenario % 8;
    
    switch(scenario) {
        case 0: { /* Basic shared cache simulation */
            /* Enable shared cache mode */
            sqlite3_enable_shared_cache(1);
            
            char *sql = "CREATE TABLE test_shared (id INTEGER PRIMARY KEY, data TEXT)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            for (int i = 0; i < (packet->lockCount % 8) + 5; i++) {
                char *insertSql = sqlite3_mprintf("INSERT INTO test_shared VALUES (%d, 'shared_data_%d')", i, i);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
            }
            
            /* Simulate table locks through transactions */
            sqlite3_exec(ctx->db, "BEGIN IMMEDIATE", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "SELECT COUNT(*) FROM test_shared", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "COMMIT", NULL, NULL, NULL);
            
            sqlite3_enable_shared_cache(0);
            break;
        }
        
        case 1: { /* Multiple table shared cache */
            sqlite3_enable_shared_cache(1);
            
            char *sql = "CREATE TABLE shared_table1 (id INTEGER PRIMARY KEY, data1 TEXT); "
                       "CREATE TABLE shared_table2 (id INTEGER PRIMARY KEY, data2 TEXT); "
                       "CREATE TABLE shared_table3 (id INTEGER PRIMARY KEY, data3 TEXT)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            for (int i = 0; i < packet->tableCount + 3; i++) {
                char *insertSql = sqlite3_mprintf("INSERT INTO shared_table1 VALUES (%d, 'data1_%d')", i, i);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
                
                insertSql = sqlite3_mprintf("INSERT INTO shared_table2 VALUES (%d, 'data2_%d')", i, i);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
                
                insertSql = sqlite3_mprintf("INSERT INTO shared_table3 VALUES (%d, 'data3_%d')", i, i);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
            }
            
            /* Cross-table transactions */
            sqlite3_exec(ctx->db, "BEGIN", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "SELECT s1.*, s2.* FROM shared_table1 s1, shared_table2 s2 WHERE s1.id = s2.id", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "COMMIT", NULL, NULL, NULL);
            
            sqlite3_enable_shared_cache(0);
            break;
        }
        
        case 2: { /* Read-write lock conflicts */
            sqlite3_enable_shared_cache(1);
            
            char *sql = "CREATE TABLE test_rw_locks (id INTEGER PRIMARY KEY, data TEXT)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            for (int i = 0; i < 10; i++) {
                char *insertSql = sqlite3_mprintf("INSERT INTO test_rw_locks VALUES (%d, 'rw_data_%d')", i, i);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
            }
            
            /* Simulate read lock */
            sqlite3_exec(ctx->db, "BEGIN DEFERRED", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "SELECT * FROM test_rw_locks WHERE id = ?", NULL, NULL, NULL);
            
            /* Simulate write lock attempt */
            if (packet->lockTypes[0] % 2 == 0) {
                sqlite3_exec(ctx->db, "UPDATE test_rw_locks SET data = 'updated' WHERE id = 1", NULL, NULL, NULL);
            }
            
            sqlite3_exec(ctx->db, "COMMIT", NULL, NULL, NULL);
            sqlite3_enable_shared_cache(0);
            break;
        }
        
        case 3: { /* Nested transaction locks */
            sqlite3_enable_shared_cache(1);
            
            char *sql = "CREATE TABLE test_nested_locks (id INTEGER PRIMARY KEY, data TEXT, version INTEGER)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            for (int i = 0; i < 8; i++) {
                char *insertSql = sqlite3_mprintf("INSERT INTO test_nested_locks VALUES (%d, 'nested_data_%d', 1)", i, i);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
            }
            
            sqlite3_exec(ctx->db, "BEGIN", NULL, NULL, NULL);
            
            char *spName = sqlite3_mprintf("sp_%u", packet->tableNumbers[0] % 1000);
            if (spName) {
                char *spSql = sqlite3_mprintf("SAVEPOINT %s", spName);
                if (spSql) {
                    sqlite3_exec(ctx->db, spSql, NULL, NULL, NULL);
                    sqlite3_free(spSql);
                }
                
                char *updateSql = sqlite3_mprintf("UPDATE test_nested_locks SET version = %u WHERE id <= %u", 
                                                packet->testData[0] % 100, packet->lockCount);
                if (updateSql) {
                    sqlite3_exec(ctx->db, updateSql, NULL, NULL, NULL);
                    sqlite3_free(updateSql);
                }
                
                if (packet->lockTypes[1] % 2 == 0) {
                    char *releaseSql = sqlite3_mprintf("RELEASE %s", spName);
                    if (releaseSql) {
                        sqlite3_exec(ctx->db, releaseSql, NULL, NULL, NULL);
                        sqlite3_free(releaseSql);
                    }
                } else {
                    char *rollbackSql = sqlite3_mprintf("ROLLBACK TO %s", spName);
                    if (rollbackSql) {
                        sqlite3_exec(ctx->db, rollbackSql, NULL, NULL, NULL);
                        sqlite3_free(rollbackSql);
                    }
                }
                
                sqlite3_free(spName);
            }
            
            sqlite3_exec(ctx->db, "COMMIT", NULL, NULL, NULL);
            sqlite3_enable_shared_cache(0);
            break;
        }
        
        case 4: { /* Index lock testing */
            sqlite3_enable_shared_cache(1);
            
            char *sql = "CREATE TABLE test_idx_locks (id INTEGER, name TEXT, value INTEGER); "
                       "CREATE INDEX idx_locks_name ON test_idx_locks(name); "
                       "CREATE INDEX idx_locks_value ON test_idx_locks(value)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            for (int i = 0; i < (packet->tableCount % 8) + 10; i++) {
                char *insertSql = sqlite3_mprintf("INSERT INTO test_idx_locks VALUES (%d, 'name_%04d', %u)", 
                                                i, i, packet->testData[i % 4]);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
            }
            
            sqlite3_exec(ctx->db, "BEGIN", NULL, NULL, NULL);
            
            /* Index-based queries that require locks */
            char *searchSql = sqlite3_mprintf("SELECT * FROM test_idx_locks WHERE name = 'name_%04d'", packet->lockCount);
            if (searchSql) {
                sqlite3_exec(ctx->db, searchSql, NULL, NULL, NULL);
                sqlite3_free(searchSql);
            }
            
            searchSql = sqlite3_mprintf("SELECT * FROM test_idx_locks WHERE value BETWEEN %u AND %u", 
                                      packet->testData[0], packet->testData[1]);
            if (searchSql) {
                sqlite3_exec(ctx->db, searchSql, NULL, NULL, NULL);
                sqlite3_free(searchSql);
            }
            
            sqlite3_exec(ctx->db, "COMMIT", NULL, NULL, NULL);
            sqlite3_enable_shared_cache(0);
            break;
        }
        
        case 5: { /* Foreign key constraint locks */
            sqlite3_enable_shared_cache(1);
            
            char *sql = "PRAGMA foreign_keys=ON; "
                       "CREATE TABLE parent_locks (id INTEGER PRIMARY KEY, name TEXT); "
                       "CREATE TABLE child_locks (id INTEGER PRIMARY KEY, parent_id INTEGER, "
                       "data TEXT, FOREIGN KEY(parent_id) REFERENCES parent_locks(id))";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            for (int i = 1; i <= packet->tableCount + 5; i++) {
                char *parentSql = sqlite3_mprintf("INSERT INTO parent_locks VALUES (%d, 'parent_%d')", i, i);
                if (parentSql) {
                    sqlite3_exec(ctx->db, parentSql, NULL, NULL, NULL);
                    sqlite3_free(parentSql);
                }
                
                char *childSql = sqlite3_mprintf("INSERT INTO child_locks VALUES (%d, %d, 'child_data_%d')", i + 100, i, i);
                if (childSql) {
                    sqlite3_exec(ctx->db, childSql, NULL, NULL, NULL);
                    sqlite3_free(childSql);
                }
            }
            
            sqlite3_exec(ctx->db, "BEGIN", NULL, NULL, NULL);
            
            /* Operations that trigger foreign key checks */
            char *updateSql = sqlite3_mprintf("UPDATE parent_locks SET name = 'updated_parent_%u' WHERE id = %u", 
                                            packet->testData[0], packet->lockCount % (packet->tableCount + 5) + 1);
            if (updateSql) {
                sqlite3_exec(ctx->db, updateSql, NULL, NULL, NULL);
                sqlite3_free(updateSql);
            }
            
            sqlite3_exec(ctx->db, "COMMIT", NULL, NULL, NULL);
            sqlite3_enable_shared_cache(0);
            break;
        }
        
        case 6: { /* Trigger-based lock testing */
            sqlite3_enable_shared_cache(1);
            
            char *sql = "CREATE TABLE trigger_locks (id INTEGER PRIMARY KEY, data TEXT, updated_at INTEGER); "
                       "CREATE TABLE trigger_log (action TEXT, table_name TEXT, row_id INTEGER, timestamp INTEGER); "
                       "CREATE TRIGGER lock_update_trigger AFTER UPDATE ON trigger_locks "
                       "BEGIN INSERT INTO trigger_log VALUES ('UPDATE', 'trigger_locks', NEW.id, strftime('%s', 'now')); END";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            for (int i = 1; i <= (packet->lockCount % 8) + 8; i++) {
                char *insertSql = sqlite3_mprintf("INSERT INTO trigger_locks VALUES (%d, 'trigger_data_%d', %u)", 
                                                i, i, packet->testData[i % 4]);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
            }
            
            sqlite3_exec(ctx->db, "BEGIN", NULL, NULL, NULL);
            
            /* Update that triggers the trigger (which requires additional locks) */
            char *updateSql = sqlite3_mprintf("UPDATE trigger_locks SET data = 'updated_trigger_%u', updated_at = %u WHERE id = %u", 
                                            packet->testData[0], packet->testData[1], packet->lockCount % 8 + 1);
            if (updateSql) {
                sqlite3_exec(ctx->db, updateSql, NULL, NULL, NULL);
                sqlite3_free(updateSql);
            }
            
            sqlite3_exec(ctx->db, "COMMIT", NULL, NULL, NULL);
            sqlite3_enable_shared_cache(0);
            break;
        }
        
        case 7: { /* Complex multi-database lock scenario */
            sqlite3_enable_shared_cache(1);
            
            /* Attach additional database */
            char *attachSql = sqlite3_mprintf("ATTACH DATABASE ':memory:' AS db2");
            if (attachSql) {
                sqlite3_exec(ctx->db, attachSql, NULL, NULL, NULL);
                sqlite3_free(attachSql);
            }
            
            char *sql = "CREATE TABLE main.complex_locks (id INTEGER PRIMARY KEY, data TEXT); "
                       "CREATE TABLE db2.complex_locks2 (id INTEGER PRIMARY KEY, ref_id INTEGER, value TEXT)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            for (int i = 1; i <= packet->tableCount + 6; i++) {
                char *insertSql = sqlite3_mprintf("INSERT INTO main.complex_locks VALUES (%d, 'main_data_%d')", i, i);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
                
                insertSql = sqlite3_mprintf("INSERT INTO db2.complex_locks2 VALUES (%d, %d, 'db2_value_%d')", i + 100, i, i);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
            }
            
            sqlite3_exec(ctx->db, "BEGIN", NULL, NULL, NULL);
            
            /* Cross-database operations */
            char *joinSql = sqlite3_mprintf("SELECT m.*, d.value FROM main.complex_locks m "
                                          "JOIN db2.complex_locks2 d ON m.id = d.ref_id WHERE m.id <= %u", packet->lockCount);
            if (joinSql) {
                sqlite3_exec(ctx->db, joinSql, NULL, NULL, NULL);
                sqlite3_free(joinSql);
            }
            
            sqlite3_exec(ctx->db, "COMMIT", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "DETACH DATABASE db2", NULL, NULL, NULL);
            sqlite3_enable_shared_cache(0);
            break;
        }
    }
    
    return 1;
}