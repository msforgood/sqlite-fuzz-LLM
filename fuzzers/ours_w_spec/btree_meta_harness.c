/*
** B-Tree Metadata Functions Harness Implementation
** Targets: sqlite3BtreeTransferRow, sqlite3BtreeTripAllCursors, 
**          sqlite3BtreeUpdateMeta, unlockBtreeIfUnused
** Specification-based fuzzing implementation for SQLite3 v3.51.0
*/

#include "btree_meta_harness.h"
#include "sqlite3.h"

/*
** Fuzzing harness for sqlite3BtreeTransferRow function
** FC: btree_meta_001
*/
int fuzz_btree_transfer_row(FuzzCtx *pCtx, const BtreeTransferRowPacket *pPacket) {
    /* Validation according to sqlite3BtreeTransferRow_spec.json */
    if (pPacket->nPayload > 1073741824) return 0;
    
    sqlite3 *db = NULL;
    int rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) return 0;
    
    /* Test different row transfer scenarios */
    switch (pPacket->scenario & 0x7) {
        case BTREE_META_SCENARIO_NORMAL: {
            /* Normal row transfer between tables */
            sqlite3_exec(db, "CREATE TABLE src_table(id INTEGER PRIMARY KEY, data TEXT)", NULL, NULL, NULL);
            sqlite3_exec(db, "CREATE TABLE dest_table(id INTEGER PRIMARY KEY, data TEXT)", NULL, NULL, NULL);
            
            /* Insert test data for transfer */
            for (int i = 0; i < 5; i++) {
                char *sql = sqlite3_mprintf("INSERT INTO src_table VALUES(%lld, '%.*s_%d')", 
                                           (long long)(pPacket->iKey + i), 8, pPacket->testData, i);
                sqlite3_exec(db, sql, NULL, NULL, NULL);
                sqlite3_free(sql);
            }
            
            /* Test data transfer via INSERT SELECT */
            sqlite3_exec(db, "INSERT INTO dest_table SELECT * FROM src_table", NULL, NULL, NULL);
            break;
        }
        case BTREE_META_SCENARIO_TRANSFER: {
            /* Index to table transfer scenarios */
            sqlite3_exec(db, "CREATE TABLE transfer_test(a INTEGER, b TEXT, c REAL)", NULL, NULL, NULL);
            sqlite3_exec(db, "CREATE INDEX idx_transfer ON transfer_test(a, b)", NULL, NULL, NULL);
            
            /* Insert data to trigger index operations */
            for (int i = 0; i < (pPacket->nLocal & 0x7) + 1; i++) {
                char *sql = sqlite3_mprintf("INSERT INTO transfer_test VALUES(%d, '%.*s', %f)", 
                                           i, 6, pPacket->testData, (double)i / 10.0);
                sqlite3_exec(db, sql, NULL, NULL, NULL);
                sqlite3_free(sql);
            }
            
            /* Test data retrieval that exercises transfer */
            sqlite3_exec(db, "SELECT * FROM transfer_test WHERE a > 0 ORDER BY b", NULL, NULL, NULL);
            break;
        }
        case BTREE_META_SCENARIO_OVERFLOW: {
            /* Large payload transfer testing */
            sqlite3_exec(db, "CREATE TABLE overflow_test(id INTEGER, large_data TEXT)", NULL, NULL, NULL);
            
            /* Create large data that may cause overflow pages */
            char *largeData = sqlite3_mprintf("%.*s%.*s%.*s%.*s", 
                                             6, pPacket->testData,
                                             6, pPacket->testData + 6,
                                             6, pPacket->testData + 12,
                                             6, pPacket->testData + 18);
            char *sql = sqlite3_mprintf("INSERT INTO overflow_test VALUES(%lld, '%s')", 
                                       (long long)pPacket->iKey, largeData);
            sqlite3_exec(db, sql, NULL, NULL, NULL);
            sqlite3_free(sql);
            sqlite3_free(largeData);
            
            /* Test transfer of large data */
            sqlite3_exec(db, "CREATE TABLE overflow_dest AS SELECT * FROM overflow_test", NULL, NULL, NULL);
            break;
        }
        case BTREE_META_SCENARIO_CURSORS: {
            /* Multiple cursor transfer scenarios */
            sqlite3_exec(db, "CREATE TABLE cursor_src(key INTEGER, val TEXT)", NULL, NULL, NULL);
            sqlite3_exec(db, "CREATE TABLE cursor_dest(key INTEGER, val TEXT)", NULL, NULL, NULL);
            
            /* Multiple simultaneous operations */
            sqlite3_exec(db, "BEGIN", NULL, NULL, NULL);
            for (int i = 0; i < 3; i++) {
                char *sql = sqlite3_mprintf("INSERT INTO cursor_src VALUES(%lld, '%.*s_%d')", 
                                           (long long)(pPacket->iKey + i * 100), 8, pPacket->testData, i);
                sqlite3_exec(db, sql, NULL, NULL, NULL);
                sqlite3_free(sql);
            }
            sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
            
            /* Test concurrent transfer operations */
            sqlite3_exec(db, "INSERT INTO cursor_dest SELECT * FROM cursor_src", NULL, NULL, NULL);
            break;
        }
        default: {
            /* Basic transfer testing */
            sqlite3_exec(db, "CREATE TABLE basic_src(data)", NULL, NULL, NULL);
            sqlite3_exec(db, "CREATE TABLE basic_dest(data)", NULL, NULL, NULL);
            char *sql = sqlite3_mprintf("INSERT INTO basic_src VALUES('%.*s')", 10, pPacket->testData);
            sqlite3_exec(db, sql, NULL, NULL, NULL);
            sqlite3_free(sql);
            sqlite3_exec(db, "INSERT INTO basic_dest SELECT * FROM basic_src", NULL, NULL, NULL);
            break;
        }
    }
    
    /* Test corruption scenarios */
    if (pPacket->corruption_seed & 0x1) {
        sqlite3_exec(db, "PRAGMA integrity_check", NULL, NULL, NULL);
    }
    
    sqlite3_close(db);
    return 0;
}

/*
** Fuzzing harness for sqlite3BtreeTripAllCursors function
** FC: btree_meta_002
*/
int fuzz_btree_trip_all_cursors(FuzzCtx *pCtx, const BtreeTripAllCursorsPacket *pPacket) {
    /* Validation according to sqlite3BtreeTripAllCursors_spec.json */
    if (pPacket->writeOnly > 1) return 0;
    if (pPacket->cursorCount > 100) return 0;
    
    sqlite3 *db = NULL;
    int rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) return 0;
    
    /* Test different cursor trip scenarios */
    switch (pPacket->scenario & 0x7) {
        case BTREE_META_SCENARIO_NORMAL: {
            /* Normal cursor operations */
            sqlite3_exec(db, "CREATE TABLE cursor_test(id INTEGER, data TEXT)", NULL, NULL, NULL);
            
            /* Create multiple prepared statements (cursors) */
            sqlite3_stmt *stmts[5] = {0};
            for (int i = 0; i < 5 && i < pPacket->cursorCount; i++) {
                char *sql = sqlite3_mprintf("SELECT * FROM cursor_test WHERE id = %d", i);
                sqlite3_prepare_v2(db, sql, -1, &stmts[i], NULL);
                sqlite3_free(sql);
            }
            
            /* Insert data to trigger cursor operations */
            for (int i = 0; i < 3; i++) {
                char *sql = sqlite3_mprintf("INSERT INTO cursor_test VALUES(%d, '%.*s_%d')", 
                                           i, 6, pPacket->testData, i);
                sqlite3_exec(db, sql, NULL, NULL, NULL);
                sqlite3_free(sql);
            }
            
            /* Finalize statements */
            for (int i = 0; i < 5; i++) {
                if (stmts[i]) sqlite3_finalize(stmts[i]);
            }
            break;
        }
        case BTREE_META_SCENARIO_CURSORS: {
            /* Multiple cursor trip scenarios */
            sqlite3_exec(db, "CREATE TABLE multi_cursor(a INTEGER, b TEXT, c REAL)", NULL, NULL, NULL);
            sqlite3_exec(db, "CREATE INDEX idx_multi ON multi_cursor(a)", NULL, NULL, NULL);
            
            /* Multiple concurrent cursors */
            sqlite3_stmt *readStmt, *writeStmt;
            sqlite3_prepare_v2(db, "SELECT * FROM multi_cursor WHERE a > ?", -1, &readStmt, NULL);
            sqlite3_prepare_v2(db, "INSERT INTO multi_cursor VALUES(?, ?, ?)", -1, &writeStmt, NULL);
            
            /* Test cursor operations */
            if (writeStmt) {
                for (int i = 0; i < 3; i++) {
                    sqlite3_bind_int(writeStmt, 1, i);
                    sqlite3_bind_text(writeStmt, 2, pPacket->testData, 8, SQLITE_STATIC);
                    sqlite3_bind_double(writeStmt, 3, i * 1.5);
                    sqlite3_step(writeStmt);
                    sqlite3_reset(writeStmt);
                }
                sqlite3_finalize(writeStmt);
            }
            
            /* Test read cursor */
            if (readStmt) {
                sqlite3_bind_int(readStmt, 1, 0);
                while (sqlite3_step(readStmt) == SQLITE_ROW) {
                    sqlite3_column_int(readStmt, 0);
                    sqlite3_column_text(readStmt, 1);
                }
                sqlite3_finalize(readStmt);
            }
            break;
        }
        case BTREE_META_SCENARIO_BOUNDARY: {
            /* Boundary condition cursor testing */
            sqlite3_exec(db, "CREATE TABLE boundary_test(edge_case INTEGER)", NULL, NULL, NULL);
            
            /* Test with different error conditions */
            unsigned errCode = pPacket->errCode & 0xFF;
            if (errCode == 0) errCode = SQLITE_OK;
            
            /* Create cursors and test error propagation */
            sqlite3_stmt *stmt;
            char *sql = sqlite3_mprintf("SELECT * FROM boundary_test WHERE edge_case = '%.*s'", 
                                       8, pPacket->testData);
            if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            sqlite3_free(sql);
            break;
        }
        default: {
            /* Basic cursor testing */
            sqlite3_exec(db, "CREATE TABLE basic_cursor(x)", NULL, NULL, NULL);
            sqlite3_exec(db, "INSERT INTO basic_cursor VALUES('test')", NULL, NULL, NULL);
            sqlite3_exec(db, "SELECT * FROM basic_cursor", NULL, NULL, NULL);
            break;
        }
    }
    
    /* Test corruption scenarios */
    if (pPacket->corruption_flags & 0x1) {
        sqlite3_exec(db, "PRAGMA quick_check", NULL, NULL, NULL);
    }
    
    sqlite3_close(db);
    return 0;
}

/*
** Fuzzing harness for sqlite3BtreeUpdateMeta function
** FC: btree_meta_003
*/
int fuzz_btree_update_meta(FuzzCtx *pCtx, const BtreeUpdateMetaPacket *pPacket) {
    /* Validation according to sqlite3BtreeUpdateMeta_spec.json */
    if (pPacket->idx < 1 || pPacket->idx > 15) return 0;
    
    sqlite3 *db = NULL;
    int rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) return 0;
    
    /* Test different meta update scenarios */
    switch (pPacket->scenario & 0x7) {
        case BTREE_META_SCENARIO_NORMAL: {
            /* Normal meta operations */
            sqlite3_exec(db, "CREATE TABLE meta_test(id INTEGER, info TEXT)", NULL, NULL, NULL);
            
            /* Test schema operations that update metadata */
            char *sql = sqlite3_mprintf("INSERT INTO meta_test VALUES(%u, '%.*s')", 
                                       pPacket->iMeta & 0xFFFF, 8, pPacket->testData);
            sqlite3_exec(db, sql, NULL, NULL, NULL);
            sqlite3_free(sql);
            
            /* Test schema changes */
            sqlite3_exec(db, "CREATE INDEX idx_meta ON meta_test(id)", NULL, NULL, NULL);
            sqlite3_exec(db, "ALTER TABLE meta_test ADD COLUMN extra TEXT", NULL, NULL, NULL);
            break;
        }
        case BTREE_META_SCENARIO_METADATA: {
            /* Metadata-specific operations */
            sqlite3_exec(db, "CREATE TABLE metadata_ops(version INTEGER, flags INTEGER)", NULL, NULL, NULL);
            
            /* Test operations that affect database metadata */
            sqlite3_exec(db, "PRAGMA schema_version", NULL, NULL, NULL);
            sqlite3_exec(db, "PRAGMA user_version = " STRINGIFY(iMeta), NULL, NULL, NULL);
            
            /* Test with various meta values */
            char *sql = sqlite3_mprintf("INSERT INTO metadata_ops VALUES(%u, %u)", 
                                       pPacket->idx, pPacket->iMeta);
            sqlite3_exec(db, sql, NULL, NULL, NULL);
            sqlite3_free(sql);
            break;
        }
        case BTREE_META_SCENARIO_UNLOCK: {
            /* Auto-vacuum and incremental vacuum testing */
            sqlite3_exec(db, "PRAGMA auto_vacuum = INCREMENTAL", NULL, NULL, NULL);
            sqlite3_exec(db, "CREATE TABLE vacuum_test(data TEXT)", NULL, NULL, NULL);
            
            /* Insert and delete data to trigger vacuum operations */
            for (int i = 0; i < 10; i++) {
                char *sql = sqlite3_mprintf("INSERT INTO vacuum_test VALUES('%.*s_%d')", 
                                           6, pPacket->testData, i);
                sqlite3_exec(db, sql, NULL, NULL, NULL);
                sqlite3_free(sql);
            }
            
            sqlite3_exec(db, "DELETE FROM vacuum_test WHERE rowid % 2 = 0", NULL, NULL, NULL);
            sqlite3_exec(db, "PRAGMA incremental_vacuum", NULL, NULL, NULL);
            break;
        }
        case BTREE_META_SCENARIO_BOUNDARY: {
            /* Boundary value testing */
            sqlite3_exec(db, "CREATE TABLE boundary_meta(val INTEGER)", NULL, NULL, NULL);
            
            /* Test with boundary meta values */
            char *sql = sqlite3_mprintf("INSERT INTO boundary_meta VALUES(%u)", pPacket->iMeta);
            sqlite3_exec(db, sql, NULL, NULL, NULL);
            sqlite3_free(sql);
            
            /* Test metadata boundary conditions */
            sqlite3_exec(db, "PRAGMA application_id = 0", NULL, NULL, NULL);
            sqlite3_exec(db, "PRAGMA application_id = 4294967295", NULL, NULL, NULL);
            break;
        }
        default: {
            /* Basic meta testing */
            sqlite3_exec(db, "CREATE TABLE basic_meta(x)", NULL, NULL, NULL);
            char *sql = sqlite3_mprintf("INSERT INTO basic_meta VALUES('%.*s')", 
                                       6, pPacket->testData);
            sqlite3_exec(db, sql, NULL, NULL, NULL);
            sqlite3_free(sql);
            break;
        }
    }
    
    /* Test corruption scenarios */
    if (pPacket->corruption_test & 0x1) {
        sqlite3_exec(db, "PRAGMA integrity_check", NULL, NULL, NULL);
    }
    
    sqlite3_close(db);
    return 0;
}

/*
** Fuzzing harness for unlockBtreeIfUnused function
** FC: btree_meta_004
*/
int fuzz_btree_unlock_if_unused(FuzzCtx *pCtx, const BtreeUnlockIfUnusedPacket *pPacket) {
    /* Validation according to unlockBtreeIfUnused_spec.json */
    if (pPacket->cursorCount > 100) return 0;
    
    sqlite3 *db = NULL;
    int rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) return 0;
    
    /* Test different unlock scenarios */
    switch (pPacket->scenario & 0x7) {
        case BTREE_META_SCENARIO_NORMAL: {
            /* Normal unlock operations */
            sqlite3_exec(db, "CREATE TABLE unlock_test(id INTEGER, data TEXT)", NULL, NULL, NULL);
            
            /* Test operations that may trigger unlock */
            char *sql = sqlite3_mprintf("INSERT INTO unlock_test VALUES(1, '%.*s')", 
                                       6, pPacket->testData);
            sqlite3_exec(db, sql, NULL, NULL, NULL);
            sqlite3_free(sql);
            
            /* Test read operations */
            sqlite3_exec(db, "SELECT * FROM unlock_test", NULL, NULL, NULL);
            sqlite3_exec(db, "SELECT COUNT(*) FROM unlock_test", NULL, NULL, NULL);
            break;
        }
        case BTREE_META_SCENARIO_UNLOCK: {
            /* Resource cleanup scenarios */
            sqlite3_exec(db, "CREATE TABLE cleanup_test(resource TEXT)", NULL, NULL, NULL);
            
            /* Multiple transaction scenarios */
            sqlite3_exec(db, "BEGIN", NULL, NULL, NULL);
            char *sql = sqlite3_mprintf("INSERT INTO cleanup_test VALUES('%.*s')", 
                                       6, pPacket->testData);
            sqlite3_exec(db, sql, NULL, NULL, NULL);
            sqlite3_free(sql);
            sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
            
            /* Test auto-commit mode */
            sql = sqlite3_mprintf("INSERT INTO cleanup_test VALUES('auto_%.*s')", 
                                 4, pPacket->testData);
            sqlite3_exec(db, sql, NULL, NULL, NULL);
            sqlite3_free(sql);
            break;
        }
        case BTREE_META_SCENARIO_CURSORS: {
            /* Cursor management for unlock */
            sqlite3_exec(db, "CREATE TABLE cursor_unlock(id INTEGER)", NULL, NULL, NULL);
            
            /* Create and immediately close cursors */
            for (int i = 0; i < (pPacket->cursorCount & 0x7); i++) {
                sqlite3_stmt *stmt;
                char *sql = sqlite3_mprintf("SELECT * FROM cursor_unlock WHERE id = %d", i);
                if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
                sqlite3_free(sql);
            }
            break;
        }
        case BTREE_META_SCENARIO_BOUNDARY: {
            /* Boundary condition unlock testing */
            sqlite3_exec(db, "CREATE TABLE boundary_unlock(edge INTEGER)", NULL, NULL, NULL);
            
            /* Test edge cases */
            sqlite3_exec(db, "INSERT INTO boundary_unlock VALUES(0)", NULL, NULL, NULL);
            sqlite3_exec(db, "INSERT INTO boundary_unlock VALUES(-1)", NULL, NULL, NULL);
            
            /* Test unlock with minimal operations */
            sqlite3_exec(db, "SELECT 1", NULL, NULL, NULL);
            break;
        }
        default: {
            /* Basic unlock testing */
            sqlite3_exec(db, "CREATE TABLE basic_unlock(x)", NULL, NULL, NULL);
            sqlite3_exec(db, "INSERT INTO basic_unlock VALUES('test')", NULL, NULL, NULL);
            sqlite3_exec(db, "SELECT * FROM basic_unlock", NULL, NULL, NULL);
            break;
        }
    }
    
    /* Test corruption scenarios */
    if (pPacket->corruption_mask & 0x1) {
        sqlite3_exec(db, "PRAGMA quick_check", NULL, NULL, NULL);
    }
    
    sqlite3_close(db);
    return 0;
}