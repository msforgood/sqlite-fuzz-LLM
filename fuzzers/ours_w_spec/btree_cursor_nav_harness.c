/*
** SQLite3 B-Tree Cursor Navigation Harness Implementation
** Target functions: btreeCursorWithLock, btreeLast, btreeNext
** Specification-based fuzzing for critical cursor navigation functions
*/

#include "btree_cursor_nav_harness.h"

/* Utility function to setup test B-Tree structure for navigation testing */
static int setup_test_btree_for_navigation(sqlite3 *db, uint32_t rootPage) {
    int rc;
    char *zErrMsg = 0;
    char sql[256];
    
    /* Create test table with various record types */
    rc = sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS nav_test(id INTEGER PRIMARY KEY, data TEXT, num REAL, blob_data BLOB);", NULL, NULL, &zErrMsg);
    if (rc != SQLITE_OK) {
        if (zErrMsg) sqlite3_free(zErrMsg);
        return rc;
    }
    
    /* Insert test records for cursor navigation */
    const char* insert_queries[] = {
        "INSERT OR IGNORE INTO nav_test VALUES (1, 'first_record', 1.1, x'deadbeef');",
        "INSERT OR IGNORE INTO nav_test VALUES (2, 'second_record', 2.2, x'cafebabe');",
        "INSERT OR IGNORE INTO nav_test VALUES (3, 'third_record', 3.3, x'feedface');",
        "INSERT OR IGNORE INTO nav_test VALUES (10, 'tenth_record', 10.0, x'12345678');",
        "INSERT OR IGNORE INTO nav_test VALUES (20, 'twentieth_record', 20.0, x'87654321');"
    };
    
    for (int i = 0; i < 5; i++) {
        rc = sqlite3_exec(db, insert_queries[i], NULL, NULL, &zErrMsg);
        if (rc != SQLITE_OK && rc != SQLITE_CONSTRAINT) {
            if (zErrMsg) sqlite3_free(zErrMsg);
            return rc;
        }
        if (zErrMsg) {
            sqlite3_free(zErrMsg);
            zErrMsg = 0;
        }
    }
    
    return SQLITE_OK;
}

/* Utility function to create test cursor state */
static int create_test_cursor_state(sqlite3 *db, uint32_t tableRoot, int wrFlag) {
    int rc;
    sqlite3_stmt *pStmt;
    
    /* Prepare statement to establish cursor context */
    const char *sql = wrFlag ? 
        "UPDATE nav_test SET data = 'modified' WHERE id = 1;" :
        "SELECT * FROM nav_test WHERE id >= 1 ORDER BY id;";
    
    rc = sqlite3_prepare_v2(db, sql, -1, &pStmt, NULL);
    if (rc != SQLITE_OK) {
        return rc;
    }
    
    /* Execute to establish cursor state */
    rc = sqlite3_step(pStmt);
    sqlite3_finalize(pStmt);
    
    return (rc == SQLITE_ROW || rc == SQLITE_DONE) ? SQLITE_OK : rc;
}

/* Fuzzing harness for btreeCursorWithLock */
int fuzz_btree_cursor_with_lock(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < sizeof(BtreeCursorWithLockPacket)) {
        return SQLITE_OK;
    }
    
    const BtreeCursorWithLockPacket *packet = (const BtreeCursorWithLockPacket*)data;
    int rc = SQLITE_OK;
    
    /* Boundary validation according to spec */
    if (packet->wrFlag > 1) return SQLITE_OK;
    if (packet->iTable == 0) return SQLITE_OK;
    
    /* Setup test environment */
    rc = setup_test_btree_for_navigation(ctx->db, packet->iTable);
    if (rc != SQLITE_OK) return rc;
    
    /* Begin transaction for cursor testing */
    char *zErrMsg = 0;
    const char *trans_sql = packet->wrFlag ? "BEGIN IMMEDIATE;" : "BEGIN;";
    rc = sqlite3_exec(ctx->db, trans_sql, NULL, NULL, &zErrMsg);
    if (rc != SQLITE_OK) {
        if (zErrMsg) sqlite3_free(zErrMsg);
        return rc;
    }
    
    /* Test various cursor scenarios based on packet data */
    sqlite3_stmt *pStmt = NULL;
    const char *test_sql;
    
    switch (packet->scenario % 8) {
        case 0: /* Basic cursor open on table */
            test_sql = "SELECT * FROM nav_test WHERE id = ?;";
            break;
        case 1: /* Index cursor scenario */
            test_sql = "SELECT * FROM nav_test WHERE data LIKE ?;";
            break;
        case 2: /* Write cursor scenario */
            test_sql = packet->wrFlag ? "UPDATE nav_test SET num = ? WHERE id = 1;" : 
                                      "SELECT * FROM nav_test ORDER BY id;";
            break;
        case 3: /* Range scan cursor */
            test_sql = "SELECT * FROM nav_test WHERE id BETWEEN ? AND ?;";
            break;
        case 4: /* Empty result cursor */
            test_sql = "SELECT * FROM nav_test WHERE id = -1;";
            break;
        case 5: /* Large scan cursor */
            test_sql = "SELECT * FROM nav_test ORDER BY data;";
            break;
        case 6: /* Aggregate cursor */
            test_sql = "SELECT COUNT(*), MAX(id) FROM nav_test;";
            break;
        default: /* Full table scan */
            test_sql = "SELECT rowid, * FROM nav_test;";
            break;
    }
    
    rc = sqlite3_prepare_v2(ctx->db, test_sql, -1, &pStmt, NULL);
    if (rc == SQLITE_OK && pStmt) {
        /* Bind parameters if needed */
        int param_count = sqlite3_bind_parameter_count(pStmt);
        for (int i = 1; i <= param_count && i <= 2; i++) {
            sqlite3_bind_int(pStmt, i, (packet->keyFields + i) % 100);
        }
        
        /* Exercise cursor through multiple steps */
        int step_count = 0;
        while ((rc = sqlite3_step(pStmt)) == SQLITE_ROW && step_count < 10) {
            /* Access columns to trigger cursor navigation */
            int cols = sqlite3_column_count(pStmt);
            for (int j = 0; j < cols && j < 4; j++) {
                sqlite3_column_int(pStmt, j);
                sqlite3_column_text(pStmt, j);
            }
            step_count++;
        }
        
        sqlite3_finalize(pStmt);
    }
    
    /* Rollback transaction */
    sqlite3_exec(ctx->db, "ROLLBACK;", NULL, NULL, NULL);
    
    return SQLITE_OK;
}

/* Fuzzing harness for btreeLast */
int fuzz_btree_last(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < sizeof(BtreeLastPacket)) {
        return SQLITE_OK;
    }
    
    const BtreeLastPacket *packet = (const BtreeLastPacket*)data;
    int rc = SQLITE_OK;
    
    /* Boundary validation */
    if (packet->rootPage == 0) return SQLITE_OK;
    
    /* Setup test environment */
    rc = setup_test_btree_for_navigation(ctx->db, packet->rootPage);
    if (rc != SQLITE_OK) return rc;
    
    /* Test cursor positioning to last record scenarios */
    sqlite3_stmt *pStmt = NULL;
    const char *test_sql;
    
    switch (packet->scenario % 6) {
        case 0: /* Basic last record access */
            test_sql = "SELECT * FROM nav_test ORDER BY id DESC LIMIT 1;";
            break;
        case 1: /* Last in index */
            test_sql = "SELECT * FROM nav_test ORDER BY data DESC LIMIT 1;";
            break;
        case 2: /* Last with WHERE clause */
            test_sql = "SELECT * FROM nav_test WHERE id > 0 ORDER BY id DESC LIMIT 1;";
            break;
        case 3: /* Last in reverse scan */
            test_sql = "SELECT * FROM nav_test ORDER BY rowid DESC;";
            break;
        case 4: /* Last in empty result */
            test_sql = "SELECT * FROM nav_test WHERE id < 0 ORDER BY id DESC;";
            break;
        default: /* Last in aggregate context */
            test_sql = "SELECT MAX(id), * FROM nav_test;";
            break;
    }
    
    rc = sqlite3_prepare_v2(ctx->db, test_sql, -1, &pStmt, NULL);
    if (rc == SQLITE_OK && pStmt) {
        /* Exercise last record positioning */
        rc = sqlite3_step(pStmt);
        if (rc == SQLITE_ROW) {
            /* Access all columns to trigger internal cursor operations */
            int cols = sqlite3_column_count(pStmt);
            for (int i = 0; i < cols; i++) {
                sqlite3_column_type(pStmt, i);
                sqlite3_column_bytes(pStmt, i);
            }
        }
        
        /* Test multiple last operations */
        sqlite3_reset(pStmt);
        for (int i = 0; i < 3; i++) {
            rc = sqlite3_step(pStmt);
            if (rc != SQLITE_ROW) break;
        }
        
        sqlite3_finalize(pStmt);
    }
    
    return SQLITE_OK;
}

/* Fuzzing harness for btreeNext */
int fuzz_btree_next(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < sizeof(BtreeNextPacket)) {
        return SQLITE_OK;
    }
    
    const BtreeNextPacket *packet = (const BtreeNextPacket*)data;
    int rc = SQLITE_OK;
    
    /* Setup test environment */
    rc = setup_test_btree_for_navigation(ctx->db, 1);
    if (rc != SQLITE_OK) return rc;
    
    /* Test cursor advancement scenarios */
    sqlite3_stmt *pStmt = NULL;
    const char *test_sql;
    
    switch (packet->scenario % 8) {
        case 0: /* Sequential forward scan */
            test_sql = "SELECT * FROM nav_test ORDER BY id;";
            break;
        case 1: /* Index scan with next operations */
            test_sql = "SELECT * FROM nav_test ORDER BY data;";
            break;
        case 2: /* Filtered scan with next */
            test_sql = "SELECT * FROM nav_test WHERE id > 1 ORDER BY id;";
            break;
        case 3: /* Join operations requiring next */
            test_sql = "SELECT a.id, b.id FROM nav_test a, nav_test b WHERE a.id < b.id;";
            break;
        case 4: /* Grouped scan with next */
            test_sql = "SELECT data, COUNT(*) FROM nav_test GROUP BY SUBSTR(data, 1, 5);";
            break;
        case 5: /* Subquery with next operations */
            test_sql = "SELECT * FROM nav_test WHERE id IN (SELECT id FROM nav_test WHERE id > 1);";
            break;
        case 6: /* DISTINCT scan requiring next */
            test_sql = "SELECT DISTINCT SUBSTR(data, 1, 10) FROM nav_test;";
            break;
        default: /* Complex scan pattern */
            test_sql = "SELECT * FROM nav_test WHERE id % 2 = 0 ORDER BY num DESC;";
            break;
    }
    
    rc = sqlite3_prepare_v2(ctx->db, test_sql, -1, &pStmt, NULL);
    if (rc == SQLITE_OK && pStmt) {
        /* Exercise cursor next operations extensively */
        int row_count = 0;
        int max_rows = (packet->cellIndex % 20) + 5; /* Limit iteration based on input */
        
        while ((rc = sqlite3_step(pStmt)) == SQLITE_ROW && row_count < max_rows) {
            /* Access columns to trigger cursor navigation */
            int cols = sqlite3_column_count(pStmt);
            for (int i = 0; i < cols && i < 3; i++) {
                sqlite3_column_int(pStmt, i);
                sqlite3_column_text(pStmt, i);
                sqlite3_column_double(pStmt, i);
            }
            
            /* Simulate various cursor states during iteration */
            if (row_count % 3 == 0) {
                /* Reset and re-execute to test cursor restoration */
                sqlite3_reset(pStmt);
                sqlite3_step(pStmt);
                
                /* Skip ahead based on input data */
                for (int skip = 0; skip < (packet->pagePosition % 4); skip++) {
                    if (sqlite3_step(pStmt) != SQLITE_ROW) break;
                }
            }
            
            row_count++;
        }
        
        sqlite3_finalize(pStmt);
    }
    
    return SQLITE_OK;
}