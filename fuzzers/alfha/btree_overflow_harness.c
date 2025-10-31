/*
** SQLite3 B-Tree Overflow Functions Harness Implementation
** Target functions: btreeOverwriteOverflowCell, btreeParseCellPtrIndex, btreeParseCellPtrNoPayload
*/

#include "btree_overflow_harness.h"
#include <string.h>

/* Setup function for creating overflow conditions */
static int setup_overflow_btree(sqlite3 *db, uint32_t pageSize) {
    int rc;
    char *zErrMsg = 0;
    char sql[512];
    
    /* Set custom page size if needed */
    if (pageSize >= 512 && pageSize <= 65536 && (pageSize & (pageSize - 1)) == 0) {
        snprintf(sql, sizeof(sql), "PRAGMA page_size=%u;", pageSize);
        rc = sqlite3_exec(db, sql, NULL, NULL, &zErrMsg);
        if (rc != SQLITE_OK) {
            if (zErrMsg) sqlite3_free(zErrMsg);
            return rc;
        }
    }
    
    /* Create table with large data to trigger overflow pages */
    rc = sqlite3_exec(db, 
        "CREATE TABLE IF NOT EXISTS overflow_test("
        "  id INTEGER PRIMARY KEY,"
        "  large_text TEXT,"
        "  large_blob BLOB,"
        "  metadata TEXT"
        ");", NULL, NULL, &zErrMsg);
    
    if (rc != SQLITE_OK) {
        if (zErrMsg) sqlite3_free(zErrMsg);
        return rc;
    }
    
    /* Insert data that will create overflow pages */
    const char *insert_sql = 
        "INSERT OR REPLACE INTO overflow_test(id, large_text, large_blob, metadata) "
        "VALUES (?, ?, ?, ?);";
    
    sqlite3_stmt *pStmt;
    rc = sqlite3_prepare_v2(db, insert_sql, -1, &pStmt, NULL);
    if (rc != SQLITE_OK) return rc;
    
    /* Create large data that exceeds inline storage */
    char largeText[4096];
    memset(largeText, 'A', sizeof(largeText) - 1);
    largeText[sizeof(largeText) - 1] = '\0';
    
    sqlite3_bind_int(pStmt, 1, 1);
    sqlite3_bind_text(pStmt, 2, largeText, -1, SQLITE_STATIC);
    sqlite3_bind_blob(pStmt, 3, largeText, 2048, SQLITE_STATIC);
    sqlite3_bind_text(pStmt, 4, "overflow_metadata", -1, SQLITE_STATIC);
    
    rc = sqlite3_step(pStmt);
    sqlite3_finalize(pStmt);
    
    return (rc == SQLITE_DONE) ? SQLITE_OK : rc;
}

/* Fuzzing harness for btreeOverwriteOverflowCell */
int fuzz_btree_overwrite_overflow_cell(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < sizeof(BtreeOverwriteOverflowCellPacket)) {
        return SQLITE_OK;
    }
    
    const BtreeOverwriteOverflowCellPacket *packet = (const BtreeOverwriteOverflowCellPacket*)data;
    int rc = SQLITE_OK;
    
    /* Validate inputs according to spec */
    if (packet->dataSize > 1000000000) return SQLITE_OK;
    if (packet->zeroTail > 1000000) return SQLITE_OK;
    if (packet->pageSize < 512 || packet->pageSize > 65536) return SQLITE_OK;
    
    /* Setup overflow conditions */
    rc = setup_overflow_btree(ctx->db, packet->pageSize);
    if (rc != SQLITE_OK) return rc;
    
    /* Begin write transaction */
    if (packet->wrFlag) {
        rc = sqlite3_exec(ctx->db, "BEGIN IMMEDIATE;", NULL, NULL, NULL);
        if (rc != SQLITE_OK) return rc;
    } else {
        rc = sqlite3_exec(ctx->db, "BEGIN;", NULL, NULL, NULL);
        if (rc != SQLITE_OK) return rc;
    }
    
    /* Prepare statement that will trigger overflow operations */
    sqlite3_stmt *pStmt = NULL;
    const char *update_sql = NULL;
    
    switch (packet->scenario % 6) {
        case 0: /* Update existing overflow cell */
            update_sql = "UPDATE overflow_test SET large_text = ? WHERE id = 1;";
            break;
        case 1: /* Replace with larger data */
            update_sql = "UPDATE overflow_test SET large_blob = ? WHERE id = 1;";
            break;
        case 2: /* Insert new overflow record */
            update_sql = "INSERT INTO overflow_test(id, large_text) VALUES (?, ?);";
            break;
        case 3: /* Delete and reinsert */
            sqlite3_exec(ctx->db, "DELETE FROM overflow_test WHERE id = 1;", NULL, NULL, NULL);
            update_sql = "INSERT INTO overflow_test(id, large_blob) VALUES (1, ?);";
            break;
        case 4: /* Update with zero tail */
            update_sql = "UPDATE overflow_test SET large_blob = zeroblob(?) WHERE id = 1;";
            break;
        case 5: /* Complex update with multiple fields */
            update_sql = "UPDATE overflow_test SET large_text = ?, large_blob = ? WHERE id = 1;";
            break;
    }
    
    if (update_sql) {
        rc = sqlite3_prepare_v2(ctx->db, update_sql, -1, &pStmt, NULL);
        if (rc == SQLITE_OK) {
            /* Bind data based on scenario */
            if (packet->scenario % 6 == 2) {
                sqlite3_bind_int(pStmt, 1, 2 + (packet->scenario % 100));
                sqlite3_bind_blob(pStmt, 2, packet->payloadData, 
                                 packet->dataSize % sizeof(packet->payloadData), SQLITE_STATIC);
            } else if (packet->scenario % 6 == 4) {
                sqlite3_bind_int(pStmt, 1, packet->zeroTail);
            } else if (packet->scenario % 6 == 5) {
                sqlite3_bind_blob(pStmt, 1, packet->payloadData, 
                                 packet->dataSize % sizeof(packet->payloadData), SQLITE_STATIC);
                sqlite3_bind_zeroblob(pStmt, 2, packet->zeroTail);
            } else {
                sqlite3_bind_blob(pStmt, 1, packet->payloadData, 
                                 packet->dataSize % sizeof(packet->payloadData), SQLITE_STATIC);
            }
            
            rc = sqlite3_step(pStmt);
            sqlite3_finalize(pStmt);
        }
    }
    
    /* Commit or rollback */
    if (rc == SQLITE_DONE || rc == SQLITE_ROW) {
        sqlite3_exec(ctx->db, "COMMIT;", NULL, NULL, NULL);
    } else {
        sqlite3_exec(ctx->db, "ROLLBACK;", NULL, NULL, NULL);
    }
    
    return SQLITE_OK;
}

/* Fuzzing harness for btreeParseCellPtrIndex */
int fuzz_btree_parse_cell_ptr_index(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < sizeof(BtreeParseCellPtrIndexPacket)) {
        return SQLITE_OK;
    }
    
    const BtreeParseCellPtrIndexPacket *packet = (const BtreeParseCellPtrIndexPacket*)data;
    int rc = SQLITE_OK;
    
    /* Validate cell size bounds */
    if (packet->cellSize < 4 || packet->cellSize > 65535) return SQLITE_OK;
    if (packet->payloadSize > 1073741823) return SQLITE_OK;
    
    /* Create index to trigger index page parsing */
    char *zErrMsg = 0;
    rc = sqlite3_exec(ctx->db, 
        "CREATE TABLE IF NOT EXISTS index_test("
        "  id INTEGER PRIMARY KEY,"
        "  data TEXT,"
        "  value REAL"
        ");", NULL, NULL, &zErrMsg);
    
    if (rc != SQLITE_OK) {
        if (zErrMsg) sqlite3_free(zErrMsg);
        return rc;
    }
    
    /* Create various index types */
    const char *index_sql[] = {
        "CREATE INDEX IF NOT EXISTS idx_data ON index_test(data);",
        "CREATE INDEX IF NOT EXISTS idx_value ON index_test(value);",
        "CREATE INDEX IF NOT EXISTS idx_compound ON index_test(data, value);",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_unique ON index_test(data) WHERE value > 0;"
    };
    
    int idx_type = packet->scenario % 4;
    rc = sqlite3_exec(ctx->db, index_sql[idx_type], NULL, NULL, &zErrMsg);
    if (rc != SQLITE_OK) {
        if (zErrMsg) sqlite3_free(zErrMsg);
        return rc;
    }
    
    /* Insert data to populate index */
    sqlite3_stmt *pStmt;
    const char *insert_sql = "INSERT OR IGNORE INTO index_test(id, data, value) VALUES (?, ?, ?);";
    rc = sqlite3_prepare_v2(ctx->db, insert_sql, -1, &pStmt, NULL);
    if (rc != SQLITE_OK) return rc;
    
    /* Generate diverse data patterns */
    for (int i = 0; i < 10; i++) {
        char textData[256];
        snprintf(textData, sizeof(textData), "data_%d_%u", i, packet->scenario);
        
        sqlite3_bind_int(pStmt, 1, i + packet->scenario);
        sqlite3_bind_text(pStmt, 2, textData, -1, SQLITE_STATIC);
        sqlite3_bind_double(pStmt, 3, (double)(packet->payloadSize % 1000) / 10.0);
        
        sqlite3_step(pStmt);
        sqlite3_reset(pStmt);
    }
    sqlite3_finalize(pStmt);
    
    /* Query using index to trigger parsing */
    const char *query_sql[] = {
        "SELECT * FROM index_test WHERE data = ?;",
        "SELECT * FROM index_test WHERE value > ?;",
        "SELECT * FROM index_test WHERE data LIKE ? AND value < ?;",
        "SELECT * FROM index_test ORDER BY data, value;"
    };
    
    int query_type = packet->pageType % 4;
    rc = sqlite3_prepare_v2(ctx->db, query_sql[query_type], -1, &pStmt, NULL);
    if (rc == SQLITE_OK) {
        if (query_type < 3) {
            sqlite3_bind_text(pStmt, 1, "data_5", -1, SQLITE_STATIC);
            if (query_type == 2) {
                sqlite3_bind_double(pStmt, 2, 50.0);
            }
        }
        
        while (sqlite3_step(pStmt) == SQLITE_ROW) {
            /* Iterate through results to exercise index parsing */
        }
        sqlite3_finalize(pStmt);
    }
    
    /* Test index integrity */
    rc = sqlite3_exec(ctx->db, "PRAGMA integrity_check;", NULL, NULL, NULL);
    
    return SQLITE_OK;
}

/* Fuzzing harness for btreeParseCellPtrNoPayload */
int fuzz_btree_parse_cell_ptr_no_payload(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < sizeof(BtreeParseCellPtrNoPayloadPacket)) {
        return SQLITE_OK;
    }
    
    const BtreeParseCellPtrNoPayloadPacket *packet = (const BtreeParseCellPtrNoPayloadPacket*)data;
    int rc = SQLITE_OK;
    
    /* Validate interior page constraints */
    if (packet->pageLeaf) return SQLITE_OK;  /* Must be non-leaf */
    if (packet->childPtrSize != 4) return SQLITE_OK;  /* Must be 4 bytes */
    if (packet->varintBytes < 1 || packet->varintBytes > 9) return SQLITE_OK;
    
    /* Create table structure that will have interior pages */
    char *zErrMsg = 0;
    rc = sqlite3_exec(ctx->db,
        "CREATE TABLE IF NOT EXISTS interior_test("
        "  id INTEGER PRIMARY KEY,"
        "  parent_id INTEGER,"
        "  level INTEGER,"
        "  data TEXT"
        ");", NULL, NULL, &zErrMsg);
    
    if (rc != SQLITE_OK) {
        if (zErrMsg) sqlite3_free(zErrMsg);
        return rc;
    }
    
    /* Create hierarchical data to ensure interior pages */
    sqlite3_stmt *pStmt;
    const char *insert_sql = "INSERT OR IGNORE INTO interior_test(id, parent_id, level, data) VALUES (?, ?, ?, ?);";
    rc = sqlite3_prepare_v2(ctx->db, insert_sql, -1, &pStmt, NULL);
    if (rc != SQLITE_OK) return rc;
    
    /* Build tree structure */
    int base_id = packet->keyValue % 1000;
    for (int level = 0; level < 4; level++) {
        for (int node = 0; node < (1 << level); node++) {
            int id = base_id + (level * 100) + node;
            int parent = (level > 0) ? base_id + ((level - 1) * 100) + (node / 2) : -1;
            
            char nodeData[128];
            snprintf(nodeData, sizeof(nodeData), "node_L%d_N%d", level, node);
            
            sqlite3_bind_int(pStmt, 1, id);
            sqlite3_bind_int(pStmt, 2, parent);
            sqlite3_bind_int(pStmt, 3, level);
            sqlite3_bind_text(pStmt, 4, nodeData, -1, SQLITE_STATIC);
            
            sqlite3_step(pStmt);
            sqlite3_reset(pStmt);
        }
    }
    sqlite3_finalize(pStmt);
    
    /* Create index on parent_id to generate interior index pages */
    rc = sqlite3_exec(ctx->db, 
        "CREATE INDEX IF NOT EXISTS idx_parent ON interior_test(parent_id, level);",
        NULL, NULL, &zErrMsg);
    if (rc != SQLITE_OK) {
        if (zErrMsg) sqlite3_free(zErrMsg);
    }
    
    /* Perform recursive query to traverse tree (exercises interior pages) */
    const char *recursive_sql = 
        "WITH RECURSIVE tree AS ("
        "  SELECT id, parent_id, level, data FROM interior_test WHERE parent_id = -1"
        "  UNION ALL"
        "  SELECT t.id, t.parent_id, t.level, t.data"
        "  FROM interior_test t"
        "  JOIN tree ON t.parent_id = tree.id"
        ") SELECT * FROM tree ORDER BY level, id;";
    
    rc = sqlite3_prepare_v2(ctx->db, recursive_sql, -1, &pStmt, NULL);
    if (rc == SQLITE_OK) {
        while (sqlite3_step(pStmt) == SQLITE_ROW) {
            /* Traverse results to exercise interior page navigation */
        }
        sqlite3_finalize(pStmt);
    }
    
    /* Force page reorganization */
    switch (packet->scenario % 4) {
        case 0:
            sqlite3_exec(ctx->db, "VACUUM;", NULL, NULL, NULL);
            break;
        case 1:
            sqlite3_exec(ctx->db, "REINDEX;", NULL, NULL, NULL);
            break;
        case 2:
            sqlite3_exec(ctx->db, "ANALYZE;", NULL, NULL, NULL);
            break;
        case 3:
            sqlite3_exec(ctx->db, "PRAGMA incremental_vacuum;", NULL, NULL, NULL);
            break;
    }
    
    return SQLITE_OK;
}