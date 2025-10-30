/*
** SQLite3 Parser Expression Functions Harness Implementation
** Target functions: sqlite3ExprAttachSubtrees, sqlite3NestedParse, sqlite3TableLock
*/

#include "parser_expr_harness.h"
#include <string.h>

/* Setup function for parser context */
static int setup_parser_context(sqlite3 *db, sqlite3_stmt **ppStmt, const char *sql) {
    int rc = sqlite3_exec(db, 
        "CREATE TABLE IF NOT EXISTS parser_test("
        "  id INTEGER PRIMARY KEY,"
        "  name TEXT,"
        "  value INTEGER,"
        "  data BLOB"
        ");", NULL, NULL, NULL);
    
    if (rc == SQLITE_OK && ppStmt && sql) {
        rc = sqlite3_prepare_v2(db, sql, -1, ppStmt, NULL);
    }
    return rc;
}

/* Fuzzing harness for sqlite3ExprAttachSubtrees */
int fuzz_expr_attach_subtrees(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < sizeof(ExprAttachSubtreesPacket)) {
        return SQLITE_OK;
    }
    
    const ExprAttachSubtreesPacket *packet = (const ExprAttachSubtreesPacket*)data;
    int rc = SQLITE_OK;
    
    /* Validate tree depth */
    if (packet->treeDepth > 100) return SQLITE_OK;
    
    sqlite3_stmt *pStmt = NULL;
    const char *expr_sql = NULL;
    
    /* Test expression tree construction scenarios */
    switch (packet->scenario % 8) {
        case 0:
            expr_sql = "SELECT (id + value) * 2 FROM parser_test";
            break;
        case 1:
            expr_sql = "SELECT name || ' - ' || CAST(value AS TEXT) FROM parser_test";
            break;
        case 2:
            expr_sql = "SELECT CASE WHEN value > 10 THEN 'high' ELSE 'low' END FROM parser_test";
            break;
        case 3:
            expr_sql = "SELECT id AND value OR name IS NOT NULL FROM parser_test";
            break;
        case 4:
            expr_sql = "SELECT (id * value) + (LENGTH(name) - 1) FROM parser_test";
            break;
        case 5:
            expr_sql = "SELECT value BETWEEN 1 AND 100 AND name LIKE 'test%' FROM parser_test";
            break;
        case 6:
            expr_sql = "SELECT COALESCE(name, 'default') || CAST(id + value AS TEXT) FROM parser_test";
            break;
        case 7:
            expr_sql = "SELECT (id < value) OR (LENGTH(name) > value) FROM parser_test";
            break;
    }
    
    /* Setup and execute */
    rc = setup_parser_context(ctx->db, &pStmt, expr_sql);
    if (rc == SQLITE_OK && pStmt) {
        while (sqlite3_step(pStmt) == SQLITE_ROW) {
            /* Exercise expression evaluation */
            for (int col = 0; col < sqlite3_column_count(pStmt); col++) {
                sqlite3_column_type(pStmt, col);
                sqlite3_column_bytes(pStmt, col);
            }
        }
        sqlite3_finalize(pStmt);
    }
    
    /* Test complex nested expressions */
    const char *complex_sql = "SELECT ((id + 1) * (value - 2)) / CASE WHEN name IS NULL THEN 1 ELSE LENGTH(name) END FROM parser_test";
    rc = setup_parser_context(ctx->db, &pStmt, complex_sql);
    if (rc == SQLITE_OK && pStmt) {
        sqlite3_step(pStmt);
        sqlite3_finalize(pStmt);
    }
    
    return SQLITE_OK;
}

/* Fuzzing harness for sqlite3NestedParse */
int fuzz_nested_parse(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < sizeof(NestedParsePacket)) {
        return SQLITE_OK;
    }
    
    const NestedParsePacket *packet = (const NestedParsePacket*)data;
    int rc = SQLITE_OK;
    
    /* Validate nesting depth and SQL length */
    if (packet->nestingDepth > 20) return SQLITE_OK;
    if (packet->sqlLength > 1000000) return SQLITE_OK;
    
    /* Setup context */
    rc = setup_parser_context(ctx->db, NULL, NULL);
    if (rc != SQLITE_OK) return rc;
    
    sqlite3_stmt *pStmt = NULL;
    const char *nested_sql = NULL;
    
    /* Test nested parsing scenarios */
    switch (packet->scenario % 10) {
        case 0:
            nested_sql = "CREATE VIEW test_view AS SELECT * FROM parser_test WHERE id > 0";
            break;
        case 1:
            nested_sql = "CREATE TRIGGER test_trigger AFTER INSERT ON parser_test BEGIN UPDATE parser_test SET value = NEW.value + 1 WHERE id = NEW.id; END";
            break;
        case 2:
            nested_sql = "CREATE INDEX test_idx ON parser_test(name, value)";
            break;
        case 3:
            nested_sql = "WITH RECURSIVE cnt AS (SELECT 1 AS x UNION ALL SELECT x+1 FROM cnt WHERE x < 5) SELECT * FROM cnt";
            break;
        case 4:
            nested_sql = "INSERT INTO parser_test SELECT id+100, name||'_copy', value*2, data FROM parser_test";
            break;
        case 5:
            nested_sql = "UPDATE parser_test SET value = (SELECT MAX(value)+1 FROM parser_test WHERE id < parser_test.id)";
            break;
        case 6:
            nested_sql = "DELETE FROM parser_test WHERE id IN (SELECT id FROM parser_test WHERE value < 0)";
            break;
        case 7:
            nested_sql = "CREATE TEMPORARY TABLE temp_test AS SELECT * FROM parser_test ORDER BY value DESC";
            break;
        case 8:
            nested_sql = "ALTER TABLE parser_test ADD COLUMN extra_data TEXT DEFAULT 'default'";
            break;
        case 9:
            nested_sql = "PRAGMA table_info(parser_test)";
            break;
    }
    
    /* Execute nested parsing */
    rc = sqlite3_prepare_v2(ctx->db, nested_sql, -1, &pStmt, NULL);
    if (rc == SQLITE_OK && pStmt) {
        sqlite3_step(pStmt);
        sqlite3_finalize(pStmt);
    }
    
    /* Test parameterized nested parsing */
    char dynamic_sql[512];
    snprintf(dynamic_sql, sizeof(dynamic_sql), 
        "SELECT * FROM parser_test WHERE value > %d AND name LIKE '%%%s%%'",
        packet->scenario % 100, "test");
    
    rc = sqlite3_prepare_v2(ctx->db, dynamic_sql, -1, &pStmt, NULL);
    if (rc == SQLITE_OK && pStmt) {
        while (sqlite3_step(pStmt) == SQLITE_ROW) {
            /* Process results */
        }
        sqlite3_finalize(pStmt);
    }
    
    return SQLITE_OK;
}

/* Fuzzing harness for sqlite3TableLock */
int fuzz_table_lock(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < sizeof(TableLockPacket)) {
        return SQLITE_OK;
    }
    
    const TableLockPacket *packet = (const TableLockPacket*)data;
    int rc = SQLITE_OK;
    
    /* Validate database index and page number */
    if (packet->databaseIndex > 125) return SQLITE_OK;
    if (packet->pageNumber == 0) return SQLITE_OK;
    
    /* Setup context */
    rc = setup_parser_context(ctx->db, NULL, NULL);
    if (rc != SQLITE_OK) return rc;
    
    sqlite3_stmt *pStmt = NULL;
    const char *lock_sql = NULL;
    
    /* Test table locking scenarios */
    switch (packet->scenario % 8) {
        case 0:
            lock_sql = "BEGIN IMMEDIATE; SELECT * FROM parser_test; COMMIT;";
            break;
        case 1:
            lock_sql = "BEGIN EXCLUSIVE; INSERT INTO parser_test(name, value) VALUES('test', 1); COMMIT;";
            break;
        case 2:
            lock_sql = "SELECT * FROM parser_test WHERE id = 1 FOR UPDATE";
            break;
        case 3:
            lock_sql = "CREATE TABLE lock_test(id INTEGER); DROP TABLE lock_test;";
            break;
        case 4:
            lock_sql = "PRAGMA locking_mode=EXCLUSIVE; SELECT COUNT(*) FROM parser_test;";
            break;
        case 5:
            lock_sql = "ATTACH DATABASE ':memory:' AS mem_db; CREATE TABLE mem_db.test_table(x);";
            break;
        case 6:
            lock_sql = "SAVEPOINT sp1; UPDATE parser_test SET value = value + 1; ROLLBACK TO sp1;";
            break;
        case 7:
            lock_sql = "PRAGMA journal_mode=WAL; INSERT INTO parser_test DEFAULT VALUES;";
            break;
    }
    
    /* Execute with transaction control */
    char *full_sql = sqlite3_mprintf("%s", lock_sql);
    if (full_sql) {
        rc = sqlite3_exec(ctx->db, full_sql, NULL, NULL, NULL);
        sqlite3_free(full_sql);
    }
    
    /* Test concurrent access patterns */
    if (packet->isWriteLock) {
        rc = sqlite3_exec(ctx->db, "BEGIN IMMEDIATE;", NULL, NULL, NULL);
        if (rc == SQLITE_OK) {
            rc = sqlite3_prepare_v2(ctx->db, "UPDATE parser_test SET value = ? WHERE id = ?", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                sqlite3_bind_int(pStmt, 1, packet->scenario);
                sqlite3_bind_int(pStmt, 2, 1);
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
            sqlite3_exec(ctx->db, "COMMIT;", NULL, NULL, NULL);
        }
    } else {
        rc = sqlite3_prepare_v2(ctx->db, "SELECT COUNT(*) FROM parser_test", -1, &pStmt, NULL);
        if (rc == SQLITE_OK && pStmt) {
            sqlite3_step(pStmt);
            sqlite3_finalize(pStmt);
        }
    }
    
    /* Test multiple table operations */
    char table_name[65];
    size_t nameLen = packet->nameLength % sizeof(packet->tableName);
    memcpy(table_name, packet->tableName, nameLen);
    table_name[nameLen] = '\0';
    
    char create_sql[256];
    snprintf(create_sql, sizeof(create_sql), 
        "CREATE TEMPORARY TABLE temp_%s AS SELECT * FROM parser_test LIMIT 1", 
        nameLen > 0 ? table_name : "default");
    
    sqlite3_exec(ctx->db, create_sql, NULL, NULL, NULL);
    
    return SQLITE_OK;
}