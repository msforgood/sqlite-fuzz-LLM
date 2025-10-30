#include "fuzz.h"
#include "btree_cursor_nav_harness.h"

static int setup_test_database_with_data(FuzzCtx *ctx, int record_count) {
    if (!ctx || !ctx->db) return 0;
    
    int rc = sqlite3_exec(ctx->db, "BEGIN IMMEDIATE;", NULL, NULL, NULL);
    if (rc != SQLITE_OK) return 0;
    
    rc = sqlite3_exec(ctx->db, "CREATE TABLE IF NOT EXISTS nav_test(id INTEGER PRIMARY KEY, data TEXT, value INTEGER);", NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_exec(ctx->db, "ROLLBACK;", NULL, NULL, NULL);
        return 0;
    }
    
    char sql[256];
    for (int i = 1; i <= record_count; i++) {
        snprintf(sql, sizeof(sql), "INSERT OR REPLACE INTO nav_test(id, data, value) VALUES(%d, 'record_%d', %d);", 
                 i, i, i * 10);
        rc = sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
        if (rc != SQLITE_OK) {
            sqlite3_exec(ctx->db, "ROLLBACK;", NULL, NULL, NULL);
            return 0;
        }
    }
    
    rc = sqlite3_exec(ctx->db, "COMMIT;", NULL, NULL, NULL);
    return (rc == SQLITE_OK) ? 1 : 0;
}

static int create_test_cursor(FuzzCtx *ctx, sqlite3_stmt **stmt) {
    if (!ctx || !ctx->db || !stmt) return 0;
    
    const char *sql = "SELECT id, data, value FROM nav_test ORDER BY id";
    int rc = sqlite3_prepare_v2(ctx->db, sql, -1, stmt, NULL);
    return (rc == SQLITE_OK && *stmt != NULL) ? 1 : 0;
}

int fuzz_btree_cursor_with_lock(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (!ctx || !data || size < 28) return 0;
    
    btree_cursor_lock_packet packet;
    memcpy(&packet, data, sizeof(packet));
    
    if (packet.scenario >= 15) return 0;
    if (packet.lockMode > 3) return 0;
    if (packet.cursorType > 2) return 0;
    
    if (!setup_test_database_with_data(ctx, 50)) return 0;
    
    sqlite3_stmt *stmt = NULL;
    switch (packet.scenario) {
        case 0:
            if (create_test_cursor(ctx, &stmt)) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
            
        case 1:
            if (create_test_cursor(ctx, &stmt)) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    sqlite3_column_int(stmt, 0);
                    sqlite3_column_text(stmt, 1);
                    sqlite3_column_int(stmt, 2);
                }
                sqlite3_finalize(stmt);
            }
            break;
            
        case 2:
            sqlite3_exec(ctx->db, "BEGIN EXCLUSIVE;", NULL, NULL, NULL);
            if (create_test_cursor(ctx, &stmt)) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            sqlite3_exec(ctx->db, "COMMIT;", NULL, NULL, NULL);
            break;
            
        case 3:
            sqlite3_exec(ctx->db, "BEGIN DEFERRED;", NULL, NULL, NULL);
            if (create_test_cursor(ctx, &stmt)) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            sqlite3_exec(ctx->db, "COMMIT;", NULL, NULL, NULL);
            break;
            
        case 4:
            for (int i = 0; i < 3; i++) {
                if (create_test_cursor(ctx, &stmt)) {
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
            }
            break;
            
        case 5:
            if (create_test_cursor(ctx, &stmt)) {
                int count = 0;
                while (sqlite3_step(stmt) == SQLITE_ROW && count < 10) {
                    sqlite3_column_bytes(stmt, 1);
                    count++;
                }
                sqlite3_finalize(stmt);
            }
            break;
            
        case 6:
            sqlite3_exec(ctx->db, "PRAGMA read_uncommitted=1;", NULL, NULL, NULL);
            if (create_test_cursor(ctx, &stmt)) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            sqlite3_exec(ctx->db, "PRAGMA read_uncommitted=0;", NULL, NULL, NULL);
            break;
            
        case 7:
            sqlite3_exec(ctx->db, "SAVEPOINT test_sp;", NULL, NULL, NULL);
            if (create_test_cursor(ctx, &stmt)) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            sqlite3_exec(ctx->db, "RELEASE SAVEPOINT test_sp;", NULL, NULL, NULL);
            break;
            
        case 8:
            if (create_test_cursor(ctx, &stmt)) {
                for (int step = 0; step < 5 && sqlite3_step(stmt) == SQLITE_ROW; step++) {
                    sqlite3_column_int64(stmt, 0);
                }
                sqlite3_finalize(stmt);
            }
            break;
            
        case 9:
            if (packet.lockTimeout > 0) {
                char pragma_sql[128];
                snprintf(pragma_sql, sizeof(pragma_sql), "PRAGMA busy_timeout=%u;", packet.lockTimeout);
                sqlite3_exec(ctx->db, pragma_sql, NULL, NULL, NULL);
            }
            if (create_test_cursor(ctx, &stmt)) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
            
        case 10:
            sqlite3_exec(ctx->db, "PRAGMA locking_mode=EXCLUSIVE;", NULL, NULL, NULL);
            if (create_test_cursor(ctx, &stmt)) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            sqlite3_exec(ctx->db, "PRAGMA locking_mode=NORMAL;", NULL, NULL, NULL);
            break;
            
        case 11:
            sqlite3_exec(ctx->db, "BEGIN IMMEDIATE;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "CREATE INDEX IF NOT EXISTS nav_idx ON nav_test(value);", NULL, NULL, NULL);
            if (create_test_cursor(ctx, &stmt)) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            sqlite3_exec(ctx->db, "COMMIT;", NULL, NULL, NULL);
            break;
            
        case 12:
            if (create_test_cursor(ctx, &stmt)) {
                sqlite3_step(stmt);
                sqlite3_reset(stmt);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
            
        case 13:
            sqlite3_exec(ctx->db, "PRAGMA cache_size=100;", NULL, NULL, NULL);
            if (create_test_cursor(ctx, &stmt)) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
            
        case 14:
            if (create_test_cursor(ctx, &stmt)) {
                sqlite3_step(stmt);
                sqlite3_clear_bindings(stmt);
                sqlite3_finalize(stmt);
            }
            break;
    }
    
    return 1;
}

int fuzz_btree_last(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (!ctx || !data || size < 28) return 0;
    
    btree_last_packet packet;
    memcpy(&packet, data, sizeof(packet));
    
    if (packet.scenario >= 10) return 0;
    if (packet.navigationMode > 2) return 0;
    
    if (!setup_test_database_with_data(ctx, 25)) return 0;
    
    sqlite3_stmt *stmt = NULL;
    const char *sql;
    
    switch (packet.scenario) {
        case 0:
            sql = "SELECT * FROM nav_test ORDER BY id DESC LIMIT 1";
            if (sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL) == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
            
        case 1:
            sql = "SELECT MAX(id) FROM nav_test";
            if (sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL) == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_column_int(stmt, 0);
                sqlite3_finalize(stmt);
            }
            break;
            
        case 2:
            sql = "SELECT * FROM nav_test WHERE id = (SELECT MAX(id) FROM nav_test)";
            if (sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL) == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
            
        case 3:
            sql = "SELECT * FROM nav_test ORDER BY value DESC, id DESC LIMIT 1";
            if (sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL) == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
            
        case 4:
            for (int order = 0; order < 2; order++) {
                sql = (order == 0) ? "SELECT * FROM nav_test ORDER BY id DESC" : "SELECT * FROM nav_test ORDER BY id ASC";
                if (sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL) == SQLITE_OK) {
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
            }
            break;
            
        case 5:
            sqlite3_exec(ctx->db, "DELETE FROM nav_test WHERE id > 20;", NULL, NULL, NULL);
            sql = "SELECT * FROM nav_test ORDER BY id DESC LIMIT 1";
            if (sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL) == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
            
        case 6:
            sqlite3_exec(ctx->db, "DELETE FROM nav_test;", NULL, NULL, NULL);
            sql = "SELECT * FROM nav_test ORDER BY id DESC LIMIT 1";
            if (sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL) == SQLITE_OK) {
                int rc = sqlite3_step(stmt);
                if (rc == SQLITE_DONE) {
                }
                sqlite3_finalize(stmt);
            }
            break;
            
        case 7:
            sqlite3_exec(ctx->db, "BEGIN;", NULL, NULL, NULL);
            sql = "SELECT * FROM nav_test ORDER BY id DESC LIMIT 1";
            if (sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL) == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            sqlite3_exec(ctx->db, "COMMIT;", NULL, NULL, NULL);
            break;
            
        case 8:
            sql = "SELECT * FROM nav_test ORDER BY RANDOM() LIMIT 1";
            if (sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL) == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
            
        case 9:
            sqlite3_exec(ctx->db, "CREATE INDEX IF NOT EXISTS last_idx ON nav_test(id DESC);", NULL, NULL, NULL);
            sql = "SELECT * FROM nav_test ORDER BY id DESC LIMIT 1";
            if (sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL) == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
    }
    
    return 1;
}

int fuzz_btree_next(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (!ctx || !data || size < 24) return 0;
    
    btree_next_packet packet;
    memcpy(&packet, data, sizeof(packet));
    
    if (packet.scenario >= 12) return 0;
    if (packet.iterationMode > 3) return 0;
    
    if (!setup_test_database_with_data(ctx, 30)) return 0;
    
    sqlite3_stmt *stmt = NULL;
    const char *sql;
    
    switch (packet.scenario) {
        case 0:
            sql = "SELECT * FROM nav_test ORDER BY id";
            if (sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL) == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    sqlite3_column_int(stmt, 0);
                    sqlite3_column_text(stmt, 1);
                    sqlite3_column_int(stmt, 2);
                }
                sqlite3_finalize(stmt);
            }
            break;
            
        case 1:
            sql = "SELECT * FROM nav_test ORDER BY id";
            if (sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL) == SQLITE_OK) {
                int count = 0;
                while (sqlite3_step(stmt) == SQLITE_ROW && count < packet.maxIterations) {
                    sqlite3_column_bytes(stmt, 1);
                    count++;
                }
                sqlite3_finalize(stmt);
            }
            break;
            
        case 2:
            sql = "SELECT * FROM nav_test ORDER BY value";
            if (sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL) == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    sqlite3_column_int64(stmt, 0);
                    sqlite3_column_double(stmt, 2);
                }
                sqlite3_finalize(stmt);
            }
            break;
            
        case 3:
            sql = "SELECT * FROM nav_test WHERE id > ? ORDER BY id";
            if (sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL) == SQLITE_OK) {
                sqlite3_bind_int(stmt, 1, packet.startId);
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    sqlite3_column_int(stmt, 0);
                }
                sqlite3_finalize(stmt);
            }
            break;
            
        case 4:
            sql = "SELECT * FROM nav_test ORDER BY id";
            if (sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL) == SQLITE_OK) {
                for (int step = 0; step < 5; step++) {
                    int rc = sqlite3_step(stmt);
                    if (rc != SQLITE_ROW) break;
                    sqlite3_column_text(stmt, 1);
                }
                sqlite3_finalize(stmt);
            }
            break;
            
        case 5:
            sqlite3_exec(ctx->db, "BEGIN;", NULL, NULL, NULL);
            sql = "SELECT * FROM nav_test ORDER BY id";
            if (sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL) == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    sqlite3_column_int(stmt, 0);
                }
                sqlite3_finalize(stmt);
            }
            sqlite3_exec(ctx->db, "COMMIT;", NULL, NULL, NULL);
            break;
            
        case 6:
            sql = "SELECT * FROM nav_test ORDER BY id";
            if (sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL) == SQLITE_OK) {
                int rc = sqlite3_step(stmt);
                if (rc == SQLITE_ROW) {
                    sqlite3_reset(stmt);
                    sqlite3_step(stmt);
                }
                sqlite3_finalize(stmt);
            }
            break;
            
        case 7:
            sqlite3_exec(ctx->db, "CREATE INDEX IF NOT EXISTS nav_val_idx ON nav_test(value);", NULL, NULL, NULL);
            sql = "SELECT * FROM nav_test ORDER BY value";
            if (sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL) == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    sqlite3_column_int(stmt, 2);
                }
                sqlite3_finalize(stmt);
            }
            break;
            
        case 8:
            sql = "SELECT * FROM nav_test WHERE data LIKE 'record_%' ORDER BY id";
            if (sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL) == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    const char *text = (const char*)sqlite3_column_text(stmt, 1);
                    if (text) {
                        size_t len = strlen(text);
                        (void)len;
                    }
                }
                sqlite3_finalize(stmt);
            }
            break;
            
        case 9:
            sqlite3_exec(ctx->db, "UPDATE nav_test SET value = value * 2 WHERE id <= 10;", NULL, NULL, NULL);
            sql = "SELECT * FROM nav_test ORDER BY id";
            if (sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL) == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    sqlite3_column_int(stmt, 2);
                }
                sqlite3_finalize(stmt);
            }
            break;
            
        case 10:
            for (int pass = 0; pass < 2; pass++) {
                sql = "SELECT * FROM nav_test ORDER BY id";
                if (sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL) == SQLITE_OK) {
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
            }
            break;
            
        case 11:
            sql = "SELECT COUNT(*), SUM(value) FROM nav_test";
            if (sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL) == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_column_int(stmt, 0);
                sqlite3_column_int64(stmt, 1);
                sqlite3_finalize(stmt);
            }
            sql = "SELECT * FROM nav_test ORDER BY id";
            if (sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL) == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    sqlite3_column_int(stmt, 0);
                }
                sqlite3_finalize(stmt);
            }
            break;
    }
    
    return 1;
}