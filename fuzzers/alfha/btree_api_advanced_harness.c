#include "fuzz.h"
#include "btree_api_advanced_harness.h"

static int setup_database_with_tables(FuzzCtx *ctx, int table_count) {
    if (!ctx || !ctx->db) return 0;
    
    int rc = sqlite3_exec(ctx->db, "BEGIN IMMEDIATE;", NULL, NULL, NULL);
    if (rc != SQLITE_OK) return 0;
    
    char sql[512];
    for (int i = 1; i <= table_count; i++) {
        snprintf(sql, sizeof(sql), 
                "CREATE TABLE IF NOT EXISTS test_table_%d(id INTEGER PRIMARY KEY, data TEXT, value INTEGER, blob_data BLOB);", i);
        rc = sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
        if (rc != SQLITE_OK) {
            sqlite3_exec(ctx->db, "ROLLBACK;", NULL, NULL, NULL);
            return 0;
        }
        
        for (int j = 1; j <= 10; j++) {
            snprintf(sql, sizeof(sql), 
                    "INSERT OR REPLACE INTO test_table_%d(id, data, value, blob_data) VALUES(%d, 'data_%d_%d', %d, x'%08x%08x');", 
                    i, j, i, j, j * 10, i, j);
            rc = sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            if (rc != SQLITE_OK) break;
        }
    }
    
    rc = sqlite3_exec(ctx->db, "COMMIT;", NULL, NULL, NULL);
    return (rc == SQLITE_OK) ? 1 : 0;
}

int fuzz_sqlite3_btree_begin_stmt(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (!ctx || !data || size < sizeof(btree_begin_stmt_packet)) return 0;
    
    btree_begin_stmt_packet packet;
    memcpy(&packet, data, sizeof(packet));
    
    if (packet.scenario >= 12) return 0;
    if (packet.stmtMode > 2) return 0;
    
    if (!setup_database_with_tables(ctx, 3)) return 0;
    
    switch (packet.scenario) {
        case 0: {
            int rc = sqlite3_exec(ctx->db, "BEGIN;", NULL, NULL, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_stmt *stmt;
                rc = sqlite3_prepare_v2(ctx->db, "SAVEPOINT stmt_test;", -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
                sqlite3_exec(ctx->db, "COMMIT;", NULL, NULL, NULL);
            }
            break;
        }
        
        case 1: {
            sqlite3_exec(ctx->db, "BEGIN;", NULL, NULL, NULL);
            for (int i = 1; i <= 3; i++) {
                char sql[256];
                snprintf(sql, sizeof(sql), "SAVEPOINT nested_stmt_%d;", i);
                sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
                snprintf(sql, sizeof(sql), "INSERT INTO test_table_1(data) VALUES('stmt_%d');", i);
                sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            }
            sqlite3_exec(ctx->db, "ROLLBACK;", NULL, NULL, NULL);
            break;
        }
        
        case 2: {
            sqlite3_exec(ctx->db, "BEGIN IMMEDIATE;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "SAVEPOINT complex_stmt;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "UPDATE test_table_1 SET value = value + 1;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "RELEASE SAVEPOINT complex_stmt;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "COMMIT;", NULL, NULL, NULL);
            break;
        }
        
        case 3: {
            sqlite3_exec(ctx->db, "BEGIN EXCLUSIVE;", NULL, NULL, NULL);
            for (int level = 0; level < 5; level++) {
                char sql[256];
                snprintf(sql, sizeof(sql), "SAVEPOINT level_%d;", level);
                sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            }
            sqlite3_exec(ctx->db, "ROLLBACK;", NULL, NULL, NULL);
            break;
        }
        
        case 4: {
            sqlite3_exec(ctx->db, "BEGIN;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "SAVEPOINT error_test;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "INSERT INTO test_table_1(id, id) VALUES(1, 2);", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "ROLLBACK TO SAVEPOINT error_test;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "COMMIT;", NULL, NULL, NULL);
            break;
        }
        
        case 5: {
            for (int i = 0; i < 3; i++) {
                sqlite3_exec(ctx->db, "BEGIN;", NULL, NULL, NULL);
                sqlite3_exec(ctx->db, "SAVEPOINT batch_stmt;", NULL, NULL, NULL);
                sqlite3_exec(ctx->db, "INSERT INTO test_table_2(data) VALUES('batch_data');", NULL, NULL, NULL);
                sqlite3_exec(ctx->db, "RELEASE SAVEPOINT batch_stmt;", NULL, NULL, NULL);
                sqlite3_exec(ctx->db, "COMMIT;", NULL, NULL, NULL);
            }
            break;
        }
        
        case 6: {
            sqlite3_exec(ctx->db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "BEGIN;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "SAVEPOINT wal_stmt;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "DELETE FROM test_table_1 WHERE id > 5;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "ROLLBACK TO SAVEPOINT wal_stmt;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "COMMIT;", NULL, NULL, NULL);
            break;
        }
        
        case 7: {
            sqlite3_exec(ctx->db, "BEGIN;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "SAVEPOINT concurrent_stmt;", NULL, NULL, NULL);
            sqlite3_stmt *stmt;
            int rc = sqlite3_prepare_v2(ctx->db, "SELECT * FROM test_table_1;", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    sqlite3_column_int(stmt, 0);
                }
                sqlite3_finalize(stmt);
            }
            sqlite3_exec(ctx->db, "COMMIT;", NULL, NULL, NULL);
            break;
        }
        
        case 8: {
            sqlite3_exec(ctx->db, "CREATE INDEX IF NOT EXISTS idx_test ON test_table_1(value);", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "BEGIN;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "SAVEPOINT index_stmt;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "UPDATE test_table_1 SET value = value * 2 WHERE id <= 5;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "RELEASE SAVEPOINT index_stmt;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "COMMIT;", NULL, NULL, NULL);
            break;
        }
        
        case 9: {
            sqlite3_exec(ctx->db, "PRAGMA foreign_keys=ON;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "CREATE TABLE IF NOT EXISTS parent(id INTEGER PRIMARY KEY);", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "CREATE TABLE IF NOT EXISTS child(id INTEGER, parent_id INTEGER REFERENCES parent(id));", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "BEGIN;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "SAVEPOINT fk_stmt;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "INSERT INTO parent(id) VALUES(1);", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "INSERT INTO child(id, parent_id) VALUES(1, 1);", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "COMMIT;", NULL, NULL, NULL);
            break;
        }
        
        case 10: {
            sqlite3_exec(ctx->db, "PRAGMA cache_size=10;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "BEGIN;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "SAVEPOINT memory_stmt;", NULL, NULL, NULL);
            for (int i = 0; i < 50; i++) {
                char sql[256];
                snprintf(sql, sizeof(sql), "INSERT INTO test_table_1(data) VALUES('large_data_%d_" 
                        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx');", i);
                sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            }
            sqlite3_exec(ctx->db, "ROLLBACK TO SAVEPOINT memory_stmt;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "COMMIT;", NULL, NULL, NULL);
            break;
        }
        
        case 11: {
            sqlite3_exec(ctx->db, "BEGIN;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "SAVEPOINT trigger_stmt;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "CREATE TRIGGER IF NOT EXISTS test_trigger AFTER INSERT ON test_table_1 BEGIN UPDATE test_table_2 SET value = NEW.id; END;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "INSERT INTO test_table_1(data) VALUES('trigger_test');", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "COMMIT;", NULL, NULL, NULL);
            break;
        }
    }
    
    return 1;
}

int fuzz_sqlite3_btree_checkpoint(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (!ctx || !data || size < sizeof(btree_checkpoint_packet)) return 0;
    
    btree_checkpoint_packet packet;
    memcpy(&packet, data, sizeof(packet));
    
    if (packet.scenario >= 15) return 0;
    if (packet.checkpointMode > 3) return 0;
    
    if (!setup_database_with_tables(ctx, 2)) return 0;
    
    sqlite3_exec(ctx->db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);
    
    switch (packet.scenario) {
        case 0: {
            sqlite3_exec(ctx->db, "INSERT INTO test_table_1(data) VALUES('checkpoint_test');", NULL, NULL, NULL);
            sqlite3_wal_checkpoint(ctx->db, NULL);
            break;
        }
        
        case 1: {
            for (int i = 0; i < 10; i++) {
                char sql[256];
                snprintf(sql, sizeof(sql), "INSERT INTO test_table_1(data) VALUES('bulk_insert_%d');", i);
                sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            }
            int nLog = 0, nCkpt = 0;
            sqlite3_wal_checkpoint_v2(ctx->db, NULL, SQLITE_CHECKPOINT_PASSIVE, &nLog, &nCkpt);
            break;
        }
        
        case 2: {
            sqlite3_exec(ctx->db, "UPDATE test_table_1 SET data = 'updated_data' WHERE id <= 5;", NULL, NULL, NULL);
            int nLog = 0, nCkpt = 0;
            sqlite3_wal_checkpoint_v2(ctx->db, NULL, SQLITE_CHECKPOINT_FULL, &nLog, &nCkpt);
            break;
        }
        
        case 3: {
            sqlite3_exec(ctx->db, "DELETE FROM test_table_1 WHERE id > 8;", NULL, NULL, NULL);
            int nLog = 0, nCkpt = 0;
            sqlite3_wal_checkpoint_v2(ctx->db, NULL, SQLITE_CHECKPOINT_RESTART, &nLog, &nCkpt);
            break;
        }
        
        case 4: {
            sqlite3_exec(ctx->db, "BEGIN;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "INSERT INTO test_table_2(data) VALUES('transaction_checkpoint');", NULL, NULL, NULL);
            sqlite3_wal_checkpoint(ctx->db, NULL);
            sqlite3_exec(ctx->db, "COMMIT;", NULL, NULL, NULL);
            break;
        }
        
        case 5: {
            for (int i = 0; i < 5; i++) {
                sqlite3_exec(ctx->db, "BEGIN;", NULL, NULL, NULL);
                char sql[256];
                snprintf(sql, sizeof(sql), "INSERT INTO test_table_1(data) VALUES('multi_txn_%d');", i);
                sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
                sqlite3_exec(ctx->db, "COMMIT;", NULL, NULL, NULL);
                if (i % 2 == 0) {
                    sqlite3_wal_checkpoint(ctx->db, NULL);
                }
            }
            break;
        }
        
        case 6: {
            sqlite3_exec(ctx->db, "PRAGMA wal_autocheckpoint=5;", NULL, NULL, NULL);
            for (int i = 0; i < 10; i++) {
                char sql[256];
                snprintf(sql, sizeof(sql), "INSERT INTO test_table_1(data) VALUES('auto_checkpoint_%d');", i);
                sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            }
            break;
        }
        
        case 7: {
            sqlite3_exec(ctx->db, "CREATE INDEX IF NOT EXISTS wal_idx ON test_table_1(data);", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "UPDATE test_table_1 SET data = 'indexed_data';", NULL, NULL, NULL);
            int nLog = 0, nCkpt = 0;
            sqlite3_wal_checkpoint_v2(ctx->db, NULL, SQLITE_CHECKPOINT_TRUNCATE, &nLog, &nCkpt);
            break;
        }
        
        case 8: {
            sqlite3_stmt *stmt;
            int rc = sqlite3_prepare_v2(ctx->db, "SELECT * FROM test_table_1;", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_wal_checkpoint(ctx->db, NULL);
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    sqlite3_column_text(stmt, 1);
                }
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 9: {
            sqlite3_exec(ctx->db, "PRAGMA busy_timeout=1000;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "INSERT INTO test_table_1(data) VALUES('busy_checkpoint');", NULL, NULL, NULL);
            sqlite3_wal_checkpoint(ctx->db, NULL);
            break;
        }
        
        case 10: {
            sqlite3_exec(ctx->db, "PRAGMA cache_size=5;", NULL, NULL, NULL);
            for (int i = 0; i < 20; i++) {
                char sql[512];
                snprintf(sql, sizeof(sql), "INSERT INTO test_table_1(data, blob_data) VALUES('memory_pressure_%d', x'%s');", 
                        i, "deadbeefcafebabedeadbeefcafebabedeadbeefcafebabe");
                sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            }
            sqlite3_wal_checkpoint(ctx->db, NULL);
            break;
        }
        
        case 11: {
            sqlite3_exec(ctx->db, "PRAGMA synchronous=OFF;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "INSERT INTO test_table_1(data) VALUES('async_checkpoint');", NULL, NULL, NULL);
            sqlite3_wal_checkpoint(ctx->db, NULL);
            sqlite3_exec(ctx->db, "PRAGMA synchronous=FULL;", NULL, NULL, NULL);
            break;
        }
        
        case 12: {
            sqlite3_exec(ctx->db, "CREATE TEMP TABLE temp_checkpoint(id INTEGER);", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "INSERT INTO temp_checkpoint VALUES(1);", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "INSERT INTO test_table_1(data) VALUES('temp_with_wal');", NULL, NULL, NULL);
            sqlite3_wal_checkpoint(ctx->db, NULL);
            break;
        }
        
        case 13: {
            sqlite3_exec(ctx->db, "PRAGMA journal_size_limit=1024;", NULL, NULL, NULL);
            for (int i = 0; i < 15; i++) {
                char sql[256];
                snprintf(sql, sizeof(sql), "INSERT INTO test_table_1(data) VALUES('limit_test_%d_xxxxxxxxxx');", i);
                sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            }
            sqlite3_wal_checkpoint(ctx->db, NULL);
            break;
        }
        
        case 14: {
            sqlite3_exec(ctx->db, "BEGIN IMMEDIATE;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "UPDATE test_table_1 SET value = id * 3;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "DELETE FROM test_table_2 WHERE id % 2 = 0;", NULL, NULL, NULL);
            sqlite3_wal_checkpoint(ctx->db, NULL);
            sqlite3_exec(ctx->db, "COMMIT;", NULL, NULL, NULL);
            break;
        }
    }
    
    return 1;
}

int fuzz_sqlite3_btree_commit(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (!ctx || !data || size < sizeof(btree_commit_packet)) return 0;
    
    btree_commit_packet packet;
    memcpy(&packet, data, sizeof(packet));
    
    if (packet.scenario >= 18) return 0;
    if (packet.commitMode > 2) return 0;
    
    if (!setup_database_with_tables(ctx, 3)) return 0;
    
    switch (packet.scenario) {
        case 0: {
            sqlite3_exec(ctx->db, "BEGIN;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "INSERT INTO test_table_1(data) VALUES('simple_commit');", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "COMMIT;", NULL, NULL, NULL);
            break;
        }
        
        case 1: {
            sqlite3_exec(ctx->db, "BEGIN IMMEDIATE;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "UPDATE test_table_1 SET value = value * 2;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "DELETE FROM test_table_2 WHERE id > 5;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "COMMIT;", NULL, NULL, NULL);
            break;
        }
        
        case 2: {
            sqlite3_exec(ctx->db, "BEGIN EXCLUSIVE;", NULL, NULL, NULL);
            for (int i = 0; i < 10; i++) {
                char sql[256];
                snprintf(sql, sizeof(sql), "INSERT INTO test_table_3(data) VALUES('batch_%d');", i);
                sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            }
            sqlite3_exec(ctx->db, "COMMIT;", NULL, NULL, NULL);
            break;
        }
        
        case 3: {
            sqlite3_exec(ctx->db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "BEGIN;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "INSERT INTO test_table_1(data) VALUES('wal_commit');", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "COMMIT;", NULL, NULL, NULL);
            break;
        }
        
        case 4: {
            sqlite3_exec(ctx->db, "PRAGMA journal_mode=MEMORY;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "BEGIN;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "UPDATE test_table_1 SET data = 'memory_journal';", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "COMMIT;", NULL, NULL, NULL);
            break;
        }
        
        case 5: {
            for (int i = 0; i < 5; i++) {
                sqlite3_exec(ctx->db, "BEGIN;", NULL, NULL, NULL);
                char sql[256];
                snprintf(sql, sizeof(sql), "INSERT INTO test_table_1(data) VALUES('nested_commit_%d');", i);
                sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
                sqlite3_exec(ctx->db, "SAVEPOINT sp1;", NULL, NULL, NULL);
                sqlite3_exec(ctx->db, "UPDATE test_table_1 SET value = id WHERE id = last_insert_rowid();", NULL, NULL, NULL);
                sqlite3_exec(ctx->db, "RELEASE SAVEPOINT sp1;", NULL, NULL, NULL);
                sqlite3_exec(ctx->db, "COMMIT;", NULL, NULL, NULL);
            }
            break;
        }
        
        case 6: {
            sqlite3_exec(ctx->db, "CREATE INDEX IF NOT EXISTS commit_idx ON test_table_1(data);", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "BEGIN;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "INSERT INTO test_table_1(data) VALUES('indexed_commit');", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "COMMIT;", NULL, NULL, NULL);
            break;
        }
        
        case 7: {
            sqlite3_exec(ctx->db, "PRAGMA foreign_keys=ON;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "CREATE TABLE IF NOT EXISTS fk_parent(id INTEGER PRIMARY KEY);", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "CREATE TABLE IF NOT EXISTS fk_child(id INTEGER, parent_id INTEGER REFERENCES fk_parent(id));", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "BEGIN;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "INSERT INTO fk_parent(id) VALUES(100);", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "INSERT INTO fk_child(id, parent_id) VALUES(1, 100);", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "COMMIT;", NULL, NULL, NULL);
            break;
        }
        
        case 8: {
            sqlite3_exec(ctx->db, "CREATE TRIGGER IF NOT EXISTS commit_trigger AFTER INSERT ON test_table_1 BEGIN INSERT INTO test_table_2(data) VALUES('triggered'); END;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "BEGIN;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "INSERT INTO test_table_1(data) VALUES('trigger_commit');", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "COMMIT;", NULL, NULL, NULL);
            break;
        }
        
        case 9: {
            sqlite3_exec(ctx->db, "PRAGMA synchronous=OFF;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "BEGIN;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "INSERT INTO test_table_1(data) VALUES('async_commit');", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "COMMIT;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "PRAGMA synchronous=FULL;", NULL, NULL, NULL);
            break;
        }
        
        case 10: {
            sqlite3_exec(ctx->db, "PRAGMA cache_size=5;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "BEGIN;", NULL, NULL, NULL);
            for (int i = 0; i < 20; i++) {
                char sql[512];
                snprintf(sql, sizeof(sql), "INSERT INTO test_table_1(data, blob_data) VALUES('memory_commit_%d', x'%s');", 
                        i, "deadbeefcafebabedeadbeefcafebabedeadbeefcafebabe");
                sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            }
            sqlite3_exec(ctx->db, "COMMIT;", NULL, NULL, NULL);
            break;
        }
        
        case 11: {
            sqlite3_exec(ctx->db, "PRAGMA busy_timeout=100;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "BEGIN IMMEDIATE;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "UPDATE test_table_1 SET data = 'busy_commit';", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "COMMIT;", NULL, NULL, NULL);
            break;
        }
        
        case 12: {
            sqlite3_exec(ctx->db, "CREATE VIEW IF NOT EXISTS commit_view AS SELECT * FROM test_table_1 WHERE value > 50;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "BEGIN;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "UPDATE test_table_1 SET value = 100 WHERE id <= 3;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "COMMIT;", NULL, NULL, NULL);
            break;
        }
        
        case 13: {
            sqlite3_exec(ctx->db, "BEGIN;", NULL, NULL, NULL);
            sqlite3_stmt *stmt;
            int rc = sqlite3_prepare_v2(ctx->db, "INSERT INTO test_table_1(data) VALUES(?);", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                for (int i = 0; i < 5; i++) {
                    char data_val[64];
                    snprintf(data_val, sizeof(data_val), "prepared_commit_%d", i);
                    sqlite3_bind_text(stmt, 1, data_val, -1, SQLITE_STATIC);
                    sqlite3_step(stmt);
                    sqlite3_reset(stmt);
                }
                sqlite3_finalize(stmt);
            }
            sqlite3_exec(ctx->db, "COMMIT;", NULL, NULL, NULL);
            break;
        }
        
        case 14: {
            sqlite3_exec(ctx->db, "PRAGMA locking_mode=EXCLUSIVE;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "BEGIN;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "INSERT INTO test_table_1(data) VALUES('exclusive_commit');", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "COMMIT;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "PRAGMA locking_mode=NORMAL;", NULL, NULL, NULL);
            break;
        }
        
        case 15: {
            sqlite3_exec(ctx->db, "BEGIN;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "CREATE TEMP TABLE temp_commit(data TEXT);", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "INSERT INTO temp_commit VALUES('temp_data');", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "INSERT INTO test_table_1(data) VALUES('with_temp');", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "COMMIT;", NULL, NULL, NULL);
            break;
        }
        
        case 16: {
            sqlite3_exec(ctx->db, "PRAGMA auto_vacuum=INCREMENTAL;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "BEGIN;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "DELETE FROM test_table_1 WHERE id % 3 = 0;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "COMMIT;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "PRAGMA incremental_vacuum(10);", NULL, NULL, NULL);
            break;
        }
        
        case 17: {
            sqlite3_exec(ctx->db, "PRAGMA secure_delete=ON;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "BEGIN;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "DELETE FROM test_table_1 WHERE id > 7;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "INSERT INTO test_table_1(data, blob_data) VALUES('secure_commit', x'deadbeefcafebabe');", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "COMMIT;", NULL, NULL, NULL);
            break;
        }
    }
    
    return 1;
}

int fuzz_sqlite3_btree_count(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (!ctx || !data || size < sizeof(btree_count_packet)) return 0;
    
    btree_count_packet packet;
    memcpy(&packet, data, sizeof(packet));
    
    if (packet.scenario >= 10) return 0;
    if (packet.countMode > 3) return 0;
    
    if (!setup_database_with_tables(ctx, 3)) return 0;
    
    switch (packet.scenario) {
        case 0: {
            sqlite3_stmt *stmt;
            int rc = sqlite3_prepare_v2(ctx->db, "SELECT COUNT(*) FROM test_table_1;", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_column_int64(stmt, 0);
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 1: {
            sqlite3_stmt *stmt;
            int rc = sqlite3_prepare_v2(ctx->db, "SELECT COUNT(DISTINCT data) FROM test_table_1;", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_column_int64(stmt, 0);
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 2: {
            sqlite3_stmt *stmt;
            int rc = sqlite3_prepare_v2(ctx->db, "SELECT COUNT(*) FROM test_table_1 WHERE value > 50;", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_column_int64(stmt, 0);
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 3: {
            sqlite3_exec(ctx->db, "CREATE INDEX IF NOT EXISTS count_idx ON test_table_1(value);", NULL, NULL, NULL);
            sqlite3_stmt *stmt;
            int rc = sqlite3_prepare_v2(ctx->db, "SELECT COUNT(*) FROM test_table_1 WHERE value BETWEEN 20 AND 80;", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_column_int64(stmt, 0);
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 4: {
            for (int i = 1; i <= 3; i++) {
                char sql[256];
                snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM test_table_%d;", i);
                sqlite3_stmt *stmt;
                int rc = sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    sqlite3_step(stmt);
                    sqlite3_column_int64(stmt, 0);
                    sqlite3_finalize(stmt);
                }
            }
            break;
        }
        
        case 5: {
            sqlite3_stmt *stmt;
            int rc = sqlite3_prepare_v2(ctx->db, "SELECT t1.id, COUNT(t2.id) FROM test_table_1 t1 LEFT JOIN test_table_2 t2 ON t1.id = t2.id GROUP BY t1.id;", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    sqlite3_column_int(stmt, 0);
                    sqlite3_column_int64(stmt, 1);
                }
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 6: {
            sqlite3_stmt *stmt;
            int rc = sqlite3_prepare_v2(ctx->db, "SELECT COUNT(*) OVER() FROM test_table_1 LIMIT 5;", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    sqlite3_column_int64(stmt, 0);
                }
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 7: {
            sqlite3_exec(ctx->db, "BEGIN;", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "DELETE FROM test_table_1 WHERE id % 2 = 0;", NULL, NULL, NULL);
            sqlite3_stmt *stmt;
            int rc = sqlite3_prepare_v2(ctx->db, "SELECT COUNT(*) FROM test_table_1;", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_column_int64(stmt, 0);
                sqlite3_finalize(stmt);
            }
            sqlite3_exec(ctx->db, "ROLLBACK;", NULL, NULL, NULL);
            break;
        }
        
        case 8: {
            sqlite3_exec(ctx->db, "PRAGMA cache_size=5;", NULL, NULL, NULL);
            for (int i = 0; i < 50; i++) {
                char sql[256];
                snprintf(sql, sizeof(sql), "INSERT INTO test_table_1(data) VALUES('count_test_%d');", i);
                sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            }
            sqlite3_stmt *stmt;
            int rc = sqlite3_prepare_v2(ctx->db, "SELECT COUNT(*) FROM test_table_1;", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_column_int64(stmt, 0);
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 9: {
            sqlite3_stmt *stmt;
            int rc = sqlite3_prepare_v2(ctx->db, "WITH RECURSIVE count_series(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM count_series WHERE x < 10) SELECT COUNT(*) FROM count_series;", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_column_int64(stmt, 0);
                sqlite3_finalize(stmt);
            }
            break;
        }
    }
    
    return 1;
}

int fuzz_sqlite3_btree_create_table(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (!ctx || !data || size < sizeof(btree_create_table_packet)) return 0;
    
    btree_create_table_packet packet;
    memcpy(&packet, data, sizeof(packet));
    
    if (packet.scenario >= 14) return 0;
    if (packet.createMode > 2) return 0;
    
    char dynamic_name[64];
    snprintf(dynamic_name, sizeof(dynamic_name), "dynamic_table_%u", packet.testParams[0] % 1000);
    
    switch (packet.scenario) {
        case 0: {
            char sql[256];
            snprintf(sql, sizeof(sql), "CREATE TABLE %s(id INTEGER PRIMARY KEY);", dynamic_name);
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            break;
        }
        
        case 1: {
            char sql[512];
            snprintf(sql, sizeof(sql), "CREATE TABLE %s(id INTEGER PRIMARY KEY, data TEXT NOT NULL, value REAL DEFAULT 0.0, blob_data BLOB);", dynamic_name);
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            break;
        }
        
        case 2: {
            char sql[256];
            snprintf(sql, sizeof(sql), "CREATE TEMP TABLE %s(temp_id INTEGER, temp_data TEXT);", dynamic_name);
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            break;
        }
        
        case 3: {
            char sql[512];
            snprintf(sql, sizeof(sql), "CREATE TABLE %s(id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES %s(id), data TEXT);", dynamic_name, dynamic_name);
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            break;
        }
        
        case 4: {
            sqlite3_exec(ctx->db, "BEGIN;", NULL, NULL, NULL);
            char sql[256];
            snprintf(sql, sizeof(sql), "CREATE TABLE %s(id INTEGER, data TEXT);", dynamic_name);
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            snprintf(sql, sizeof(sql), "INSERT INTO %s VALUES(1, 'test');", dynamic_name);
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "COMMIT;", NULL, NULL, NULL);
            break;
        }
        
        case 5: {
            char sql[512];
            snprintf(sql, sizeof(sql), "CREATE TABLE %s(id INTEGER PRIMARY KEY, data TEXT UNIQUE, value INTEGER CHECK(value >= 0));", dynamic_name);
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            break;
        }
        
        case 6: {
            char sql[256];
            snprintf(sql, sizeof(sql), "CREATE TABLE %s AS SELECT id, data FROM test_table_1 WHERE id <= 5;", dynamic_name);
            setup_database_with_tables(ctx, 1);
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            break;
        }
        
        case 7: {
            char sql[512];
            snprintf(sql, sizeof(sql), "CREATE TABLE %s(id INTEGER PRIMARY KEY, data TEXT COLLATE NOCASE, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);", dynamic_name);
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            break;
        }
        
        case 8: {
            sqlite3_exec(ctx->db, "PRAGMA foreign_keys=ON;", NULL, NULL, NULL);
            setup_database_with_tables(ctx, 1);
            char sql[512];
            snprintf(sql, sizeof(sql), "CREATE TABLE %s(id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES test_table_1(id) ON DELETE CASCADE, data TEXT);", dynamic_name);
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            break;
        }
        
        case 9: {
            char sql[1024];
            snprintf(sql, sizeof(sql), "CREATE TABLE %s(id INTEGER PRIMARY KEY, "
                    "col1 TEXT, col2 TEXT, col3 TEXT, col4 TEXT, col5 TEXT, "
                    "col6 TEXT, col7 TEXT, col8 TEXT, col9 TEXT, col10 TEXT);", dynamic_name);
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            break;
        }
        
        case 10: {
            char sql[512];
            snprintf(sql, sizeof(sql), "CREATE TABLE %s(id INTEGER PRIMARY KEY, json_data JSON, computed AS (json_extract(json_data, '$.name')));", dynamic_name);
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            break;
        }
        
        case 11: {
            sqlite3_exec(ctx->db, "PRAGMA page_size=4096;", NULL, NULL, NULL);
            char sql[256];
            snprintf(sql, sizeof(sql), "CREATE TABLE %s(id INTEGER PRIMARY KEY, large_data TEXT);", dynamic_name);
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            break;
        }
        
        case 12: {
            sqlite3_exec(ctx->db, "PRAGMA auto_vacuum=FULL;", NULL, NULL, NULL);
            char sql[256];
            snprintf(sql, sizeof(sql), "CREATE TABLE %s(id INTEGER PRIMARY KEY AUTOINCREMENT, data TEXT);", dynamic_name);
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            break;
        }
        
        case 13: {
            char sql[512];
            snprintf(sql, sizeof(sql), "CREATE TABLE %s(id INTEGER PRIMARY KEY, data TEXT) WITHOUT ROWID;", dynamic_name);
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            break;
        }
    }
    
    return 1;
}

int fuzz_sqlite3_btree_cursor_api(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (!ctx || !data || size < sizeof(btree_cursor_api_packet)) return 0;
    
    btree_cursor_api_packet packet;
    memcpy(&packet, data, sizeof(packet));
    
    if (packet.scenario >= 16) return 0;
    if (packet.cursorMode > 3) return 0;
    
    if (!setup_database_with_tables(ctx, 3)) return 0;
    
    switch (packet.scenario) {
        case 0: {
            sqlite3_stmt *stmt;
            int rc = sqlite3_prepare_v2(ctx->db, "SELECT * FROM test_table_1;", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 1: {
            sqlite3_stmt *stmt;
            int rc = sqlite3_prepare_v2(ctx->db, "SELECT * FROM test_table_1 WHERE id = ?;", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_bind_int(stmt, 1, 5);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 2: {
            sqlite3_stmt *stmt;
            int rc = sqlite3_prepare_v2(ctx->db, "INSERT INTO test_table_1(data) VALUES(?);", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_bind_text(stmt, 1, "cursor_test", -1, SQLITE_STATIC);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 3: {
            sqlite3_stmt *stmt;
            int rc = sqlite3_prepare_v2(ctx->db, "UPDATE test_table_1 SET data = ? WHERE id = ?;", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_bind_text(stmt, 1, "updated_cursor", -1, SQLITE_STATIC);
                sqlite3_bind_int(stmt, 2, 3);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 4: {
            sqlite3_stmt *stmt;
            int rc = sqlite3_prepare_v2(ctx->db, "DELETE FROM test_table_1 WHERE id > ?;", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_bind_int(stmt, 1, 8);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 5: {
            sqlite3_exec(ctx->db, "CREATE INDEX IF NOT EXISTS cursor_idx ON test_table_1(data);", NULL, NULL, NULL);
            sqlite3_stmt *stmt;
            int rc = sqlite3_prepare_v2(ctx->db, "SELECT * FROM test_table_1 WHERE data LIKE 'data_%';", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    sqlite3_column_text(stmt, 1);
                }
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 6: {
            sqlite3_stmt *stmt;
            int rc = sqlite3_prepare_v2(ctx->db, "SELECT t1.*, t2.data FROM test_table_1 t1 JOIN test_table_2 t2 ON t1.id = t2.id;", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    sqlite3_column_int(stmt, 0);
                    sqlite3_column_text(stmt, 4);
                }
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 7: {
            sqlite3_exec(ctx->db, "BEGIN;", NULL, NULL, NULL);
            sqlite3_stmt *stmt;
            int rc = sqlite3_prepare_v2(ctx->db, "SELECT * FROM test_table_1 ORDER BY id;", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                for (int i = 0; i < 5 && sqlite3_step(stmt) == SQLITE_ROW; i++) {
                    sqlite3_column_int(stmt, 0);
                    sqlite3_column_text(stmt, 1);
                }
                sqlite3_finalize(stmt);
            }
            sqlite3_exec(ctx->db, "COMMIT;", NULL, NULL, NULL);
            break;
        }
        
        case 8: {
            sqlite3_stmt *stmt1, *stmt2;
            int rc1 = sqlite3_prepare_v2(ctx->db, "SELECT * FROM test_table_1;", -1, &stmt1, NULL);
            int rc2 = sqlite3_prepare_v2(ctx->db, "SELECT * FROM test_table_2;", -1, &stmt2, NULL);
            if (rc1 == SQLITE_OK && rc2 == SQLITE_OK) {
                sqlite3_step(stmt1);
                sqlite3_step(stmt2);
                sqlite3_finalize(stmt1);
                sqlite3_finalize(stmt2);
            }
            break;
        }
        
        case 9: {
            sqlite3_stmt *stmt;
            int rc = sqlite3_prepare_v2(ctx->db, "SELECT * FROM test_table_1 ORDER BY RANDOM() LIMIT 3;", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    sqlite3_column_blob(stmt, 3);
                    sqlite3_column_bytes(stmt, 3);
                }
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 10: {
            sqlite3_stmt *stmt;
            int rc = sqlite3_prepare_v2(ctx->db, "SELECT COUNT(*), AVG(value), MAX(id) FROM test_table_1 GROUP BY data HAVING COUNT(*) > 0;", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    sqlite3_column_int64(stmt, 0);
                    sqlite3_column_double(stmt, 1);
                    sqlite3_column_int(stmt, 2);
                }
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 11: {
            sqlite3_stmt *stmt;
            int rc = sqlite3_prepare_v2(ctx->db, "WITH RECURSIVE cursor_series(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM cursor_series WHERE x < 5) SELECT * FROM cursor_series;", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    sqlite3_column_int(stmt, 0);
                }
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 12: {
            sqlite3_exec(ctx->db, "PRAGMA cache_size=3;", NULL, NULL, NULL);
            sqlite3_stmt *stmt;
            int rc = sqlite3_prepare_v2(ctx->db, "SELECT * FROM test_table_1, test_table_2, test_table_3;", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                for (int i = 0; i < 10 && sqlite3_step(stmt) == SQLITE_ROW; i++) {
                    sqlite3_column_count(stmt);
                }
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 13: {
            sqlite3_stmt *stmt;
            int rc = sqlite3_prepare_v2(ctx->db, "EXPLAIN QUERY PLAN SELECT * FROM test_table_1 WHERE id > 5;", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    sqlite3_column_text(stmt, 3);
                }
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 14: {
            sqlite3_stmt *stmt;
            int rc = sqlite3_prepare_v2(ctx->db, "SELECT * FROM test_table_1 WHERE rowid BETWEEN ? AND ?;", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_bind_int64(stmt, 1, 2);
                sqlite3_bind_int64(stmt, 2, 7);
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    sqlite3_last_insert_rowid(ctx->db);
                }
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 15: {
            sqlite3_stmt *stmt;
            int rc = sqlite3_prepare_v2(ctx->db, "SELECT *, ROW_NUMBER() OVER(ORDER BY id) as rn FROM test_table_1;", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    sqlite3_column_int64(stmt, 4);
                }
                sqlite3_finalize(stmt);
            }
            break;
        }
    }
    
    return 1;
}