/*
** B-Tree Advanced Functions Fuzzing Harness Implementation
** Target: btreeInvokeBusyHandler, btreeRestoreCursorPosition, setSharedCacheTableLock
** Category: B-Tree subsystem Critical/High functions
**
** Note: These internal functions are tested through SQL operations and scenarios
** that trigger the specific internal function paths.
*/
#include "btree_advanced_harness.h"

/* Global variables for busy handler testing */
static int g_busy_call_count = 0;
static int g_busy_return_value = 0;

/* Custom busy handler for testing */
static int test_busy_handler(void *pArg, int nCalls) {
    g_busy_call_count++;
    (void)pArg;
    
    /* Simulate various busy handler scenarios */
    if (nCalls > 10) return 0;  /* Give up after 10 attempts */
    if (g_busy_return_value == 1) return 1;  /* Continue waiting */
    if (g_busy_return_value == 2 && nCalls < 5) return 1;  /* Wait for first 5 attempts */
    
    return 0;  /* Give up */
}

/* Helper function to setup busy handler context */
int setup_busy_handler_context(sqlite3 **db, int timeout_ms) {
    int rc;
    
    rc = sqlite3_initialize();
    if (rc != SQLITE_OK) return rc;
    
    rc = sqlite3_open(":memory:", db);
    if (rc != SQLITE_OK) return rc;
    
    /* Set busy timeout and handler */
    sqlite3_busy_timeout(*db, timeout_ms);
    sqlite3_busy_handler(*db, test_busy_handler, NULL);
    
    /* Enable shared cache for more complex scenarios */
    sqlite3_enable_shared_cache(1);
    
    return SQLITE_OK;
}

/* Helper function to setup cursor context */
int setup_cursor_context(sqlite3 **db, sqlite3_stmt **stmt) {
    int rc;
    
    rc = sqlite3_initialize();
    if (rc != SQLITE_OK) return rc;
    
    rc = sqlite3_open(":memory:", db);
    if (rc != SQLITE_OK) return rc;
    
    /* Create table for cursor operations */
    rc = sqlite3_exec(*db, "CREATE TABLE test_cursor(id INTEGER PRIMARY KEY, data TEXT)", NULL, NULL, NULL);
    if (rc != SQLITE_OK) return rc;
    
    /* Insert test data */
    rc = sqlite3_exec(*db, "INSERT INTO test_cursor VALUES (1, 'test1'), (2, 'test2'), (3, 'test3')", NULL, NULL, NULL);
    if (rc != SQLITE_OK) return rc;
    
    /* Prepare statement for cursor operations */
    rc = sqlite3_prepare_v2(*db, "SELECT * FROM test_cursor WHERE id >= ?", -1, stmt, NULL);
    
    return rc;
}

/* Helper function to setup shared cache context */
int setup_shared_cache_context(sqlite3 **db1, sqlite3 **db2) {
    int rc;
    
    rc = sqlite3_initialize();
    if (rc != SQLITE_OK) return rc;
    
    /* Enable shared cache */
    sqlite3_enable_shared_cache(1);
    
    /* Open two connections to the same database */
    rc = sqlite3_open("file:test_shared.db?cache=shared", db1);
    if (rc != SQLITE_OK) return rc;
    
    rc = sqlite3_open("file:test_shared.db?cache=shared", db2);
    if (rc != SQLITE_OK) return rc;
    
    /* Create test table */
    rc = sqlite3_exec(*db1, "CREATE TABLE IF NOT EXISTS shared_test(id INTEGER, data TEXT)", NULL, NULL, NULL);
    
    return rc;
}

/* Helper function to cleanup contexts */
void cleanup_advanced_context(sqlite3 *db, sqlite3_stmt *stmt) {
    if (stmt) {
        sqlite3_finalize(stmt);
    }
    if (db) {
        sqlite3_close(db);
    }
}

/* Fuzzer for btreeInvokeBusyHandler function - triggered through busy scenarios */
int fuzz_btreeInvokeBusyHandler(const uint8_t *data, size_t size) {
    if (size < sizeof(BtreeAdvancedFuzzHeader) + sizeof(BusyHandlerData)) {
        return 0;
    }
    
    const BtreeAdvancedFuzzHeader *header = (const BtreeAdvancedFuzzHeader *)data;
    const BusyHandlerData *busy_data = 
        (const BusyHandlerData *)(data + sizeof(BtreeAdvancedFuzzHeader));
    
    sqlite3 *db1 = NULL, *db2 = NULL;
    int rc;
    
    /* Reset global counters */
    g_busy_call_count = 0;
    g_busy_return_value = busy_data->handler_return % 3;
    
    /* Setup busy handler context */
    int timeout = (busy_data->timeout_ms % 5000) + 100;  /* 100-5100ms */
    rc = setup_busy_handler_context(&db1, timeout);
    if (rc != SQLITE_OK) return 0;
    
    /* Create second connection for lock contention */
    if (busy_data->concurrent_access) {
        rc = setup_busy_handler_context(&db2, timeout);
        if (rc != SQLITE_OK) {
            cleanup_advanced_context(db1, NULL);
            return 0;
        }
    }
    
    /* Create test table and data */
    sqlite3_exec(db1, "CREATE TABLE busy_test(id INTEGER PRIMARY KEY, data TEXT)", NULL, NULL, NULL);
    sqlite3_exec(db1, "INSERT INTO busy_test VALUES (1, 'data1')", NULL, NULL, NULL);
    
    /* Test busy handler scenarios */
    if (header->flags & 0x01) {
        /* Scenario 1: WAL mode with checkpoint contention */
        sqlite3_exec(db1, "PRAGMA journal_mode=WAL", NULL, NULL, NULL);
        sqlite3_exec(db1, "BEGIN IMMEDIATE", NULL, NULL, NULL);
        
        if (db2) {
            /* Create lock contention from second connection */
            sqlite3_exec(db2, "BEGIN IMMEDIATE", NULL, NULL, NULL);
            sqlite3_exec(db2, "INSERT INTO busy_test VALUES (2, 'data2')", NULL, NULL, NULL);
        }
        
        /* This should trigger busy handler */
        sqlite3_exec(db1, "INSERT INTO busy_test VALUES (3, 'data3')", NULL, NULL, NULL);
        sqlite3_exec(db1, "COMMIT", NULL, NULL, NULL);
        
        if (db2) {
            sqlite3_exec(db2, "COMMIT", NULL, NULL, NULL);
        }
    }
    
    if (header->flags & 0x02) {
        /* Scenario 2: Multiple table lock contention */
        for (int i = 0; i < (int)(busy_data->retry_count % 5 + 1); i++) {
            char sql[128];
            snprintf(sql, sizeof(sql), "CREATE TABLE IF NOT EXISTS table_%d(id INTEGER)", i);
            sqlite3_exec(db1, sql, NULL, NULL, NULL);
            
            sqlite3_exec(db1, "BEGIN EXCLUSIVE", NULL, NULL, NULL);
            snprintf(sql, sizeof(sql), "INSERT INTO table_%d VALUES (%d)", i, i);
            sqlite3_exec(db1, sql, NULL, NULL, NULL);
            sqlite3_exec(db1, "COMMIT", NULL, NULL, NULL);
        }
    }
    
    if (header->flags & 0x04) {
        /* Scenario 3: Long-running transaction with timeout */
        sqlite3_exec(db1, "BEGIN", NULL, NULL, NULL);
        
        if (db2 && busy_data->simulate_busy) {
            sqlite3_exec(db2, "BEGIN EXCLUSIVE", NULL, NULL, NULL);
            /* Hold lock for extended period */
            for (int i = 0; i < 10; i++) {
                sqlite3_exec(db2, "SELECT * FROM busy_test", NULL, NULL, NULL);
            }
            sqlite3_exec(db2, "COMMIT", NULL, NULL, NULL);
        }
        
        sqlite3_exec(db1, "INSERT INTO busy_test VALUES (4, 'data4')", NULL, NULL, NULL);
        sqlite3_exec(db1, "COMMIT", NULL, NULL, NULL);
    }
    
    /* Stress test scenario */
    if (busy_data->stress_test) {
        for (int i = 0; i < 20; i++) {
            sqlite3_exec(db1, "BEGIN", NULL, NULL, NULL);
            sqlite3_exec(db1, "UPDATE busy_test SET data = 'updated' WHERE id = 1", NULL, NULL, NULL);
            sqlite3_exec(db1, "COMMIT", NULL, NULL, NULL);
        }
    }
    
    /* Cleanup */
    cleanup_advanced_context(db1, NULL);
    if (db2) {
        cleanup_advanced_context(db2, NULL);
    }
    
    return 0;
}

/* Fuzzer for btreeRestoreCursorPosition function - triggered through cursor operations */
int fuzz_btreeRestoreCursorPosition(const uint8_t *data, size_t size) {
    if (size < sizeof(BtreeAdvancedFuzzHeader) + sizeof(RestoreCursorData)) {
        return 0;
    }
    
    const BtreeAdvancedFuzzHeader *header = (const BtreeAdvancedFuzzHeader *)data;
    const RestoreCursorData *cursor_data = 
        (const RestoreCursorData *)(data + sizeof(BtreeAdvancedFuzzHeader));
    
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int rc;
    
    /* Setup cursor context */
    rc = setup_cursor_context(&db, &stmt);
    if (rc != SQLITE_OK) return 0;
    
    /* Insert more test data for cursor positioning */
    for (int i = 4; i <= 100; i++) {
        char sql[128];
        snprintf(sql, sizeof(sql), "INSERT INTO test_cursor VALUES (%d, 'data%d')", i, i);
        sqlite3_exec(db, sql, NULL, NULL, NULL);
    }
    
    /* Test cursor restoration scenarios */
    if (header->flags & 0x01) {
        /* Scenario 1: Cursor invalidation through schema change */
        sqlite3_bind_int(stmt, 1, cursor_data->initial_state % 50 + 1);
        sqlite3_step(stmt);  /* Position cursor */
        
        /* Invalidate cursor through schema change */
        sqlite3_exec(db, "ALTER TABLE test_cursor ADD COLUMN extra TEXT", NULL, NULL, NULL);
        
        /* Try to continue with cursor - should trigger restore */
        sqlite3_step(stmt);
        sqlite3_reset(stmt);
    }
    
    if (header->flags & 0x02) {
        /* Scenario 2: Cursor invalidation through transaction rollback */
        sqlite3_exec(db, "BEGIN", NULL, NULL, NULL);
        
        sqlite3_bind_int(stmt, 1, cursor_data->initial_state % 50 + 10);
        sqlite3_step(stmt);
        
        /* Modify data and rollback */
        sqlite3_exec(db, "INSERT INTO test_cursor VALUES (999, 'rollback_test')", NULL, NULL, NULL);
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        
        /* Continue with cursor */
        sqlite3_step(stmt);
        sqlite3_reset(stmt);
    }
    
    if (header->flags & 0x04) {
        /* Scenario 3: Multiple cursor operations with seeks */
        for (int i = 0; i < 10; i++) {
            sqlite3_bind_int(stmt, 1, (cursor_data->initial_state + i) % 100 + 1);
            
            /* Step through results */
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                sqlite3_column_int(stmt, 0);  /* Access data */
                if (cursor_data->skip_next_scenario && (i % 3 == 0)) {
                    break;  /* Early exit to test skipNext scenarios */
                }
            }
            sqlite3_reset(stmt);
        }
    }
    
    /* Test fault simulation scenario */
    if (cursor_data->fault_simulation) {
        /* Enable various PRAGMA settings that affect cursor behavior */
        sqlite3_exec(db, "PRAGMA cache_size=10", NULL, NULL, NULL);  /* Small cache */
        sqlite3_exec(db, "PRAGMA temp_store=memory", NULL, NULL, NULL);
        
        /* Create memory pressure */
        for (int i = 0; i < 50; i++) {
            sqlite3_bind_int(stmt, 1, 1);
            sqlite3_step(stmt);
            sqlite3_reset(stmt);
        }
    }
    
    /* Key preservation test */
    if (cursor_data->key_preservation) {
        sqlite3_bind_int(stmt, 1, cursor_data->key_size % 100 + 1);
        sqlite3_step(stmt);
        
        /* Force cursor invalidation */
        sqlite3_exec(db, "VACUUM", NULL, NULL, NULL);
        
        /* Try to continue */
        sqlite3_step(stmt);
        sqlite3_reset(stmt);
    }
    
    /* Cleanup */
    cleanup_advanced_context(db, stmt);
    
    return 0;
}

/* Fuzzer for setSharedCacheTableLock function - triggered through shared cache operations */
int fuzz_setSharedCacheTableLock(const uint8_t *data, size_t size) {
    if (size < sizeof(BtreeAdvancedFuzzHeader) + sizeof(SharedCacheLockData)) {
        return 0;
    }
    
    const BtreeAdvancedFuzzHeader *header = (const BtreeAdvancedFuzzHeader *)data;
    const SharedCacheLockData *lock_data = 
        (const SharedCacheLockData *)(data + sizeof(BtreeAdvancedFuzzHeader));
    
    sqlite3 *db1 = NULL, *db2 = NULL;
    int rc;
    
    /* Setup shared cache context */
    rc = setup_shared_cache_context(&db1, &db2);
    if (rc != SQLITE_OK) return 0;
    
    /* Configure read uncommitted mode if specified */
    if (lock_data->read_uncommitted) {
        sqlite3_exec(db1, "PRAGMA read_uncommitted=1", NULL, NULL, NULL);
        sqlite3_exec(db2, "PRAGMA read_uncommitted=1", NULL, NULL, NULL);
    }
    
    /* Create multiple tables for lock testing */
    int table_count = (lock_data->concurrent_tables % 10) + 1;
    for (int i = 0; i < table_count; i++) {
        char sql[128];
        snprintf(sql, sizeof(sql), "CREATE TABLE IF NOT EXISTS lock_test_%d(id INTEGER, data TEXT)", i);
        sqlite3_exec(db1, sql, NULL, NULL, NULL);
        
        snprintf(sql, sizeof(sql), "INSERT INTO lock_test_%d VALUES (%d, 'data%d')", i, i, i);
        sqlite3_exec(db1, sql, NULL, NULL, NULL);
    }
    
    /* Test shared cache lock scenarios */
    if (header->flags & 0x01) {
        /* Scenario 1: Read lock conflicts */
        sqlite3_exec(db1, "BEGIN", NULL, NULL, NULL);
        sqlite3_exec(db1, "SELECT * FROM lock_test_0", NULL, NULL, NULL);
        
        sqlite3_exec(db2, "BEGIN", NULL, NULL, NULL);
        sqlite3_exec(db2, "SELECT * FROM lock_test_0", NULL, NULL, NULL);  /* Should share read lock */
        
        sqlite3_exec(db1, "COMMIT", NULL, NULL, NULL);
        sqlite3_exec(db2, "COMMIT", NULL, NULL, NULL);
    }
    
    if (header->flags & 0x02) {
        /* Scenario 2: Write lock conflicts */
        sqlite3_exec(db1, "BEGIN IMMEDIATE", NULL, NULL, NULL);
        sqlite3_exec(db1, "UPDATE lock_test_0 SET data='updated1' WHERE id=0", NULL, NULL, NULL);
        
        /* This should test lock conflict detection */
        sqlite3_exec(db2, "BEGIN IMMEDIATE", NULL, NULL, NULL);
        sqlite3_exec(db2, "UPDATE lock_test_0 SET data='updated2' WHERE id=0", NULL, NULL, NULL);
        
        sqlite3_exec(db1, "COMMIT", NULL, NULL, NULL);
        sqlite3_exec(db2, "COMMIT", NULL, NULL, NULL);
    }
    
    if (header->flags & 0x04) {
        /* Scenario 3: Multiple table locking */
        sqlite3_exec(db1, "BEGIN", NULL, NULL, NULL);
        
        for (int i = 0; i < table_count; i++) {
            char sql[128];
            snprintf(sql, sizeof(sql), "SELECT * FROM lock_test_%d", i);
            sqlite3_exec(db1, sql, NULL, NULL, NULL);
        }
        
        sqlite3_exec(db2, "BEGIN", NULL, NULL, NULL);
        for (int i = 0; i < table_count; i++) {
            char sql[128];
            if (lock_data->lock_type % 2 == 0) {
                snprintf(sql, sizeof(sql), "SELECT * FROM lock_test_%d", i);  /* Read lock */
            } else {
                snprintf(sql, sizeof(sql), "UPDATE lock_test_%d SET data='concurrent' WHERE id=%d", i, i);  /* Write lock */
            }
            sqlite3_exec(db2, sql, NULL, NULL, NULL);
        }
        
        sqlite3_exec(db1, "COMMIT", NULL, NULL, NULL);
        sqlite3_exec(db2, "COMMIT", NULL, NULL, NULL);
    }
    
    /* Conflict scenario testing */
    if (lock_data->conflict_scenario) {
        /* Test lock upgrade scenarios */
        sqlite3_exec(db1, "BEGIN", NULL, NULL, NULL);
        sqlite3_exec(db1, "SELECT * FROM lock_test_0", NULL, NULL, NULL);  /* Read lock */
        
        sqlite3_exec(db2, "BEGIN", NULL, NULL, NULL);
        sqlite3_exec(db2, "SELECT * FROM lock_test_0", NULL, NULL, NULL);  /* Shared read lock */
        
        /* Try to upgrade to write lock */
        sqlite3_exec(db1, "UPDATE lock_test_0 SET data='upgrade_test' WHERE id=0", NULL, NULL, NULL);
        
        sqlite3_exec(db1, "COMMIT", NULL, NULL, NULL);
        sqlite3_exec(db2, "COMMIT", NULL, NULL, NULL);
    }
    
    /* Stress test with rapid lock acquisition/release */
    if (header->flags & 0x08) {
        for (int i = 0; i < 20; i++) {
            sqlite3_exec(db1, "BEGIN", NULL, NULL, NULL);
            sqlite3_exec(db1, "SELECT * FROM lock_test_0", NULL, NULL, NULL);
            sqlite3_exec(db1, "COMMIT", NULL, NULL, NULL);
            
            sqlite3_exec(db2, "BEGIN", NULL, NULL, NULL);
            sqlite3_exec(db2, "SELECT * FROM lock_test_0", NULL, NULL, NULL);
            sqlite3_exec(db2, "COMMIT", NULL, NULL, NULL);
        }
    }
    
    /* Cleanup */
    cleanup_advanced_context(db1, NULL);
    cleanup_advanced_context(db2, NULL);
    
    /* Disable shared cache */
    sqlite3_enable_shared_cache(0);
    
    return 0;
}