/*
** Enhanced SQLite3 Fuzzer - B-Tree Integrity Check Harness
** Target: sqlite3BtreeIntegrityCheck function (btree.c:11102)
** Focus: Database integrity verification with corruption scenarios
*/
#include "btree_integrity_harness.h"

typedef struct {
    uint32_t pgno_root;         // Root page number for integrity check
    uint8_t check_flags;        // Integrity check flags
    uint8_t max_errors;         // Maximum errors to report
    uint8_t corruption_type;    // Corruption simulation type
    uint8_t test_data[13];      // Additional test data
} IntegrityCheckInput;

int test_sqlite3BtreeIntegrityCheck(const uint8_t *data, size_t size) {
    if (size < sizeof(IntegrityCheckInput)) return 0;
    
    const IntegrityCheckInput *input = (const IntegrityCheckInput *)data;
    
    // Input validation
    if ((uintptr_t)input % 8 != 0) return 0;
    if (input->max_errors == 0) return 0;
    
    sqlite3 *db = NULL;
    int rc = SQLITE_OK;
    
    // Initialize SQLite
    rc = sqlite3_initialize();
    if (rc != SQLITE_OK) return 0;
    
    // Open database for integrity testing
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) goto cleanup;
    
    // Create comprehensive test schema for integrity checking
    sqlite3_stmt *stmt;
    const char *schema_sql[] = {
        "CREATE TABLE integrity_test1(id INTEGER PRIMARY KEY, data TEXT, blob_data BLOB)",
        "CREATE TABLE integrity_test2(key INTEGER, value REAL, info TEXT)",
        "CREATE INDEX idx_data ON integrity_test1(data)",
        "CREATE INDEX idx_key ON integrity_test2(key, value)",
        "CREATE TABLE integrity_test3(a INTEGER, b INTEGER, c TEXT, PRIMARY KEY(a, b))"
    };
    
    for (int i = 0; i < 5; i++) {
        rc = sqlite3_prepare_v2(db, schema_sql[i], -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }
    
    // Scenario 1: Integrity check on empty database
    if (input->check_flags & 0x01) {
        rc = sqlite3_prepare_v2(db, "PRAGMA integrity_check", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const char *result = (const char*)sqlite3_column_text(stmt, 0);
                if (result) {
                    volatile int len = strlen(result);
                    (void)len; // Prevent optimization
                }
            }
            sqlite3_finalize(stmt);
        }
    }
    
    // Insert test data for more complex integrity scenarios
    int insert_count = (input->corruption_type % 50) + 10;
    for (int i = 0; i < insert_count; i++) {
        char *sql = sqlite3_mprintf("INSERT INTO integrity_test1(data, blob_data) VALUES ('test_%d_%.*s', ?)", 
                                  i, (int)sizeof(input->test_data), (char*)input->test_data);
        if (sql) {
            rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_bind_blob(stmt, 1, input->test_data, sizeof(input->test_data), SQLITE_STATIC);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            sqlite3_free(sql);
        }
        
        char *sql2 = sqlite3_mprintf("INSERT INTO integrity_test2(key, value, info) VALUES (%d, %f, 'info_%d')", 
                                   i, (double)(input->pgno_root % 1000) / 100.0, i);
        if (sql2) {
            rc = sqlite3_prepare_v2(db, sql2, -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            sqlite3_free(sql2);
        }
    }
    
    // Scenario 2: Comprehensive integrity check with data
    if (input->check_flags & 0x02) {
        char *check_sql = sqlite3_mprintf("PRAGMA integrity_check(%u)", 
                                        (input->max_errors % 100) + 1);
        if (check_sql) {
            rc = sqlite3_prepare_v2(db, check_sql, -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    const char *result = (const char*)sqlite3_column_text(stmt, 0);
                    if (result) {
                        volatile int len = strlen(result);
                        (void)len;
                    }
                }
                sqlite3_finalize(stmt);
            }
            sqlite3_free(check_sql);
        }
    }
    
    // Scenario 3: Quick integrity check
    if (input->check_flags & 0x04) {
        rc = sqlite3_prepare_v2(db, "PRAGMA quick_check", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const char *result = (const char*)sqlite3_column_text(stmt, 0);
                if (result) {
                    volatile int len = strlen(result);
                    (void)len;
                }
            }
            sqlite3_finalize(stmt);
        }
    }
    
    // Scenario 4: Foreign key integrity check
    if (input->check_flags & 0x08) {
        rc = sqlite3_prepare_v2(db, "PRAGMA foreign_key_check", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                // Process foreign key violations
                for (int i = 0; i < sqlite3_column_count(stmt); i++) {
                    const char *col_text = (const char*)sqlite3_column_text(stmt, i);
                    if (col_text) {
                        volatile int len = strlen(col_text);
                        (void)len;
                    }
                }
            }
            sqlite3_finalize(stmt);
        }
    }
    
    // Scenario 5: Memory pressure during integrity check
    if (input->corruption_type & 0x10) {
        void *pressure_mem = sqlite3_malloc64((input->test_data[0] + 1) * 4096);
        if (pressure_mem) {
            memset(pressure_mem, input->test_data[1], (input->test_data[0] + 1) * 4096);
            
            rc = sqlite3_prepare_v2(db, "PRAGMA integrity_check(10)", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    const char *result = (const char*)sqlite3_column_text(stmt, 0);
                    if (result) {
                        volatile int len = strlen(result);
                        (void)len;
                    }
                }
                sqlite3_finalize(stmt);
            }
            
            sqlite3_free(pressure_mem);
        }
    }
    
    // Scenario 6: Transaction boundaries during integrity check
    if (input->corruption_type & 0x20) {
        rc = sqlite3_prepare_v2(db, "BEGIN", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
            
            // Insert some data during transaction
            rc = sqlite3_prepare_v2(db, "INSERT INTO integrity_test3(a, b, c) VALUES (?, ?, ?)", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                for (int i = 0; i < 5; i++) {
                    sqlite3_bind_int(stmt, 1, input->test_data[i % 13] + i);
                    sqlite3_bind_int(stmt, 2, input->test_data[(i+1) % 13] + i);
                    char value_str[64];
                    snprintf(value_str, sizeof(value_str), "trans_%d_%u", i, input->pgno_root);
                    sqlite3_bind_text(stmt, 3, value_str, -1, SQLITE_STATIC);
                    sqlite3_step(stmt);
                    sqlite3_reset(stmt);
                }
                sqlite3_finalize(stmt);
            }
            
            // Run integrity check within transaction
            rc = sqlite3_prepare_v2(db, "PRAGMA integrity_check", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    const char *result = (const char*)sqlite3_column_text(stmt, 0);
                    if (result) {
                        volatile int len = strlen(result);
                        (void)len;
                    }
                }
                sqlite3_finalize(stmt);
            }
            
            rc = sqlite3_prepare_v2(db, "COMMIT", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
        }
    }
    
    // Scenario 7: Index corruption detection
    if (input->corruption_type & 0x40) {
        // Create additional indexes for testing
        const char *index_sql[] = {
            "CREATE INDEX idx_composite ON integrity_test1(data, id)",
            "CREATE UNIQUE INDEX idx_unique ON integrity_test2(key)",
            "CREATE INDEX idx_partial ON integrity_test1(data) WHERE id > 10"
        };
        
        for (int i = 0; i < 3; i++) {
            rc = sqlite3_prepare_v2(db, index_sql[i], -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
        }
        
        // Check index integrity
        rc = sqlite3_prepare_v2(db, "PRAGMA integrity_check", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const char *result = (const char*)sqlite3_column_text(stmt, 0);
                if (result) {
                    volatile int len = strlen(result);
                    (void)len;
                }
            }
            sqlite3_finalize(stmt);
        }
    }
    
    // Scenario 8: Cache pressure integrity scenarios
    if (input->corruption_type & 0x80) {
        // Force small cache size
        rc = sqlite3_prepare_v2(db, "PRAGMA cache_size=10", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
        
        // Insert large amount of data to stress cache
        rc = sqlite3_prepare_v2(db, "BEGIN", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
            
            for (int i = 0; i < 50; i++) {
                char large_data[256];
                memset(large_data, 'A' + (i % 26), sizeof(large_data) - 1);
                large_data[sizeof(large_data) - 1] = '\0';
                
                char *sql = sqlite3_mprintf("INSERT INTO integrity_test1(data, blob_data) VALUES ('%q', ?)", large_data);
                if (sql) {
                    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
                    if (rc == SQLITE_OK) {
                        sqlite3_bind_blob(stmt, 1, large_data, sizeof(large_data), SQLITE_STATIC);
                        sqlite3_step(stmt);
                        sqlite3_finalize(stmt);
                    }
                    sqlite3_free(sql);
                }
            }
            
            rc = sqlite3_prepare_v2(db, "COMMIT", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
        }
        
        // Run integrity check under cache pressure
        rc = sqlite3_prepare_v2(db, "PRAGMA integrity_check", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const char *result = (const char*)sqlite3_column_text(stmt, 0);
                if (result) {
                    volatile int len = strlen(result);
                    (void)len;
                }
            }
            sqlite3_finalize(stmt);
        }
    }
    
cleanup:
    if (db) {
        sqlite3_close(db);
    }
    
    return 1;
}