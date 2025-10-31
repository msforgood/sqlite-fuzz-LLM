/*
** Enhanced SQLite3 Fuzzer - Advanced B-Tree Batch Harness
** Target: Multiple critical B-Tree functions with high crash potential
** Focus: Integrity checks, data transfers, cursor management, metadata operations
*/
#include "btree_advanced_batch_harness.h"

typedef struct {
    uint8_t function_selector;   // Function selector (0-7)
    uint8_t operation_flags;     // Operation flags
    uint8_t data_size;          // Data size parameter
    uint8_t corruption_mode;    // Corruption simulation mode
    uint8_t test_payload[12];   // Test payload data
} AdvancedBatchInput;

int test_batch_btree_advanced_functions(const uint8_t *data, size_t size) {
    if (size < sizeof(AdvancedBatchInput)) return 0;
    
    const AdvancedBatchInput *input = (const AdvancedBatchInput *)data;
    
    // Input validation
    if (input->function_selector > 7) return 0;
    if (input->data_size == 0) return 0;
    
    sqlite3 *db = NULL;
    int rc = SQLITE_OK;
    
    // Initialize SQLite
    rc = sqlite3_initialize();
    if (rc != SQLITE_OK) return 0;
    
    // Open database for advanced operations
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) goto cleanup;
    
    // Create comprehensive test schema
    sqlite3_stmt *stmt;
    const char *schema[] = {
        "CREATE TABLE source_table(id INTEGER PRIMARY KEY, data TEXT, blob_field BLOB)",
        "CREATE TABLE dest_table(id INTEGER PRIMARY KEY, data TEXT, blob_field BLOB)", 
        "CREATE TABLE meta_table(key INTEGER, value TEXT, meta_info BLOB)",
        "CREATE INDEX idx_source ON source_table(data)",
        "CREATE INDEX idx_dest ON dest_table(data)"
    };
    
    for (int i = 0; i < 5; i++) {
        rc = sqlite3_prepare_v2(db, schema[i], -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }
    
    // Insert test data for operations
    int data_count = (input->data_size % 50) + 10;
    for (int i = 0; i < data_count; i++) {
        char *sql = sqlite3_mprintf("INSERT INTO source_table(data, blob_field) VALUES ('data_%d_%.*s', ?)", 
                                  i, (int)sizeof(input->test_payload), (char*)input->test_payload);
        if (sql) {
            rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_bind_blob(stmt, 1, input->test_payload, sizeof(input->test_payload), SQLITE_STATIC);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            sqlite3_free(sql);
        }
    }
    
    // Execute selected advanced function simulation
    switch (input->function_selector) {
        case 0: { // sqlite3BtreeIntegrityCheck equivalent
            if (input->operation_flags & 0x01) {
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
            
            if (input->operation_flags & 0x02) {
                char *quick_check = sqlite3_mprintf("PRAGMA quick_check(%u)", (input->data_size % 20) + 1);
                if (quick_check) {
                    rc = sqlite3_prepare_v2(db, quick_check, -1, &stmt, NULL);
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
                    sqlite3_free(quick_check);
                }
            }
            break;
        }
        
        case 1: { // sqlite3BtreeTransferRow equivalent (INSERT...SELECT)
            rc = sqlite3_prepare_v2(db, "INSERT INTO dest_table(data, blob_field) SELECT data, blob_field FROM source_table WHERE id <= ?", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_bind_int(stmt, 1, (input->data_size % 20) + 1);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            
            if (input->operation_flags & 0x04) {
                // Transfer with modification
                rc = sqlite3_prepare_v2(db, "INSERT INTO dest_table(data, blob_field) SELECT 'modified_' || data, blob_field FROM source_table WHERE id > ?", -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    sqlite3_bind_int(stmt, 1, input->data_size % 10);
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
            }
            break;
        }
        
        case 2: { // sqlite3BtreeTripAllCursors equivalent (Schema change)
            if (input->operation_flags & 0x08) {
                rc = sqlite3_prepare_v2(db, "ALTER TABLE source_table ADD COLUMN new_field INTEGER DEFAULT 0", -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
            }
            
            // Trigger cursor invalidation through DROP/CREATE
            if (input->operation_flags & 0x10) {
                rc = sqlite3_prepare_v2(db, "DROP INDEX IF EXISTS idx_temp", -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
                
                rc = sqlite3_prepare_v2(db, "CREATE INDEX idx_temp ON source_table(id, data)", -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
            }
            break;
        }
        
        case 3: { // sqlite3BtreeSavepoint equivalent
            rc = sqlite3_prepare_v2(db, "SAVEPOINT sp1", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
                
                // Make changes
                rc = sqlite3_prepare_v2(db, "INSERT INTO meta_table(key, value) VALUES (?, ?)", -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    for (int i = 0; i < 5; i++) {
                        sqlite3_bind_int(stmt, 1, input->test_payload[i % 12] + i);
                        char value_str[32];
                        snprintf(value_str, sizeof(value_str), "savepoint_%d", i);
                        sqlite3_bind_text(stmt, 2, value_str, -1, SQLITE_STATIC);
                        sqlite3_step(stmt);
                        sqlite3_reset(stmt);
                    }
                    sqlite3_finalize(stmt);
                }
                
                if (input->operation_flags & 0x20) {
                    rc = sqlite3_prepare_v2(db, "ROLLBACK TO sp1", -1, &stmt, NULL);
                } else {
                    rc = sqlite3_prepare_v2(db, "RELEASE sp1", -1, &stmt, NULL);
                }
                if (rc == SQLITE_OK) {
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
            }
            break;
        }
        
        case 4: { // sqlite3BtreePayloadChecked equivalent (BLOB access)
            rc = sqlite3_prepare_v2(db, "SELECT data, blob_field FROM source_table WHERE id = ?", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_bind_int(stmt, 1, (input->data_size % data_count) + 1);
                if (sqlite3_step(stmt) == SQLITE_ROW) {
                    const void *blob_data = sqlite3_column_blob(stmt, 1);
                    int blob_size = sqlite3_column_bytes(stmt, 1);
                    if (blob_data && blob_size > 0) {
                        // Simulate payload access
                        volatile char first_byte = ((const char*)blob_data)[0];
                        volatile char last_byte = ((const char*)blob_data)[blob_size - 1];
                        (void)first_byte; (void)last_byte;
                    }
                }
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 5: { // sqlite3BtreeUpdateMeta equivalent (User version)
            uint32_t new_version = (input->test_payload[0] << 8) | input->test_payload[1];
            char *sql = sqlite3_mprintf("PRAGMA user_version=%u", new_version % 1000);
            if (sql) {
                rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
                sqlite3_free(sql);
            }
            
            // Update application_id
            uint32_t app_id = (input->test_payload[2] << 8) | input->test_payload[3];
            sql = sqlite3_mprintf("PRAGMA application_id=%u", app_id);
            if (sql) {
                rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
                sqlite3_free(sql);
            }
            break;
        }
        
        case 6: { // sqlite3BtreeMaxRecordSize testing
            // Create large record for size testing
            size_t large_size = (input->data_size * 100) + 1000;
            char *large_data = sqlite3_malloc64(large_size);
            if (large_data) {
                memset(large_data, 'X', large_size - 1);
                large_data[large_size - 1] = '\0';
                
                char *sql = sqlite3_mprintf("INSERT INTO meta_table(key, value) VALUES (9999, '%q')", large_data);
                if (sql) {
                    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
                    if (rc == SQLITE_OK) {
                        sqlite3_step(stmt);
                        sqlite3_finalize(stmt);
                    }
                    sqlite3_free(sql);
                }
                sqlite3_free(large_data);
            }
            break;
        }
        
        case 7: { // sqlite3BtreeTableMoveto equivalent (Positioning)
            rc = sqlite3_prepare_v2(db, "SELECT * FROM source_table WHERE id >= ? ORDER BY id LIMIT 5", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_bind_int(stmt, 1, input->test_payload[0] % data_count);
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    // Access all columns to simulate moveto + data access
                    sqlite3_column_int(stmt, 0);
                    sqlite3_column_text(stmt, 1);
                    sqlite3_column_blob(stmt, 2);
                }
                sqlite3_finalize(stmt);
            }
            
            // Reverse direction search
            if (input->operation_flags & 0x40) {
                rc = sqlite3_prepare_v2(db, "SELECT * FROM source_table WHERE id <= ? ORDER BY id DESC LIMIT 3", -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    sqlite3_bind_int(stmt, 1, (input->test_payload[1] % data_count) + 1);
                    while (sqlite3_step(stmt) == SQLITE_ROW) {
                        sqlite3_column_int(stmt, 0);
                        sqlite3_column_text(stmt, 1);
                    }
                    sqlite3_finalize(stmt);
                }
            }
            break;
        }
    }
    
    // Additional corruption scenarios based on corruption_mode
    if (input->corruption_mode & 0x01) {
        // Memory pressure scenario
        void *pressure_mem = sqlite3_malloc64((input->test_payload[0] + 1) * 2048);
        if (pressure_mem) {
            memset(pressure_mem, input->test_payload[1], (input->test_payload[0] + 1) * 2048);
            
            rc = sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM source_table", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            
            sqlite3_free(pressure_mem);
        }
    }
    
    if (input->corruption_mode & 0x02) {
        // Cache pressure with operations
        rc = sqlite3_prepare_v2(db, "PRAGMA cache_size=5", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
        
        // Force cache thrashing
        for (int i = 0; i < 10; i++) {
            rc = sqlite3_prepare_v2(db, "SELECT * FROM source_table ORDER BY RANDOM() LIMIT 5", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    // Force page access
                }
                sqlite3_finalize(stmt);
            }
        }
    }
    
    if (input->corruption_mode & 0x04) {
        // Transaction stress test
        rc = sqlite3_prepare_v2(db, "BEGIN", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
            
            for (int i = 0; i < 20; i++) {
                char *sql = sqlite3_mprintf("INSERT INTO meta_table(key, value) VALUES (%d, 'stress_%d')", 
                                          1000 + i, i);
                if (sql) {
                    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
                    if (rc == SQLITE_OK) {
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
    }
    
cleanup:
    if (db) {
        sqlite3_close(db);
    }
    
    return 1;
}