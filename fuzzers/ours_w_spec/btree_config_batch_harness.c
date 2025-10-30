/*
** Enhanced SQLite3 Fuzzer - Batch B-Tree Configuration Functions Harness
** Target: Multiple B-Tree configuration functions for coverage
** Focus: Database configuration and setting management
*/
#include "btree_config_batch_harness.h"

typedef struct {
    uint8_t function_selector;   // Function selector (0-9)
    uint32_t config_value;       // Configuration value parameter
    uint8_t config_flags;        // Configuration flags
    uint8_t scenario_mode;       // Scenario mode selector
    uint8_t test_data[7];        // Additional test data
} ConfigBatchInput;

int test_batch_btree_config_functions(const uint8_t *data, size_t size) {
    if (size < sizeof(ConfigBatchInput)) return 0;
    
    const ConfigBatchInput *input = (const ConfigBatchInput *)data;
    
    // Input validation
    if (input->function_selector > 9) return 0;
    
    sqlite3 *db = NULL;
    int rc = SQLITE_OK;
    
    // Initialize SQLite
    rc = sqlite3_initialize();
    if (rc != SQLITE_OK) return 0;
    
    // Open database for configuration operations
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) goto cleanup;
    
    // Create test table for configuration testing
    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(db, "CREATE TABLE config_test(id INTEGER PRIMARY KEY, data TEXT)", -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
    
    // Execute selected configuration function simulation
    switch (input->function_selector) {
        case 0: { // sqlite3BtreeSetCacheSize equivalent
            uint32_t cache_size = (input->config_value % 10000) + 100; // 100-10099
            char *sql = sqlite3_mprintf("PRAGMA cache_size=%u", cache_size);
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
        
        case 1: { // sqlite3BtreeSetSpillSize equivalent  
            uint32_t spill_size = (input->config_value % 1000) + 1; // 1-1000
            char *sql = sqlite3_mprintf("PRAGMA cache_spill=%u", spill_size);
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
        
        case 2: { // sqlite3BtreeSetAutoVacuum equivalent
            int auto_vacuum = input->config_value % 3; // 0=NONE, 1=FULL, 2=INCREMENTAL
            const char *vacuum_modes[] = {"NONE", "FULL", "INCREMENTAL"};
            char *sql = sqlite3_mprintf("PRAGMA auto_vacuum=%s", vacuum_modes[auto_vacuum]);
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
        
        case 3: { // sqlite3BtreeSetMmapLimit equivalent
            uint32_t mmap_size = (input->config_value % (1024*1024)) + 0; // 0 to 1MB
            char *sql = sqlite3_mprintf("PRAGMA mmap_size=%u", mmap_size);
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
        
        case 4: { // sqlite3BtreeSecureDelete equivalent
            int secure_delete = input->config_value % 2; // 0=OFF, 1=ON
            char *sql = sqlite3_mprintf("PRAGMA secure_delete=%d", secure_delete);
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
        
        case 5: { // sqlite3BtreeSetVersion equivalent (via user_version)
            uint32_t version = input->config_value % 100; // 0-99
            char *sql = sqlite3_mprintf("PRAGMA user_version=%u", version);
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
        
        case 6: { // sqlite3BtreeSetPagerFlags equivalent
            // Simulate pager flags through journal mode and synchronous settings
            const char *journal_modes[] = {"DELETE", "TRUNCATE", "PERSIST", "MEMORY", "WAL", "OFF"};
            int journal_idx = input->config_value % 6;
            
            char *sql = sqlite3_mprintf("PRAGMA journal_mode=%s", journal_modes[journal_idx]);
            if (sql) {
                rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
                sqlite3_free(sql);
            }
            
            int sync_mode = (input->config_value >> 8) % 4; // 0=OFF, 1=NORMAL, 2=FULL, 3=EXTRA
            const char *sync_modes[] = {"OFF", "NORMAL", "FULL", "EXTRA"};
            sql = sqlite3_mprintf("PRAGMA synchronous=%s", sync_modes[sync_mode]);
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
        
        case 7: { // sqlite3BtreeClose equivalent (close and reopen)
            sqlite3_close(db);
            db = NULL;
            
            // Reopen database
            rc = sqlite3_open(":memory:", &db);
            if (rc == SQLITE_OK) {
                rc = sqlite3_prepare_v2(db, "CREATE TABLE close_test(x)", -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
            }
            break;
        }
        
        case 8: { // sqlite3BtreeConnectionCount equivalent
            // Simulate multiple connections by opening/closing rapidly
            for (int i = 0; i < (input->config_flags & 0x0F) + 1; i++) {
                sqlite3 *temp_db;
                rc = sqlite3_open(":memory:", &temp_db);
                if (rc == SQLITE_OK) {
                    rc = sqlite3_prepare_v2(temp_db, "SELECT 1", -1, &stmt, NULL);
                    if (rc == SQLITE_OK) {
                        sqlite3_step(stmt);
                        sqlite3_finalize(stmt);
                    }
                    sqlite3_close(temp_db);
                }
            }
            break;
        }
        
        case 9: { // sqlite3BtreeSharable equivalent
            // Test sharable cache settings
            int cache_mode = input->config_value % 2;
            char *sql = sqlite3_mprintf("PRAGMA cache_sharing=%d", cache_mode);
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
        
        default:
            break;
    }
    
    // Additional scenarios based on scenario_mode
    if (input->scenario_mode & 0x01) {
        // Configuration verification
        const char *pragmas[] = {
            "PRAGMA cache_size",
            "PRAGMA page_size", 
            "PRAGMA auto_vacuum",
            "PRAGMA synchronous"
        };
        
        for (int i = 0; i < 4; i++) {
            rc = sqlite3_prepare_v2(db, pragmas[i], -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
        }
    }
    
    if (input->scenario_mode & 0x02) {
        // Performance testing with current configuration
        rc = sqlite3_prepare_v2(db, "INSERT INTO config_test(data) VALUES (?)", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            for (int i = 0; i < (input->config_flags & 0x1F) + 10; i++) {
                char data_str[64];
                snprintf(data_str, sizeof(data_str), "perf_test_%d_%.*s", 
                        i, (int)sizeof(input->test_data), (char*)input->test_data);
                sqlite3_bind_text(stmt, 1, data_str, -1, SQLITE_STATIC);
                sqlite3_step(stmt);
                sqlite3_reset(stmt);
            }
            sqlite3_finalize(stmt);
        }
        
        rc = sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM config_test", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }
    
    if (input->scenario_mode & 0x04) {
        // Configuration changes under load
        rc = sqlite3_prepare_v2(db, "BEGIN", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
            
            // Insert data
            rc = sqlite3_prepare_v2(db, "INSERT INTO config_test(data) VALUES ('load_test')", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            
            // Change configuration during transaction
            char *cache_sql = sqlite3_mprintf("PRAGMA cache_size=%u", 
                                            (input->config_value % 1000) + 500);
            if (cache_sql) {
                rc = sqlite3_prepare_v2(db, cache_sql, -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
                sqlite3_free(cache_sql);
            }
            
            rc = sqlite3_prepare_v2(db, "COMMIT", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
        }
    }
    
    if (input->scenario_mode & 0x08) {
        // Memory pressure during configuration
        void *pressure_mem = sqlite3_malloc64((input->config_flags + 1) * 2048);
        if (pressure_mem) {
            memset(pressure_mem, input->test_data[0], (input->config_flags + 1) * 2048);
            
            // Try various configurations under memory pressure
            const char *mem_pragmas[] = {
                "PRAGMA shrink_memory",
                "PRAGMA cache_size=50",
                "PRAGMA temp_store=MEMORY"
            };
            
            for (int i = 0; i < 3; i++) {
                rc = sqlite3_prepare_v2(db, mem_pragmas[i], -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
            }
            
            sqlite3_free(pressure_mem);
        }
    }
    
    // Stress test based on config_flags
    if (input->config_flags & 0x80) {
        // Rapid configuration changes
        for (int i = 0; i < 5; i++) {
            char *sql = sqlite3_mprintf("PRAGMA cache_size=%d", 100 + (i * 50));
            if (sql) {
                rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
                sqlite3_free(sql);
            }
        }
        
        // Reset to default
        rc = sqlite3_prepare_v2(db, "PRAGMA cache_size=-2000", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }
    
cleanup:
    if (db) {
        sqlite3_close(db);
    }
    
    return 1;
}