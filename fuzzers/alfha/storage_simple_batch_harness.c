/*
** Enhanced SQLite3 Fuzzer - Simple Storage Batch Harness
** Target: Multiple simple Storage/Pager functions for coverage
** Focus: Basic database information and configuration queries
*/
#include "storage_simple_batch_harness.h"

typedef struct {
    uint8_t function_selector;   // Function selector (0-9)
    uint8_t page_flags;         // Page operation flags
    uint8_t journal_mode;       // Journal mode selector
    uint8_t cache_mode;         // Cache operation mode
    uint8_t test_data[8];       // Additional test data
} StorageSimpleInput;

int test_batch_storage_simple_functions(const uint8_t *data, size_t size) {
    if (size < sizeof(StorageSimpleInput)) return 0;
    
    const StorageSimpleInput *input = (const StorageSimpleInput *)data;
    
    // Input validation
    if (input->function_selector > 9) return 0;
    
    sqlite3 *db = NULL;
    int rc = SQLITE_OK;
    
    // Initialize SQLite
    rc = sqlite3_initialize();
    if (rc != SQLITE_OK) return 0;
    
    // Open database for storage operations
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) goto cleanup;
    
    // Create simple test schema
    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(db, "CREATE TABLE storage_test(id INTEGER, data TEXT)", -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
    
    // Execute selected storage function simulation
    switch (input->function_selector) {
        case 0: { // sqlite3PagerIsreadonly equivalent
            rc = sqlite3_prepare_v2(db, "PRAGMA query_only", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                if (sqlite3_step(stmt) == SQLITE_ROW) {
                    volatile int readonly = sqlite3_column_int(stmt, 0);
                    (void)readonly;
                }
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 1: { // sqlite3PagerIswriteable equivalent  
            rc = sqlite3_prepare_v2(db, "INSERT INTO storage_test(id, data) VALUES (1, 'test')", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                rc = sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 2: { // sqlite3PagerGetJournalMode equivalent
            const char *modes[] = {"DELETE", "TRUNCATE", "PERSIST", "MEMORY", "WAL", "OFF"};
            int mode_idx = input->journal_mode % 6;
            char *sql = sqlite3_mprintf("PRAGMA journal_mode=%s", modes[mode_idx]);
            if (sql) {
                rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    if (sqlite3_step(stmt) == SQLITE_ROW) {
                        const char *current_mode = (const char*)sqlite3_column_text(stmt, 0);
                        if (current_mode) {
                            volatile int len = strlen(current_mode);
                            (void)len;
                        }
                    }
                    sqlite3_finalize(stmt);
                }
                sqlite3_free(sql);
            }
            break;
        }
        
        case 3: { // sqlite3PagerDataVersion equivalent
            rc = sqlite3_prepare_v2(db, "PRAGMA data_version", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                if (sqlite3_step(stmt) == SQLITE_ROW) {
                    volatile int version = sqlite3_column_int(stmt, 0);
                    (void)version;
                }
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 4: { // sqlite3PagerDirectReadOk equivalent
            rc = sqlite3_prepare_v2(db, "SELECT * FROM storage_test", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    sqlite3_column_int(stmt, 0);
                    sqlite3_column_text(stmt, 1);
                }
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 5: { // sqlite3PagerDontWrite equivalent (read-only operations)
            rc = sqlite3_prepare_v2(db, "PRAGMA cache_size", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                if (sqlite3_step(stmt) == SQLITE_ROW) {
                    volatile int cache_size = sqlite3_column_int(stmt, 0);
                    (void)cache_size;
                }
                sqlite3_finalize(stmt);
            }
            
            rc = sqlite3_prepare_v2(db, "PRAGMA page_size", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                if (sqlite3_step(stmt) == SQLITE_ROW) {
                    volatile int page_size = sqlite3_column_int(stmt, 0);
                    (void)page_size;
                }
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 6: { // sqlite3PagerMaxPageCount equivalent
            uint32_t max_pages = (input->page_flags * 1000) + 1000;
            char *sql = sqlite3_mprintf("PRAGMA max_page_count=%u", max_pages);
            if (sql) {
                rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    if (sqlite3_step(stmt) == SQLITE_ROW) {
                        volatile int current_max = sqlite3_column_int(stmt, 0);
                        (void)current_max;
                    }
                    sqlite3_finalize(stmt);
                }
                sqlite3_free(sql);
            }
            break;
        }
        
        case 7: { // sqlite3PagerLockingMode equivalent
            const char *lock_modes[] = {"NORMAL", "EXCLUSIVE"};
            int lock_idx = input->cache_mode % 2;
            char *sql = sqlite3_mprintf("PRAGMA locking_mode=%s", lock_modes[lock_idx]);
            if (sql) {
                rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    if (sqlite3_step(stmt) == SQLITE_ROW) {
                        const char *current_mode = (const char*)sqlite3_column_text(stmt, 0);
                        if (current_mode) {
                            volatile int len = strlen(current_mode);
                            (void)len;
                        }
                    }
                    sqlite3_finalize(stmt);
                }
                sqlite3_free(sql);
            }
            break;
        }
        
        case 8: { // sqlite3PagerJournalSizeLimit equivalent  
            int64_t size_limit = (int64_t)(input->test_data[0] + 1) * 1024 * 1024; // 1-256 MB
            char *sql = sqlite3_mprintf("PRAGMA journal_size_limit=%lld", size_limit);
            if (sql) {
                rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    if (sqlite3_step(stmt) == SQLITE_ROW) {
                        volatile int64_t current_limit = sqlite3_column_int64(stmt, 0);
                        (void)current_limit;
                    }
                    sqlite3_finalize(stmt);
                }
                sqlite3_free(sql);
            }
            break;
        }
        
        case 9: { // sqlite3PagerCacheStat equivalent
            // Insert some data to create cache activity
            for (int i = 0; i < (input->test_data[1] % 20) + 5; i++) {
                char *sql = sqlite3_mprintf("INSERT INTO storage_test(id, data) VALUES (%d, 'cache_test_%.*s')", 
                                          i, (int)sizeof(input->test_data), (char*)input->test_data);
                if (sql) {
                    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
                    if (rc == SQLITE_OK) {
                        sqlite3_step(stmt);
                        sqlite3_finalize(stmt);
                    }
                    sqlite3_free(sql);
                }
            }
            
            // Query cache statistics
            const char *cache_pragmas[] = {
                "PRAGMA cache_size",
                "PRAGMA page_count", 
                "PRAGMA freelist_count"
            };
            
            for (int i = 0; i < 3; i++) {
                rc = sqlite3_prepare_v2(db, cache_pragmas[i], -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    if (sqlite3_step(stmt) == SQLITE_ROW) {
                        volatile int stat_value = sqlite3_column_int(stmt, 0);
                        (void)stat_value;
                    }
                    sqlite3_finalize(stmt);
                }
            }
            break;
        }
    }
    
    // Additional simple scenarios based on flags
    if (input->page_flags & 0x01) {
        rc = sqlite3_prepare_v2(db, "PRAGMA compile_options", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const char *option = (const char*)sqlite3_column_text(stmt, 0);
                if (option) {
                    volatile int len = strlen(option);
                    (void)len;
                }
            }
            sqlite3_finalize(stmt);
        }
    }
    
    if (input->page_flags & 0x02) {
        rc = sqlite3_prepare_v2(db, "PRAGMA database_list", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
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
    
    if (input->page_flags & 0x04) {
        rc = sqlite3_prepare_v2(db, "PRAGMA table_info(storage_test)", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
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
    
cleanup:
    if (db) {
        sqlite3_close(db);
    }
    
    return 1;
}