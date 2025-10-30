/*
** Enhanced SQLite3 Fuzzer - B-Tree Page Size Configuration Harness
** Target: sqlite3BtreeSetPageSize function (btree.c:3069)
** Focus: Database page size configuration and structure changes
*/
#include "btree_pagesize_harness.h"

typedef struct {
    uint16_t page_size;         // Target page size
    uint8_t reserve_bytes;      // Reserved bytes per page
    uint8_t fix_flag;           // Fix flag parameter
    uint8_t scenario_flags;     // Test scenario selector
    uint8_t test_data[11];      // Additional test data
} PageSizeInput;

int test_sqlite3BtreeSetPageSize(const uint8_t *data, size_t size) {
    if (size < sizeof(PageSizeInput)) return 0;
    
    const PageSizeInput *input = (const PageSizeInput *)data;
    
    // Input validation
    if ((uintptr_t)input % 8 != 0) return 0;
    
    // Normalize page size to valid range (power of 2 between 512 and 65536)
    uint16_t normalized_page_size = 1024; // Default
    uint16_t raw_size = input->page_size;
    if (raw_size >= 512 && raw_size <= 65536) {
        // Round to nearest power of 2
        if (raw_size <= 512) normalized_page_size = 512;
        else if (raw_size <= 1024) normalized_page_size = 1024;
        else if (raw_size <= 2048) normalized_page_size = 2048;
        else if (raw_size <= 4096) normalized_page_size = 4096;
        else if (raw_size <= 8192) normalized_page_size = 8192;
        else if (raw_size <= 16384) normalized_page_size = 16384;
        else if (raw_size <= 32768) normalized_page_size = 32768;
        else normalized_page_size = 65536;
    }
    
    sqlite3 *db = NULL;
    int rc = SQLITE_OK;
    
    // Initialize SQLite
    rc = sqlite3_initialize();
    if (rc != SQLITE_OK) return 0;
    
    // Scenario 1: Set page size on new database
    if (input->scenario_flags & 0x01) {
        rc = sqlite3_open(":memory:", &db);
        if (rc == SQLITE_OK) {
            sqlite3_stmt *stmt;
            char *sql = sqlite3_mprintf("PRAGMA page_size=%d", normalized_page_size);
            if (sql) {
                rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
                sqlite3_free(sql);
            }
            sqlite3_close(db);
            db = NULL;
        }
    }
    
    // Scenario 2: Set page size with reserved bytes
    if (input->scenario_flags & 0x02) {
        rc = sqlite3_open(":memory:", &db);
        if (rc == SQLITE_OK) {
            sqlite3_stmt *stmt;
            
            // Set page size first
            char *sql1 = sqlite3_mprintf("PRAGMA page_size=%d", normalized_page_size);
            if (sql1) {
                rc = sqlite3_prepare_v2(db, sql1, -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
                sqlite3_free(sql1);
            }
            
            // Set reserved bytes
            char *sql2 = sqlite3_mprintf("PRAGMA reserved_bytes=%d", input->reserve_bytes);
            if (sql2) {
                rc = sqlite3_prepare_v2(db, sql2, -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
                sqlite3_free(sql2);
            }
            
            sqlite3_close(db);
            db = NULL;
        }
    }
    
    // Scenario 3: Page size change after table creation
    if (input->scenario_flags & 0x04) {
        rc = sqlite3_open(":memory:", &db);
        if (rc == SQLITE_OK) {
            sqlite3_stmt *stmt;
            
            // Create table first with default page size
            rc = sqlite3_prepare_v2(db, "CREATE TABLE pagesize_test(id INTEGER, data TEXT)", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            
            // Try to change page size (should be ignored after table creation)
            char *sql = sqlite3_mprintf("PRAGMA page_size=%d", normalized_page_size);
            if (sql) {
                rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
                sqlite3_free(sql);
            }
            
            sqlite3_close(db);
            db = NULL;
        }
    }
    
    // Scenario 4: Various page sizes with data insertion
    if (input->scenario_flags & 0x08) {
        rc = sqlite3_open(":memory:", &db);
        if (rc == SQLITE_OK) {
            sqlite3_stmt *stmt;
            
            char *sql = sqlite3_mprintf("PRAGMA page_size=%d", normalized_page_size);
            if (sql) {
                rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
                sqlite3_free(sql);
            }
            
            // Create table and insert data
            rc = sqlite3_prepare_v2(db, "CREATE TABLE size_test(data BLOB)", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
                
                // Insert data based on test_data
                rc = sqlite3_prepare_v2(db, "INSERT INTO size_test VALUES (?)", -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    sqlite3_bind_blob(stmt, 1, input->test_data, sizeof(input->test_data), SQLITE_STATIC);
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
            }
            
            sqlite3_close(db);
            db = NULL;
        }
    }
    
    // Scenario 5: Page size with auto-vacuum
    if (input->scenario_flags & 0x10) {
        rc = sqlite3_open(":memory:", &db);
        if (rc == SQLITE_OK) {
            sqlite3_stmt *stmt;
            
            char *sql1 = sqlite3_mprintf("PRAGMA page_size=%d", normalized_page_size);
            if (sql1) {
                rc = sqlite3_prepare_v2(db, sql1, -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
                sqlite3_free(sql1);
            }
            
            rc = sqlite3_prepare_v2(db, "PRAGMA auto_vacuum=FULL", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            
            rc = sqlite3_prepare_v2(db, "CREATE TABLE vacuum_test(x)", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            
            sqlite3_close(db);
            db = NULL;
        }
    }
    
    // Scenario 6: Page size with WAL mode
    if (input->scenario_flags & 0x20) {
        rc = sqlite3_open(":memory:", &db);
        if (rc == SQLITE_OK) {
            sqlite3_stmt *stmt;
            
            char *sql = sqlite3_mprintf("PRAGMA page_size=%d", normalized_page_size);
            if (sql) {
                rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
                sqlite3_free(sql);
            }
            
            rc = sqlite3_prepare_v2(db, "PRAGMA journal_mode=WAL", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            
            sqlite3_close(db);
            db = NULL;
        }
    }
    
    // Scenario 7: Stress test with large page size and data
    if (input->scenario_flags & 0x40) {
        rc = sqlite3_open(":memory:", &db);
        if (rc == SQLITE_OK) {
            sqlite3_stmt *stmt;
            
            // Use largest possible page size
            rc = sqlite3_prepare_v2(db, "PRAGMA page_size=65536", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            
            rc = sqlite3_prepare_v2(db, "CREATE TABLE large_test(data TEXT)", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
                
                // Insert large data to stress page management
                char large_data[32768];
                memset(large_data, 'A', sizeof(large_data) - 1);
                large_data[sizeof(large_data) - 1] = '\0';
                
                rc = sqlite3_prepare_v2(db, "INSERT INTO large_test VALUES (?)", -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    sqlite3_bind_text(stmt, 1, large_data, -1, SQLITE_STATIC);
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
            }
            
            sqlite3_close(db);
            db = NULL;
        }
    }
    
    // Scenario 8: Page size edge cases
    if (input->scenario_flags & 0x80) {
        rc = sqlite3_open(":memory:", &db);
        if (rc == SQLITE_OK) {
            sqlite3_stmt *stmt;
            
            // Test multiple page size changes
            int page_sizes[] = {512, 1024, 2048, 4096};
            int page_count = sizeof(page_sizes) / sizeof(page_sizes[0]);
            int selected = (input->fix_flag % page_count);
            
            char *sql = sqlite3_mprintf("PRAGMA page_size=%d", page_sizes[selected]);
            if (sql) {
                rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
                sqlite3_free(sql);
            }
            
            // Test reserved bytes with edge values
            uint8_t reserve_val = input->reserve_bytes;
            if (reserve_val > 0) {
                char *rsv_sql = sqlite3_mprintf("PRAGMA reserved_bytes=%d", reserve_val);
                if (rsv_sql) {
                    rc = sqlite3_prepare_v2(db, rsv_sql, -1, &stmt, NULL);
                    if (rc == SQLITE_OK) {
                        sqlite3_step(stmt);
                        sqlite3_finalize(stmt);
                    }
                    sqlite3_free(rsv_sql);
                }
            }
            
            // Verify settings
            rc = sqlite3_prepare_v2(db, "PRAGMA page_size", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            
            rc = sqlite3_prepare_v2(db, "PRAGMA reserved_bytes", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            
            sqlite3_close(db);
            db = NULL;
        }
    }
    
    // Additional stress testing based on fix_flag
    if (input->fix_flag & 0x01) {
        // Memory allocation stress during page size operations
        void *ptr = sqlite3_malloc64(normalized_page_size * 10);
        if (ptr) {
            memset(ptr, input->test_data[0], normalized_page_size);
            
            rc = sqlite3_open(":memory:", &db);
            if (rc == SQLITE_OK) {
                sqlite3_stmt *stmt;
                char *sql = sqlite3_mprintf("PRAGMA page_size=%d", normalized_page_size);
                if (sql) {
                    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
                    if (rc == SQLITE_OK) {
                        sqlite3_step(stmt);
                        sqlite3_finalize(stmt);
                    }
                    sqlite3_free(sql);
                }
                sqlite3_close(db);
                db = NULL;
            }
            
            sqlite3_free(ptr);
        }
    }
    
cleanup:
    if (db) {
        sqlite3_close(db);
    }
    
    return 1;
}