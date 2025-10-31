/*
** Enhanced SQLite3 Fuzzer - Batch B-Tree Mutex Functions Harness
** Target: Multiple mutex and concurrency functions for coverage
** Focus: Concurrency control and thread safety operations
*/
#include "btree_mutex_batch_harness.h"

typedef struct {
    uint8_t function_selector;   // Function selector (0-8)
    uint8_t operation_mode;      // Operation mode flags
    uint8_t thread_flags;        // Thread operation flags
    uint8_t stress_level;        // Stress testing level
    uint8_t test_data[12];       // Additional test data
} MutexBatchInput;

int test_batch_btree_mutex_functions(const uint8_t *data, size_t size) {
    if (size < sizeof(MutexBatchInput)) return 0;
    
    const MutexBatchInput *input = (const MutexBatchInput *)data;
    
    // Input validation
    if (input->function_selector > 8) return 0;
    
    sqlite3 *db = NULL;
    int rc = SQLITE_OK;
    
    // Initialize SQLite
    rc = sqlite3_initialize();
    if (rc != SQLITE_OK) return 0;
    
    // Open database for mutex operations
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) goto cleanup;
    
    // Create test table for operations
    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(db, "CREATE TABLE mutex_test(id INTEGER PRIMARY KEY, data TEXT)", -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
    
    // Execute selected function simulation
    switch (input->function_selector) {
        case 0: { // sqlite3BtreeEnter equivalent
            rc = sqlite3_prepare_v2(db, "BEGIN", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
                
                rc = sqlite3_prepare_v2(db, "INSERT INTO mutex_test(data) VALUES ('enter_test')", -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
                
                rc = sqlite3_prepare_v2(db, "COMMIT", -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
            }
            break;
        }
        
        case 1: { // sqlite3BtreeLeave equivalent
            rc = sqlite3_prepare_v2(db, "BEGIN", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
                
                rc = sqlite3_prepare_v2(db, "INSERT INTO mutex_test(data) VALUES ('leave_test')", -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
                
                rc = sqlite3_prepare_v2(db, "ROLLBACK", -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
            }
            break;
        }
        
        case 2: { // sqlite3BtreeEnterAll equivalent
            rc = sqlite3_prepare_v2(db, "BEGIN EXCLUSIVE", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
                
                for (int i = 0; i < (input->stress_level & 0x07) + 1; i++) {
                    char *sql = sqlite3_mprintf("INSERT INTO mutex_test(data) VALUES ('enter_all_%d')", i);
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
            break;
        }
        
        case 3: { // sqlite3BtreeLeaveAll equivalent
            rc = sqlite3_prepare_v2(db, "BEGIN EXCLUSIVE", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
                
                rc = sqlite3_prepare_v2(db, "INSERT INTO mutex_test(data) VALUES ('leave_all_test')", -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
                
                rc = sqlite3_prepare_v2(db, "ROLLBACK", -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
            }
            break;
        }
        
        case 4: { // sqlite3BtreeEnterCursor equivalent
            rc = sqlite3_prepare_v2(db, "SELECT * FROM mutex_test WHERE id = ?", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_bind_int(stmt, 1, input->operation_mode & 0xFF);
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    // Process cursor operations
                }
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 5: { // sqlite3BtreeLeaveCursor equivalent
            rc = sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM mutex_test", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 6: { // sqlite3BtreeHoldsMutex equivalent
            rc = sqlite3_prepare_v2(db, "PRAGMA locking_mode=EXCLUSIVE", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
                
                rc = sqlite3_prepare_v2(db, "BEGIN", -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                    
                    rc = sqlite3_prepare_v2(db, "INSERT INTO mutex_test(data) VALUES (?)", -1, &stmt, NULL);
                    if (rc == SQLITE_OK) {
                        sqlite3_bind_blob(stmt, 1, input->test_data, sizeof(input->test_data), SQLITE_STATIC);
                        sqlite3_step(stmt);
                        sqlite3_finalize(stmt);
                    }
                    
                    rc = sqlite3_prepare_v2(db, "COMMIT", -1, &stmt, NULL);
                    if (rc == SQLITE_OK) {
                        sqlite3_step(stmt);
                        sqlite3_finalize(stmt);
                    }
                }
            }
            break;
        }
        
        case 7: { // sqlite3BtreeHoldsAllMutexes equivalent
            rc = sqlite3_prepare_v2(db, "PRAGMA locking_mode=EXCLUSIVE", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
                
                rc = sqlite3_prepare_v2(db, "BEGIN IMMEDIATE", -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                    
                    // Multiple operations under exclusive lock
                    const char *operations[] = {
                        "INSERT INTO mutex_test(data) VALUES ('holds_all_1')",
                        "UPDATE mutex_test SET data = 'holds_all_updated' WHERE id = 1",
                        "DELETE FROM mutex_test WHERE id > 100"
                    };
                    
                    for (int i = 0; i < 3; i++) {
                        rc = sqlite3_prepare_v2(db, operations[i], -1, &stmt, NULL);
                        if (rc == SQLITE_OK) {
                            sqlite3_step(stmt);
                            sqlite3_finalize(stmt);
                        }
                    }
                    
                    rc = sqlite3_prepare_v2(db, "COMMIT", -1, &stmt, NULL);
                    if (rc == SQLITE_OK) {
                        sqlite3_step(stmt);
                        sqlite3_finalize(stmt);
                    }
                }
            }
            break;
        }
        
        case 8: { // lockBtreeMutex equivalent
            rc = sqlite3_prepare_v2(db, "PRAGMA synchronous=FULL", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
                
                rc = sqlite3_prepare_v2(db, "BEGIN", -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                    
                    // Stress test with multiple operations
                    int op_count = (input->thread_flags & 0x0F) + 1;
                    for (int i = 0; i < op_count; i++) {
                        char *sql = sqlite3_mprintf("INSERT INTO mutex_test(data) VALUES ('lock_mutex_%d_%.*s')", 
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
                    
                    rc = sqlite3_prepare_v2(db, "COMMIT", -1, &stmt, NULL);
                    if (rc == SQLITE_OK) {
                        sqlite3_step(stmt);
                        sqlite3_finalize(stmt);
                    }
                }
            }
            break;
        }
        
        default:
            break;
    }
    
    // Additional operations based on operation_mode
    if (input->operation_mode & 0x01) {
        // Concurrent read operations simulation
        for (int i = 0; i < 3; i++) {
            rc = sqlite3_prepare_v2(db, "SELECT * FROM mutex_test ORDER BY id", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    // Process results
                }
                sqlite3_finalize(stmt);
            }
        }
    }
    
    if (input->operation_mode & 0x02) {
        // Write conflict simulation
        rc = sqlite3_prepare_v2(db, "BEGIN IMMEDIATE", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
            
            rc = sqlite3_prepare_v2(db, "UPDATE mutex_test SET data = ? WHERE id = 1", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                char update_data[64];
                snprintf(update_data, sizeof(update_data), "concurrent_update_%u", 
                        (unsigned)(input->test_data[0] | (input->test_data[1] << 8)));
                sqlite3_bind_text(stmt, 1, update_data, -1, SQLITE_STATIC);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            
            rc = sqlite3_prepare_v2(db, "COMMIT", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
        }
    }
    
    if (input->operation_mode & 0x04) {
        // Transaction nesting simulation
        rc = sqlite3_prepare_v2(db, "BEGIN", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
            
            rc = sqlite3_prepare_v2(db, "SAVEPOINT nested", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
                
                rc = sqlite3_prepare_v2(db, "INSERT INTO mutex_test(data) VALUES ('nested_transaction')", -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
                
                if (input->thread_flags & 0x01) {
                    rc = sqlite3_prepare_v2(db, "ROLLBACK TO nested", -1, &stmt, NULL);
                    if (rc == SQLITE_OK) {
                        sqlite3_step(stmt);
                        sqlite3_finalize(stmt);
                    }
                }
                
                rc = sqlite3_prepare_v2(db, "COMMIT", -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
            }
        }
    }
    
    if (input->operation_mode & 0x08) {
        // Memory pressure during mutex operations
        void *ptr = sqlite3_malloc64((input->stress_level + 1) * 1024);
        if (ptr) {
            memset(ptr, input->test_data[0], (input->stress_level + 1) * 1024);
            
            rc = sqlite3_prepare_v2(db, "PRAGMA shrink_memory", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
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