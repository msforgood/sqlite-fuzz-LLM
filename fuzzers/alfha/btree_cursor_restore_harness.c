/*
** Enhanced SQLite3 Fuzzer - B-Tree Cursor Restore Harness
** Target: sqlite3BtreeCursorRestore function (btree.c:971)
** Focus: Cursor state restoration and recovery scenarios
*/
#include "btree_cursor_restore_harness.h"

typedef struct {
    uint8_t cursor_state;       // Cursor state flags
    uint8_t page_flags;         // Page operation flags  
    uint8_t restore_mode;       // Restoration mode
    uint8_t corruption_type;    // Corruption simulation type
    uint8_t test_data[12];      // Additional test data
} CursorRestoreInput;

int test_sqlite3BtreeCursorRestore(const uint8_t *data, size_t size) {
    if (size < sizeof(CursorRestoreInput)) return 0;
    
    const CursorRestoreInput *input = (const CursorRestoreInput *)data;
    
    // Input validation
    if ((uintptr_t)input % 8 != 0) return 0;
    if (input->cursor_state > 7) return 0;
    
    sqlite3 *db = NULL;
    int rc = SQLITE_OK;
    
    // Initialize SQLite
    rc = sqlite3_initialize();
    if (rc != SQLITE_OK) return 0;
    
    // Open database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) goto cleanup;
    
    // Create test table for cursor operations
    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(db, "CREATE TABLE cursor_restore_test(id INTEGER PRIMARY KEY, data TEXT, extra BLOB)", -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
    
    // Insert test data for cursor positioning
    for (int i = 0; i < 10; i++) {
        char *sql = sqlite3_mprintf("INSERT INTO cursor_restore_test(data, extra) VALUES ('data_%d', ?)", i);
        if (sql) {
            rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_bind_blob(stmt, 1, input->test_data, sizeof(input->test_data), SQLITE_STATIC);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            sqlite3_free(sql);
        }
    }
    
    // Scenario 1: Normal cursor save/restore sequence
    if (input->restore_mode & 0x01) {
        rc = sqlite3_prepare_v2(db, "SELECT * FROM cursor_restore_test WHERE id = ?", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_bind_int(stmt, 1, input->cursor_state + 1);
            
            // Simulate cursor save/restore by stepping and resetting
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                // Save cursor position (simulated)
                sqlite3_reset(stmt);
                
                // Restore cursor position
                sqlite3_bind_int(stmt, 1, input->cursor_state + 1);
                sqlite3_step(stmt);
            }
            sqlite3_finalize(stmt);
        }
    }
    
    // Scenario 2: Cursor restore after table modification
    if (input->restore_mode & 0x02) {
        rc = sqlite3_prepare_v2(db, "SELECT * FROM cursor_restore_test ORDER BY id", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            // Step to position cursor
            sqlite3_step(stmt);
            
            // Modify table while cursor is positioned
            sqlite3_stmt *modify_stmt;
            rc = sqlite3_prepare_v2(db, "UPDATE cursor_restore_test SET data = ? WHERE id = 1", -1, &modify_stmt, NULL);
            if (rc == SQLITE_OK) {
                char update_data[32];
                snprintf(update_data, sizeof(update_data), "modified_%u", (unsigned)input->page_flags);
                sqlite3_bind_text(modify_stmt, 1, update_data, -1, SQLITE_STATIC);
                sqlite3_step(modify_stmt);
                sqlite3_finalize(modify_stmt);
            }
            
            // Try to continue with original cursor
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                // Process results to test cursor validity
            }
            sqlite3_finalize(stmt);
        }
    }
    
    // Scenario 3: Concurrent cursor operations
    if (input->restore_mode & 0x04) {
        sqlite3_stmt *stmt1, *stmt2;
        
        rc = sqlite3_prepare_v2(db, "SELECT * FROM cursor_restore_test WHERE id > ?", -1, &stmt1, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_bind_int(stmt1, 1, 0);
            
            rc = sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM cursor_restore_test", -1, &stmt2, NULL);
            if (rc == SQLITE_OK) {
                // Interleave cursor operations
                sqlite3_step(stmt1);  // Position first cursor
                sqlite3_step(stmt2);  // Use second cursor
                sqlite3_step(stmt1);  // Continue with first cursor
                
                sqlite3_finalize(stmt2);
            }
            sqlite3_finalize(stmt1);
        }
    }
    
    // Scenario 4: Memory pressure during cursor operations
    if (input->restore_mode & 0x08) {
        void *pressure_ptr = sqlite3_malloc64((input->corruption_type + 1) * 1024);
        if (pressure_ptr) {
            memset(pressure_ptr, input->test_data[0], (input->corruption_type + 1) * 1024);
            
            rc = sqlite3_prepare_v2(db, "SELECT * FROM cursor_restore_test", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    // Access data under memory pressure
                    const char *data = (const char*)sqlite3_column_text(stmt, 1);
                    if (data) {
                        volatile int len = strlen(data);
                        (void)len; // Prevent optimization
                    }
                }
                sqlite3_finalize(stmt);
            }
            
            sqlite3_free(pressure_ptr);
        }
    }
    
    // Scenario 5: Transaction boundary cursor restore
    if (input->cursor_state & 0x01) {
        rc = sqlite3_prepare_v2(db, "BEGIN", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
            
            rc = sqlite3_prepare_v2(db, "SELECT * FROM cursor_restore_test WHERE id = ?", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_bind_int(stmt, 1, (input->page_flags % 10) + 1);
                sqlite3_step(stmt);
                
                // Rollback transaction while cursor is active
                sqlite3_stmt *rollback_stmt;
                rc = sqlite3_prepare_v2(db, "ROLLBACK", -1, &rollback_stmt, NULL);
                if (rc == SQLITE_OK) {
                    sqlite3_step(rollback_stmt);
                    sqlite3_finalize(rollback_stmt);
                }
                
                // Try to use cursor after rollback
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
        }
    }
    
    // Scenario 6: Large result set cursor operations  
    if (input->cursor_state & 0x02) {
        // Create larger dataset
        rc = sqlite3_prepare_v2(db, "BEGIN", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
            
            int insert_count = (input->corruption_type & 0x0F) + 50;
            for (int i = 0; i < insert_count; i++) {
                char *sql = sqlite3_mprintf("INSERT INTO cursor_restore_test(data) VALUES ('large_data_%d_%.*s')", 
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
            
            // Use cursor on large dataset
            rc = sqlite3_prepare_v2(db, "SELECT * FROM cursor_restore_test ORDER BY id DESC", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                int count = 0;
                while (sqlite3_step(stmt) == SQLITE_ROW && count < 20) {
                    count++;
                    // Simulate cursor save/restore by accessing data
                    sqlite3_column_int(stmt, 0);
                    sqlite3_column_text(stmt, 1);
                    sqlite3_column_blob(stmt, 2);
                }
                sqlite3_finalize(stmt);
            }
        }
    }
    
    // Scenario 7: Index cursor restore
    if (input->cursor_state & 0x04) {
        rc = sqlite3_prepare_v2(db, "CREATE INDEX idx_data ON cursor_restore_test(data)", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
            
            rc = sqlite3_prepare_v2(db, "SELECT * FROM cursor_restore_test WHERE data LIKE ? ORDER BY data", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                char pattern[32];
                snprintf(pattern, sizeof(pattern), "data_%u%%", (unsigned)(input->page_flags % 10));
                sqlite3_bind_text(stmt, 1, pattern, -1, SQLITE_STATIC);
                
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    // Access indexed data
                }
                sqlite3_finalize(stmt);
            }
        }
    }
    
    // Scenario 8: Cursor restore with schema changes
    if (input->cursor_state & 0x08) {
        rc = sqlite3_prepare_v2(db, "SELECT * FROM cursor_restore_test", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_step(stmt); // Position cursor
            
            // Attempt schema change (may invalidate cursors)
            sqlite3_stmt *alter_stmt;
            rc = sqlite3_prepare_v2(db, "ALTER TABLE cursor_restore_test ADD COLUMN new_col INTEGER DEFAULT 0", -1, &alter_stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(alter_stmt);
                sqlite3_finalize(alter_stmt);
            }
            
            // Try to continue with original cursor
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                // Process results
            }
            sqlite3_finalize(stmt);
        }
    }
    
    // Additional corruption simulation based on page_flags
    if (input->page_flags & 0x80) {
        // Force cache pressure
        rc = sqlite3_prepare_v2(db, "PRAGMA cache_size=1", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
        
        // Heavy cursor operations under cache pressure
        for (int i = 0; i < 3; i++) {
            rc = sqlite3_prepare_v2(db, "SELECT * FROM cursor_restore_test WHERE id > ? LIMIT 5", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_bind_int(stmt, 1, i * 3);
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    // Force page access
                }
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