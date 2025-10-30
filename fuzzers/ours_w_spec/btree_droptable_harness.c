/*
** Enhanced SQLite3 Fuzzer - B-Tree Drop Table Harness
** Target: sqlite3BtreeDropTable function (btree.c:10374)
** Focus: Table dropping operations with page reorganization scenarios
*/
#include "btree_droptable_harness.h"

typedef struct {
    uint32_t table_id;           // Table identifier 
    uint8_t scenario_flags;      // Test scenario selector
    uint8_t drop_mode;           // Drop operation mode
    uint8_t corruption_type;     // Corruption simulation type
    uint8_t flags;
} DropTableInput;

int test_sqlite3BtreeDropTable(const uint8_t *data, size_t size) {
    if (size < sizeof(DropTableInput)) return 0;
    
    const DropTableInput *input = (const DropTableInput *)data;
    
    // Input validation
    if ((uintptr_t)input % 8 != 0) return 0;
    if (input->table_id == 0 || input->table_id > 0x7FFFFFFF) return 0;
    
    sqlite3 *db = NULL;
    int rc = SQLITE_OK;
    
    // Initialize SQLite
    rc = sqlite3_initialize();
    if (rc != SQLITE_OK) return 0;
    
    // Open database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) goto cleanup;
    
    // Create test tables for drop operations
    sqlite3_stmt *stmt;
    for (int i = 0; i < 5; i++) {
        char *sql = sqlite3_mprintf("CREATE TABLE drop_test_%d(id INTEGER, data TEXT)", i);
        if (sql) {
            rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            sqlite3_free(sql);
        }
    }
    
    // Scenario 1: Normal table drop
    if (input->scenario_flags & 0x01) {
        rc = sqlite3_prepare_v2(db, "DROP TABLE IF EXISTS drop_test_0", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }
    
    // Scenario 2: Drop non-existent table
    if (input->scenario_flags & 0x02) {
        char *sql = sqlite3_mprintf("DROP TABLE IF EXISTS nonexistent_%u", input->table_id);
        if (sql) {
            rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            sqlite3_free(sql);
        }
    }
    
    // Scenario 3: Drop table with data
    if (input->scenario_flags & 0x04) {
        // Insert data first
        rc = sqlite3_prepare_v2(db, "INSERT INTO drop_test_1 VALUES (1, 'test_data')", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
        
        // Drop the table
        rc = sqlite3_prepare_v2(db, "DROP TABLE drop_test_1", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }
    
    // Scenario 4: Drop table with index
    if (input->scenario_flags & 0x08) {
        // Create index first
        rc = sqlite3_prepare_v2(db, "CREATE INDEX idx_drop_test ON drop_test_2(id)", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
        
        // Drop the table (should also drop index)
        rc = sqlite3_prepare_v2(db, "DROP TABLE drop_test_2", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }
    
    // Scenario 5: Multiple table drops in transaction
    if (input->scenario_flags & 0x10) {
        rc = sqlite3_prepare_v2(db, "BEGIN", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
            
            for (int i = 3; i < 5; i++) {
                char *sql = sqlite3_mprintf("DROP TABLE IF EXISTS drop_test_%d", i);
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
    
    // Scenario 6: Drop table with trigger
    if (input->scenario_flags & 0x20) {
        // Create table and trigger
        rc = sqlite3_prepare_v2(db, "CREATE TABLE trigger_test(x)", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
            
            rc = sqlite3_prepare_v2(db, "CREATE TRIGGER trig_test AFTER INSERT ON trigger_test BEGIN UPDATE trigger_test SET x = x + 1; END", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            
            // Drop table (should also drop trigger)
            rc = sqlite3_prepare_v2(db, "DROP TABLE trigger_test", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
        }
    }
    
    // Scenario 7: Drop temporary table
    if (input->scenario_flags & 0x40) {
        rc = sqlite3_prepare_v2(db, "CREATE TEMP TABLE temp_drop_test(y)", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
            
            rc = sqlite3_prepare_v2(db, "DROP TABLE temp.temp_drop_test", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
        }
    }
    
    // Scenario 8: Drop with rollback
    if (input->scenario_flags & 0x80) {
        rc = sqlite3_prepare_v2(db, "CREATE TABLE rollback_test(z)", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
            
            rc = sqlite3_prepare_v2(db, "BEGIN", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
                
                rc = sqlite3_prepare_v2(db, "DROP TABLE rollback_test", -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
                
                // Rollback the drop
                rc = sqlite3_prepare_v2(db, "ROLLBACK", -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
            }
        }
    }
    
    // Additional operations based on drop_mode
    switch (input->drop_mode & 0x07) {
        case 1: { // Schema table access attempt
            rc = sqlite3_prepare_v2(db, "SELECT name FROM sqlite_master WHERE type='table'", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    // Process schema information
                }
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 2: { // Foreign key constraint test
            rc = sqlite3_prepare_v2(db, "PRAGMA foreign_keys=ON", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
                
                rc = sqlite3_prepare_v2(db, "CREATE TABLE parent(id PRIMARY KEY)", -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                    
                    rc = sqlite3_prepare_v2(db, "CREATE TABLE child(pid REFERENCES parent(id))", -1, &stmt, NULL);
                    if (rc == SQLITE_OK) {
                        sqlite3_step(stmt);
                        sqlite3_finalize(stmt);
                        
                        // Try to drop parent (should fail due to FK)
                        rc = sqlite3_prepare_v2(db, "DROP TABLE parent", -1, &stmt, NULL);
                        if (rc == SQLITE_OK) {
                            sqlite3_step(stmt);
                            sqlite3_finalize(stmt);
                        }
                    }
                }
            }
            break;
        }
        
        case 3: { // View dependency test
            rc = sqlite3_prepare_v2(db, "CREATE TABLE view_base(a, b)", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
                
                rc = sqlite3_prepare_v2(db, "CREATE VIEW test_view AS SELECT * FROM view_base", -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                    
                    // Try to drop base table (view depends on it)
                    rc = sqlite3_prepare_v2(db, "DROP TABLE view_base", -1, &stmt, NULL);
                    if (rc == SQLITE_OK) {
                        sqlite3_step(stmt);
                        sqlite3_finalize(stmt);
                    }
                }
            }
            break;
        }
        
        default: { // Simple integrity check
            rc = sqlite3_prepare_v2(db, "PRAGMA integrity_check(1)", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
        }
    }
    
    // Stress test based on corruption_type
    if (input->corruption_type & 0x0F) {
        int count = input->corruption_type & 0x0F;
        for (int i = 0; i < count; i++) {
            char *sql = sqlite3_mprintf("CREATE TABLE stress_%d(x); DROP TABLE IF EXISTS stress_%d", i, i);
            if (sql) {
                rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
                sqlite3_free(sql);
            }
        }
    }
    
cleanup:
    if (db) {
        sqlite3_close(db);
    }
    
    return 1;
}