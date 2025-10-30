/*
** Enhanced SQLite3 Fuzzer - B-Tree Commit Phase Harness
** Target: sqlite3BtreeCommitPhaseOne function (btree.c:4285)
** Focus: Transaction commit operations with corruption scenarios
*/
#include "btree_commit_harness.h"

typedef struct {
    uint32_t transaction_id;     // Transaction identifier
    uint8_t scenario_flags;      // Test scenario selector
    uint8_t corruption_type;     // Type of corruption to simulate
    uint8_t journal_mode;        // Journal mode flags
    uint8_t padding;
    char journal_name[64];       // Journal filename data
} CommitPhaseInput;

int test_sqlite3BtreeCommitPhaseOne(const uint8_t *data, size_t size) {
    if (size < sizeof(CommitPhaseInput)) return 0;
    
    const CommitPhaseInput *input = (const CommitPhaseInput *)data;
    
    // Input validation
    if ((uintptr_t)input % 8 != 0) return 0;
    
    sqlite3 *db = NULL;
    int rc = SQLITE_OK;
    
    // Initialize SQLite
    rc = sqlite3_initialize();
    if (rc != SQLITE_OK) return 0;
    
    // Open database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) goto cleanup;
    
    // Create test table for transaction operations
    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(db, "CREATE TABLE commit_test(id INTEGER, data TEXT)", -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
    
    // Scenario 1: Normal transaction commit
    if (input->scenario_flags & 0x01) {
        rc = sqlite3_prepare_v2(db, "BEGIN IMMEDIATE", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
            
            rc = sqlite3_prepare_v2(db, "INSERT INTO commit_test VALUES (1, 'test')", -1, &stmt, NULL);
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
    }
    
    // Scenario 2: Large transaction commit
    if (input->scenario_flags & 0x02) {
        rc = sqlite3_prepare_v2(db, "BEGIN", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
            
            // Multiple insertions to create large transaction
            for (int i = 0; i < (input->corruption_type & 0x0F) + 5; i++) {
                char *sql = sqlite3_mprintf("INSERT INTO commit_test VALUES (%d, 'data_%d')", i, i);
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
    
    // Scenario 3: Nested transactions
    if (input->scenario_flags & 0x04) {
        rc = sqlite3_prepare_v2(db, "BEGIN", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
            
            rc = sqlite3_prepare_v2(db, "SAVEPOINT sp1", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
                
                rc = sqlite3_prepare_v2(db, "INSERT INTO commit_test VALUES (100, 'nested')", -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
                
                if (input->corruption_type & 0x01) {
                    rc = sqlite3_prepare_v2(db, "ROLLBACK TO sp1", -1, &stmt, NULL);
                } else {
                    rc = sqlite3_prepare_v2(db, "RELEASE sp1", -1, &stmt, NULL);
                }
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
    
    // Scenario 4: WAL mode operations
    if (input->scenario_flags & 0x08) {
        rc = sqlite3_prepare_v2(db, "PRAGMA journal_mode=WAL", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
            
            rc = sqlite3_prepare_v2(db, "BEGIN", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
                
                rc = sqlite3_prepare_v2(db, "INSERT INTO commit_test VALUES (200, 'wal_test')", -1, &stmt, NULL);
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
        }
    }
    
    // Scenario 5: Rollback after changes
    if (input->scenario_flags & 0x10) {
        rc = sqlite3_prepare_v2(db, "BEGIN", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
            
            rc = sqlite3_prepare_v2(db, "INSERT INTO commit_test VALUES (300, 'rollback_test')", -1, &stmt, NULL);
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
    }
    
    // Scenario 6: Journal mode switching
    if (input->scenario_flags & 0x20) {
        const char *modes[] = {"DELETE", "TRUNCATE", "PERSIST", "MEMORY", "WAL", "OFF"};
        int mode_idx = input->journal_mode % 6;
        
        char *sql = sqlite3_mprintf("PRAGMA journal_mode=%s", modes[mode_idx]);
        if (sql) {
            rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            sqlite3_free(sql);
        }
        
        // Test transaction in new mode
        rc = sqlite3_prepare_v2(db, "BEGIN", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
            
            rc = sqlite3_prepare_v2(db, "INSERT INTO commit_test VALUES (400, 'mode_test')", -1, &stmt, NULL);
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
    }
    
    // Scenario 7: Concurrent transaction simulation
    if (input->scenario_flags & 0x40) {
        // Create multiple statements to simulate concurrent access
        sqlite3_stmt *stmt1, *stmt2;
        
        rc = sqlite3_prepare_v2(db, "BEGIN IMMEDIATE", -1, &stmt1, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_step(stmt1);
            
            rc = sqlite3_prepare_v2(db, "INSERT INTO commit_test VALUES (500, 'concurrent')", -1, &stmt2, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt2);
                sqlite3_finalize(stmt2);
            }
            
            rc = sqlite3_prepare_v2(db, "COMMIT", -1, &stmt2, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt2);
                sqlite3_finalize(stmt2);
            }
            
            sqlite3_finalize(stmt1);
        }
    }
    
    // Scenario 8: Checkpoint operations
    if (input->scenario_flags & 0x80) {
        rc = sqlite3_prepare_v2(db, "PRAGMA journal_mode=WAL", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
            
            // Force checkpoint
            rc = sqlite3_wal_checkpoint(db, NULL);
            
            // Test commit after checkpoint
            rc = sqlite3_prepare_v2(db, "BEGIN", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
                
                rc = sqlite3_prepare_v2(db, "INSERT INTO commit_test VALUES (600, 'checkpoint')", -1, &stmt, NULL);
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
        }
    }
    
    // Additional stress based on corruption_type
    switch (input->corruption_type & 0x07) {
        case 1: { // Memory pressure
            for (int i = 0; i < 32; i++) {
                rc = sqlite3_prepare_v2(db, "BEGIN; INSERT INTO commit_test VALUES (?, 'stress'); COMMIT", -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    sqlite3_bind_int(stmt, 1, 1000 + i);
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
            }
            break;
        }
        
        case 2: { // Large data operations
            rc = sqlite3_prepare_v2(db, "BEGIN", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
                
                char large_data[1024];
                memset(large_data, 'X', sizeof(large_data) - 1);
                large_data[sizeof(large_data) - 1] = '\0';
                
                rc = sqlite3_prepare_v2(db, "INSERT INTO commit_test VALUES (?, ?)", -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    sqlite3_bind_int(stmt, 1, 2000);
                    sqlite3_bind_text(stmt, 2, large_data, -1, SQLITE_STATIC);
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
        
        default: { // Standard integrity check
            rc = sqlite3_prepare_v2(db, "PRAGMA integrity_check", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
        }
    }
    
cleanup:
    if (db) {
        sqlite3_close(db);
    }
    
    return 1;
}