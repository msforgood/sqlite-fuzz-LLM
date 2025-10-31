/*
** Enhanced SQLite3 Fuzzer - B-Tree Commit Phase Two Harness
** Target: sqlite3BtreeCommitPhaseTwo function (btree.c:4374)
** Focus: Transaction finalization and cleanup scenarios
*/
#include "btree_commitphase2_harness.h"

typedef struct {
    uint8_t btree_flags;        // Btree operation flags
    uint8_t cleanup_mode;       // Cleanup mode selector
    uint8_t error_injection;    // Error injection type
    uint8_t operation_flags;    // Additional operation flags
    uint8_t test_data[12];      // Test data for scenarios
} CommitPhase2Input;

int test_sqlite3BtreeCommitPhaseTwo(const uint8_t *data, size_t size) {
    if (size < sizeof(CommitPhase2Input)) return 0;
    
    const CommitPhase2Input *input = (const CommitPhase2Input *)data;
    
    // Input validation
    if ((uintptr_t)input % 8 != 0) return 0;
    if (input->cleanup_mode > 3) return 0;
    
    sqlite3 *db = NULL;
    int rc = SQLITE_OK;
    
    // Initialize SQLite
    rc = sqlite3_initialize();
    if (rc != SQLITE_OK) return 0;
    
    // Open database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) goto cleanup;
    
    // Create test table
    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(db, "CREATE TABLE commit_test(id INTEGER PRIMARY KEY, data TEXT)", -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
    
    // Scenario 1: Normal transaction commit sequence
    if (input->operation_flags & 0x01) {
        rc = sqlite3_prepare_v2(db, "BEGIN", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
            
            // Insert some data
            rc = sqlite3_prepare_v2(db, "INSERT INTO commit_test(data) VALUES ('phase2_test')", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            
            // Commit transaction
            rc = sqlite3_prepare_v2(db, "COMMIT", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
        }
    }
    
    // Scenario 2: WAL mode commit
    if (input->operation_flags & 0x02) {
        rc = sqlite3_prepare_v2(db, "PRAGMA journal_mode=WAL", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
            
            rc = sqlite3_prepare_v2(db, "BEGIN", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
                
                for (int i = 0; i < (input->btree_flags & 0x0F); i++) {
                    char *sql = sqlite3_mprintf("INSERT INTO commit_test(data) VALUES ('wal_test_%d')", i);
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
    }
    
    // Scenario 3: Nested transaction with savepoints
    if (input->operation_flags & 0x04) {
        rc = sqlite3_prepare_v2(db, "BEGIN", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
            
            rc = sqlite3_prepare_v2(db, "SAVEPOINT sp1", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
                
                rc = sqlite3_prepare_v2(db, "INSERT INTO commit_test(data) VALUES ('savepoint_test')", -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
                
                if (input->cleanup_mode & 0x01) {
                    rc = sqlite3_prepare_v2(db, "ROLLBACK TO sp1", -1, &stmt, NULL);
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
    
    // Scenario 4: Immediate transaction commit
    if (input->operation_flags & 0x08) {
        rc = sqlite3_prepare_v2(db, "BEGIN IMMEDIATE", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
            
            rc = sqlite3_prepare_v2(db, "INSERT INTO commit_test(data) VALUES (?)", -1, &stmt, NULL);
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
    
    // Scenario 5: Exclusive transaction commit
    if (input->operation_flags & 0x10) {
        rc = sqlite3_prepare_v2(db, "BEGIN EXCLUSIVE", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
            
            // Multiple operations in exclusive mode
            for (int i = 0; i < 3; i++) {
                char *sql = sqlite3_mprintf("INSERT INTO commit_test(data) VALUES ('exclusive_%d_%.*s')", 
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
    
    // Scenario 6: Checkpoint operations during commit
    if (input->operation_flags & 0x20) {
        rc = sqlite3_prepare_v2(db, "PRAGMA journal_mode=WAL", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
            
            rc = sqlite3_prepare_v2(db, "BEGIN", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
                
                rc = sqlite3_prepare_v2(db, "INSERT INTO commit_test(data) VALUES ('checkpoint_test')", -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
                
                // Force checkpoint
                rc = sqlite3_prepare_v2(db, "PRAGMA wal_checkpoint", -1, &stmt, NULL);
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
    
    // Scenario 7: Large transaction commit
    if (input->operation_flags & 0x40) {
        rc = sqlite3_prepare_v2(db, "BEGIN", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
            
            int insertCount = (input->error_injection & 0x0F) + 10;
            for (int i = 0; i < insertCount; i++) {
                char largeData[1024];
                memset(largeData, 'A' + (i % 26), sizeof(largeData) - 1);
                largeData[sizeof(largeData) - 1] = '\0';
                
                rc = sqlite3_prepare_v2(db, "INSERT INTO commit_test(data) VALUES (?)", -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    sqlite3_bind_text(stmt, 1, largeData, -1, SQLITE_STATIC);
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
    
    // Scenario 8: Error injection during commit
    if (input->operation_flags & 0x80) {
        rc = sqlite3_prepare_v2(db, "BEGIN", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
            
            rc = sqlite3_prepare_v2(db, "INSERT INTO commit_test(data) VALUES ('error_test')", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            
            // Simulate various error conditions
            switch (input->error_injection & 0x07) {
                case 1: {
                    // Force a sync error simulation via disk full
                    rc = sqlite3_prepare_v2(db, "PRAGMA synchronous=FULL", -1, &stmt, NULL);
                    if (rc == SQLITE_OK) {
                        sqlite3_step(stmt);
                        sqlite3_finalize(stmt);
                    }
                    break;
                }
                case 2: {
                    // Memory pressure during commit
                    void *ptr = sqlite3_malloc64(1024 * 1024);  // Allocate large memory
                    if (ptr) {
                        memset(ptr, input->test_data[0], 1024);
                    }
                    rc = sqlite3_prepare_v2(db, "COMMIT", -1, &stmt, NULL);
                    if (rc == SQLITE_OK) {
                        sqlite3_step(stmt);
                        sqlite3_finalize(stmt);
                    }
                    if (ptr) {
                        sqlite3_free(ptr);
                    }
                    break;
                }
                default: {
                    // Normal commit
                    rc = sqlite3_prepare_v2(db, "COMMIT", -1, &stmt, NULL);
                    if (rc == SQLITE_OK) {
                        sqlite3_step(stmt);
                        sqlite3_finalize(stmt);
                    }
                    break;
                }
            }
        }
    }
    
    // Additional operations based on cleanup_mode
    switch (input->cleanup_mode) {
        case 1: {
            // Integrity check after operations
            rc = sqlite3_prepare_v2(db, "PRAGMA integrity_check(1)", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
        }
        case 2: {
            // Quick check
            rc = sqlite3_prepare_v2(db, "PRAGMA quick_check(1)", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
        }
        case 3: {
            // Force vacuum
            rc = sqlite3_prepare_v2(db, "VACUUM", -1, &stmt, NULL);
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