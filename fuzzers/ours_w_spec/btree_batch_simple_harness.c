/*
** Enhanced SQLite3 Fuzzer - Batch B-Tree Simple Functions Harness  
** Target: Multiple simple B-Tree functions for rapid coverage
** Focus: Fast execution of B-Tree management operations
*/
#include "btree_batch_simple_harness.h"

typedef struct {
    uint8_t function_id;         // Function selector (0-25)
    uint8_t operation_flags;     // Operation flags
    uint16_t data_size;          // Data size parameter
    uint32_t page_number;        // Page number parameter
    uint8_t test_data[16];       // Additional test data
} BtreeBatchInput;

int test_batch_btree_simple_functions(const uint8_t *data, size_t size) {
    if (size < sizeof(BtreeBatchInput)) return 0;
    
    const BtreeBatchInput *input = (const BtreeBatchInput *)data;
    
    // Input validation
    if (input->function_id > 25) return 0;
    
    sqlite3 *db = NULL;
    int rc = SQLITE_OK;
    
    // Initialize SQLite
    rc = sqlite3_initialize();
    if (rc != SQLITE_OK) return 0;
    
    // Open database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) goto cleanup;
    
    // Create test table for B-Tree operations
    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(db, "CREATE TABLE btree_test(id INTEGER PRIMARY KEY, data BLOB)", -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
    
    // Execute selected function simulation
    switch (input->function_id) {
        case 0: { // btreePageFromDbPage equivalent
            rc = sqlite3_prepare_v2(db, "PRAGMA page_size", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 1: { // btreePagecount equivalent  
            rc = sqlite3_prepare_v2(db, "PRAGMA page_count", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 2: { // btreeParseCell simulation
            rc = sqlite3_prepare_v2(db, "INSERT INTO btree_test VALUES (?, ?)", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_bind_int(stmt, 1, input->page_number & 0xFFFF);
                sqlite3_bind_blob(stmt, 2, input->test_data, sizeof(input->test_data), SQLITE_STATIC);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 3: { // btreePayloadToLocal simulation
            rc = sqlite3_prepare_v2(db, "SELECT * FROM btree_test WHERE id = ?", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_bind_int(stmt, 1, input->page_number & 0xFF);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 4: { // btreePrevious equivalent
            rc = sqlite3_prepare_v2(db, "SELECT * FROM btree_test ORDER BY id DESC LIMIT 1", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 5: { // btreeSetHasContent simulation
            rc = sqlite3_prepare_v2(db, "UPDATE btree_test SET data = ? WHERE id = ?", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_bind_blob(stmt, 1, input->test_data, input->data_size & 0x0F, SQLITE_STATIC);
                sqlite3_bind_int(stmt, 2, 1);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 6: { // btreeSetNPage simulation
            char *sql = sqlite3_mprintf("PRAGMA max_page_count=%u", input->page_number & 0xFFFF);
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
        
        case 7: { // checkTreePage equivalent
            rc = sqlite3_prepare_v2(db, "PRAGMA integrity_check(1)", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 8: { // corruptPageError simulation
            rc = sqlite3_prepare_v2(db, "PRAGMA quick_check(1)", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 9: { // editPage simulation
            rc = sqlite3_prepare_v2(db, "DELETE FROM btree_test WHERE id = ?", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_bind_int(stmt, 1, input->page_number & 0xFF);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 10: { // freePage2 simulation
            rc = sqlite3_prepare_v2(db, "PRAGMA freelist_count", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 11: { // freeSpace equivalent
            rc = sqlite3_prepare_v2(db, "VACUUM", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 12: { // freeTempSpace simulation
            rc = sqlite3_prepare_v2(db, "CREATE TEMP TABLE temp_test(x); DROP TABLE temp.temp_test", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 13: { // getAndInitPage simulation
            rc = sqlite3_prepare_v2(db, "CREATE TABLE new_page_test(y)", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 14: { // getOverflowPage simulation
            // Create large data to potentially trigger overflow
            char large_data[2048];
            memset(large_data, 'A', sizeof(large_data) - 1);
            large_data[sizeof(large_data) - 1] = '\0';
            
            rc = sqlite3_prepare_v2(db, "INSERT INTO btree_test VALUES (?, ?)", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_bind_int(stmt, 1, 999);
                sqlite3_bind_text(stmt, 2, large_data, -1, SQLITE_STATIC);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 15: { // getPageReferenced simulation
            rc = sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM btree_test", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 16: { // lockBtree simulation
            rc = sqlite3_prepare_v2(db, "BEGIN EXCLUSIVE", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
                rc = sqlite3_prepare_v2(db, "COMMIT", -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
            }
            break;
        }
        
        case 17: { // modifyPagePointer simulation
            rc = sqlite3_prepare_v2(db, "REINDEX", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 18: { // pageFreeArray simulation
            rc = sqlite3_prepare_v2(db, "DROP TABLE IF EXISTS btree_test", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 19: { // pageInsertArray simulation
            rc = sqlite3_prepare_v2(db, "CREATE TABLE array_test(data)", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
                for (int i = 0; i < (input->operation_flags & 0x0F); i++) {
                    char *sql = sqlite3_mprintf("INSERT INTO array_test VALUES ('item_%d')", i);
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
            break;
        }
        
        case 20: { // pageReinit simulation
            rc = sqlite3_prepare_v2(db, "PRAGMA incremental_vacuum(1)", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 21: { // ptrmapCheckPages simulation
            rc = sqlite3_prepare_v2(db, "PRAGMA auto_vacuum=INCREMENTAL", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 22: { // ptrmapPageno simulation
            rc = sqlite3_prepare_v2(db, "PRAGMA auto_vacuum", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 23: { // rebuildPage simulation
            rc = sqlite3_prepare_v2(db, "CREATE INDEX rebuild_idx ON btree_test(data)", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 24: { // releasePage simulation
            rc = sqlite3_prepare_v2(db, "PRAGMA cache_spill=1", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 25: { // releasePageNotNull simulation
            rc = sqlite3_prepare_v2(db, "PRAGMA cache_size=100", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        default:
            break;
    }
    
    // Additional operations based on flags
    if (input->operation_flags & 0x01) {
        // Memory operations
        void *ptr = sqlite3_malloc64(input->data_size & 0xFFF);
        if (ptr) {
            memset(ptr, input->test_data[0], input->data_size & 0xFFF);
            sqlite3_free(ptr);
        }
    }
    
    if (input->operation_flags & 0x02) {
        // String operations
        char *test_str = sqlite3_mprintf("test_%u_%.*s", 
                                        input->page_number, 
                                        (int)(sizeof(input->test_data)), 
                                        (char*)input->test_data);
        if (test_str) {
            sqlite3_free(test_str);
        }
    }
    
    if (input->operation_flags & 0x04) {
        // Multiple table operations
        for (int i = 0; i < 3; i++) {
            char *sql = sqlite3_mprintf("CREATE TABLE batch_%d(x); INSERT INTO batch_%d VALUES (%d); DROP TABLE batch_%d", 
                                       i, i, i, i);
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
    
    if (input->operation_flags & 0x08) {
        // PRAGMA operations
        const char *pragmas[] = {
            "PRAGMA compile_options",
            "PRAGMA database_list",
            "PRAGMA table_info(btree_test)",
            "PRAGMA schema_version"
        };
        
        for (int i = 0; i < 4; i++) {
            rc = sqlite3_prepare_v2(db, pragmas[i], -1, &stmt, NULL);
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