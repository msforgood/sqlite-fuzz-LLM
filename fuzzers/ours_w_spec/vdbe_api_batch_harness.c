/*
** Enhanced SQLite3 Fuzzer - VDBE API Batch Harness  
** Target: Multiple VDBE API functions for coverage
** Focus: Statement information and result value management
*/
#include "vdbe_api_batch_harness.h"

typedef struct {
    uint8_t function_selector;   // Function selector (0-12)
    uint8_t value_type;         // Value type selector
    int32_t int_value;          // Integer value parameter
    uint32_t double_value;      // Double value (as uint32 for fuzzing)
    uint8_t text_data[6];       // Text data for string values
} VdbeApiInput;

int test_batch_vdbe_api_functions(const uint8_t *data, size_t size) {
    if (size < sizeof(VdbeApiInput)) return 0;
    
    const VdbeApiInput *input = (const VdbeApiInput *)data;
    
    // Input validation
    if (input->function_selector > 12) return 0;
    
    sqlite3 *db = NULL;
    int rc = SQLITE_OK;
    
    // Initialize SQLite
    rc = sqlite3_initialize();
    if (rc != SQLITE_OK) return 0;
    
    // Open database for API operations
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) goto cleanup;
    
    // Create test table and function for API testing
    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(db, "CREATE TABLE api_test(id INTEGER, data TEXT, value REAL)", -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
    
    // Insert test data
    for (int i = 0; i < 5; i++) {
        char *sql = sqlite3_mprintf("INSERT INTO api_test(id, data, value) VALUES (%d, 'test_%.*s', %f)", 
                                  i, (int)sizeof(input->text_data), (char*)input->text_data,
                                  (double)input->double_value / 1000000.0);
        if (sql) {
            rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            sqlite3_free(sql);
        }
    }
    
    // Execute selected VDBE API function simulation
    switch (input->function_selector) {
        case 0: { // sqlite3_data_count equivalent
            rc = sqlite3_prepare_v2(db, "SELECT * FROM api_test", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    volatile int col_count = sqlite3_data_count(stmt);
                    (void)col_count;
                }
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 1: { // sqlite3_stmt_busy equivalent
            rc = sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM api_test", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                volatile int busy_before = sqlite3_stmt_busy(stmt);
                sqlite3_step(stmt);
                volatile int busy_after = sqlite3_stmt_busy(stmt);
                (void)busy_before; (void)busy_after;
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 2: { // sqlite3_stmt_readonly equivalent
            const char *queries[] = {
                "SELECT * FROM api_test",
                "INSERT INTO api_test(id) VALUES (999)",
                "UPDATE api_test SET data = 'updated' WHERE id = 1",
                "DELETE FROM api_test WHERE id = 0"
            };
            
            int query_idx = input->value_type % 4;
            rc = sqlite3_prepare_v2(db, queries[query_idx], -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                volatile int readonly = sqlite3_stmt_readonly(stmt);
                (void)readonly;
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 3: { // sqlite3_stmt_explain equivalent
            rc = sqlite3_prepare_v2(db, "SELECT * FROM api_test WHERE id = ?", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                volatile int explain_mode = sqlite3_stmt_explain(stmt, input->value_type % 3);
                (void)explain_mode;
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 4: { // sqlite3_stmt_isexplain equivalent
            rc = sqlite3_prepare_v2(db, "EXPLAIN SELECT * FROM api_test", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                volatile int is_explain = sqlite3_stmt_isexplain(stmt);
                (void)is_explain;
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 5: { // sqlite3_result_null (via custom function)
            // Test via SELECT with NULL
            rc = sqlite3_prepare_v2(db, "SELECT NULL", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                if (sqlite3_step(stmt) == SQLITE_ROW) {
                    volatile int type = sqlite3_column_type(stmt, 0);
                    (void)type;
                }
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 6: { // sqlite3_result_int equivalent
            char *sql = sqlite3_mprintf("SELECT %d", input->int_value);
            if (sql) {
                rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    if (sqlite3_step(stmt) == SQLITE_ROW) {
                        volatile int result = sqlite3_column_int(stmt, 0);
                        (void)result;
                    }
                    sqlite3_finalize(stmt);
                }
                sqlite3_free(sql);
            }
            break;
        }
        
        case 7: { // sqlite3_result_double equivalent
            double test_double = (double)input->double_value / 1000.0;
            char *sql = sqlite3_mprintf("SELECT %f", test_double);
            if (sql) {
                rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    if (sqlite3_step(stmt) == SQLITE_ROW) {
                        volatile double result = sqlite3_column_double(stmt, 0);
                        (void)result;
                    }
                    sqlite3_finalize(stmt);
                }
                sqlite3_free(sql);
            }
            break;
        }
        
        case 8: { // sqlite3_result_text equivalent
            char text_value[32];
            snprintf(text_value, sizeof(text_value), "text_%.*s_%d", 
                    (int)sizeof(input->text_data), (char*)input->text_data, input->int_value);
            char *sql = sqlite3_mprintf("SELECT '%q'", text_value);
            if (sql) {
                rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    if (sqlite3_step(stmt) == SQLITE_ROW) {
                        const char *result = (const char*)sqlite3_column_text(stmt, 0);
                        if (result) {
                            volatile int len = strlen(result);
                            (void)len;
                        }
                    }
                    sqlite3_finalize(stmt);
                }
                sqlite3_free(sql);
            }
            break;
        }
        
        case 9: { // sqlite3_value_type equivalent
            rc = sqlite3_prepare_v2(db, "SELECT id, data, value FROM api_test LIMIT 1", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                if (sqlite3_step(stmt) == SQLITE_ROW) {
                    for (int i = 0; i < 3; i++) {
                        volatile int type = sqlite3_column_type(stmt, i);
                        (void)type;
                    }
                }
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 10: { // sqlite3_value_int equivalent
            rc = sqlite3_prepare_v2(db, "SELECT id FROM api_test WHERE id = ?", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_bind_int(stmt, 1, input->int_value % 5);
                if (sqlite3_step(stmt) == SQLITE_ROW) {
                    volatile int int_value = sqlite3_column_int(stmt, 0);
                    (void)int_value;
                }
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 11: { // sqlite3_value_double equivalent
            rc = sqlite3_prepare_v2(db, "SELECT value FROM api_test WHERE id = ?", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_bind_int(stmt, 1, input->value_type % 5);
                if (sqlite3_step(stmt) == SQLITE_ROW) {
                    volatile double double_value = sqlite3_column_double(stmt, 0);
                    (void)double_value;
                }
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 12: { // sqlite3_value_text equivalent
            rc = sqlite3_prepare_v2(db, "SELECT data FROM api_test WHERE id = ?", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_bind_int(stmt, 1, input->value_type % 5);
                if (sqlite3_step(stmt) == SQLITE_ROW) {
                    const char *text_value = (const char*)sqlite3_column_text(stmt, 0);
                    if (text_value) {
                        volatile int len = strlen(text_value);
                        (void)len;
                    }
                }
                sqlite3_finalize(stmt);
            }
            break;
        }
    }
    
    // Additional API scenarios based on value_type
    if (input->value_type & 0x01) {
        // Test column information APIs
        rc = sqlite3_prepare_v2(db, "SELECT * FROM api_test LIMIT 1", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            volatile int col_count = sqlite3_column_count(stmt);
            for (int i = 0; i < col_count && i < 5; i++) {
                const char *col_name = sqlite3_column_name(stmt, i);
                if (col_name) {
                    volatile int len = strlen(col_name);
                    (void)len;
                }
            }
            sqlite3_finalize(stmt);
        }
    }
    
    if (input->value_type & 0x02) {
        // Test binding APIs
        rc = sqlite3_prepare_v2(db, "SELECT * FROM api_test WHERE id = ? AND data LIKE ?", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_bind_int(stmt, 1, input->int_value % 5);
            char pattern[16];
            snprintf(pattern, sizeof(pattern), "test_%.*s%%", 3, (char*)input->text_data);
            sqlite3_bind_text(stmt, 2, pattern, -1, SQLITE_STATIC);
            
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                sqlite3_column_int(stmt, 0);
                sqlite3_column_text(stmt, 1);
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