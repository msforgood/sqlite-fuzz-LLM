/*
** High-Impact Operations Functions Harness Implementation
** Target functions: sqlite3BtreeClearTable, sqlite3VdbeSorterInit, sqlite3WhereExprAnalyze,
**                   sqlite3VdbeSorterWrite, sqlite3DbMallocSize, downgradeAllSharedCacheTableLocks
*/
#include <time.h>
#include "high_impact_ops_harness.h"

/* Fuzz sqlite3BtreeClearTable function - Critical table clearing */
int fuzz_sqlite3_btree_clear_table(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < sizeof(BtreeClearTablePacket)) return 0;
    
    const BtreeClearTablePacket *packet = (const BtreeClearTablePacket*)data;
    
    /* Validation checks */
    if (packet->iTable == 0) return 0;
    if (packet->pageCount > 1000000) return 0;
    
    uint8_t scenario = packet->scenario % 12;
    
    switch(scenario) {
        case 0: { /* Basic table clear */
            char *sql = "CREATE TABLE test_clear (id INTEGER PRIMARY KEY, data TEXT)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            for (int i = 1; i <= (packet->pageCount % 100) + 10; i++) {
                char *insertSql = sqlite3_mprintf("INSERT INTO test_clear VALUES (%d, 'data_%d')", i, i);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
            }
            
            char *clearSql = "DELETE FROM test_clear";
            sqlite3_exec(ctx->db, clearSql, NULL, NULL, NULL);
            break;
        }
        
        case 1: { /* Transaction rollback scenario */
            char *sql = "CREATE TABLE test_rollback (id INTEGER PRIMARY KEY, data TEXT)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            sqlite3_exec(ctx->db, "BEGIN TRANSACTION", NULL, NULL, NULL);
            
            for (int i = 0; i < (packet->clearMode % 50) + 20; i++) {
                char *insertSql = sqlite3_mprintf("INSERT INTO test_rollback VALUES (%d, 'rollback_%d')", i, i);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
            }
            
            if (packet->transactionType % 2 == 0) {
                sqlite3_exec(ctx->db, "COMMIT", NULL, NULL, NULL);
                sqlite3_exec(ctx->db, "DELETE FROM test_rollback", NULL, NULL, NULL);
            } else {
                sqlite3_exec(ctx->db, "ROLLBACK", NULL, NULL, NULL);
            }
            break;
        }
        
        case 2: { /* Large table clear */
            char *sql = "CREATE TABLE test_large_clear (id INTEGER, data TEXT, blob_data BLOB)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            int insertCount = (packet->pageCount % 500) + 100;
            for (int i = 0; i < insertCount; i++) {
                char *insertSql = sqlite3_mprintf("INSERT INTO test_large_clear VALUES (%d, 'large_data_%d', ?)", i, i);
                if (insertSql) {
                    sqlite3_stmt *stmt;
                    if (sqlite3_prepare_v2(ctx->db, insertSql, -1, &stmt, NULL) == SQLITE_OK) {
                        sqlite3_bind_blob(stmt, 1, packet->testData, sizeof(packet->testData), SQLITE_STATIC);
                        sqlite3_step(stmt);
                        sqlite3_finalize(stmt);
                    }
                    sqlite3_free(insertSql);
                }
            }
            
            sqlite3_exec(ctx->db, "DELETE FROM test_large_clear", NULL, NULL, NULL);
            break;
        }
        
        case 3: { /* Indexed table clear */
            char *sql = "CREATE TABLE test_indexed_clear (id INTEGER, name TEXT, value INTEGER); "
                       "CREATE INDEX idx_clear_name ON test_indexed_clear(name); "
                       "CREATE INDEX idx_clear_value ON test_indexed_clear(value)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            for (int i = 0; i < (packet->clearMode % 100) + 50; i++) {
                char *insertSql = sqlite3_mprintf("INSERT INTO test_indexed_clear VALUES (%d, 'name_%04d', %u)", 
                                                i, i, packet->testData[i % 6]);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
            }
            
            sqlite3_exec(ctx->db, "DELETE FROM test_indexed_clear", NULL, NULL, NULL);
            break;
        }
        
        case 4: { /* Foreign key constraints */
            char *sql = "PRAGMA foreign_keys=ON; "
                       "CREATE TABLE parent_clear (id INTEGER PRIMARY KEY, name TEXT); "
                       "CREATE TABLE child_clear (id INTEGER PRIMARY KEY, parent_id INTEGER, "
                       "data TEXT, FOREIGN KEY(parent_id) REFERENCES parent_clear(id))";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            for (int i = 1; i <= 20; i++) {
                char *parentSql = sqlite3_mprintf("INSERT INTO parent_clear VALUES (%d, 'parent_%d')", i, i);
                if (parentSql) {
                    sqlite3_exec(ctx->db, parentSql, NULL, NULL, NULL);
                    sqlite3_free(parentSql);
                }
                
                char *childSql = sqlite3_mprintf("INSERT INTO child_clear VALUES (%d, %d, 'child_%d')", i + 100, i, i);
                if (childSql) {
                    sqlite3_exec(ctx->db, childSql, NULL, NULL, NULL);
                    sqlite3_free(childSql);
                }
            }
            
            sqlite3_exec(ctx->db, "DELETE FROM child_clear", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "DELETE FROM parent_clear", NULL, NULL, NULL);
            break;
        }
        
        case 5: { /* Trigger-based clear */
            char *sql = "CREATE TABLE test_trigger_clear (id INTEGER PRIMARY KEY, data TEXT); "
                       "CREATE TABLE clear_log (action TEXT, table_name TEXT, count INTEGER); "
                       "CREATE TRIGGER clear_trigger AFTER DELETE ON test_trigger_clear "
                       "BEGIN INSERT INTO clear_log VALUES ('DELETE', 'test_trigger_clear', 1); END";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            for (int i = 1; i <= 30; i++) {
                char *insertSql = sqlite3_mprintf("INSERT INTO test_trigger_clear VALUES (%d, 'trigger_data_%d')", i, i);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
            }
            
            sqlite3_exec(ctx->db, "DELETE FROM test_trigger_clear", NULL, NULL, NULL);
            break;
        }
        
        default: { /* Concurrent access simulation */
            char *sql = "CREATE TABLE test_concurrent_clear (id INTEGER PRIMARY KEY, data TEXT, timestamp INTEGER)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            for (int i = 0; i < (packet->pageCount % 200) + 50; i++) {
                char *insertSql = sqlite3_mprintf("INSERT INTO test_concurrent_clear VALUES (%d, 'concurrent_%d', %u)", 
                                                i, i, packet->testData[i % 6]);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
            }
            
            sqlite3_exec(ctx->db, "BEGIN IMMEDIATE", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "DELETE FROM test_concurrent_clear", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "COMMIT", NULL, NULL, NULL);
            break;
        }
    }
    
    return 1;
}

/* Fuzz sqlite3VdbeSorterInit function - Critical sorter initialization */
int fuzz_sqlite3_vdbe_sorter_init(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < sizeof(VdbeSorterInitPacket)) return 0;
    
    const VdbeSorterInitPacket *packet = (const VdbeSorterInitPacket*)data;
    
    /* Validation checks */
    if (packet->nField == 0 || packet->nField > 255) return 0;
    if (packet->memLimitKB < 1024 || packet->memLimitKB > 1048576) return 0;
    
    uint8_t scenario = packet->scenario % 10;
    
    switch(scenario) {
        case 0: { /* Basic ORDER BY sorting */
            char *sql = "CREATE TABLE test_sort (id INTEGER, name TEXT, value INTEGER)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            for (int i = 0; i < (packet->nField % 50) + 20; i++) {
                char *insertSql = sqlite3_mprintf("INSERT INTO test_sort VALUES (%d, 'name_%04d', %u)", 
                                                i, i, packet->testData[i % 4]);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
            }
            
            char *sortOrder = (packet->sortOrder % 2 == 0) ? "ASC" : "DESC";
            char *orderSql = sqlite3_mprintf("SELECT * FROM test_sort ORDER BY name %s, value %s", sortOrder, sortOrder);
            if (orderSql) {
                sqlite3_stmt *stmt;
                if (sqlite3_prepare_v2(ctx->db, orderSql, -1, &stmt, NULL) == SQLITE_OK) {
                    while (sqlite3_step(stmt) == SQLITE_ROW) {
                        /* Process sorted results */
                    }
                    sqlite3_finalize(stmt);
                }
                sqlite3_free(orderSql);
            }
            break;
        }
        
        case 1: { /* Large dataset sorting */
            char *sql = "CREATE TABLE test_large_sort (id INTEGER, data TEXT, sort_key BLOB)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            int recordCount = (packet->mxKeySize % 1000) + 500;
            for (int i = 0; i < recordCount; i++) {
                char *insertSql = sqlite3_mprintf("INSERT INTO test_large_sort VALUES (%d, 'large_data_%d', ?)", i, i);
                if (insertSql) {
                    sqlite3_stmt *stmt;
                    if (sqlite3_prepare_v2(ctx->db, insertSql, -1, &stmt, NULL) == SQLITE_OK) {
                        sqlite3_bind_blob(stmt, 1, packet->testData, sizeof(packet->testData), SQLITE_STATIC);
                        sqlite3_step(stmt);
                        sqlite3_finalize(stmt);
                    }
                    sqlite3_free(insertSql);
                }
            }
            
            sqlite3_stmt *stmt;
            if (sqlite3_prepare_v2(ctx->db, "SELECT * FROM test_large_sort ORDER BY sort_key", -1, &stmt, NULL) == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    /* Process large sorted dataset */
                }
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 2: { /* Multi-column sorting */
            char *sql = "CREATE TABLE test_multi_sort (col1 INTEGER, col2 TEXT, col3 REAL, col4 BLOB)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            for (int i = 0; i < (packet->nField % 100) + 30; i++) {
                char *insertSql = sqlite3_mprintf("INSERT INTO test_multi_sort VALUES (%d, 'text_%d', %f, ?)", 
                                                i, i % 50, (double)packet->testData[i % 4] / 1000.0);
                if (insertSql) {
                    sqlite3_stmt *stmt;
                    if (sqlite3_prepare_v2(ctx->db, insertSql, -1, &stmt, NULL) == SQLITE_OK) {
                        sqlite3_bind_blob(stmt, 1, &packet->testData[i % 4], sizeof(uint32_t), SQLITE_STATIC);
                        sqlite3_step(stmt);
                        sqlite3_finalize(stmt);
                    }
                    sqlite3_free(insertSql);
                }
            }
            
            sqlite3_stmt *stmt;
            if (sqlite3_prepare_v2(ctx->db, "SELECT * FROM test_multi_sort ORDER BY col1, col2, col3, col4", -1, &stmt, NULL) == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    /* Process multi-column sort */
                }
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 3: { /* GROUP BY with ORDER BY */
            char *sql = "CREATE TABLE test_group_sort (category TEXT, value INTEGER, data TEXT)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            for (int i = 0; i < 100; i++) {
                char *category = (i % 3 == 0) ? "A" : (i % 3 == 1) ? "B" : "C";
                char *insertSql = sqlite3_mprintf("INSERT INTO test_group_sort VALUES ('%s', %u, 'data_%d')", 
                                                category, packet->testData[i % 4], i);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
            }
            
            sqlite3_stmt *stmt;
            if (sqlite3_prepare_v2(ctx->db, "SELECT category, SUM(value) FROM test_group_sort GROUP BY category ORDER BY SUM(value)", -1, &stmt, NULL) == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    /* Process grouped and sorted results */
                }
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 4: { /* DISTINCT with ORDER BY */
            char *sql = "CREATE TABLE test_distinct_sort (id INTEGER, name TEXT, category TEXT)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            for (int i = 0; i < 150; i++) {
                char *category = (i % 5 == 0) ? "X" : (i % 5 == 1) ? "Y" : (i % 5 == 2) ? "Z" : (i % 5 == 3) ? "W" : "V";
                char *insertSql = sqlite3_mprintf("INSERT INTO test_distinct_sort VALUES (%d, 'name_%d', '%s')", 
                                                i % 30, i, category);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
            }
            
            sqlite3_stmt *stmt;
            if (sqlite3_prepare_v2(ctx->db, "SELECT DISTINCT name, category FROM test_distinct_sort ORDER BY name, category", -1, &stmt, NULL) == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    /* Process distinct sorted results */
                }
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        default: { /* Complex nested sorting */
            char *sql = "CREATE TABLE test_nested_sort (id INTEGER, parent_id INTEGER, level INTEGER, data TEXT)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            for (int i = 0; i < 80; i++) {
                int parent_id = (i == 0) ? 0 : (i % 10);
                int level = (i / 10) + 1;
                char *insertSql = sqlite3_mprintf("INSERT INTO test_nested_sort VALUES (%d, %d, %d, 'nested_data_%d')", 
                                                i, parent_id, level, i);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
            }
            
            sqlite3_stmt *stmt;
            if (sqlite3_prepare_v2(ctx->db, "SELECT * FROM test_nested_sort ORDER BY level, parent_id, id", -1, &stmt, NULL) == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    /* Process hierarchical sorted results */
                }
                sqlite3_finalize(stmt);
            }
            break;
        }
    }
    
    return 1;
}

/* Fuzz sqlite3WhereExprAnalyze function - Critical expression analysis */
int fuzz_sqlite3_where_expr_analyze(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < sizeof(WhereExprAnalyzePacket)) return 0;
    
    const WhereExprAnalyzePacket *packet = (const WhereExprAnalyzePacket*)data;
    
    /* Validation checks */
    if (packet->exprDepth > 50) return 0;
    if (packet->tableCount == 0 || packet->tableCount > 20) return 0;
    
    uint8_t scenario = packet->scenario % 15;
    
    switch(scenario) {
        case 0: { /* Basic WHERE clause analysis */
            char *sql = "CREATE TABLE test_where (id INTEGER, name TEXT, value INTEGER)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            for (int i = 0; i < 50; i++) {
                char *insertSql = sqlite3_mprintf("INSERT INTO test_where VALUES (%d, 'name_%d', %u)", 
                                                i, i, packet->testParams[i % 8]);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
            }
            
            char *whereSql = sqlite3_mprintf("SELECT * FROM test_where WHERE id > %u AND value < %u", 
                                           packet->testParams[0] % 50, packet->testParams[1] % 1000);
            if (whereSql) {
                sqlite3_stmt *stmt;
                if (sqlite3_prepare_v2(ctx->db, whereSql, -1, &stmt, NULL) == SQLITE_OK) {
                    while (sqlite3_step(stmt) == SQLITE_ROW) {
                        /* Process WHERE clause results */
                    }
                    sqlite3_finalize(stmt);
                }
                sqlite3_free(whereSql);
            }
            break;
        }
        
        case 1: { /* Complex expression tree */
            char *sql = "CREATE TABLE test_complex_expr (a INTEGER, b INTEGER, c INTEGER, d TEXT)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            for (int i = 0; i < 40; i++) {
                char *insertSql = sqlite3_mprintf("INSERT INTO test_complex_expr VALUES (%d, %d, %d, 'text_%d')", 
                                                i, i * 2, i * 3, i);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
            }
            
            char *complexSql = sqlite3_mprintf("SELECT * FROM test_complex_expr WHERE "
                                             "(a > %u AND b < %u) OR (c = %u AND d LIKE 'text_%%') OR "
                                             "(a + b > %u AND c - a < %u)", 
                                             packet->testParams[0] % 20, packet->testParams[1] % 50,
                                             packet->testParams[2] % 30, packet->testParams[3] % 100,
                                             packet->testParams[4] % 40);
            if (complexSql) {
                sqlite3_stmt *stmt;
                if (sqlite3_prepare_v2(ctx->db, complexSql, -1, &stmt, NULL) == SQLITE_OK) {
                    while (sqlite3_step(stmt) == SQLITE_ROW) {
                        /* Process complex expression results */
                    }
                    sqlite3_finalize(stmt);
                }
                sqlite3_free(complexSql);
            }
            break;
        }
        
        case 2: { /* Multi-table JOIN expressions */
            char *sql = "CREATE TABLE test_table1 (id INTEGER, name TEXT, value INTEGER); "
                       "CREATE TABLE test_table2 (id INTEGER, ref_id INTEGER, data TEXT)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            for (int i = 0; i < 30; i++) {
                char *insertSql = sqlite3_mprintf("INSERT INTO test_table1 VALUES (%d, 'name_%d', %u)", 
                                                i, i, packet->testParams[i % 8]);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
                
                insertSql = sqlite3_mprintf("INSERT INTO test_table2 VALUES (%d, %d, 'data_%d')", 
                                          i + 100, i, i);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
            }
            
            char *joinSql = sqlite3_mprintf("SELECT t1.*, t2.data FROM test_table1 t1 "
                                          "JOIN test_table2 t2 ON t1.id = t2.ref_id "
                                          "WHERE t1.value > %u AND t2.data LIKE 'data_%%'", 
                                          packet->testParams[0] % 500);
            if (joinSql) {
                sqlite3_stmt *stmt;
                if (sqlite3_prepare_v2(ctx->db, joinSql, -1, &stmt, NULL) == SQLITE_OK) {
                    while (sqlite3_step(stmt) == SQLITE_ROW) {
                        /* Process JOIN expression results */
                    }
                    sqlite3_finalize(stmt);
                }
                sqlite3_free(joinSql);
            }
            break;
        }
        
        case 3: { /* Subquery expressions */
            char *sql = "CREATE TABLE test_outer (id INTEGER, category TEXT, value INTEGER); "
                       "CREATE TABLE test_inner (category TEXT, threshold INTEGER)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            /* Insert test data */
            for (int i = 0; i < 25; i++) {
                char *category = (i % 3 == 0) ? "A" : (i % 3 == 1) ? "B" : "C";
                char *insertSql = sqlite3_mprintf("INSERT INTO test_outer VALUES (%d, '%s', %u)", 
                                                i, category, packet->testParams[i % 8]);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
            }
            
            sqlite3_exec(ctx->db, "INSERT INTO test_inner VALUES ('A', 100)", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "INSERT INTO test_inner VALUES ('B', 200)", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "INSERT INTO test_inner VALUES ('C', 300)", NULL, NULL, NULL);
            
            char *subquerySql = sqlite3_mprintf("SELECT * FROM test_outer WHERE value > "
                                              "(SELECT threshold FROM test_inner WHERE test_inner.category = test_outer.category)");
            if (subquerySql) {
                sqlite3_stmt *stmt;
                if (sqlite3_prepare_v2(ctx->db, subquerySql, -1, &stmt, NULL) == SQLITE_OK) {
                    while (sqlite3_step(stmt) == SQLITE_ROW) {
                        /* Process subquery results */
                    }
                    sqlite3_finalize(stmt);
                }
                sqlite3_free(subquerySql);
            }
            break;
        }
        
        default: { /* Nested function expressions */
            char *sql = "CREATE TABLE test_functions (id INTEGER, text_data TEXT, num_data REAL)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            for (int i = 0; i < 35; i++) {
                char *insertSql = sqlite3_mprintf("INSERT INTO test_functions VALUES (%d, 'function_test_%d', %f)", 
                                                i, i, (double)packet->testParams[i % 8] / 1000.0);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
            }
            
            char *functionSql = sqlite3_mprintf("SELECT * FROM test_functions WHERE "
                                              "LENGTH(text_data) > %u AND ABS(num_data) < %f AND "
                                              "SUBSTR(text_data, 1, %u) = 'function'", 
                                              packet->testParams[0] % 20, 
                                              (double)packet->testParams[1] / 100.0,
                                              packet->testParams[2] % 10);
            if (functionSql) {
                sqlite3_stmt *stmt;
                if (sqlite3_prepare_v2(ctx->db, functionSql, -1, &stmt, NULL) == SQLITE_OK) {
                    while (sqlite3_step(stmt) == SQLITE_ROW) {
                        /* Process function expression results */
                    }
                    sqlite3_finalize(stmt);
                }
                sqlite3_free(functionSql);
            }
            break;
        }
    }
    
    return 1;
}

/* Fuzz sqlite3VdbeSorterWrite function - Critical sorter write */
int fuzz_sqlite3_vdbe_sorter_write(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < sizeof(VdbeSorterWritePacket)) return 0;
    
    const VdbeSorterWritePacket *packet = (const VdbeSorterWritePacket*)data;
    
    /* Validation checks */
    if (packet->recordSize == 0 || packet->recordSize > 1048576) return 0;
    if (packet->sortKeySize == 0) return 0;
    
    uint8_t scenario = packet->scenario % 12;
    
    switch(scenario) {
        case 0: { /* Basic sorter write */
            char *sql = "CREATE TABLE test_sorter_write (key TEXT, data BLOB)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            for (int i = 0; i < (packet->recordSize % 100) + 20; i++) {
                char *insertSql = sqlite3_mprintf("INSERT INTO test_sorter_write VALUES ('key_%04d', ?)", i);
                if (insertSql) {
                    sqlite3_stmt *stmt;
                    if (sqlite3_prepare_v2(ctx->db, insertSql, -1, &stmt, NULL) == SQLITE_OK) {
                        sqlite3_bind_blob(stmt, 1, packet->recordData, sizeof(packet->recordData), SQLITE_STATIC);
                        sqlite3_step(stmt);
                        sqlite3_finalize(stmt);
                    }
                    sqlite3_free(insertSql);
                }
            }
            
            sqlite3_stmt *stmt;
            if (sqlite3_prepare_v2(ctx->db, "SELECT * FROM test_sorter_write ORDER BY key", -1, &stmt, NULL) == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    /* Process sorter write results */
                }
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 1: { /* Variable-length record write */
            char *sql = "CREATE TABLE test_variable_write (id INTEGER, var_data TEXT)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            for (int i = 0; i < 50; i++) {
                int dataSize = (packet->sortKeySize % 100) + 10;
                char *varData = sqlite3_malloc(dataSize + 1);
                if (varData) {
                    memset(varData, 'A' + (i % 26), dataSize);
                    varData[dataSize] = '\0';
                    
                    char *insertSql = sqlite3_mprintf("INSERT INTO test_variable_write VALUES (%d, '%s')", i, varData);
                    if (insertSql) {
                        sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                        sqlite3_free(insertSql);
                    }
                    sqlite3_free(varData);
                }
            }
            
            sqlite3_stmt *stmt;
            if (sqlite3_prepare_v2(ctx->db, "SELECT * FROM test_variable_write ORDER BY LENGTH(var_data), var_data", -1, &stmt, NULL) == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    /* Process variable-length records */
                }
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        case 2: { /* Large record batch write */
            char *sql = "CREATE TABLE test_batch_write (id INTEGER, large_data TEXT, blob_data BLOB)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            sqlite3_exec(ctx->db, "BEGIN TRANSACTION", NULL, NULL, NULL);
            
            int batchSize = (packet->recordSize % 200) + 100;
            for (int i = 0; i < batchSize; i++) {
                char *largeText = sqlite3_malloc(1000);
                if (largeText) {
                    snprintf(largeText, 1000, "large_batch_data_%d_%.*s", i, 
                           (int)(packet->sortKeySize % 50), packet->recordData);
                    
                    char *insertSql = sqlite3_mprintf("INSERT INTO test_batch_write VALUES (%d, '%s', ?)", i, largeText);
                    if (insertSql) {
                        sqlite3_stmt *stmt;
                        if (sqlite3_prepare_v2(ctx->db, insertSql, -1, &stmt, NULL) == SQLITE_OK) {
                            sqlite3_bind_blob(stmt, 1, packet->testParams, sizeof(packet->testParams), SQLITE_STATIC);
                            sqlite3_step(stmt);
                            sqlite3_finalize(stmt);
                        }
                        sqlite3_free(insertSql);
                    }
                    sqlite3_free(largeText);
                }
            }
            
            sqlite3_exec(ctx->db, "COMMIT", NULL, NULL, NULL);
            
            sqlite3_stmt *stmt;
            if (sqlite3_prepare_v2(ctx->db, "SELECT * FROM test_batch_write ORDER BY large_data", -1, &stmt, NULL) == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    /* Process batch write results */
                }
                sqlite3_finalize(stmt);
            }
            break;
        }
        
        default: { /* Compressed record write */
            char *sql = "CREATE TABLE test_compressed_write (id INTEGER, data TEXT, compressed INTEGER)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            for (int i = 0; i < 60; i++) {
                int isCompressed = (packet->compression % 3 == 0) ? 1 : 0;
                char *data = isCompressed ? "compressed_data_pattern_repeat_repeat_repeat" : "normal_data";
                
                char *insertSql = sqlite3_mprintf("INSERT INTO test_compressed_write VALUES (%d, '%s_%d', %d)", 
                                                i, data, i, isCompressed);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
            }
            
            sqlite3_stmt *stmt;
            if (sqlite3_prepare_v2(ctx->db, "SELECT * FROM test_compressed_write ORDER BY compressed, data", -1, &stmt, NULL) == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    /* Process compressed write results */
                }
                sqlite3_finalize(stmt);
            }
            break;
        }
    }
    
    return 1;
}

/* Fuzz sqlite3DbMallocSize function - Critical memory size check */
int fuzz_sqlite3_db_malloc_size(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < sizeof(DbMallocSizePacket)) return 0;
    
    const DbMallocSizePacket *packet = (const DbMallocSizePacket*)data;
    
    /* Validation checks */
    if (packet->allocSize == 0 || packet->allocSize > 1048576) return 0;
    
    uint8_t scenario = packet->scenario % 8;
    
    switch(scenario) {
        case 0: { /* Basic memory allocation size testing */
            char *sql = "CREATE TABLE test_malloc_size (id INTEGER, data TEXT)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            for (int i = 0; i < 20; i++) {
                int allocSize = (packet->allocSize % 1000) + 100;
                char *largeData = sqlite3_malloc(allocSize);
                if (largeData) {
                    memset(largeData, 'X', allocSize - 1);
                    largeData[allocSize - 1] = '\0';
                    
                    char *insertSql = sqlite3_mprintf("INSERT INTO test_malloc_size VALUES (%d, '%s')", i, largeData);
                    if (insertSql) {
                        sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                        sqlite3_free(insertSql);
                    }
                    sqlite3_free(largeData);
                }
            }
            break;
        }
        
        case 1: { /* Memory reallocation testing */
            char *sql = "CREATE TABLE test_realloc (id INTEGER, growing_data TEXT)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            char *growingData = sqlite3_malloc(100);
            if (growingData) {
                strcpy(growingData, "initial");
                
                for (int i = 0; i < 10; i++) {
                    int newSize = 100 + i * (packet->ptrOffset % 100);
                    char *newData = sqlite3_realloc(growingData, newSize);
                    if (newData) {
                        growingData = newData;
                        snprintf(growingData + strlen(growingData), newSize - strlen(growingData), "_grow_%d", i);
                        
                        char *insertSql = sqlite3_mprintf("INSERT INTO test_realloc VALUES (%d, '%s')", i, growingData);
                        if (insertSql) {
                            sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                            sqlite3_free(insertSql);
                        }
                    }
                }
                sqlite3_free(growingData);
            }
            break;
        }
        
        case 2: { /* BLOB allocation testing */
            char *sql = "CREATE TABLE test_blob_malloc (id INTEGER, blob_data BLOB)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            for (int i = 0; i < 15; i++) {
                int blobSize = (packet->allocSize % 500) + 50;
                void *blobData = sqlite3_malloc(blobSize);
                if (blobData) {
                    memset(blobData, i % 256, blobSize);
                    
                    sqlite3_stmt *stmt;
                    if (sqlite3_prepare_v2(ctx->db, "INSERT INTO test_blob_malloc VALUES (?, ?)", -1, &stmt, NULL) == SQLITE_OK) {
                        sqlite3_bind_int(stmt, 1, i);
                        sqlite3_bind_blob(stmt, 2, blobData, blobSize, SQLITE_STATIC);
                        sqlite3_step(stmt);
                        sqlite3_finalize(stmt);
                    }
                    sqlite3_free(blobData);
                }
            }
            break;
        }
        
        default: { /* Memory pressure testing */
            char *sql = "CREATE TABLE test_memory_pressure (id INTEGER, pressure_data TEXT)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            /* Allocate multiple blocks to test memory pressure */
            void *ptrs[20];
            int ptrCount = 0;
            
            for (int i = 0; i < 20; i++) {
                int allocSize = (packet->allocSize % 1000) + (i * 100);
                void *ptr = sqlite3_malloc(allocSize);
                if (ptr) {
                    ptrs[ptrCount++] = ptr;
                    memset(ptr, i % 256, allocSize);
                    
                    char *insertSql = sqlite3_mprintf("INSERT INTO test_memory_pressure VALUES (%d, 'pressure_test_%d')", i, i);
                    if (insertSql) {
                        sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                        sqlite3_free(insertSql);
                    }
                }
            }
            
            /* Free allocated blocks */
            for (int i = 0; i < ptrCount; i++) {
                sqlite3_free(ptrs[i]);
            }
            break;
        }
    }
    
    return 1;
}

/* Fuzz downgradeAllSharedCacheTableLocks function - Critical lock management */
int fuzz_downgrade_all_shared_cache_locks(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < sizeof(DowngradeLocksPacket)) return 0;
    
    const DowngradeLocksPacket *packet = (const DowngradeLocksPacket*)data;
    
    /* Validation checks */
    if (packet->lockCount > 8) return 0;
    
    uint8_t scenario = packet->scenario % 10;
    
    switch(scenario) {
        case 0: { /* Basic shared cache lock testing */
            sqlite3_enable_shared_cache(1);
            
            char *sql = "CREATE TABLE test_shared_locks (id INTEGER PRIMARY KEY, data TEXT)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            for (int i = 0; i < (packet->lockCount % 8) + 10; i++) {
                char *insertSql = sqlite3_mprintf("INSERT INTO test_shared_locks VALUES (%d, 'lock_data_%d')", i, i);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
            }
            
            /* Simulate lock downgrade scenarios */
            sqlite3_exec(ctx->db, "BEGIN IMMEDIATE", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "SELECT COUNT(*) FROM test_shared_locks", NULL, NULL, NULL);
            
            if (packet->transactionState % 2 == 0) {
                sqlite3_exec(ctx->db, "COMMIT", NULL, NULL, NULL);
            } else {
                sqlite3_exec(ctx->db, "ROLLBACK", NULL, NULL, NULL);
            }
            
            sqlite3_enable_shared_cache(0);
            break;
        }
        
        case 1: { /* Multi-table lock scenarios */
            sqlite3_enable_shared_cache(1);
            
            char *sql = "CREATE TABLE lock_table1 (id INTEGER PRIMARY KEY, data1 TEXT); "
                       "CREATE TABLE lock_table2 (id INTEGER PRIMARY KEY, data2 TEXT); "
                       "CREATE TABLE lock_table3 (id INTEGER PRIMARY KEY, data3 TEXT)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            for (int i = 0; i < packet->lockCount + 5; i++) {
                char *insertSql = sqlite3_mprintf("INSERT INTO lock_table1 VALUES (%d, 'data1_%d')", i, i);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
                
                insertSql = sqlite3_mprintf("INSERT INTO lock_table2 VALUES (%d, 'data2_%d')", i, i);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
                
                insertSql = sqlite3_mprintf("INSERT INTO lock_table3 VALUES (%d, 'data3_%d')", i, i);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
            }
            
            sqlite3_exec(ctx->db, "BEGIN", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "SELECT l1.*, l2.*, l3.* FROM lock_table1 l1, lock_table2 l2, lock_table3 l3 WHERE l1.id = l2.id AND l2.id = l3.id", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "COMMIT", NULL, NULL, NULL);
            
            sqlite3_enable_shared_cache(0);
            break;
        }
        
        case 2: { /* Nested transaction lock testing */
            sqlite3_enable_shared_cache(1);
            
            char *sql = "CREATE TABLE test_nested_locks (id INTEGER PRIMARY KEY, data TEXT, version INTEGER)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            for (int i = 0; i < 15; i++) {
                char *insertSql = sqlite3_mprintf("INSERT INTO test_nested_locks VALUES (%d, 'nested_data_%d', 1)", i, i);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
            }
            
            sqlite3_exec(ctx->db, "BEGIN", NULL, NULL, NULL);
            
            char *spName = sqlite3_mprintf("sp_%u", packet->testData[0] % 1000);
            if (spName) {
                char *spSql = sqlite3_mprintf("SAVEPOINT %s", spName);
                if (spSql) {
                    sqlite3_exec(ctx->db, spSql, NULL, NULL, NULL);
                    sqlite3_free(spSql);
                }
                
                char *updateSql = sqlite3_mprintf("UPDATE test_nested_locks SET version = %u WHERE id <= %u", 
                                                packet->testData[1] % 100, packet->lockCount);
                if (updateSql) {
                    sqlite3_exec(ctx->db, updateSql, NULL, NULL, NULL);
                    sqlite3_free(updateSql);
                }
                
                if (packet->transactionState % 2 == 0) {
                    char *releaseSql = sqlite3_mprintf("RELEASE %s", spName);
                    if (releaseSql) {
                        sqlite3_exec(ctx->db, releaseSql, NULL, NULL, NULL);
                        sqlite3_free(releaseSql);
                    }
                } else {
                    char *rollbackSql = sqlite3_mprintf("ROLLBACK TO %s", spName);
                    if (rollbackSql) {
                        sqlite3_exec(ctx->db, rollbackSql, NULL, NULL, NULL);
                        sqlite3_free(rollbackSql);
                    }
                }
                
                sqlite3_free(spName);
            }
            
            sqlite3_exec(ctx->db, "COMMIT", NULL, NULL, NULL);
            sqlite3_enable_shared_cache(0);
            break;
        }
        
        default: { /* Concurrent access lock simulation */
            sqlite3_enable_shared_cache(1);
            
            char *sql = "CREATE TABLE test_concurrent_locks (id INTEGER PRIMARY KEY, data TEXT, lock_type INTEGER)";
            sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
            
            for (int i = 0; i < (packet->lockCount % 8) + 20; i++) {
                int lockType = packet->lockTypes[i % 8];
                char *insertSql = sqlite3_mprintf("INSERT INTO test_concurrent_locks VALUES (%d, 'concurrent_%d', %d)", 
                                                i, i, lockType);
                if (insertSql) {
                    sqlite3_exec(ctx->db, insertSql, NULL, NULL, NULL);
                    sqlite3_free(insertSql);
                }
            }
            
            /* Simulate different lock states */
            for (int i = 0; i < 3; i++) {
                const char *lockMode = (i == 0) ? "DEFERRED" : (i == 1) ? "IMMEDIATE" : "EXCLUSIVE";
                char *beginSql = sqlite3_mprintf("BEGIN %s", lockMode);
                if (beginSql) {
                    sqlite3_exec(ctx->db, beginSql, NULL, NULL, NULL);
                    sqlite3_free(beginSql);
                }
                
                char *selectSql = sqlite3_mprintf("SELECT COUNT(*) FROM test_concurrent_locks WHERE lock_type = %d", i);
                if (selectSql) {
                    sqlite3_exec(ctx->db, selectSql, NULL, NULL, NULL);
                    sqlite3_free(selectSql);
                }
                
                sqlite3_exec(ctx->db, "COMMIT", NULL, NULL, NULL);
            }
            
            sqlite3_enable_shared_cache(0);
            break;
        }
    }
    
    return 1;
}