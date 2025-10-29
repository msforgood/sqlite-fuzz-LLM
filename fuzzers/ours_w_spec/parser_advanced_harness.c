/*
** Parser Advanced Functions Harness Implementation
** Targets: sqlite3CodeVerifyNamedSchema, sqlite3CodeVerifySchemaAtToplevel, 
**          sqlite3CommitInternalChanges, sqlite3FreeIndex
** Specification-based fuzzing implementation for SQLite3 v3.51.0
*/

#include "parser_advanced_harness.h"
#include "sqlite3.h"

/*
** Fuzzing harness for sqlite3CodeVerifyNamedSchema function
** FC: parser_001
*/
int fuzz_parser_verify_named_schema(FuzzCtx *pCtx, const ParserVerifyNamedSchemaPacket *pPacket) {
    /* Validation according to sqlite3CodeVerifyNamedSchema_spec.json */
    if (pPacket->dbCount > 15) return 0;
    if (pPacket->nameLength > 1023) return 0;
    
    sqlite3 *db = NULL;
    int rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) return 0;
    
    /* Test different schema verification scenarios */
    switch (pPacket->scenario & 0x7) {
        case PARSER_ADV_SCENARIO_NORMAL: {
            /* Normal schema verification */
            sqlite3_exec(db, "CREATE TABLE t1(id INTEGER, data TEXT)", NULL, NULL, NULL);
            sqlite3_exec(db, "CREATE INDEX idx1 ON t1(id)", NULL, NULL, NULL);
            
            /* Create named database for verification */
            char *dbName = sqlite3_mprintf("test_%.*s", 
                                          (int)(pPacket->nameLength & 0xFF), pPacket->testData);
            char *sql = sqlite3_mprintf("ATTACH DATABASE ':memory:' AS %s", dbName);
            sqlite3_exec(db, sql, NULL, NULL, NULL);
            sqlite3_free(sql);
            
            /* Test schema verification through PRAGMA */
            sql = sqlite3_mprintf("PRAGMA %s.schema_version", dbName);
            sqlite3_exec(db, sql, NULL, NULL, NULL);
            sqlite3_free(sql);
            sqlite3_free(dbName);
            break;
        }
        case PARSER_ADV_SCENARIO_MULTI_DB: {
            /* Multiple database schema verification */
            sqlite3_exec(db, "CREATE TABLE main_table(x)", NULL, NULL, NULL);
            
            for (int i = 0; i < (pPacket->dbCount & 0x7); i++) {
                char *dbName = sqlite3_mprintf("db_%.*s_%d", 
                                              8, pPacket->testData, i);
                char *sql = sqlite3_mprintf("ATTACH DATABASE ':memory:' AS %s", dbName);
                sqlite3_exec(db, sql, NULL, NULL, NULL);
                sqlite3_free(sql);
                
                /* Create objects in attached database */
                sql = sqlite3_mprintf("CREATE TABLE %s.t_%d(id INTEGER)", dbName, i);
                sqlite3_exec(db, sql, NULL, NULL, NULL);
                sqlite3_free(sql);
                sqlite3_free(dbName);
            }
            
            /* Verify all schemas */
            sqlite3_exec(db, "PRAGMA schema_version", NULL, NULL, NULL);
            break;
        }
        case PARSER_ADV_SCENARIO_TEMP_DB: {
            /* Temporary database schema verification */
            sqlite3_exec(db, "CREATE TEMP TABLE temp_table(x INTEGER)", NULL, NULL, NULL);
            sqlite3_exec(db, "CREATE TEMP INDEX temp_idx ON temp_table(x)", NULL, NULL, NULL);
            
            /* Test temp database schema operations */
            sqlite3_exec(db, "PRAGMA temp.schema_version", NULL, NULL, NULL);
            sqlite3_exec(db, "INSERT INTO temp_table VALUES(1)", NULL, NULL, NULL);
            break;
        }
        case PARSER_ADV_SCENARIO_SCHEMA: {
            /* Schema change verification */
            sqlite3_exec(db, "CREATE TABLE schema_test(a, b, c)", NULL, NULL, NULL);
            sqlite3_exec(db, "ALTER TABLE schema_test ADD COLUMN d INTEGER", NULL, NULL, NULL);
            
            /* Force schema verification */
            sqlite3_exec(db, "PRAGMA schema_version", NULL, NULL, NULL);
            sqlite3_exec(db, "SELECT * FROM schema_test", NULL, NULL, NULL);
            break;
        }
        case PARSER_ADV_SCENARIO_ATTACH: {
            /* Attach/detach schema verification */
            char *attachDb = sqlite3_mprintf("attach_%.*s", 
                                           10, pPacket->testData);
            char *sql = sqlite3_mprintf("ATTACH DATABASE ':memory:' AS %s", attachDb);
            sqlite3_exec(db, sql, NULL, NULL, NULL);
            sqlite3_free(sql);
            
            /* Create and verify schema in attached database */
            sql = sqlite3_mprintf("CREATE TABLE %s.attach_test(data TEXT)", attachDb);
            sqlite3_exec(db, sql, NULL, NULL, NULL);
            sqlite3_free(sql);
            
            sql = sqlite3_mprintf("DETACH DATABASE %s", attachDb);
            sqlite3_exec(db, sql, NULL, NULL, NULL);
            sqlite3_free(sql);
            sqlite3_free(attachDb);
            break;
        }
        default: {
            /* Mixed scenarios */
            sqlite3_exec(db, "CREATE TABLE mixed(data)", NULL, NULL, NULL);
            sqlite3_exec(db, "PRAGMA schema_version", NULL, NULL, NULL);
            break;
        }
    }
    
    /* Test corruption scenarios */
    if (pPacket->corruption_seed & 0x1) {
        sqlite3_exec(db, "PRAGMA integrity_check", NULL, NULL, NULL);
    }
    
    sqlite3_close(db);
    return 0;
}

/*
** Fuzzing harness for sqlite3CodeVerifySchemaAtToplevel function
** FC: parser_002
*/
int fuzz_parser_verify_schema_toplevel(FuzzCtx *pCtx, const ParserVerifyToplevelPacket *pPacket) {
    /* Validation according to sqlite3CodeVerifySchemaAtToplevel_spec.json */
    if (pPacket->dbIndex > 15) return 0;
    if (pPacket->cookieMask > 65535) return 0;
    
    sqlite3 *db = NULL;
    int rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) return 0;
    
    /* Test different toplevel schema verification scenarios */
    switch (pPacket->scenario & 0x7) {
        case PARSER_ADV_SCENARIO_NORMAL: {
            /* Normal toplevel verification */
            sqlite3_exec(db, "CREATE TABLE toplevel_test(id INTEGER)", NULL, NULL, NULL);
            sqlite3_exec(db, "CREATE VIEW v1 AS SELECT * FROM toplevel_test", NULL, NULL, NULL);
            
            /* Test schema verification through nested operations */
            sqlite3_exec(db, "BEGIN", NULL, NULL, NULL);
            sqlite3_exec(db, "INSERT INTO toplevel_test VALUES(1)", NULL, NULL, NULL);
            sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
            break;
        }
        case PARSER_ADV_SCENARIO_TEMP_DB: {
            /* Temporary database toplevel verification */
            sqlite3_exec(db, "CREATE TEMP TABLE temp_toplevel(x)", NULL, NULL, NULL);
            
            /* Test temp database operations that trigger toplevel verification */
            sqlite3_exec(db, "CREATE TEMP TRIGGER temp_trig AFTER INSERT ON temp_toplevel BEGIN UPDATE temp_toplevel SET x = x + 1; END", NULL, NULL, NULL);
            sqlite3_exec(db, "INSERT INTO temp_toplevel VALUES(100)", NULL, NULL, NULL);
            break;
        }
        case PARSER_ADV_SCENARIO_MULTI_DB: {
            /* Multiple database toplevel verification */
            char *dbName = sqlite3_mprintf("toplevel_%.*s", 
                                          8, pPacket->testData);
            char *sql = sqlite3_mprintf("ATTACH DATABASE ':memory:' AS %s", dbName);
            sqlite3_exec(db, sql, NULL, NULL, NULL);
            sqlite3_free(sql);
            
            /* Create cross-database operations */
            sql = sqlite3_mprintf("CREATE TABLE %s.cross_ref(ref_id INTEGER)", dbName);
            sqlite3_exec(db, sql, NULL, NULL, NULL);
            sqlite3_free(sql);
            
            sqlite3_exec(db, "CREATE TABLE main_ref(id INTEGER)", NULL, NULL, NULL);
            sqlite3_free(dbName);
            break;
        }
        case PARSER_ADV_SCENARIO_SCHEMA: {
            /* Schema change toplevel verification */
            sqlite3_exec(db, "CREATE TABLE schema_toplevel(a INTEGER)", NULL, NULL, NULL);
            sqlite3_exec(db, "CREATE TRIGGER schema_trig BEFORE UPDATE ON schema_toplevel BEGIN SELECT RAISE(ABORT, 'test'); END", NULL, NULL, NULL);
            
            /* Test schema modifications */
            sqlite3_exec(db, "DROP TRIGGER schema_trig", NULL, NULL, NULL);
            sqlite3_exec(db, "ALTER TABLE schema_toplevel ADD COLUMN b TEXT", NULL, NULL, NULL);
            break;
        }
        default: {
            /* Basic toplevel testing */
            sqlite3_exec(db, "CREATE TABLE basic_toplevel(data)", NULL, NULL, NULL);
            sqlite3_exec(db, "INSERT INTO basic_toplevel VALUES('test')", NULL, NULL, NULL);
            break;
        }
    }
    
    /* Test corruption scenarios */
    if (pPacket->corruption_flags & 0x1) {
        sqlite3_exec(db, "PRAGMA quick_check", NULL, NULL, NULL);
    }
    
    sqlite3_close(db);
    return 0;
}

/*
** Fuzzing harness for sqlite3CommitInternalChanges function
** FC: parser_003
*/
int fuzz_parser_commit_internal_changes(FuzzCtx *pCtx, const ParserCommitChangesPacket *pPacket) {
    /* Validation according to sqlite3CommitInternalChanges_spec.json */
    if (pPacket->mDbFlags > 4294967295U) return 0;
    
    sqlite3 *db = NULL;
    int rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) return 0;
    
    /* Test different commit internal changes scenarios */
    switch (pPacket->scenario & 0x7) {
        case PARSER_ADV_SCENARIO_NORMAL: {
            /* Normal commit scenario */
            sqlite3_exec(db, "CREATE TABLE commit_test(id INTEGER, data TEXT)", NULL, NULL, NULL);
            sqlite3_exec(db, "BEGIN", NULL, NULL, NULL);
            
            for (int i = 0; i < 5; i++) {
                char *sql = sqlite3_mprintf("INSERT INTO commit_test VALUES(%d, '%.*s_%d')", 
                                           i, 8, pPacket->testData, i);
                sqlite3_exec(db, sql, NULL, NULL, NULL);
                sqlite3_free(sql);
            }
            
            sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
            break;
        }
        case PARSER_ADV_SCENARIO_SCHEMA: {
            /* Schema change commit scenario */
            sqlite3_exec(db, "CREATE TABLE schema_commit(a INTEGER)", NULL, NULL, NULL);
            sqlite3_exec(db, "BEGIN", NULL, NULL, NULL);
            
            /* Schema changes within transaction */
            sqlite3_exec(db, "CREATE INDEX idx_commit ON schema_commit(a)", NULL, NULL, NULL);
            sqlite3_exec(db, "CREATE TRIGGER trig_commit AFTER INSERT ON schema_commit BEGIN UPDATE schema_commit SET a = a + 1; END", NULL, NULL, NULL);
            
            sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
            break;
        }
        case PARSER_ADV_SCENARIO_ATTACH: {
            /* Attached database commit scenario */
            char *attachDb = sqlite3_mprintf("commit_%.*s", 
                                           6, pPacket->testData);
            char *sql = sqlite3_mprintf("ATTACH DATABASE ':memory:' AS %s", attachDb);
            sqlite3_exec(db, sql, NULL, NULL, NULL);
            sqlite3_free(sql);
            
            sqlite3_exec(db, "BEGIN", NULL, NULL, NULL);
            
            /* Cross-database operations */
            sql = sqlite3_mprintf("CREATE TABLE %s.attach_commit(data TEXT)", attachDb);
            sqlite3_exec(db, sql, NULL, NULL, NULL);
            sqlite3_free(sql);
            
            sqlite3_exec(db, "CREATE TABLE main_commit(ref INTEGER)", NULL, NULL, NULL);
            sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
            sqlite3_free(attachDb);
            break;
        }
        case PARSER_ADV_SCENARIO_MEMORY: {
            /* Memory management commit scenario */
            sqlite3_exec(db, "CREATE TABLE memory_commit(large_data TEXT)", NULL, NULL, NULL);
            sqlite3_exec(db, "BEGIN", NULL, NULL, NULL);
            
            /* Large data operations */
            for (int i = 0; i < 10; i++) {
                char *largeData = sqlite3_mprintf("%.*s%.*s%.*s", 
                                                 4, pPacket->testData,
                                                 4, pPacket->testData + 4,
                                                 4, pPacket->testData + 8);
                char *sql = sqlite3_mprintf("INSERT INTO memory_commit VALUES('%s_%d')", largeData, i);
                sqlite3_exec(db, sql, NULL, NULL, NULL);
                sqlite3_free(sql);
                sqlite3_free(largeData);
            }
            
            sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
            break;
        }
        default: {
            /* Basic commit testing */
            sqlite3_exec(db, "CREATE TABLE basic_commit(x)", NULL, NULL, NULL);
            sqlite3_exec(db, "BEGIN", NULL, NULL, NULL);
            sqlite3_exec(db, "INSERT INTO basic_commit VALUES('test')", NULL, NULL, NULL);
            sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
            break;
        }
    }
    
    /* Test corruption scenarios */
    if (pPacket->corruption_test & 0x1) {
        sqlite3_exec(db, "PRAGMA integrity_check", NULL, NULL, NULL);
    }
    
    sqlite3_close(db);
    return 0;
}

/*
** Fuzzing harness for sqlite3FreeIndex function
** FC: parser_004
*/
int fuzz_parser_free_index(FuzzCtx *pCtx, const ParserFreeIndexPacket *pPacket) {
    /* Validation according to sqlite3FreeIndex_spec.json */
    if (pPacket->indexSize > 1000000) return 0;
    if (pPacket->columnCount > 2000) return 0;
    
    sqlite3 *db = NULL;
    int rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) return 0;
    
    /* Test different index freeing scenarios */
    switch (pPacket->scenario & 0x7) {
        case PARSER_ADV_SCENARIO_NORMAL: {
            /* Normal index creation and deletion */
            sqlite3_exec(db, "CREATE TABLE index_test(id INTEGER, name TEXT, value REAL)", NULL, NULL, NULL);
            
            unsigned colCount = (pPacket->columnCount & 0x7) + 1;
            for (unsigned i = 0; i < colCount; i++) {
                char *idxName = sqlite3_mprintf("idx_%.*s_%u", 
                                              8, pPacket->testData, i);
                char *sql = sqlite3_mprintf("CREATE INDEX %s ON index_test(id, name)", idxName);
                sqlite3_exec(db, sql, NULL, NULL, NULL);
                sqlite3_free(sql);
                
                /* Drop index to trigger sqlite3FreeIndex */
                sql = sqlite3_mprintf("DROP INDEX %s", idxName);
                sqlite3_exec(db, sql, NULL, NULL, NULL);
                sqlite3_free(sql);
                sqlite3_free(idxName);
            }
            break;
        }
        case PARSER_ADV_SCENARIO_INDEX: {
            /* Complex index scenarios */
            sqlite3_exec(db, "CREATE TABLE complex_index(a INTEGER, b TEXT, c REAL, d BLOB)", NULL, NULL, NULL);
            
            /* Create various index types */
            sqlite3_exec(db, "CREATE INDEX idx_single ON complex_index(a)", NULL, NULL, NULL);
            sqlite3_exec(db, "CREATE INDEX idx_multi ON complex_index(a, b, c)", NULL, NULL, NULL);
            sqlite3_exec(db, "CREATE UNIQUE INDEX idx_unique ON complex_index(b)", NULL, NULL, NULL);
            
            /* Partial index */
            char *sql = sqlite3_mprintf("CREATE INDEX idx_partial ON complex_index(a) WHERE b = '%.*s'", 
                                       10, pPacket->testData);
            sqlite3_exec(db, sql, NULL, NULL, NULL);
            sqlite3_free(sql);
            
            /* Drop all indexes */
            sqlite3_exec(db, "DROP INDEX idx_single", NULL, NULL, NULL);
            sqlite3_exec(db, "DROP INDEX idx_multi", NULL, NULL, NULL);
            sqlite3_exec(db, "DROP INDEX idx_unique", NULL, NULL, NULL);
            sqlite3_exec(db, "DROP INDEX idx_partial", NULL, NULL, NULL);
            break;
        }
        case PARSER_ADV_SCENARIO_MEMORY: {
            /* Memory-intensive index operations */
            sqlite3_exec(db, "CREATE TABLE memory_index(large_col TEXT)", NULL, NULL, NULL);
            
            /* Create index with large data */
            sqlite3_exec(db, "CREATE INDEX idx_memory ON memory_index(large_col)", NULL, NULL, NULL);
            
            /* Insert large data to exercise index */
            for (int i = 0; i < 5; i++) {
                char *largeText = sqlite3_mprintf("%.*s%.*s%.*s_%d", 
                                                 6, pPacket->testData,
                                                 6, pPacket->testData + 6,
                                                 6, pPacket->testData + 12, i);
                char *sql = sqlite3_mprintf("INSERT INTO memory_index VALUES('%s')", largeText);
                sqlite3_exec(db, sql, NULL, NULL, NULL);
                sqlite3_free(sql);
                sqlite3_free(largeText);
            }
            
            sqlite3_exec(db, "DROP INDEX idx_memory", NULL, NULL, NULL);
            break;
        }
        case PARSER_ADV_SCENARIO_ATTACH: {
            /* Attached database index operations */
            char *attachDb = sqlite3_mprintf("idx_%.*s", 
                                           8, pPacket->testData);
            char *sql = sqlite3_mprintf("ATTACH DATABASE ':memory:' AS %s", attachDb);
            sqlite3_exec(db, sql, NULL, NULL, NULL);
            sqlite3_free(sql);
            
            /* Create table and index in attached database */
            sql = sqlite3_mprintf("CREATE TABLE %s.attach_index(data TEXT)", attachDb);
            sqlite3_exec(db, sql, NULL, NULL, NULL);
            sqlite3_free(sql);
            
            sql = sqlite3_mprintf("CREATE INDEX %s.idx_attach ON attach_index(data)", attachDb);
            sqlite3_exec(db, sql, NULL, NULL, NULL);
            sqlite3_free(sql);
            
            /* Drop index in attached database */
            sql = sqlite3_mprintf("DROP INDEX %s.idx_attach", attachDb);
            sqlite3_exec(db, sql, NULL, NULL, NULL);
            sqlite3_free(sql);
            sqlite3_free(attachDb);
            break;
        }
        default: {
            /* Basic index testing */
            sqlite3_exec(db, "CREATE TABLE basic_index(x)", NULL, NULL, NULL);
            sqlite3_exec(db, "CREATE INDEX idx_basic ON basic_index(x)", NULL, NULL, NULL);
            sqlite3_exec(db, "DROP INDEX idx_basic", NULL, NULL, NULL);
            break;
        }
    }
    
    /* Test corruption scenarios */
    if (pPacket->corruption_mask & 0x1) {
        sqlite3_exec(db, "PRAGMA integrity_check", NULL, NULL, NULL);
    }
    
    sqlite3_close(db);
    return 0;
}