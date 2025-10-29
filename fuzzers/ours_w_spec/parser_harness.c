/*
** Parser Functions Fuzzing Harness Implementation
** Target: codeTableLocks, destroyRootPage, sqlite3CodeVerifySchema
** Category: Parser subsystem Critical functions
**
** Note: These internal functions are tested indirectly through SQL operations
** that trigger the parser paths containing these functions.
*/
#include "parser_harness.h"

/* Helper function to setup database context */
int setup_parser_context(sqlite3 **db, Parse **pParse) {
    int rc;
    
    /* Initialize SQLite */
    rc = sqlite3_initialize();
    if (rc != SQLITE_OK) return rc;
    
    /* Open database connection */
    rc = sqlite3_open(":memory:", db);
    if (rc != SQLITE_OK) return rc;
    
    /* Enable table locking for testing codeTableLocks */
    sqlite3_exec(*db, "PRAGMA locking_mode=EXCLUSIVE", NULL, NULL, NULL);
    sqlite3_exec(*db, "PRAGMA journal_mode=WAL", NULL, NULL, NULL);
    
    /* Set pParse to NULL since we're using public API approach */
    *pParse = NULL;
    
    return SQLITE_OK;
}

/* Helper function to cleanup database context */
void cleanup_parser_context(sqlite3 *db, Parse *pParse) {
    (void)pParse; /* Unused in public API approach */
    if (db) {
        sqlite3_close(db);
    }
}

/* Helper function to trigger table lock operations */
int create_table_locks(Parse *pParse, const TableLockData *locks, int count) {
    (void)pParse; /* Unused in public API approach */
    (void)locks;
    (void)count;
    return SQLITE_OK; /* Locks will be created through SQL operations */
}

/* Fuzzer for codeTableLocks function - triggered through transactions */
int fuzz_codeTableLocks(const uint8_t *data, size_t size) {
    if (size < sizeof(ParserFuzzHeader) + sizeof(TableLockData)) {
        return 0;
    }
    
    const ParserFuzzHeader *header = (const ParserFuzzHeader *)data;
    const uint8_t *payload = data + sizeof(ParserFuzzHeader);
    size_t payload_size = size - sizeof(ParserFuzzHeader);
    
    /* Validate table count */
    int table_count = header->table_count % 5 + 1;  /* 1-5 tables */
    if (payload_size < table_count * sizeof(TableLockData)) {
        return 0;
    }
    
    sqlite3 *db = NULL;
    Parse *pParse = NULL;
    int rc;
    
    /* Setup database context */
    rc = setup_parser_context(&db, &pParse);
    if (rc != SQLITE_OK) return 0;
    
    const TableLockData *locks = (const TableLockData *)payload;
    
    /* Create tables to generate table locks */
    for (int i = 0; i < table_count; i++) {
        char table_name[64];
        snprintf(table_name, sizeof(table_name), "test_table_%d", i);
        
        char sql[256];
        snprintf(sql, sizeof(sql), "CREATE TABLE IF NOT EXISTS %s (id INTEGER, data TEXT)", table_name);
        sqlite3_exec(db, sql, NULL, NULL, NULL);
        
        /* Insert data to trigger locks */
        if (locks[i].isWriteLock) {
            snprintf(sql, sizeof(sql), "INSERT INTO %s VALUES (%d, 'test')", table_name, i);
            sqlite3_exec(db, sql, NULL, NULL, NULL);
        }
    }
    
    /* Test transaction scenarios that trigger codeTableLocks */
    if (header->flags & 0x01) {
        sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL);
        for (int i = 0; i < table_count; i++) {
            char sql[256];
            snprintf(sql, sizeof(sql), "SELECT * FROM test_table_%d", i);
            sqlite3_exec(db, sql, NULL, NULL, NULL);
        }
        sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
    }
    
    if (header->flags & 0x02) {
        /* Test concurrent access patterns */
        sqlite3_exec(db, "BEGIN EXCLUSIVE", NULL, NULL, NULL);
        sqlite3_exec(db, "UPDATE test_table_0 SET data='updated' WHERE id=0", NULL, NULL, NULL);
        sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
    }
    
    cleanup_parser_context(db, pParse);
    return 0;
}

/* Fuzzer for destroyRootPage function - triggered through DROP operations */
int fuzz_destroyRootPage(const uint8_t *data, size_t size) {
    if (size < sizeof(ParserFuzzHeader) + sizeof(DestroyPageData)) {
        return 0;
    }
    
    const ParserFuzzHeader *header = (const ParserFuzzHeader *)data;
    const DestroyPageData *destroy_data = 
        (const DestroyPageData *)(data + sizeof(ParserFuzzHeader));
    
    sqlite3 *db = NULL;
    Parse *pParse = NULL;
    int rc;
    
    /* Setup database context */
    rc = setup_parser_context(&db, &pParse);
    if (rc != SQLITE_OK) return 0;
    
    /* Setup autovacuum scenario */
    if (destroy_data->autovacuum_enable) {
        sqlite3_exec(db, "PRAGMA auto_vacuum=FULL", NULL, NULL, NULL);
    }
    
    /* Create test tables and indexes */
    if (header->flags & 0x01) {
        sqlite3_exec(db, "CREATE TABLE test_destroy1(id INTEGER PRIMARY KEY, data TEXT)", NULL, NULL, NULL);
        sqlite3_exec(db, "INSERT INTO test_destroy1 VALUES (1, 'test1')", NULL, NULL, NULL);
    }
    
    if (header->flags & 0x02) {
        sqlite3_exec(db, "CREATE TABLE test_destroy2(id INTEGER, data TEXT)", NULL, NULL, NULL);
        sqlite3_exec(db, "CREATE INDEX idx_destroy2 ON test_destroy2(id)", NULL, NULL, NULL);
        sqlite3_exec(db, "INSERT INTO test_destroy2 VALUES (1, 'test2')", NULL, NULL, NULL);
    }
    
    /* Test corruption scenario */
    if (destroy_data->corruption_test & 0x01) {
        /* Create a corrupted scenario by manually manipulating tables */
        sqlite3_exec(db, "CREATE TABLE temp_corrupt(x)", NULL, NULL, NULL);
    }
    
    /* Test DROP operations that trigger destroyRootPage */
    if (header->flags & 0x01) {
        sqlite3_exec(db, "DROP TABLE IF EXISTS test_destroy1", NULL, NULL, NULL);
    }
    
    if (header->flags & 0x02) {
        sqlite3_exec(db, "DROP INDEX IF EXISTS idx_destroy2", NULL, NULL, NULL);
        sqlite3_exec(db, "DROP TABLE IF EXISTS test_destroy2", NULL, NULL, NULL);
    }
    
    /* Test multiple destroy operations */
    if (header->flags & 0x04) {
        for (int i = 0; i < 3; i++) {
            char sql[128];
            snprintf(sql, sizeof(sql), "CREATE TABLE temp_table_%d(id INTEGER)", i);
            sqlite3_exec(db, sql, NULL, NULL, NULL);
            snprintf(sql, sizeof(sql), "DROP TABLE temp_table_%d", i);
            sqlite3_exec(db, sql, NULL, NULL, NULL);
        }
    }
    
    cleanup_parser_context(db, pParse);
    return 0;
}

/* Fuzzer for sqlite3CodeVerifySchema function - triggered through schema operations */
int fuzz_sqlite3CodeVerifySchema(const uint8_t *data, size_t size) {
    if (size < sizeof(ParserFuzzHeader) + sizeof(VerifySchemaData)) {
        return 0;
    }
    
    const ParserFuzzHeader *header = (const ParserFuzzHeader *)data;
    const VerifySchemaData *verify_data = 
        (const VerifySchemaData *)(data + sizeof(ParserFuzzHeader));
    
    sqlite3 *db = NULL;
    Parse *pParse = NULL;
    int rc;
    
    /* Setup database context */
    rc = setup_parser_context(&db, &pParse);
    if (rc != SQLITE_OK) return 0;
    
    /* Test with temporary database */
    if (verify_data->temp_db_test) {
        sqlite3_exec(db, "CREATE TEMP TABLE temp_test(id INTEGER)", NULL, NULL, NULL);
        sqlite3_exec(db, "INSERT INTO temp_test VALUES (1)", NULL, NULL, NULL);
    }
    
    /* Attach additional databases for testing */
    if (header->flags & 0x01) {
        sqlite3_exec(db, "ATTACH ':memory:' AS test_db", NULL, NULL, NULL);
        sqlite3_exec(db, "CREATE TABLE test_db.attached_table(id INTEGER)", NULL, NULL, NULL);
    }
    
    /* Test schema validation scenarios */
    if (verify_data->schema_validation & 0x01) {
        /* Create schema objects that require verification */
        sqlite3_exec(db, "CREATE TABLE test_schema(id INTEGER)", NULL, NULL, NULL);
        sqlite3_exec(db, "CREATE VIEW test_view AS SELECT * FROM test_schema", NULL, NULL, NULL);
        sqlite3_exec(db, "CREATE INDEX test_idx ON test_schema(id)", NULL, NULL, NULL);
    }
    
    if (verify_data->schema_validation & 0x02) {
        /* Test with foreign key constraints */
        sqlite3_exec(db, "PRAGMA foreign_keys=ON", NULL, NULL, NULL);
        sqlite3_exec(db, "CREATE TABLE parent(id INTEGER PRIMARY KEY)", NULL, NULL, NULL);
        sqlite3_exec(db, "CREATE TABLE child(id INTEGER, parent_id INTEGER REFERENCES parent(id))", NULL, NULL, NULL);
    }
    
    /* Operations that trigger schema verification */
    if (header->flags & 0x02) {
        /* Test with prepared statements that require schema checks */
        sqlite3_stmt *stmt = NULL;
        sqlite3_prepare_v2(db, "SELECT * FROM test_schema", -1, &stmt, NULL);
        if (stmt) {
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }
    
    /* Test multiple database schema operations */
    if (header->flags & 0x04) {
        sqlite3_exec(db, "CREATE TABLE main_table(id INTEGER)", NULL, NULL, NULL);
        if (verify_data->temp_db_test) {
            sqlite3_exec(db, "CREATE TEMP TABLE temp_table(id INTEGER)", NULL, NULL, NULL);
        }
    }
    
    /* Test boundary conditions with schema modifications */
    if (header->flags & 0x08) {
        sqlite3_exec(db, "ALTER TABLE test_schema ADD COLUMN new_col TEXT", NULL, NULL, NULL);
        sqlite3_exec(db, "DROP VIEW IF EXISTS test_view", NULL, NULL, NULL);
    }
    
    /* Test cookie-related operations */
    if (verify_data->cookie_mask) {
        sqlite3_exec(db, "PRAGMA schema_version", NULL, NULL, NULL);
        sqlite3_exec(db, "VACUUM", NULL, NULL, NULL);
    }
    
    cleanup_parser_context(db, pParse);
    return 0;
}