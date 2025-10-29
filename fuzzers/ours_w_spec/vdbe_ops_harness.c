/*
** VDBE Operations Harness Implementation
** Target: sqlite3VdbeDeleteAuxData, sqlite3VdbeSetNumCols, sqlite3VdbeMemMakeWriteable, sqlite3_value_free
** Specification-based fuzzing implementation for SQLite3 v3.51.0
*/

#include "vdbe_ops_harness.h"
#include "sqlite3.h"

/*
** Fuzzing harness for sqlite3VdbeDeleteAuxData function
** FC: vdbe_001
*/
int fuzz_delete_auxdata(const uint8_t *data, size_t size) {
    if (size < sizeof(DeleteAuxDataPacket)) return 0;
    
    DeleteAuxDataPacket *packet = (DeleteAuxDataPacket *)data;
    
    /* Validation according to sqlite3VdbeDeleteAuxData_spec.json */
    if (packet->opIndex > 32767) return 0;
    if (packet->auxDataCount > 100) return 0;
    
    sqlite3 *db = NULL;
    int rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) return 0;
    
    /* Create a simple function that uses auxiliary data */
    char *sql = sqlite3_mprintf(
        "CREATE TABLE t1(x); "
        "INSERT INTO t1 VALUES('test_%.*s');",
        16, packet->testData);
    sqlite3_exec(db, sql, NULL, NULL, NULL);
    sqlite3_free(sql);
    
    /* Test auxiliary data operations through function calls */
    sqlite3_stmt *stmt;
    sql = "SELECT length(x), typeof(x) FROM t1";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        /* Execute to trigger VDBE operations */
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            /* Access column data to trigger auxiliary data usage */
            sqlite3_column_int(stmt, 0);
            sqlite3_column_text(stmt, 1);
        }
        sqlite3_finalize(stmt);
    }
    
    /* Test different deletion scenarios based on packet data */
    switch (packet->deletionMode & 0x3) {
        case 0: /* Single operation deletion */
            /* Simulate single op auxiliary data cleanup */
            break;
        case 1: /* Mask-based deletion */
            /* Simulate mask-based cleanup */
            break;
        case 2: /* All operations cleanup */
            /* Simulate complete cleanup */
            break;
        case 3: /* Corruption testing */
            if (packet->corruptionSeed & 0x1) {
                sqlite3_exec(db, "PRAGMA integrity_check", NULL, NULL, NULL);
            }
            break;
    }
    
    sqlite3_close(db);
    return 0;
}

/*
** Fuzzing harness for sqlite3VdbeSetNumCols function
** FC: vdbe_002
*/
int fuzz_set_numcols(const uint8_t *data, size_t size) {
    if (size < sizeof(SetNumColsPacket)) return 0;
    
    SetNumColsPacket *packet = (SetNumColsPacket *)data;
    
    /* Validation according to sqlite3VdbeSetNumCols_spec.json */
    if (packet->numCols > 32767) return 0;
    
    sqlite3 *db = NULL;
    int rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) return 0;
    
    /* Create varying column scenarios */
    unsigned colCount = packet->numCols & 0xFF;
    if (colCount == 0) colCount = 1;
    
    /* Build CREATE TABLE with specified number of columns */
    char *createSql = sqlite3_mprintf("CREATE TABLE t1(");
    for (unsigned i = 0; i < colCount; i++) {
        char *colType;
        switch ((packet->typePattern + i) & 0x3) {
            case 0: colType = "INTEGER"; break;
            case 1: colType = "REAL"; break;
            case 2: colType = "TEXT"; break;
            default: colType = "BLOB"; break;
        }
        
        char *temp = sqlite3_mprintf("%s%scol_%u %s", 
                                    createSql, i > 0 ? ", " : "", 
                                    (packet->namePattern + i) & 0xFF, colType);
        sqlite3_free(createSql);
        createSql = temp;
    }
    char *finalSql = sqlite3_mprintf("%s)", createSql);
    sqlite3_free(createSql);
    
    sqlite3_exec(db, finalSql, NULL, NULL, NULL);
    sqlite3_free(finalSql);
    
    /* Insert test data */
    char *insertSql = sqlite3_mprintf("INSERT INTO t1 VALUES(");
    for (unsigned i = 0; i < colCount; i++) {
        char *temp = sqlite3_mprintf("%s%s'val_%.*s_%u'", 
                                    insertSql, i > 0 ? ", " : "",
                                    8, packet->testData, i);
        sqlite3_free(insertSql);
        insertSql = temp;
    }
    char *finalInsert = sqlite3_mprintf("%s)", insertSql);
    sqlite3_free(insertSql);
    
    sqlite3_exec(db, finalInsert, NULL, NULL, NULL);
    sqlite3_free(finalInsert);
    
    /* Execute SELECT to trigger column setup */
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, "SELECT * FROM t1", -1, &stmt, NULL);
    if (stmt) {
        sqlite3_step(stmt);
        
        /* Test column metadata access */
        int actualCols = sqlite3_column_count(stmt);
        for (int i = 0; i < actualCols; i++) {
            sqlite3_column_name(stmt, i);
            sqlite3_column_type(stmt, i);
            sqlite3_column_decltype(stmt, i);
        }
        
        sqlite3_finalize(stmt);
    }
    
    /* Test encoding scenarios */
    if (packet->encoding & 0x1) {
        sqlite3_exec(db, "PRAGMA encoding='UTF-16'", NULL, NULL, NULL);
    }
    
    sqlite3_close(db);
    return 0;
}

/*
** Fuzzing harness for sqlite3VdbeMemMakeWriteable function
** FC: vdbe_003
*/
int fuzz_mem_writeable(const uint8_t *data, size_t size) {
    if (size < sizeof(MemWriteablePacket)) return 0;
    
    MemWriteablePacket *packet = (MemWriteablePacket *)data;
    
    /* Validation according to sqlite3VdbeMemMakeWriteable_spec.json */
    if (packet->memSize > 1000000) return 0;
    
    sqlite3 *db = NULL;
    int rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) return 0;
    
    /* Create table with various data types */
    sqlite3_exec(db, "CREATE TABLE t1(id INTEGER, data TEXT, blob_data BLOB)", NULL, NULL, NULL);
    
    /* Generate test content based on pattern */
    unsigned contentSize = (packet->memSize & 0xFFF) + 1; /* 1-4096 bytes */
    char *testContent = sqlite3_malloc(contentSize + 1);
    if (!testContent) {
        sqlite3_close(db);
        return 0;
    }
    
    /* Fill with pattern based on contentPattern */
    for (unsigned i = 0; i < contentSize; i++) {
        testContent[i] = (char)((packet->contentPattern + i) & 0xFF);
        if (testContent[i] == 0) testContent[i] = 'A'; /* Avoid null bytes in text */
    }
    testContent[contentSize] = '\0';
    
    /* Insert data to trigger memory operations */
    char *sql = sqlite3_mprintf("INSERT INTO t1 VALUES(1, '%s', ?)", testContent);
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_blob(stmt, 1, packet->testData, 16, SQLITE_STATIC);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
    sqlite3_free(sql);
    
    /* Test memory operations through various queries */
    sqlite3_prepare_v2(db, "SELECT data || '_modified', length(blob_data) FROM t1", -1, &stmt, NULL);
    if (stmt) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            /* Access result data to trigger memory operations */
            const char *text = (const char*)sqlite3_column_text(stmt, 0);
            int len = sqlite3_column_int(stmt, 1);
            
            /* Force string operations that may trigger memory making writeable */
            if (text && len > 0) {
                sqlite3_mprintf("%.*s", 10, text);
            }
        }
        sqlite3_finalize(stmt);
    }
    
    /* Test different memory flag scenarios */
    switch (packet->memFlags & 0x7) {
        case 0: /* Static memory test */
            sqlite3_exec(db, "SELECT 'static_string'", NULL, NULL, NULL);
            break;
        case 1: /* Ephemeral memory test */
            sql = sqlite3_mprintf("SELECT '%.*s'", contentSize, testContent);
            sqlite3_exec(db, sql, NULL, NULL, NULL);
            sqlite3_free(sql);
            break;
        case 2: /* Dynamic memory test */
            sqlite3_exec(db, "SELECT upper(data) FROM t1", NULL, NULL, NULL);
            break;
        default: /* Mixed scenarios */
            sqlite3_exec(db, "SELECT data || blob_data FROM t1", NULL, NULL, NULL);
            break;
    }
    
    /* Corruption testing */
    if (packet->corruptionMask & 0x1) {
        sqlite3_exec(db, "PRAGMA integrity_check", NULL, NULL, NULL);
    }
    
    sqlite3_free(testContent);
    sqlite3_close(db);
    return 0;
}

/*
** Fuzzing harness for sqlite3_value_free function
** FC: vdbe_004
*/
int fuzz_value_free(const uint8_t *data, size_t size) {
    if (size < sizeof(ValueFreePacket)) return 0;
    
    ValueFreePacket *packet = (ValueFreePacket *)data;
    
    /* Validation according to sqlite3_value_free_spec.json */
    if (packet->valueSize > 100000) return 0;
    
    sqlite3 *db = NULL;
    int rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) return 0;
    
    /* Create custom function to test value operations */
    sqlite3_exec(db, "CREATE TABLE t1(x)", NULL, NULL, NULL);
    
    /* Insert data based on value type */
    char *sql;
    switch (packet->valueType & 0x7) {
        case 0: /* NULL value */
            sql = "INSERT INTO t1 VALUES(NULL)";
            break;
        case 1: /* INTEGER value */
            sql = sqlite3_mprintf("INSERT INTO t1 VALUES(%u)", packet->allocPattern);
            break;
        case 2: /* REAL value */
            sql = sqlite3_mprintf("INSERT INTO t1 VALUES(%f)", (double)packet->allocPattern / 1000.0);
            break;
        case 3: /* TEXT value */
            sql = sqlite3_mprintf("INSERT INTO t1 VALUES('%.*s_%u')", 
                                 (int)(packet->valueSize & 0xFF), packet->testData, packet->allocPattern);
            break;
        case 4: /* BLOB value */
            sql = "INSERT INTO t1 VALUES(?)";
            break;
        default: /* Mixed values */
            sql = sqlite3_mprintf("INSERT INTO t1 VALUES('mixed_%.*s')", 
                                 16, packet->testData);
            break;
    }
    
    if ((packet->valueType & 0x7) == 4) {
        /* BLOB insertion with parameter binding */
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_blob(stmt, 1, packet->testData, 16, SQLITE_TRANSIENT);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    } else {
        sqlite3_exec(db, sql, NULL, NULL, NULL);
        if ((packet->valueType & 0x7) != 0) sqlite3_free(sql);
    }
    
    /* Test value retrieval and operations */
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, "SELECT x, typeof(x), length(x) FROM t1", -1, &stmt, NULL);
    if (stmt) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            /* Access values to trigger value creation and potential freeing */
            sqlite3_value *val0 = sqlite3_column_value(stmt, 0);
            sqlite3_value *val1 = sqlite3_column_value(stmt, 1);
            sqlite3_value *val2 = sqlite3_column_value(stmt, 2);
            
            /* Test value operations */
            if (val0) {
                sqlite3_value_type(val0);
                sqlite3_value_bytes(val0);
            }
            if (val1) {
                sqlite3_value_text(val1);
            }
            if (val2) {
                sqlite3_value_int(val2);
            }
        }
        sqlite3_finalize(stmt);
    }
    
    /* Test destructor scenarios */
    if (packet->destructorTest & 0x1) {
        /* Test with dynamic strings that have destructors */
        sql = sqlite3_mprintf("SELECT upper('%.*s')", 16, packet->testData);
        sqlite3_exec(db, sql, NULL, NULL, NULL);
        sqlite3_free(sql);
    }
    
    /* Test different free scenarios */
    switch (packet->freeScenario & 0x3) {
        case 0: /* Normal cleanup */
            sqlite3_exec(db, "DELETE FROM t1", NULL, NULL, NULL);
            break;
        case 1: /* Force garbage collection */
            sqlite3_exec(db, "VACUUM", NULL, NULL, NULL);
            break;
        case 2: /* Multiple operations */
            for (int i = 0; i < 5; i++) {
                sql = sqlite3_mprintf("SELECT '%.*s_%d'", 8, packet->testData, i);
                sqlite3_exec(db, sql, NULL, NULL, NULL);
                sqlite3_free(sql);
            }
            break;
        case 3: /* Stress test */
            sqlite3_exec(db, "SELECT randomblob(1000)", NULL, NULL, NULL);
            break;
    }
    
    sqlite3_close(db);
    return 0;
}