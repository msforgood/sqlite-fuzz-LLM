/*
** VDBE Auxiliary Functions Harness Implementation
** Targets: checkActiveVdbeCnt, sqlite3VdbeAddFunctionCall, sqlite3VdbeAddOp4, sqlite3VdbeAddOp4Dup8
** Specification-based fuzzing implementation for SQLite3 v3.51.0
*/

#include "vdbe_auxiliary_harness.h"
#include "sqlite3.h"
#include <math.h>
#include <inttypes.h>

/*
** Fuzzing harness for checkActiveVdbeCnt function
** FC: vdbe_aux_001
*/
int fuzz_vdbe_check_active_cnt(FuzzCtx *pCtx, const VdbeCheckActiveCntPacket *pPacket) {
    /* Validation according to checkActiveVdbeCnt_spec.json */
    if (pPacket->vdbeCount > 100) return 0;
    if (pPacket->activeCount > 50) return 0;
    
    sqlite3 *db = NULL;
    int rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) return 0;
    
    /* Test different VDBE counting scenarios */
    switch (pPacket->scenario & 0x7) {
        case VDBE_AUX_SCENARIO_NORMAL: {
            /* Normal VDBE operations */
            sqlite3_exec(db, "CREATE TABLE t1(id INTEGER, data TEXT)", NULL, NULL, NULL);
            sqlite3_exec(db, "INSERT INTO t1 VALUES(1, 'test')", NULL, NULL, NULL);
            
            /* Create multiple prepared statements */
            for (int i = 0; i < (pPacket->vdbeCount & 0x7); i++) {
                sqlite3_stmt *stmt;
                char *sql = sqlite3_mprintf("SELECT * FROM t1 WHERE id = %d", i);
                if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
                sqlite3_free(sql);
            }
            break;
        }
        case VDBE_AUX_SCENARIO_MULTI_STMT: {
            /* Multiple concurrent statements */
            sqlite3_exec(db, "CREATE TABLE t1(x)", NULL, NULL, NULL);
            
            sqlite3_stmt *stmts[5] = {0};
            for (int i = 0; i < 5 && i < pPacket->activeCount; i++) {
                char *sql = sqlite3_mprintf("INSERT INTO t1 VALUES('%.*s_%d')", 
                                           8, pPacket->testData, i);
                sqlite3_prepare_v2(db, sql, -1, &stmts[i], NULL);
                sqlite3_free(sql);
            }
            
            /* Execute statements */
            for (int i = 0; i < 5; i++) {
                if (stmts[i]) {
                    sqlite3_step(stmts[i]);
                    sqlite3_finalize(stmts[i]);
                }
            }
            break;
        }
        case VDBE_AUX_SCENARIO_COMPLEX: {
            /* Complex SQL with transactions */
            sqlite3_exec(db, "CREATE TABLE t1(a, b, c)", NULL, NULL, NULL);
            sqlite3_exec(db, "BEGIN", NULL, NULL, NULL);
            
            for (int i = 0; i < (pPacket->readCount & 0xF); i++) {
                char *sql = sqlite3_mprintf("INSERT INTO t1 VALUES(%d, '%.*s', %d)", 
                                           i, 6, pPacket->testData, i * 2);
                sqlite3_exec(db, sql, NULL, NULL, NULL);
                sqlite3_free(sql);
            }
            
            sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
            sqlite3_exec(db, "SELECT COUNT(*) FROM t1", NULL, NULL, NULL);
            break;
        }
        case VDBE_AUX_SCENARIO_FUNCTIONS: {
            /* Test with SQL functions */
            sqlite3_exec(db, "CREATE TABLE t1(data TEXT)", NULL, NULL, NULL);
            char *sql = sqlite3_mprintf("INSERT INTO t1 VALUES('%.*s')", 
                                       16, pPacket->testData);
            sqlite3_exec(db, sql, NULL, NULL, NULL);
            sqlite3_free(sql);
            
            sqlite3_exec(db, "SELECT length(data), upper(data), lower(data) FROM t1", NULL, NULL, NULL);
            break;
        }
        default: {
            /* Mixed scenarios */
            sqlite3_exec(db, "CREATE TABLE t1(mixed)", NULL, NULL, NULL);
            sqlite3_exec(db, "INSERT INTO t1 VALUES('test')", NULL, NULL, NULL);
            sqlite3_exec(db, "SELECT * FROM t1", NULL, NULL, NULL);
            break;
        }
    }
    
    /* Test corruption scenarios */
    if (pPacket->corruption_flags & 0x1) {
        sqlite3_exec(db, "PRAGMA integrity_check", NULL, NULL, NULL);
    }
    
    sqlite3_close(db);
    return 0;
}

/*
** Fuzzing harness for sqlite3VdbeAddFunctionCall function
** FC: vdbe_aux_002
*/
int fuzz_vdbe_add_function_call(FuzzCtx *pCtx, const VdbeAddFunctionCallPacket *pPacket) {
    /* Validation according to sqlite3VdbeAddFunctionCall_spec.json */
    if (pPacket->argCount > 127) return 0;
    if (pPacket->firstArg > 32767) return 0;
    if (pPacket->resultReg > 1000) return 0;
    
    sqlite3 *db = NULL;
    int rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) return 0;
    
    /* Test different function call scenarios */
    switch (pPacket->scenario & 0x7) {
        case VDBE_AUX_SCENARIO_FUNCTIONS: {
            /* Built-in function calls */
            sqlite3_exec(db, "CREATE TABLE t1(x INTEGER, y TEXT)", NULL, NULL, NULL);
            char *sql = sqlite3_mprintf("INSERT INTO t1 VALUES(%u, '%.*s')", 
                                       pPacket->constantMask & 0xFFFF, 
                                       12, pPacket->testData);
            sqlite3_exec(db, sql, NULL, NULL, NULL);
            sqlite3_free(sql);
            
            /* Test various functions based on packet data */
            switch (pPacket->funcFlags & 0x7) {
                case 0:
                    sqlite3_exec(db, "SELECT length(y), typeof(x) FROM t1", NULL, NULL, NULL);
                    break;
                case 1:
                    sqlite3_exec(db, "SELECT upper(y), lower(y) FROM t1", NULL, NULL, NULL);
                    break;
                case 2:
                    sqlite3_exec(db, "SELECT substr(y, 1, 5), replace(y, 'e', 'E') FROM t1", NULL, NULL, NULL);
                    break;
                default:
                    sqlite3_exec(db, "SELECT abs(x), random() FROM t1", NULL, NULL, NULL);
                    break;
            }
            break;
        }
        case VDBE_AUX_SCENARIO_COMPLEX: {
            /* Complex function combinations */
            sqlite3_exec(db, "CREATE TABLE t1(data BLOB)", NULL, NULL, NULL);
            sqlite3_stmt *stmt;
            if (sqlite3_prepare_v2(db, "INSERT INTO t1 VALUES(?)", -1, &stmt, NULL) == SQLITE_OK) {
                sqlite3_bind_blob(stmt, 1, pPacket->testData, 12, SQLITE_STATIC);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            
            sqlite3_exec(db, "SELECT hex(data), length(data), quote(data) FROM t1", NULL, NULL, NULL);
            break;
        }
        case VDBE_AUX_SCENARIO_MEMORY: {
            /* Memory-intensive function calls */
            sqlite3_exec(db, "CREATE TABLE t1(large_text TEXT)", NULL, NULL, NULL);
            char *largeText = sqlite3_mprintf("%.*s%.*s%.*s", 
                                             4, pPacket->testData,
                                             4, pPacket->testData + 4,
                                             4, pPacket->testData + 8);
            char *sql = sqlite3_mprintf("INSERT INTO t1 VALUES('%s')", largeText);
            sqlite3_exec(db, sql, NULL, NULL, NULL);
            sqlite3_free(sql);
            sqlite3_free(largeText);
            
            sqlite3_exec(db, "SELECT length(large_text), trim(large_text) FROM t1", NULL, NULL, NULL);
            break;
        }
        default: {
            /* Basic function testing */
            sqlite3_exec(db, "SELECT datetime('now'), random(), last_insert_rowid()", NULL, NULL, NULL);
            break;
        }
    }
    
    sqlite3_close(db);
    return 0;
}

/*
** Fuzzing harness for sqlite3VdbeAddOp4 function
** FC: vdbe_aux_003
*/
int fuzz_vdbe_add_op4(FuzzCtx *pCtx, const VdbeAddOp4Packet *pPacket) {
    /* Validation according to sqlite3VdbeAddOp4_spec.json */
    if (pPacket->opcode > 191) return 0;
    if (pPacket->stringLength > 65536) return 0;
    
    sqlite3 *db = NULL;
    int rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) return 0;
    
    /* Test different opcode scenarios */
    switch (pPacket->scenario & 0x7) {
        case VDBE_AUX_SCENARIO_OPCODES: {
            /* Various opcodes with string parameters */
            sqlite3_exec(db, "CREATE TABLE t1(id INTEGER, name TEXT)", NULL, NULL, NULL);
            
            unsigned strLen = (pPacket->stringLength & 0xFF) + 1;
            char *testStr = sqlite3_mprintf("%.*s", (int)strLen, pPacket->testData);
            char *sql = sqlite3_mprintf("INSERT INTO t1 VALUES(%d, '%s')", 
                                       pPacket->p1 & 0xFFFF, testStr);
            sqlite3_exec(db, sql, NULL, NULL, NULL);
            sqlite3_free(sql);
            sqlite3_free(testStr);
            break;
        }
        case VDBE_AUX_SCENARIO_COMPLEX: {
            /* Complex SQL requiring various opcodes */
            sqlite3_exec(db, "CREATE TABLE t1(a, b, c)", NULL, NULL, NULL);
            sqlite3_exec(db, "CREATE INDEX idx1 ON t1(a)", NULL, NULL, NULL);
            
            char *sql = sqlite3_mprintf("INSERT INTO t1 VALUES(%d, '%.*s', %d)", 
                                       pPacket->p1 & 0xFF, 8, pPacket->testData, pPacket->p2 & 0xFF);
            sqlite3_exec(db, sql, NULL, NULL, NULL);
            sqlite3_free(sql);
            
            sqlite3_exec(db, "SELECT * FROM t1 WHERE a > 0 ORDER BY b", NULL, NULL, NULL);
            break;
        }
        case VDBE_AUX_SCENARIO_BOUNDARY: {
            /* Boundary condition testing */
            sqlite3_exec(db, "CREATE TABLE t1(boundary_test)", NULL, NULL, NULL);
            
            /* Test with various string lengths */
            for (int i = 0; i < 3; i++) {
                unsigned len = (i == 0) ? 1 : (i == 1) ? 16 : 255;
                char *str = sqlite3_mprintf("%.*s", len, pPacket->testData);
                char *sql = sqlite3_mprintf("INSERT INTO t1 VALUES('%s')", str);
                sqlite3_exec(db, sql, NULL, NULL, NULL);
                sqlite3_free(sql);
                sqlite3_free(str);
            }
            break;
        }
        default: {
            /* Basic opcode testing */
            sqlite3_exec(db, "CREATE TABLE t1(data)", NULL, NULL, NULL);
            char *sql = sqlite3_mprintf("INSERT INTO t1 VALUES('%.*s')", 
                                       10, pPacket->testData);
            sqlite3_exec(db, sql, NULL, NULL, NULL);
            sqlite3_free(sql);
            break;
        }
    }
    
    sqlite3_close(db);
    return 0;
}

/*
** Fuzzing harness for sqlite3VdbeAddOp4Dup8 function
** FC: vdbe_aux_004
*/
int fuzz_vdbe_add_op4_dup8(FuzzCtx *pCtx, const VdbeAddOp4Dup8Packet *pPacket) {
    /* Validation according to sqlite3VdbeAddOp4Dup8_spec.json */
    if (pPacket->opcode > 191) return 0;
    
    sqlite3 *db = NULL;
    int rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) return 0;
    
    /* Test different 8-byte data duplication scenarios */
    switch (pPacket->scenario & 0x7) {
        case VDBE_AUX_SCENARIO_OPCODES: {
            /* 8-byte data opcodes */
            sqlite3_exec(db, "CREATE TABLE t1(id INTEGER, int64_val INTEGER)", NULL, NULL, NULL);
            
            /* Use the 8-byte data as an integer value */
            int64_t val = (int64_t)pPacket->data8;
            char *sql = sqlite3_mprintf("INSERT INTO t1 VALUES(%d, %lld)", 
                                       pPacket->p1 & 0xFFFF, (long long)val);
            sqlite3_exec(db, sql, NULL, NULL, NULL);
            sqlite3_free(sql);
            
            sqlite3_exec(db, "SELECT * FROM t1 WHERE int64_val IS NOT NULL", NULL, NULL, NULL);
            break;
        }
        case VDBE_AUX_SCENARIO_BOUNDARY: {
            /* Boundary values for 8-byte data */
            sqlite3_exec(db, "CREATE TABLE t1(val REAL)", NULL, NULL, NULL);
            
            /* Interpret 8-byte data as double */
            double dval;
            memcpy(&dval, &pPacket->data8, sizeof(double));
            
            /* Ensure finite value for SQL safety */
            if (isfinite(dval)) {
                char *sql = sqlite3_mprintf("INSERT INTO t1 VALUES(%g)", dval);
                sqlite3_exec(db, sql, NULL, NULL, NULL);
                sqlite3_free(sql);
            } else {
                sqlite3_exec(db, "INSERT INTO t1 VALUES(0.0)", NULL, NULL, NULL);
            }
            break;
        }
        case VDBE_AUX_SCENARIO_MEMORY: {
            /* Memory operations with 8-byte data */
            sqlite3_exec(db, "CREATE TABLE t1(blob_data BLOB)", NULL, NULL, NULL);
            
            sqlite3_stmt *stmt;
            if (sqlite3_prepare_v2(db, "INSERT INTO t1 VALUES(?)", -1, &stmt, NULL) == SQLITE_OK) {
                sqlite3_bind_blob(stmt, 1, &pPacket->data8, 8, SQLITE_STATIC);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            
            sqlite3_exec(db, "SELECT length(blob_data), hex(blob_data) FROM t1", NULL, NULL, NULL);
            break;
        }
        default: {
            /* Basic 8-byte data testing */
            sqlite3_exec(db, "CREATE TABLE t1(test_data)", NULL, NULL, NULL);
            char *sql = sqlite3_mprintf("INSERT INTO t1 VALUES('data_%.*s')", 
                                       8, pPacket->testData);
            sqlite3_exec(db, sql, NULL, NULL, NULL);
            sqlite3_free(sql);
            break;
        }
    }
    
    sqlite3_close(db);
    return 0;
}