#include "vdbe_memory_harness.h"
#include <string.h>

/* sqlite3ExpirePreparedStatements fuzzing implementation */
void fuzz_vdbe_expire_statements(FuzzCtx *pCtx, const VdbeExpireStmtPacket *pPacket) {
    int rc;
    sqlite3_stmt *pStmt = NULL;
    
    /* Create multiple prepared statements to test expiration */
    const char *setupSql = 
        "CREATE TABLE expire_test(id INTEGER PRIMARY KEY, data TEXT);"
        "INSERT INTO expire_test VALUES(1, 'test1'), (2, 'test2'), (3, 'test3');";
    
    rc = sqlite3_exec(pCtx->db, setupSql, NULL, NULL, NULL);
    if( rc != SQLITE_OK ) return;
    
    /* Test statement expiration scenarios */
    uint8_t expireMode = pPacket->expireMode % 4;
    uint32_t expireCode = pPacket->expireCode % 1000;
    
    switch( expireMode ) {
        case 0: { /* Single statement expiration */
            sqlite3_prepare_v2(pCtx->db, "SELECT * FROM expire_test WHERE id = ?;", -1, &pStmt, NULL);
            if( pStmt ) {
                sqlite3_bind_int(pStmt, 1, 1);
                sqlite3_step(pStmt);
                
                /* Trigger statement expiration */
                sqlite3_exec(pCtx->db, "PRAGMA schema_version;", NULL, NULL, NULL);
                
                /* Try to reuse expired statement */
                sqlite3_reset(pStmt);
                sqlite3_bind_int(pStmt, 1, 2);
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
            break;
        }
        
        case 1: { /* Multiple statement expiration */
            sqlite3_stmt *pStmt1 = NULL, *pStmt2 = NULL, *pStmt3 = NULL;
            
            sqlite3_prepare_v2(pCtx->db, "SELECT COUNT(*) FROM expire_test;", -1, &pStmt1, NULL);
            sqlite3_prepare_v2(pCtx->db, "SELECT * FROM expire_test ORDER BY id;", -1, &pStmt2, NULL);
            sqlite3_prepare_v2(pCtx->db, "SELECT data FROM expire_test WHERE id > ?;", -1, &pStmt3, NULL);
            
            if( pStmt1 ) sqlite3_step(pStmt1);
            if( pStmt2 ) sqlite3_step(pStmt2);
            if( pStmt3 ) {
                sqlite3_bind_int(pStmt3, 1, 1);
                sqlite3_step(pStmt3);
            }
            
            /* Force expiration with schema change */
            sqlite3_exec(pCtx->db, "ALTER TABLE expire_test ADD COLUMN extra TEXT;", NULL, NULL, NULL);
            
            /* Try to use expired statements */
            if( pStmt1 ) { sqlite3_step(pStmt1); sqlite3_finalize(pStmt1); }
            if( pStmt2 ) { sqlite3_step(pStmt2); sqlite3_finalize(pStmt2); }
            if( pStmt3 ) { sqlite3_step(pStmt3); sqlite3_finalize(pStmt3); }
            break;
        }
        
        case 2: { /* Transaction-based expiration */
            sqlite3_prepare_v2(pCtx->db, "INSERT INTO expire_test(data) VALUES(?);", -1, &pStmt, NULL);
            if( pStmt ) {
                sqlite3_exec(pCtx->db, "BEGIN;", NULL, NULL, NULL);
                
                sqlite3_bind_text(pStmt, 1, "new_data", -1, SQLITE_STATIC);
                sqlite3_step(pStmt);
                sqlite3_reset(pStmt);
                
                /* Rollback to test statement handling */
                sqlite3_exec(pCtx->db, "ROLLBACK;", NULL, NULL, NULL);
                
                sqlite3_bind_text(pStmt, 1, "after_rollback", -1, SQLITE_STATIC);
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
            break;
        }
        
        case 3: { /* Corruption simulation with expiration */
            if( pPacket->corruptionMask & 0x1 ) {
                sqlite3_prepare_v2(pCtx->db, "SELECT * FROM expire_test;", -1, &pStmt, NULL);
                if( pStmt ) {
                    sqlite3_step(pStmt);
                    
                    /* Simulate database corruption */
                    sqlite3_exec(pCtx->db, "PRAGMA integrity_check;", NULL, NULL, NULL);
                    
                    sqlite3_step(pStmt);
                    sqlite3_finalize(pStmt);
                }
            }
            break;
        }
    }
}

/* sqlite3Stat4ProbeFree fuzzing implementation */
void fuzz_vdbe_stat4_probe_free(FuzzCtx *pCtx, const VdbeStat4ProbePacket *pPacket) {
    /* Create test scenario for STAT4 operations */
    const char *setupSql = 
        "CREATE TABLE stat4_test(id INTEGER, name TEXT, value REAL);"
        "CREATE INDEX idx_stat4_name ON stat4_test(name);"
        "CREATE INDEX idx_stat4_composite ON stat4_test(id, value);";
    
    sqlite3_exec(pCtx->db, setupSql, NULL, NULL, NULL);
    
    /* Insert test data to trigger statistics */
    uint8_t probeMode = pPacket->probeMode % 4;
    
    switch( probeMode ) {
        case 0: { /* Basic statistics collection */
            for( int i = 0; i < (pPacket->fieldCount % 20) + 1; i++ ) {
                sqlite3_stmt *pStmt = NULL;
                sqlite3_prepare_v2(pCtx->db, "INSERT INTO stat4_test VALUES(?, ?, ?);", -1, &pStmt, NULL);
                if( pStmt ) {
                    sqlite3_bind_int(pStmt, 1, i);
                    sqlite3_bind_text(pStmt, 2, "name", -1, SQLITE_STATIC);
                    sqlite3_bind_double(pStmt, 3, i * 1.5);
                    sqlite3_step(pStmt);
                    sqlite3_finalize(pStmt);
                }
            }
            
            /* Trigger statistics update */
            sqlite3_exec(pCtx->db, "ANALYZE stat4_test;", NULL, NULL, NULL);
            break;
        }
        
        case 1: { /* Complex query to trigger probe allocation */
            sqlite3_stmt *pStmt = NULL;
            sqlite3_prepare_v2(pCtx->db, "SELECT * FROM stat4_test WHERE name LIKE ? AND id > ? ORDER BY value;", -1, &pStmt, NULL);
            if( pStmt ) {
                sqlite3_bind_text(pStmt, 1, "name%", -1, SQLITE_STATIC);
                sqlite3_bind_int(pStmt, 2, 5);
                while( sqlite3_step(pStmt) == SQLITE_ROW ) {
                    /* Process results */
                }
                sqlite3_finalize(pStmt);
            }
            break;
        }
        
        case 2: { /* Multiple index probes */
            sqlite3_stmt *pStmt = NULL;
            
            /* Query using composite index */
            sqlite3_prepare_v2(pCtx->db, "SELECT COUNT(*) FROM stat4_test WHERE id BETWEEN ? AND ? AND value > ?;", -1, &pStmt, NULL);
            if( pStmt ) {
                sqlite3_bind_int(pStmt, 1, 1);
                sqlite3_bind_int(pStmt, 2, 10);
                sqlite3_bind_double(pStmt, 3, 5.0);
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
            
            /* Query using single-column index */
            sqlite3_prepare_v2(pCtx->db, "SELECT id FROM stat4_test WHERE name = ? LIMIT 5;", -1, &pStmt, NULL);
            if( pStmt ) {
                sqlite3_bind_text(pStmt, 1, "name", -1, SQLITE_STATIC);
                while( sqlite3_step(pStmt) == SQLITE_ROW ) {
                    /* Process results */
                }
                sqlite3_finalize(pStmt);
            }
            break;
        }
        
        case 3: { /* Corruption testing for statistics */
            if( pPacket->corruptionMask & 0x2 ) {
                /* Create large dataset */
                sqlite3_exec(pCtx->db, "INSERT INTO stat4_test SELECT value, 'bulk' || value, value * 2.0 FROM generate_series(1, 100);", NULL, NULL, NULL);
                
                /* Update statistics */
                sqlite3_exec(pCtx->db, "ANALYZE;", NULL, NULL, NULL);
                
                /* Test integrity */
                sqlite3_exec(pCtx->db, "PRAGMA integrity_check;", NULL, NULL, NULL);
            }
            break;
        }
    }
}

/* sqlite3ValueFree fuzzing implementation */
void fuzz_vdbe_value_free(FuzzCtx *pCtx, const VdbeValueFreePacket *pPacket) {
    /* Test value creation and destruction */
    uint8_t valueType = pPacket->valueType % 6;
    
    switch( valueType ) {
        case 0: { /* Integer values */
            sqlite3_stmt *pStmt = NULL;
            sqlite3_prepare_v2(pCtx->db, "SELECT ?;", -1, &pStmt, NULL);
            if( pStmt ) {
                sqlite3_bind_int64(pStmt, 1, pPacket->valueSize);
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
            break;
        }
        
        case 1: { /* Text values */
            sqlite3_stmt *pStmt = NULL;
            sqlite3_prepare_v2(pCtx->db, "SELECT LENGTH(?);", -1, &pStmt, NULL);
            if( pStmt ) {
                char *testStr = sqlite3_mprintf("test_string_%d", pPacket->valueSize % 1000);
                if( testStr ) {
                    sqlite3_bind_text(pStmt, 1, testStr, -1, sqlite3_free);
                    sqlite3_step(pStmt);
                }
                sqlite3_finalize(pStmt);
            }
            break;
        }
        
        case 2: { /* BLOB values */
            sqlite3_stmt *pStmt = NULL;
            sqlite3_prepare_v2(pCtx->db, "SELECT LENGTH(?);", -1, &pStmt, NULL);
            if( pStmt ) {
                int blobSize = (pPacket->valueSize % 1000) + 1;
                char *blob = sqlite3_malloc(blobSize);
                if( blob ) {
                    memset(blob, 0xAA, blobSize);
                    sqlite3_bind_blob(pStmt, 1, blob, blobSize, sqlite3_free);
                    sqlite3_step(pStmt);
                }
                sqlite3_finalize(pStmt);
            }
            break;
        }
        
        case 3: { /* NULL values */
            sqlite3_stmt *pStmt = NULL;
            sqlite3_prepare_v2(pCtx->db, "SELECT ? IS NULL;", -1, &pStmt, NULL);
            if( pStmt ) {
                sqlite3_bind_null(pStmt, 1);
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
            break;
        }
        
        case 4: { /* Real values */
            sqlite3_stmt *pStmt = NULL;
            sqlite3_prepare_v2(pCtx->db, "SELECT ROUND(?, 2);", -1, &pStmt, NULL);
            if( pStmt ) {
                sqlite3_bind_double(pStmt, 1, pPacket->valueSize * 0.123456);
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
            break;
        }
        
        case 5: { /* Mixed value operations */
            if( pPacket->corruptionMask & 0x4 ) {
                /* Create multiple values and test cleanup */
                sqlite3_stmt *pStmt = NULL;
                sqlite3_prepare_v2(pCtx->db, "SELECT ?, ?, ?, ?;", -1, &pStmt, NULL);
                if( pStmt ) {
                    sqlite3_bind_int(pStmt, 1, 42);
                    sqlite3_bind_text(pStmt, 2, "mixed", -1, SQLITE_STATIC);
                    sqlite3_bind_double(pStmt, 3, 3.14159);
                    sqlite3_bind_null(pStmt, 4);
                    sqlite3_step(pStmt);
                    sqlite3_finalize(pStmt);
                }
            }
            break;
        }
    }
}

/* freeEphemeralFunction fuzzing implementation */
void fuzz_vdbe_ephemeral_function(FuzzCtx *pCtx, const VdbeEphemeralFuncPacket *pPacket) {
    /* Test custom function creation and cleanup */
    uint8_t funcMode = pPacket->funcFlags % 4;
    
    switch( funcMode ) {
        case 0: { /* Simple scalar function */
            /* Test built-in functions that might create ephemeral functions */
            sqlite3_stmt *pStmt = NULL;
            sqlite3_prepare_v2(pCtx->db, "SELECT ABS(?), UPPER(?), LENGTH(?);", -1, &pStmt, NULL);
            if( pStmt ) {
                sqlite3_bind_int(pStmt, 1, -42);
                sqlite3_bind_text(pStmt, 2, "test", -1, SQLITE_STATIC);
                sqlite3_bind_text(pStmt, 3, "function", -1, SQLITE_STATIC);
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
            break;
        }
        
        case 1: { /* Aggregate function usage */
            const char *aggSql = 
                "CREATE TABLE func_test(id INTEGER, value REAL);"
                "INSERT INTO func_test VALUES(1, 10.5), (2, 20.3), (3, 15.7);";
            sqlite3_exec(pCtx->db, aggSql, NULL, NULL, NULL);
            
            sqlite3_stmt *pStmt = NULL;
            sqlite3_prepare_v2(pCtx->db, "SELECT COUNT(*), AVG(value), MAX(value), MIN(value) FROM func_test;", -1, &pStmt, NULL);
            if( pStmt ) {
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
            break;
        }
        
        case 2: { /* Complex function combinations */
            sqlite3_stmt *pStmt = NULL;
            sqlite3_prepare_v2(pCtx->db, "SELECT SUBSTR(PRINTF('test_%d', ?), 1, ?), ROUND(RANDOM() * ?, 2);", -1, &pStmt, NULL);
            if( pStmt ) {
                sqlite3_bind_int(pStmt, 1, pPacket->nameLength % 100);
                sqlite3_bind_int(pStmt, 2, (pPacket->argCount % 10) + 1);
                sqlite3_bind_double(pStmt, 3, 100.0);
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
            break;
        }
        
        case 3: { /* Function cleanup under stress */
            if( pPacket->corruptionMask & 0x8 ) {
                /* Multiple function calls to test cleanup */
                for( int i = 0; i < (pPacket->argCount % 5) + 1; i++ ) {
                    sqlite3_stmt *pStmt = NULL;
                    sqlite3_prepare_v2(pCtx->db, "SELECT HEX(RANDOMBLOB(?)), DATETIME('now', '+' || ? || ' seconds');", -1, &pStmt, NULL);
                    if( pStmt ) {
                        sqlite3_bind_int(pStmt, 1, (i % 10) + 1);
                        sqlite3_bind_int(pStmt, 2, i);
                        sqlite3_step(pStmt);
                        sqlite3_finalize(pStmt);
                    }
                }
            }
            break;
        }
    }
}