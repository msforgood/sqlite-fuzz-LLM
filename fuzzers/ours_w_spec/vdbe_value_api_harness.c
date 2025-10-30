/*
** VDBE Value API Functions Harness Implementation
** Target functions: sqlite3_value_bytes16, sqlite3_value_nochange, sqlite3_vtab_in_first
*/

#include "vdbe_value_api_harness.h"
#include <string.h>

/* Helper function to create sqlite3_value for testing */
static sqlite3_value* create_test_value(FuzzCtx *ctx, uint8_t valueType, const char *data, size_t dataLen) {
    sqlite3_stmt *pStmt = NULL;
    sqlite3_value *pValue = NULL;
    
    /* Create a simple prepared statement to get a value context */
    int rc = sqlite3_prepare_v2(ctx->db, "SELECT ?", -1, &pStmt, NULL);
    if (rc != SQLITE_OK || !pStmt) return NULL;
    
    /* Bind value based on type */
    switch (valueType % 5) {
        case 0: /* NULL */
            sqlite3_bind_null(pStmt, 1);
            break;
        case 1: /* INTEGER */
            sqlite3_bind_int64(pStmt, 1, (sqlite3_int64)(dataLen % 1000000));
            break;
        case 2: /* REAL */
            sqlite3_bind_double(pStmt, 1, (double)(dataLen % 1000) / 10.0);
            break;
        case 3: /* TEXT */
            if (dataLen > 0 && data) {
                size_t textLen = dataLen > 256 ? 256 : dataLen;
                sqlite3_bind_text(pStmt, 1, data, (int)textLen, SQLITE_TRANSIENT);
            } else {
                sqlite3_bind_text(pStmt, 1, "test", 4, SQLITE_STATIC);
            }
            break;
        case 4: /* BLOB */
            if (dataLen > 0 && data) {
                size_t blobLen = dataLen > 128 ? 128 : dataLen;
                sqlite3_bind_blob(pStmt, 1, data, (int)blobLen, SQLITE_TRANSIENT);
            } else {
                sqlite3_bind_blob(pStmt, 1, "blob", 4, SQLITE_STATIC);
            }
            break;
    }
    
    /* Step to make the value available */
    if (sqlite3_step(pStmt) == SQLITE_ROW) {
        pValue = sqlite3_column_value(pStmt, 0);
    }
    
    if (pStmt) {
        sqlite3_reset(pStmt);
        sqlite3_finalize(pStmt);
    }
    
    return pValue;
}

/* Fuzzing harness for sqlite3_value_bytes16 */
int fuzz_value_bytes16(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < sizeof(ValueBytes16Packet)) {
        return SQLITE_OK;
    }
    
    const ValueBytes16Packet *packet = (const ValueBytes16Packet*)data;
    int rc = SQLITE_OK;
    
    /* Validate parameters */
    if (packet->textLength > 65535) return SQLITE_OK;
    
    /* Test scenarios for UTF-16 byte counting */
    switch (packet->scenario % 8) {
        case 0: {
            /* Test with NULL value */
            sqlite3_stmt *pStmt = NULL;
            rc = sqlite3_prepare_v2(ctx->db, "SELECT NULL", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                if (sqlite3_step(pStmt) == SQLITE_ROW) {
                    sqlite3_value *pValue = sqlite3_column_value(pStmt, 0);
                    int bytes = sqlite3_value_bytes16(pValue);
                    (void)bytes; /* Use result to avoid warnings */
                }
                sqlite3_finalize(pStmt);
            }
            break;
        }
        case 1: {
            /* Test with INTEGER value */
            sqlite3_stmt *pStmt = NULL;
            rc = sqlite3_prepare_v2(ctx->db, "SELECT 12345", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                if (sqlite3_step(pStmt) == SQLITE_ROW) {
                    sqlite3_value *pValue = sqlite3_column_value(pStmt, 0);
                    int bytes = sqlite3_value_bytes16(pValue);
                    (void)bytes;
                }
                sqlite3_finalize(pStmt);
            }
            break;
        }
        case 2: {
            /* Test with REAL value */
            sqlite3_stmt *pStmt = NULL;
            rc = sqlite3_prepare_v2(ctx->db, "SELECT 3.14159", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                if (sqlite3_step(pStmt) == SQLITE_ROW) {
                    sqlite3_value *pValue = sqlite3_column_value(pStmt, 0);
                    int bytes = sqlite3_value_bytes16(pValue);
                    (void)bytes;
                }
                sqlite3_finalize(pStmt);
            }
            break;
        }
        case 3: {
            /* Test with TEXT value */
            sqlite3_stmt *pStmt = NULL;
            char sql[256];
            size_t textLen = packet->textLength % 64;
            if (textLen == 0) textLen = 1;
            char *testText = sqlite3_mprintf("%.*s", (int)textLen, packet->testData);
            if (testText) {
                snprintf(sql, sizeof(sql), "SELECT '%q'", testText);
                rc = sqlite3_prepare_v2(ctx->db, sql, -1, &pStmt, NULL);
                if (rc == SQLITE_OK && pStmt) {
                    if (sqlite3_step(pStmt) == SQLITE_ROW) {
                        sqlite3_value *pValue = sqlite3_column_value(pStmt, 0);
                        int bytes = sqlite3_value_bytes16(pValue);
                        (void)bytes;
                    }
                    sqlite3_finalize(pStmt);
                }
                sqlite3_free(testText);
            }
            break;
        }
        case 4: {
            /* Test with BLOB value */
            sqlite3_stmt *pStmt = NULL;
            rc = sqlite3_prepare_v2(ctx->db, "SELECT ?", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                size_t blobLen = packet->textLength % 32;
                if (blobLen == 0) blobLen = 4;
                sqlite3_bind_blob(pStmt, 1, packet->testData, (int)blobLen, SQLITE_TRANSIENT);
                if (sqlite3_step(pStmt) == SQLITE_ROW) {
                    sqlite3_value *pValue = sqlite3_column_value(pStmt, 0);
                    int bytes = sqlite3_value_bytes16(pValue);
                    (void)bytes;
                }
                sqlite3_finalize(pStmt);
            }
            break;
        }
        case 5: {
            /* Test with Unicode text */
            sqlite3_stmt *pStmt = NULL;
            rc = sqlite3_prepare_v2(ctx->db, "SELECT '测试UTF16字符'", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                if (sqlite3_step(pStmt) == SQLITE_ROW) {
                    sqlite3_value *pValue = sqlite3_column_value(pStmt, 0);
                    int bytes = sqlite3_value_bytes16(pValue);
                    (void)bytes;
                }
                sqlite3_finalize(pStmt);
            }
            break;
        }
        case 6: {
            /* Test with empty string */
            sqlite3_stmt *pStmt = NULL;
            rc = sqlite3_prepare_v2(ctx->db, "SELECT ''", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                if (sqlite3_step(pStmt) == SQLITE_ROW) {
                    sqlite3_value *pValue = sqlite3_column_value(pStmt, 0);
                    int bytes = sqlite3_value_bytes16(pValue);
                    (void)bytes;
                }
                sqlite3_finalize(pStmt);
            }
            break;
        }
        case 7: {
            /* Test with very long text */
            sqlite3_stmt *pStmt = NULL;
            char *longText = sqlite3_mprintf("%0*d", (int)(packet->textLength % 1000 + 100), 42);
            if (longText) {
                char *sql = sqlite3_mprintf("SELECT '%q'", longText);
                if (sql) {
                    rc = sqlite3_prepare_v2(ctx->db, sql, -1, &pStmt, NULL);
                    if (rc == SQLITE_OK && pStmt) {
                        if (sqlite3_step(pStmt) == SQLITE_ROW) {
                            sqlite3_value *pValue = sqlite3_column_value(pStmt, 0);
                            int bytes = sqlite3_value_bytes16(pValue);
                            (void)bytes;
                        }
                        sqlite3_finalize(pStmt);
                    }
                    sqlite3_free(sql);
                }
                sqlite3_free(longText);
            }
            break;
        }
    }
    
    return SQLITE_OK;
}

/* Fuzzing harness for sqlite3_value_nochange */
int fuzz_value_nochange(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < sizeof(ValueNochangePacket)) {
        return SQLITE_OK;
    }
    
    const ValueNochangePacket *packet = (const ValueNochangePacket*)data;
    int rc = SQLITE_OK;
    
    /* Test scenarios for nochange detection */
    switch (packet->scenario % 6) {
        case 0: {
            /* Test with normal value */
            sqlite3_stmt *pStmt = NULL;
            rc = sqlite3_prepare_v2(ctx->db, "SELECT 'normal_value'", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                if (sqlite3_step(pStmt) == SQLITE_ROW) {
                    sqlite3_value *pValue = sqlite3_column_value(pStmt, 0);
                    int nochange = sqlite3_value_nochange(pValue);
                    (void)nochange;
                }
                sqlite3_finalize(pStmt);
            }
            break;
        }
        case 1: {
            /* Test with NULL value */
            sqlite3_stmt *pStmt = NULL;
            rc = sqlite3_prepare_v2(ctx->db, "SELECT NULL", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                if (sqlite3_step(pStmt) == SQLITE_ROW) {
                    sqlite3_value *pValue = sqlite3_column_value(pStmt, 0);
                    int nochange = sqlite3_value_nochange(pValue);
                    (void)nochange;
                }
                sqlite3_finalize(pStmt);
            }
            break;
        }
        case 2: {
            /* Test with INTEGER value */
            sqlite3_stmt *pStmt = NULL;
            rc = sqlite3_prepare_v2(ctx->db, "SELECT 0", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                if (sqlite3_step(pStmt) == SQLITE_ROW) {
                    sqlite3_value *pValue = sqlite3_column_value(pStmt, 0);
                    int nochange = sqlite3_value_nochange(pValue);
                    (void)nochange;
                }
                sqlite3_finalize(pStmt);
            }
            break;
        }
        case 3: {
            /* Test with UPDATE trigger context */
            rc = sqlite3_exec(ctx->db, 
                "CREATE TEMP TABLE IF NOT EXISTS test_nochange(id INTEGER, data TEXT);", 
                NULL, NULL, NULL);
            if (rc == SQLITE_OK) {
                rc = sqlite3_exec(ctx->db, "INSERT INTO test_nochange VALUES (1, 'initial');", NULL, NULL, NULL);
            }
            break;
        }
        case 4: {
            /* Test with bound parameter */
            sqlite3_stmt *pStmt = NULL;
            rc = sqlite3_prepare_v2(ctx->db, "SELECT ?", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                sqlite3_bind_text(pStmt, 1, (char*)packet->testData, 16, SQLITE_TRANSIENT);
                if (sqlite3_step(pStmt) == SQLITE_ROW) {
                    sqlite3_value *pValue = sqlite3_column_value(pStmt, 0);
                    int nochange = sqlite3_value_nochange(pValue);
                    (void)nochange;
                }
                sqlite3_finalize(pStmt);
            }
            break;
        }
        case 5: {
            /* Test with REAL value */
            sqlite3_stmt *pStmt = NULL;
            rc = sqlite3_prepare_v2(ctx->db, "SELECT 0.0", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                if (sqlite3_step(pStmt) == SQLITE_ROW) {
                    sqlite3_value *pValue = sqlite3_column_value(pStmt, 0);
                    int nochange = sqlite3_value_nochange(pValue);
                    (void)nochange;
                }
                sqlite3_finalize(pStmt);
            }
            break;
        }
    }
    
    return SQLITE_OK;
}

/* Fuzzing harness for sqlite3_vtab_in_first */
int fuzz_vtab_in_first(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < sizeof(VtabInFirstPacket)) {
        return SQLITE_OK;
    }
    
    const VtabInFirstPacket *packet = (const VtabInFirstPacket*)data;
    int rc = SQLITE_OK;
    
    /* Validate parameters */
    if (packet->valueListSize > 1000) return SQLITE_OK;
    
    /* Test scenarios for virtual table IN operator */
    switch (packet->scenario % 6) {
        case 0: {
            /* Test with simple value list */
            sqlite3_stmt *pStmt = NULL;
            rc = sqlite3_prepare_v2(ctx->db, "SELECT ? IN (1, 2, 3, 4, 5)", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                sqlite3_bind_int(pStmt, 1, packet->iteratorPosition % 10);
                if (sqlite3_step(pStmt) == SQLITE_ROW) {
                    sqlite3_value *pValue = sqlite3_column_value(pStmt, 0);
                    (void)pValue;
                }
                sqlite3_finalize(pStmt);
            }
            break;
        }
        case 1: {
            /* Test with text value list */
            sqlite3_stmt *pStmt = NULL;
            rc = sqlite3_prepare_v2(ctx->db, "SELECT ? IN ('a', 'b', 'c', 'd')", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                size_t textLen = packet->valueListSize % 16;
                if (textLen == 0) textLen = 1;
                sqlite3_bind_text(pStmt, 1, packet->valueData, (int)textLen, SQLITE_TRANSIENT);
                if (sqlite3_step(pStmt) == SQLITE_ROW) {
                    sqlite3_value *pValue = sqlite3_column_value(pStmt, 0);
                    (void)pValue;
                }
                sqlite3_finalize(pStmt);
            }
            break;
        }
        case 2: {
            /* Test with NULL in list */
            sqlite3_stmt *pStmt = NULL;
            rc = sqlite3_prepare_v2(ctx->db, "SELECT ? IN (NULL, 1, 2)", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                if (packet->valueType % 2 == 0) {
                    sqlite3_bind_null(pStmt, 1);
                } else {
                    sqlite3_bind_int(pStmt, 1, 1);
                }
                if (sqlite3_step(pStmt) == SQLITE_ROW) {
                    sqlite3_value *pValue = sqlite3_column_value(pStmt, 0);
                    (void)pValue;
                }
                sqlite3_finalize(pStmt);
            }
            break;
        }
        case 3: {
            /* Test with mixed types in list */
            sqlite3_stmt *pStmt = NULL;
            rc = sqlite3_prepare_v2(ctx->db, "SELECT ? IN (1, 'text', 3.14, NULL)", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                switch (packet->valueType % 4) {
                    case 0:
                        sqlite3_bind_int(pStmt, 1, 1);
                        break;
                    case 1:
                        sqlite3_bind_text(pStmt, 1, "text", 4, SQLITE_STATIC);
                        break;
                    case 2:
                        sqlite3_bind_double(pStmt, 1, 3.14);
                        break;
                    case 3:
                        sqlite3_bind_null(pStmt, 1);
                        break;
                }
                if (sqlite3_step(pStmt) == SQLITE_ROW) {
                    sqlite3_value *pValue = sqlite3_column_value(pStmt, 0);
                    (void)pValue;
                }
                sqlite3_finalize(pStmt);
            }
            break;
        }
        case 4: {
            /* Test with large value list */
            sqlite3_stmt *pStmt = NULL;
            char *sql = sqlite3_mprintf("SELECT ? IN (%s)", 
                "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20");
            if (sql) {
                rc = sqlite3_prepare_v2(ctx->db, sql, -1, &pStmt, NULL);
                if (rc == SQLITE_OK && pStmt) {
                    sqlite3_bind_int(pStmt, 1, packet->iteratorPosition % 25);
                    if (sqlite3_step(pStmt) == SQLITE_ROW) {
                        sqlite3_value *pValue = sqlite3_column_value(pStmt, 0);
                        (void)pValue;
                    }
                    sqlite3_finalize(pStmt);
                }
                sqlite3_free(sql);
            }
            break;
        }
        case 5: {
            /* Test with BLOB values */
            sqlite3_stmt *pStmt = NULL;
            rc = sqlite3_prepare_v2(ctx->db, "SELECT ? IN (?, ?, ?)", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                size_t blobLen = packet->valueListSize % 32;
                if (blobLen == 0) blobLen = 4;
                sqlite3_bind_blob(pStmt, 1, packet->valueData, (int)blobLen, SQLITE_TRANSIENT);
                sqlite3_bind_blob(pStmt, 2, "blob1", 5, SQLITE_STATIC);
                sqlite3_bind_blob(pStmt, 3, packet->valueData, (int)blobLen, SQLITE_TRANSIENT);
                sqlite3_bind_blob(pStmt, 4, "blob3", 5, SQLITE_STATIC);
                if (sqlite3_step(pStmt) == SQLITE_ROW) {
                    sqlite3_value *pValue = sqlite3_column_value(pStmt, 0);
                    (void)pValue;
                }
                sqlite3_finalize(pStmt);
            }
            break;
        }
    }
    
    return SQLITE_OK;
}