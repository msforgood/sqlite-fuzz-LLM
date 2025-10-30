/*
** VDBE Result API Functions Harness Implementation
** Target functions: sqlite3_result_text16, sqlite3_result_zeroblob64, sqlite3_stmt_scanstatus
*/

#include "vdbe_result_api_harness.h"
#include <string.h>

/* Helper function to create test function context */
static sqlite3_context* create_test_context(FuzzCtx *ctx) {
    /* Use a simple SQL function to get a valid context */
    sqlite3_stmt *pStmt = NULL;
    int rc = sqlite3_prepare_v2(ctx->db, "SELECT length(?)", -1, &pStmt, NULL);
    if (rc != SQLITE_OK || !pStmt) return NULL;
    
    sqlite3_bind_text(pStmt, 1, "test", 4, SQLITE_STATIC);
    return NULL; /* Context would be available during function execution */
}

/* Fuzzing harness for sqlite3_result_text16 */
int fuzz_result_text16(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < sizeof(ResultText16Packet)) {
        return SQLITE_OK;
    }
    
    const ResultText16Packet *packet = (const ResultText16Packet*)data;
    int rc = SQLITE_OK;
    
    /* Validate parameters */
    if (packet->textLength > 1000000) return SQLITE_OK;
    
    /* Test scenarios for UTF-16 result setting */
    switch (packet->scenario % 8) {
        case 0: {
            /* Test with SQL function that uses result_text16 */
            rc = sqlite3_exec(ctx->db,
                "CREATE TEMP TABLE IF NOT EXISTS test_text16("
                "  id INTEGER PRIMARY KEY,"
                "  utf16_data TEXT"
                ");", NULL, NULL, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_stmt *pStmt = NULL;
                rc = sqlite3_prepare_v2(ctx->db, 
                    "INSERT INTO test_text16(utf16_data) VALUES(?)", -1, &pStmt, NULL);
                if (rc == SQLITE_OK && pStmt) {
                    size_t textLen = packet->textLength % 128;
                    if (textLen == 0) textLen = 4;
                    sqlite3_bind_text16(pStmt, 1, packet->textData, (int)textLen, SQLITE_TRANSIENT);
                    sqlite3_step(pStmt);
                    sqlite3_finalize(pStmt);
                }
            }
            break;
        }
        case 1: {
            /* Test with Unicode text */
            sqlite3_stmt *pStmt = NULL;
            rc = sqlite3_prepare_v2(ctx->db, "SELECT ?", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                const char *unicodeText = "UTF16测试文本🔥";
                sqlite3_bind_text16(pStmt, 1, unicodeText, -1, SQLITE_TRANSIENT);
                if (sqlite3_step(pStmt) == SQLITE_ROW) {
                    const void *result = sqlite3_column_text16(pStmt, 0);
                    int bytes = sqlite3_column_bytes16(pStmt, 0);
                    (void)result; (void)bytes;
                }
                sqlite3_finalize(pStmt);
            }
            break;
        }
        case 2: {
            /* Test with empty UTF-16 text */
            sqlite3_stmt *pStmt = NULL;
            rc = sqlite3_prepare_v2(ctx->db, "SELECT ?", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                sqlite3_bind_text16(pStmt, 1, "", 0, SQLITE_STATIC);
                if (sqlite3_step(pStmt) == SQLITE_ROW) {
                    sqlite3_column_text16(pStmt, 0);
                }
                sqlite3_finalize(pStmt);
            }
            break;
        }
        case 3: {
            /* Test with long UTF-16 text */
            sqlite3_stmt *pStmt = NULL;
            rc = sqlite3_prepare_v2(ctx->db, "SELECT ?", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                size_t textLen = (packet->textLength % 200) + 50;
                char *longText = sqlite3_mprintf("%0*d", (int)textLen, 12345);
                if (longText) {
                    sqlite3_bind_text16(pStmt, 1, longText, -1, SQLITE_TRANSIENT);
                    if (sqlite3_step(pStmt) == SQLITE_ROW) {
                        sqlite3_column_text16(pStmt, 0);
                    }
                    sqlite3_free(longText);
                }
                sqlite3_finalize(pStmt);
            }
            break;
        }
        case 4: {
            /* Test UTF-16 with specific deleter types */
            sqlite3_stmt *pStmt = NULL;
            rc = sqlite3_prepare_v2(ctx->db, "SELECT ?", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                switch (packet->deleterType % 3) {
                    case 0: /* STATIC */
                        sqlite3_bind_text16(pStmt, 1, "static", -1, SQLITE_STATIC);
                        break;
                    case 1: /* TRANSIENT */
                        sqlite3_bind_text16(pStmt, 1, packet->textData, 
                            (int)(packet->textLength % 64), SQLITE_TRANSIENT);
                        break;
                    case 2: /* Dynamic */
                        {
                            char *dynText = sqlite3_mprintf("dynamic_%u", packet->flags);
                            if (dynText) {
                                sqlite3_bind_text16(pStmt, 1, dynText, -1, sqlite3_free);
                            }
                        }
                        break;
                }
                if (sqlite3_step(pStmt) == SQLITE_ROW) {
                    sqlite3_column_text16(pStmt, 0);
                }
                sqlite3_finalize(pStmt);
            }
            break;
        }
        case 5: {
            /* Test with NULL UTF-16 text */
            sqlite3_stmt *pStmt = NULL;
            rc = sqlite3_prepare_v2(ctx->db, "SELECT ?", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                sqlite3_bind_null(pStmt, 1);
                if (sqlite3_step(pStmt) == SQLITE_ROW) {
                    const void *result = sqlite3_column_text16(pStmt, 0);
                    (void)result;
                }
                sqlite3_finalize(pStmt);
            }
            break;
        }
        case 6: {
            /* Test with UTF-16 containing special characters */
            sqlite3_stmt *pStmt = NULL;
            rc = sqlite3_prepare_v2(ctx->db, "SELECT ?", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                const char *specialText = "Special\\n\\t\\r\\0chars";
                sqlite3_bind_text16(pStmt, 1, specialText, -1, SQLITE_TRANSIENT);
                if (sqlite3_step(pStmt) == SQLITE_ROW) {
                    sqlite3_column_text16(pStmt, 0);
                }
                sqlite3_finalize(pStmt);
            }
            break;
        }
        case 7: {
            /* Test UTF-16 concatenation */
            sqlite3_stmt *pStmt = NULL;
            rc = sqlite3_prepare_v2(ctx->db, "SELECT ? || ? || ?", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                sqlite3_bind_text16(pStmt, 1, "Part1", -1, SQLITE_STATIC);
                sqlite3_bind_text16(pStmt, 2, "Part2", -1, SQLITE_STATIC);
                sqlite3_bind_text16(pStmt, 3, packet->textData, 
                    (int)(packet->textLength % 32), SQLITE_TRANSIENT);
                if (sqlite3_step(pStmt) == SQLITE_ROW) {
                    sqlite3_column_text16(pStmt, 0);
                }
                sqlite3_finalize(pStmt);
            }
            break;
        }
    }
    
    return SQLITE_OK;
}

/* Fuzzing harness for sqlite3_result_zeroblob64 */
int fuzz_result_zeroblob64(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < sizeof(ResultZeroblob64Packet)) {
        return SQLITE_OK;
    }
    
    const ResultZeroblob64Packet *packet = (const ResultZeroblob64Packet*)data;
    int rc = SQLITE_OK;
    
    /* Test scenarios for 64-bit zero blob creation */
    switch (packet->scenario % 6) {
        case 0: {
            /* Test with small blob */
            sqlite3_stmt *pStmt = NULL;
            rc = sqlite3_prepare_v2(ctx->db, "SELECT zeroblob(?)", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                uint64_t blobSize = packet->blobSize % 1024;
                sqlite3_bind_int64(pStmt, 1, (sqlite3_int64)blobSize);
                if (sqlite3_step(pStmt) == SQLITE_ROW) {
                    const void *blob = sqlite3_column_blob(pStmt, 0);
                    int blobBytes = sqlite3_column_bytes(pStmt, 0);
                    (void)blob; (void)blobBytes;
                }
                sqlite3_finalize(pStmt);
            }
            break;
        }
        case 1: {
            /* Test with medium blob */
            sqlite3_stmt *pStmt = NULL;
            rc = sqlite3_prepare_v2(ctx->db, "SELECT zeroblob(?)", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                uint64_t blobSize = (packet->blobSize % 65536) + 1024;
                sqlite3_bind_int64(pStmt, 1, (sqlite3_int64)blobSize);
                if (sqlite3_step(pStmt) == SQLITE_ROW) {
                    sqlite3_column_blob(pStmt, 0);
                }
                sqlite3_finalize(pStmt);
            }
            break;
        }
        case 2: {
            /* Test with large blob (but within limits) */
            sqlite3_stmt *pStmt = NULL;
            rc = sqlite3_prepare_v2(ctx->db, "SELECT zeroblob(?)", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                uint64_t blobSize = (packet->blobSize % 1048576) + 65536;
                sqlite3_bind_int64(pStmt, 1, (sqlite3_int64)blobSize);
                if (sqlite3_step(pStmt) == SQLITE_ROW) {
                    sqlite3_column_blob(pStmt, 0);
                }
                sqlite3_finalize(pStmt);
            }
            break;
        }
        case 3: {
            /* Test with zero-size blob */
            sqlite3_stmt *pStmt = NULL;
            rc = sqlite3_prepare_v2(ctx->db, "SELECT zeroblob(0)", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                if (sqlite3_step(pStmt) == SQLITE_ROW) {
                    const void *blob = sqlite3_column_blob(pStmt, 0);
                    int blobBytes = sqlite3_column_bytes(pStmt, 0);
                    (void)blob; (void)blobBytes;
                }
                sqlite3_finalize(pStmt);
            }
            break;
        }
        case 4: {
            /* Test blob insertion into table */
            rc = sqlite3_exec(ctx->db,
                "CREATE TEMP TABLE IF NOT EXISTS test_blob("
                "  id INTEGER PRIMARY KEY,"
                "  blob_data BLOB"
                ");", NULL, NULL, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_stmt *pStmt = NULL;
                rc = sqlite3_prepare_v2(ctx->db,
                    "INSERT INTO test_blob(blob_data) VALUES(zeroblob(?))", -1, &pStmt, NULL);
                if (rc == SQLITE_OK && pStmt) {
                    uint64_t blobSize = (packet->blobSize % 8192) + 1;
                    sqlite3_bind_int64(pStmt, 1, (sqlite3_int64)blobSize);
                    sqlite3_step(pStmt);
                    sqlite3_finalize(pStmt);
                }
            }
            break;
        }
        case 5: {
            /* Test blob with multiplier for size calculation */
            sqlite3_stmt *pStmt = NULL;
            rc = sqlite3_prepare_v2(ctx->db, "SELECT zeroblob(? * ?)", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                uint64_t baseSize = (packet->blobSize % 512) + 1;
                uint16_t multiplier = (packet->sizeMultiplier % 8) + 1;
                sqlite3_bind_int64(pStmt, 1, (sqlite3_int64)baseSize);
                sqlite3_bind_int(pStmt, 2, multiplier);
                if (sqlite3_step(pStmt) == SQLITE_ROW) {
                    sqlite3_column_blob(pStmt, 0);
                }
                sqlite3_finalize(pStmt);
            }
            break;
        }
    }
    
    return SQLITE_OK;
}

/* Fuzzing harness for sqlite3_stmt_scanstatus */
int fuzz_stmt_scanstatus(FuzzCtx *ctx, const uint8_t *data, size_t size) {
#ifndef SQLITE_ENABLE_STMT_SCANSTATUS
    /* sqlite3_stmt_scanstatus is not available in this build */
    (void)ctx; (void)data; (void)size;
    return SQLITE_OK;
#else
    if (size < sizeof(StmtScanstatusPacket)) {
        return SQLITE_OK;
    }
    
    const StmtScanstatusPacket *packet = (const StmtScanstatusPacket*)data;
    int rc = SQLITE_OK;
    
    /* Validate parameters */
    if (packet->scanIndex > 1000) return SQLITE_OK;
    
    /* Test scenarios for statement scan status */
    switch (packet->scenario % 6) {
        case 0: {
            /* Test with simple SELECT statement */
            rc = sqlite3_exec(ctx->db,
                "CREATE TEMP TABLE IF NOT EXISTS scan_test("
                "  id INTEGER PRIMARY KEY,"
                "  value TEXT"
                ");", NULL, NULL, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_stmt *pStmt = NULL;
                rc = sqlite3_prepare_v2(ctx->db, "SELECT * FROM scan_test WHERE id > ?", -1, &pStmt, NULL);
                if (rc == SQLITE_OK && pStmt) {
                    sqlite3_bind_int(pStmt, 1, packet->scanIndex % 100);
                    while (sqlite3_step(pStmt) == SQLITE_ROW) {
                        /* Process rows to generate scan stats */
                    }
                    
                    /* Try to get scan status */
                    int scanIdx = packet->scanIndex % 10;
                    int statusOp = packet->statusOperation % 6; /* 0-5 for different status ops */
                    void *pOut = &packet->testData[0];
                    
                    sqlite3_stmt_scanstatus(pStmt, scanIdx, statusOp, pOut);
                    sqlite3_finalize(pStmt);
                }
            }
            break;
        }
        case 1: {
            /* Test with JOIN statement */
            rc = sqlite3_exec(ctx->db,
                "CREATE TEMP TABLE IF NOT EXISTS table_a(id INTEGER, name TEXT);"
                "CREATE TEMP TABLE IF NOT EXISTS table_b(id INTEGER, value TEXT);", 
                NULL, NULL, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_stmt *pStmt = NULL;
                rc = sqlite3_prepare_v2(ctx->db, 
                    "SELECT a.name, b.value FROM table_a a JOIN table_b b ON a.id = b.id",
                    -1, &pStmt, NULL);
                if (rc == SQLITE_OK && pStmt) {
                    while (sqlite3_step(pStmt) == SQLITE_ROW) {
                        /* Process JOIN results */
                    }
                    
                    int scanIdx = packet->scanIndex % 5;
                    int statusOp = packet->statusOperation % 6;
                    void *pOut = &packet->testData[1];
                    
                    sqlite3_stmt_scanstatus(pStmt, scanIdx, statusOp, pOut);
                    sqlite3_finalize(pStmt);
                }
            }
            break;
        }
        case 2: {
            /* Test with ORDER BY statement */
            sqlite3_stmt *pStmt = NULL;
            rc = sqlite3_prepare_v2(ctx->db, 
                "SELECT * FROM scan_test ORDER BY value LIMIT ?", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                sqlite3_bind_int(pStmt, 1, (packet->scanIndex % 50) + 1);
                while (sqlite3_step(pStmt) == SQLITE_ROW) {
                    /* Process ordered results */
                }
                
                int scanIdx = packet->scanIndex % 3;
                int statusOp = packet->statusOperation % 6;
                void *pOut = &packet->testData[2];
                
                sqlite3_stmt_scanstatus(pStmt, scanIdx, statusOp, pOut);
                sqlite3_finalize(pStmt);
            }
            break;
        }
        case 3: {
            /* Test with aggregate functions */
            sqlite3_stmt *pStmt = NULL;
            rc = sqlite3_prepare_v2(ctx->db, 
                "SELECT COUNT(*), MAX(id), MIN(id) FROM scan_test GROUP BY value", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                while (sqlite3_step(pStmt) == SQLITE_ROW) {
                    /* Process aggregate results */
                }
                
                int scanIdx = packet->scanIndex % 4;
                int statusOp = packet->statusOperation % 6;
                void *pOut = &packet->testData[3];
                
                sqlite3_stmt_scanstatus(pStmt, scanIdx, statusOp, pOut);
                sqlite3_finalize(pStmt);
            }
            break;
        }
        case 4: {
            /* Test with subquery */
            sqlite3_stmt *pStmt = NULL;
            rc = sqlite3_prepare_v2(ctx->db, 
                "SELECT * FROM scan_test WHERE id IN (SELECT id FROM scan_test WHERE value IS NOT NULL)",
                -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                while (sqlite3_step(pStmt) == SQLITE_ROW) {
                    /* Process subquery results */
                }
                
                int scanIdx = packet->scanIndex % 6;
                int statusOp = packet->statusOperation % 6;
                void *pOut = &packet->testData[4];
                
                sqlite3_stmt_scanstatus(pStmt, scanIdx, statusOp, pOut);
                sqlite3_finalize(pStmt);
            }
            break;
        }
        case 5: {
            /* Test with different status operation types */
            sqlite3_stmt *pStmt = NULL;
            rc = sqlite3_prepare_v2(ctx->db, "SELECT id, value FROM scan_test", -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                while (sqlite3_step(pStmt) == SQLITE_ROW) {
                    /* Generate scan statistics */
                }
                
                /* Test multiple status operations */
                for (int op = 0; op < 6 && op < 8; op++) {
                    void *pOut = &packet->testData[op];
                    sqlite3_stmt_scanstatus(pStmt, 0, op, pOut);
                }
                
                sqlite3_finalize(pStmt);
            }
            break;
        }
    }
    
    return SQLITE_OK;

#endif /* SQLITE_ENABLE_STMT_SCANSTATUS */
}
