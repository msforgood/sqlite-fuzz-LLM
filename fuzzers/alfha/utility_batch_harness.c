/*
** SQLite3 Utility Functions Batch Harness Implementation
** 저위험 유틸리티 함수들의 대량 배치 테스팅 구현
*/

#include "utility_batch_harness.h"
#include <string.h>
#include <stdlib.h>
#include <math.h>

/* 수학 함수 배치 테스트 */
int fuzz_math_functions_batch(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < sizeof(utility_batch_packet)) return 0;
    
    utility_batch_packet *packet = (utility_batch_packet*)data;
    sqlite3 *db = ctx->db;
    sqlite3_stmt *pStmt = NULL;
    int rc;
    
    /* 수학 함수 테스트용 SQL들 */
    const char *math_queries[] = {
        "SELECT ABS(?1), ABS(?2)",
        "SELECT ROUND(?1), ROUND(?2, 2)",
        "SELECT RANDOM(), RANDOM()",
        "SELECT MIN(?1, ?2), MAX(?1, ?2)",
        "SELECT SIGN(?1), SIGN(?2)",
        "SELECT SQRT(?1), POWER(?2, 2)",
        "SELECT SIN(?1), COS(?2)",
        "SELECT LOG(?1), EXP(?2)",
        "SELECT FLOOR(?1), CEIL(?2)",
        "SELECT MOD(?1, 7), (?2 % 5)"
    };
    
    int iterations = packet->iteration_count % 20 + 5; // 5-24 반복
    
    for (int i = 0; i < iterations; i++) {
        for (size_t q = 0; q < sizeof(math_queries) / sizeof(math_queries[0]); q++) {
            rc = sqlite3_prepare_v2(db, math_queries[q], -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                /* 매개변수 바인딩 */
                double val1 = packet->numeric_params[i % 8];
                double val2 = packet->numeric_params[(i + 1) % 8];
                
                /* 매개변수 변형 적용 */
                switch (packet->param_variation % 4) {
                    case 0: // 정상 값
                        break;
                    case 1: // 큰 값
                        val1 *= 1000000;
                        val2 *= 1000000;
                        break;
                    case 2: // 작은 값
                        val1 /= 1000000;
                        val2 /= 1000000;
                        break;
                    case 3: // 음수
                        val1 = -fabs(val1);
                        val2 = -fabs(val2);
                        break;
                }
                
                sqlite3_bind_double(pStmt, 1, val1);
                sqlite3_bind_double(pStmt, 2, val2);
                
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
        }
    }
    
    return 1;
}

/* 날짜/시간 함수 배치 테스트 */
int fuzz_datetime_functions_batch(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < sizeof(utility_batch_packet)) return 0;
    
    utility_batch_packet *packet = (utility_batch_packet*)data;
    sqlite3 *db = ctx->db;
    sqlite3_stmt *pStmt = NULL;
    int rc;
    
    /* 날짜/시간 함수 테스트용 SQL들 */
    const char *datetime_queries[] = {
        "SELECT datetime('now'), date('now'), time('now')",
        "SELECT datetime(?1), date(?1), time(?1)",
        "SELECT strftime('%Y-%m-%d', 'now'), strftime('%H:%M:%S', 'now')",
        "SELECT julianday('now'), julianday(?1)",
        "SELECT datetime('now', '+1 day'), datetime('now', '-1 hour')",
        "SELECT datetime(?1, '+' || ?2 || ' days')",
        "SELECT CAST(strftime('%s', 'now') AS INTEGER)",
        "SELECT datetime(?, 'unixepoch'), datetime(?, 'unixepoch', 'localtime')"
    };
    
    /* 테스트용 날짜 문자열들 */
    const char *test_dates[] = {
        "2023-01-01",
        "2023-12-31 23:59:59",
        "1970-01-01 00:00:00",
        "2038-01-19 03:14:07",
        packet->string_params
    };
    
    int iterations = packet->iteration_count % 10 + 3;
    
    for (int i = 0; i < iterations; i++) {
        for (size_t q = 0; q < sizeof(datetime_queries) / sizeof(datetime_queries[0]); q++) {
            rc = sqlite3_prepare_v2(db, datetime_queries[q], -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                int param_count = sqlite3_bind_parameter_count(pStmt);
                
                for (int p = 1; p <= param_count; p++) {
                    if (q < 6) { // 문자열 날짜
                        sqlite3_bind_text(pStmt, p, 
                                         test_dates[i % (sizeof(test_dates) / sizeof(test_dates[0]))], 
                                         -1, SQLITE_STATIC);
                    } else { // Unix 타임스탬프
                        sqlite3_bind_int64(pStmt, p, 
                                          (sqlite3_int64)(packet->numeric_params[i % 8] * 86400 + 946684800));
                    }
                }
                
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
        }
    }
    
    return 1;
}

/* 시스템 정보 함수 배치 테스트 */
int fuzz_system_info_batch(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < sizeof(utility_batch_packet)) return 0;
    
    sqlite3 *db = ctx->db;
    
    /* 시스템 정보 함수들 */
    const char *sysinfo_queries[] = {
        "SELECT sqlite_version()",
        "SELECT sqlite_source_id()",
        "SELECT sqlite_compileoption_used('THREADSAFE')",
        "SELECT sqlite_compileoption_get(0)",
        "SELECT changes(), total_changes()",
        "SELECT last_insert_rowid()",
        "PRAGMA compile_options",
        "PRAGMA integrity_check(1)",
        "PRAGMA quick_check(1)",
        "PRAGMA table_info('sqlite_master')"
    };
    
    for (size_t q = 0; q < sizeof(sysinfo_queries) / sizeof(sysinfo_queries[0]); q++) {
        sqlite3_stmt *pStmt;
        int rc = sqlite3_prepare_v2(db, sysinfo_queries[q], -1, &pStmt, NULL);
        if (rc == SQLITE_OK && pStmt) {
            while (sqlite3_step(pStmt) == SQLITE_ROW) {
                /* 결과 읽기 */
                int cols = sqlite3_column_count(pStmt);
                for (int i = 0; i < cols; i++) {
                    sqlite3_column_text(pStmt, i);
                }
            }
            sqlite3_finalize(pStmt);
        }
    }
    
    return 1;
}

/* 타입 변환 함수 배치 테스트 */
int fuzz_type_conversion_batch(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < sizeof(utility_batch_packet)) return 0;
    
    utility_batch_packet *packet = (utility_batch_packet*)data;
    sqlite3 *db = ctx->db;
    sqlite3_stmt *pStmt = NULL;
    int rc;
    
    /* 타입 변환 테스트용 SQL들 */
    const char *conversion_queries[] = {
        "SELECT CAST(?1 AS INTEGER), CAST(?2 AS REAL)",
        "SELECT CAST(?1 AS TEXT), CAST(?2 AS BLOB)",
        "SELECT TYPEOF(?1), TYPEOF(?2)",
        "SELECT HEX(?1), QUOTE(?2)",
        "SELECT COALESCE(?1, ?2), IFNULL(?1, ?2)",
        "SELECT NULLIF(?1, ?2)",
        "SELECT ?1 + 0, ?2 || ''",
        "SELECT PRINTF('%d', ?1), PRINTF('%f', ?2)"
    };
    
    int iterations = packet->iteration_count % 15 + 5;
    
    for (int i = 0; i < iterations; i++) {
        for (size_t q = 0; q < sizeof(conversion_queries) / sizeof(conversion_queries[0]); q++) {
            rc = sqlite3_prepare_v2(db, conversion_queries[q], -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                /* 다양한 타입 데이터 바인딩 */
                switch (i % 4) {
                    case 0: // 숫자들
                        sqlite3_bind_double(pStmt, 1, packet->numeric_params[i % 8]);
                        sqlite3_bind_int64(pStmt, 2, (sqlite3_int64)packet->numeric_params[(i + 1) % 8]);
                        break;
                    case 1: // 문자열들
                        sqlite3_bind_text(pStmt, 1, packet->string_params, 
                                         (strlen(packet->string_params) < 50) ? strlen(packet->string_params) : 50, 
                                         SQLITE_TRANSIENT);
                        sqlite3_bind_text(pStmt, 2, packet->string_params + 50, 
                                         (strlen(packet->string_params + 50) < 50) ? strlen(packet->string_params + 50) : 50, 
                                         SQLITE_TRANSIENT);
                        break;
                    case 2: // BLOB들
                        sqlite3_bind_blob(pStmt, 1, packet->binary_params, 64, SQLITE_TRANSIENT);
                        sqlite3_bind_blob(pStmt, 2, packet->binary_params + 64, 64, SQLITE_TRANSIENT);
                        break;
                    case 3: // NULL들
                        sqlite3_bind_null(pStmt, 1);
                        sqlite3_bind_null(pStmt, 2);
                        break;
                }
                
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
        }
    }
    
    return 1;
}

/* 단순 집계 함수 배치 테스트 */
int fuzz_aggregate_simple_batch(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < sizeof(utility_batch_packet)) return 0;
    
    utility_batch_packet *packet = (utility_batch_packet*)data;
    sqlite3 *db = ctx->db;
    sqlite3_stmt *pStmt = NULL;
    int rc;
    
    /* 테스트용 임시 테이블 생성 */
    const char *create_sql = "CREATE TEMP TABLE agg_batch_test ("
                            "id INTEGER, "
                            "num_col REAL, "
                            "text_col TEXT)";
    
    rc = sqlite3_exec(db, create_sql, NULL, NULL, NULL);
    if (rc != SQLITE_OK) return 0;
    
    /* 테스트 데이터 삽입 */
    const char *insert_sql = "INSERT INTO agg_batch_test VALUES (?, ?, ?)";
    rc = sqlite3_prepare_v2(db, insert_sql, -1, &pStmt, NULL);
    if (rc != SQLITE_OK) return 0;
    
    int data_count = packet->iteration_count % 50 + 10;
    for (int i = 0; i < data_count; i++) {
        sqlite3_bind_int(pStmt, 1, i);
        sqlite3_bind_double(pStmt, 2, packet->numeric_params[i % 8]);
        sqlite3_bind_text(pStmt, 3, packet->string_params, 
                         (strlen(packet->string_params) < 100) ? strlen(packet->string_params) : 100, 
                         SQLITE_TRANSIENT);
        sqlite3_step(pStmt);
        sqlite3_reset(pStmt);
    }
    sqlite3_finalize(pStmt);
    
    /* 집계 함수 테스트용 SQL들 */
    const char *aggregate_queries[] = {
        "SELECT COUNT(*), COUNT(num_col), COUNT(DISTINCT text_col) FROM agg_batch_test",
        "SELECT SUM(num_col), AVG(num_col), MIN(num_col), MAX(num_col) FROM agg_batch_test",
        "SELECT GROUP_CONCAT(text_col), GROUP_CONCAT(DISTINCT text_col) FROM agg_batch_test",
        "SELECT TOTAL(num_col), TOTAL(id) FROM agg_batch_test",
        "SELECT COUNT(*) FILTER (WHERE num_col > 0) FROM agg_batch_test",
        "SELECT SUM(CASE WHEN num_col > 0 THEN 1 ELSE 0 END) FROM agg_batch_test"
    };
    
    for (size_t q = 0; q < sizeof(aggregate_queries) / sizeof(aggregate_queries[0]); q++) {
        rc = sqlite3_prepare_v2(db, aggregate_queries[q], -1, &pStmt, NULL);
        if (rc == SQLITE_OK && pStmt) {
            sqlite3_step(pStmt);
            sqlite3_finalize(pStmt);
        }
    }
    
    return 1;
}

/* JSON 함수 배치 테스트 */
int fuzz_json_functions_batch(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < sizeof(utility_batch_packet)) return 0;
    
    utility_batch_packet *packet = (utility_batch_packet*)data;
    sqlite3 *db = ctx->db;
    sqlite3_stmt *pStmt = NULL;
    int rc;
    
    /* JSON 함수 테스트용 SQL들 (SQLite 3.51.0 JSON 지원) */
    const char *json_queries[] = {
        "SELECT json_object('key1', ?1, 'key2', ?2)",
        "SELECT json_array(?1, ?2, ?3)",
        "SELECT json_extract(json_object('test', ?1), '$.test')",
        "SELECT json_type(json_object('num', ?1))",
        "SELECT json_valid(?1)",
        "SELECT json_quote(?1)",
        "SELECT json_array_length(json_array(?1, ?2))",
        "SELECT json_insert('{}', '$.new', ?1)"
    };
    
    int iterations = packet->iteration_count % 10 + 3;
    
    for (int i = 0; i < iterations; i++) {
        for (size_t q = 0; q < sizeof(json_queries) / sizeof(json_queries[0]); q++) {
            rc = sqlite3_prepare_v2(db, json_queries[q], -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                int param_count = sqlite3_bind_parameter_count(pStmt);
                
                for (int p = 1; p <= param_count; p++) {
                    switch ((i + p) % 3) {
                        case 0: // 숫자
                            sqlite3_bind_double(pStmt, p, packet->numeric_params[p % 8]);
                            break;
                        case 1: // 문자열
                            sqlite3_bind_text(pStmt, p, packet->string_params, 
                                             (strlen(packet->string_params) < 50) ? strlen(packet->string_params) : 50, 
                                             SQLITE_TRANSIENT);
                            break;
                        case 2: // JSON 문자열
                            sqlite3_bind_text(pStmt, p, "{\"test\":\"value\"}", -1, SQLITE_STATIC);
                            break;
                    }
                }
                
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
        }
    }
    
    return 1;
}

/* 기타 유틸리티 함수 배치 테스트 */
int fuzz_misc_utilities_batch(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < sizeof(utility_batch_packet)) return 0;
    
    utility_batch_packet *packet = (utility_batch_packet*)data;
    sqlite3 *db = ctx->db;
    sqlite3_stmt *pStmt = NULL;
    int rc;
    
    /* 기타 유틸리티 함수들 */
    const char *misc_queries[] = {
        "SELECT INSTR(?1, ?2), INSTR(?2, ?1)",
        "SELECT TRIM(?1), LTRIM(?1), RTRIM(?1)",
        "SELECT PADL(?1, 20, 'X'), PADR(?1, 20, 'Y')",
        "SELECT SOUNDEX(?1)",
        "SELECT RANDOMBLOB(16)",
        "SELECT ZEROBLOB(64)",
        "SELECT IIF(?1 > 0, 'positive', 'negative')",
        "SELECT UNICODE(?1), CHAR(65, 66, 67)",
        "SELECT LOAD_EXTENSION('test') WHERE 0", // 실행되지 않음
        "SELECT ?1 IS NULL, ?1 IS NOT NULL"
    };
    
    int iterations = packet->iteration_count % 8 + 2;
    
    for (int i = 0; i < iterations; i++) {
        for (size_t q = 0; q < sizeof(misc_queries) / sizeof(misc_queries[0]) - 1; q++) { // 마지막 제외
            rc = sqlite3_prepare_v2(db, misc_queries[q], -1, &pStmt, NULL);
            if (rc == SQLITE_OK && pStmt) {
                int param_count = sqlite3_bind_parameter_count(pStmt);
                
                for (int p = 1; p <= param_count; p++) {
                    switch (p % 3) {
                        case 0:
                            sqlite3_bind_text(pStmt, p, packet->string_params, 
                                             (strlen(packet->string_params) < 100) ? strlen(packet->string_params) : 100, 
                                             SQLITE_TRANSIENT);
                            break;
                        case 1:
                            sqlite3_bind_double(pStmt, p, packet->numeric_params[p % 8]);
                            break;
                        case 2:
                            sqlite3_bind_blob(pStmt, p, packet->binary_params, 32, SQLITE_TRANSIENT);
                            break;
                    }
                }
                
                sqlite3_step(pStmt);
                sqlite3_finalize(pStmt);
            }
        }
    }
    
    /* NULL 테스트 */
    const char *null_sql = "SELECT ?1 IS NULL, ?1 IS NOT NULL";
    rc = sqlite3_prepare_v2(db, null_sql, -1, &pStmt, NULL);
    if (rc == SQLITE_OK && pStmt) {
        sqlite3_bind_null(pStmt, 1);
        sqlite3_step(pStmt);
        sqlite3_finalize(pStmt);
    }
    
    return 1;
}