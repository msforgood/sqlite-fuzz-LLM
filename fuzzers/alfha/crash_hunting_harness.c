/*
** SQLite3 Crash Hunting Harness Implementation
** 크래시 발견 확률을 극대화하는 공격적인 하니스
*/

#include "crash_hunting_harness.h"
#include "fuzz.h"
#include <string.h>
#include <stdio.h>

/*
** 고위험 메모리 관리 함수 스트레스 테스트
** 메모리 할당/해제 패턴을 공격적으로 조작해서 크래시 유발
*/
int fuzz_memory_stress_crash(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < sizeof(memory_stress_packet)) return 0;
    
    const memory_stress_packet *packet = (const memory_stress_packet *)data;
    
    /* sqlite3_mprintf/sqlite3_free 대량 호출로 힙 파편화 */
    for (int i = 0; i < (packet->alloc_count % 1000); i++) {
        char *ptrs[100];
        int alloc_sizes[] = {1, 7, 15, 31, 63, 127, 255, 511, 1023, 2047, 4095, 8191};
        
        /* 다양한 크기로 할당 */
        for (int j = 0; j < 100; j++) {
            int size_idx = (packet->fragmentation_level + i + j) % 12;
            ptrs[j] = sqlite3_mprintf("%*c", alloc_sizes[size_idx], 'A' + (j % 26));
        }
        
        /* 패턴별 해제 (크래시 유발) */
        switch (packet->alloc_pattern % 4) {
            case 0: /* 역순 해제 */
                for (int j = 99; j >= 0; j--) {
                    if (ptrs[j]) sqlite3_free(ptrs[j]);
                }
                break;
            case 1: /* 홀수만 해제 (메모리 누수 유발) */
                for (int j = 1; j < 100; j += 2) {
                    if (ptrs[j]) sqlite3_free(ptrs[j]);
                }
                break;
            case 2: /* 랜덤 패턴 해제 */
                for (int j = 0; j < 100; j++) {
                    if ((packet->payload[j % 64] & 1) && ptrs[j]) {
                        sqlite3_free(ptrs[j]);
                    }
                }
                break;
            case 3: /* 모두 해제 */
                for (int j = 0; j < 100; j++) {
                    if (ptrs[j]) sqlite3_free(ptrs[j]);
                }
                break;
        }
    }
    
    /* VDBE 메모리 조작 - sqlite3VdbeMemSetStr 크래시 시도 */
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(ctx->db, "SELECT ?", -1, &stmt, NULL) == SQLITE_OK) {
        /* 극단적인 문자열 크기로 메모리 압박 */
        char large_string[8192];
        memset(large_string, 'X', sizeof(large_string) - 1);
        large_string[sizeof(large_string) - 1] = '\0';
        
        /* 대량 바인딩으로 메모리 재할당 강제 */
        for (int i = 0; i < (packet->pressure_intensity % 100); i++) {
            sqlite3_bind_text(stmt, 1, large_string, -1, SQLITE_TRANSIENT);
            sqlite3_step(stmt);
            sqlite3_reset(stmt);
        }
        sqlite3_finalize(stmt);
    }
    
    return 1;
}

/*
** 파서 오버플로우 크래시 하니스
** SQL 파서의 경계 조건을 악용해서 크래시 유발
*/
int fuzz_parser_overflow_crash(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < sizeof(parser_overflow_packet)) return 0;
    
    const parser_overflow_packet *packet = (const parser_overflow_packet *)data;
    
    /* 깊이 중첩된 SQL로 스택 오버플로우 시도 */
    char deep_sql[4096];
    snprintf(deep_sql, sizeof(deep_sql), "SELECT ");
    
    int nest_count = packet->nesting_depth % 200;
    for (int i = 0; i < nest_count; i++) {
        strncat(deep_sql, "(SELECT ", sizeof(deep_sql) - strlen(deep_sql) - 1);
    }
    strncat(deep_sql, "1", sizeof(deep_sql) - strlen(deep_sql) - 1);
    for (int i = 0; i < nest_count; i++) {
        strncat(deep_sql, ")", sizeof(deep_sql) - strlen(deep_sql) - 1);
    }
    
    sqlite3_exec(ctx->db, deep_sql, NULL, NULL, NULL);
    
    /* 극단적인 UNION 체인으로 메모리 소진 시도 */
    char union_sql[4096] = "SELECT 1 ";
    for (int i = 0; i < (packet->overflow_type % 100); i++) {
        strncat(union_sql, "UNION ALL SELECT ", sizeof(union_sql) - strlen(union_sql) - 1);
        char num[16];
        snprintf(num, sizeof(num), "%d ", i);
        strncat(union_sql, num, sizeof(union_sql) - strlen(union_sql) - 1);
    }
    
    sqlite3_exec(ctx->db, union_sql, NULL, NULL, NULL);
    
    /* 악형 SQL 직접 실행 */
    if (packet->sql_length > 0 && packet->sql_length < 512) {
        char malformed[513];
        memcpy(malformed, packet->malformed_sql, packet->sql_length);
        malformed[packet->sql_length] = '\0';
        sqlite3_exec(ctx->db, malformed, NULL, NULL, NULL);
    }
    
    return 1;
}

/*
** 경계 위반 크래시 하니스
** 배열 경계, 인덱스 오버플로우 등으로 크래시 유발
*/
int fuzz_boundary_violation_crash(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < sizeof(boundary_violation_packet)) return 0;
    
    const boundary_violation_packet *packet = (const boundary_violation_packet *)data;
    
    /* 대용량 테이블 생성 후 경계 위반 시도 */
    sqlite3_exec(ctx->db, "CREATE TABLE IF NOT EXISTS boundary_test (id INTEGER, data TEXT)", NULL, NULL, NULL);
    
    /* 극단적인 인덱스 값으로 접근 시도 */
    char boundary_sql[512];
    snprintf(boundary_sql, sizeof(boundary_sql), 
        "INSERT INTO boundary_test VALUES (%u, '%.*s')", 
        packet->target_index,
        (int)(packet->boundary_value % 100),
        (char*)packet->crash_data);
    
    sqlite3_exec(ctx->db, boundary_sql, NULL, NULL, NULL);
    
    /* LIMIT/OFFSET 경계 위반 */
    snprintf(boundary_sql, sizeof(boundary_sql),
        "SELECT * FROM boundary_test LIMIT %d OFFSET %u",
        packet->signed_overflow,
        packet->boundary_value);
    
    sqlite3_exec(ctx->db, boundary_sql, NULL, NULL, NULL);
    
    /* 컬럼 인덱스 오버플로우 시도 */
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(ctx->db, "SELECT * FROM boundary_test", -1, &stmt, NULL) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            /* 존재하지 않는 컬럼 인덱스 접근 시도 */
            sqlite3_column_text(stmt, packet->target_index % 1000);
            sqlite3_column_int(stmt, packet->boundary_value % 1000);
        }
        sqlite3_finalize(stmt);
    }
    
    return 1;
}

/*
** 문자열 조작 크래시 하니스
** 문자열 처리 함수의 버퍼 오버플로우 유발
*/
int fuzz_string_manipulation_crash(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < 32) return 0;
    
    /* 극단적인 문자열 조작 */
    char extreme_strings[][256] = {
        "%n%n%n%n%s%s%s%x%x%x",  /* 포맷 문자열 */
        "A" "\x00" "B" "\xFF" "C",  /* 널 바이트 포함 */
        "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F",  /* 제어 문자 */
        "'';DROP TABLE test;--",  /* SQL 인젝션 */
        "SELECT load_extension('../../../../../../bin/sh')",  /* 경로 순회 */
    };
    
    for (int i = 0; i < 5; i++) {
        char *result = sqlite3_mprintf("%q", extreme_strings[i]);
        if (result) {
            /* 결과 문자열 조작으로 크래시 시도 */
            char manipulation_sql[1024];
            snprintf(manipulation_sql, sizeof(manipulation_sql),
                "SELECT '%s' AS test_col", result);
            sqlite3_exec(ctx->db, manipulation_sql, NULL, NULL, NULL);
            sqlite3_free(result);
        }
    }
    
    /* UTF-8 처리 크래시 시도 */
    const char *utf8_crash[] = {
        "\xF0\x90\x80\x80",  /* 올바른 4바이트 UTF-8 */
        "\xF0\x90\x80",      /* 불완전한 4바이트 */
        "\xF0\x90",          /* 불완전한 4바이트 */
        "\xF0",              /* 불완전한 4바이트 */
        "\xFF\xFE\xFD\xFC",  /* 잘못된 UTF-8 */
    };
    
    for (int i = 0; i < 5; i++) {
        char utf8_sql[256];
        snprintf(utf8_sql, sizeof(utf8_sql), "SELECT '%s'", utf8_crash[i]);
        sqlite3_exec(ctx->db, utf8_sql, NULL, NULL, NULL);
    }
    
    return 1;
}

/*
** 재귀 호출 크래시 하니스
** WITH RECURSIVE, 트리거 등으로 스택 오버플로우 유발
*/
int fuzz_recursive_calls_crash(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < 16) return 0;
    
    uint32_t depth = *(uint32_t*)data % 10000;
    
    /* 깊은 재귀 CTE */
    char recursive_sql[2048];
    snprintf(recursive_sql, sizeof(recursive_sql),
        "WITH RECURSIVE deep_recursion(x) AS ("
        "  SELECT 1 "
        "  UNION ALL "
        "  SELECT x+1 FROM deep_recursion WHERE x < %u"
        ") SELECT COUNT(*) FROM deep_recursion", depth);
    
    sqlite3_exec(ctx->db, recursive_sql, NULL, NULL, NULL);
    
    /* 중첩 트리거로 무한 재귀 시도 */
    sqlite3_exec(ctx->db, "CREATE TABLE IF NOT EXISTS trigger_test (id INTEGER)", NULL, NULL, NULL);
    sqlite3_exec(ctx->db, "DROP TRIGGER IF EXISTS recursive_trigger", NULL, NULL, NULL);
    sqlite3_exec(ctx->db, 
        "CREATE TRIGGER recursive_trigger AFTER INSERT ON trigger_test "
        "BEGIN "
        "  INSERT INTO trigger_test VALUES (NEW.id + 1); "
        "END", NULL, NULL, NULL);
    
    sqlite3_exec(ctx->db, "INSERT INTO trigger_test VALUES (1)", NULL, NULL, NULL);
    
    return 1;
}

/*
** 악형 SQL 크래시 하니스
** 다양한 SQL 문법 오류와 극단적인 조건으로 크래시 유발
*/
int fuzz_malformed_sql_crash(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    /* 크래시를 유발할 수 있는 악형 SQL 패턴들 */
    const char *crash_sqls[] = {
        "SELECT * FROM sqlite_master WHERE sql LIKE '%'||CHAR(0)||'%'",
        "PRAGMA table_info('" "\x00\xFF\xFE" "')",
        "CREATE TABLE test AS SELECT * FROM (" "\x00" "malformed" "\x00" ")",
        "INSERT INTO nonexistent VALUES (1/0, 1%0, 1<<1000)",
        "SELECT CASE WHEN 1=1 THEN (SELECT COUNT(*) FROM sqlite_temp_master) END",
        "ATTACH ':memory:' AS crash_db; SELECT * FROM crash_db.sqlite_master",
        "WITH x(a,b) AS (SELECT 1,2 UNION ALL SELECT 3,4) SELECT * FROM x,x,x,x,x,x,x,x",
        "SELECT randomblob(-1), randomblob(2147483647)",
        "CREATE UNIQUE INDEX crash_idx ON nonexistent(nonexistent_col)",
        "PRAGMA journal_mode=DELETE; PRAGMA journal_mode=WAL; PRAGMA journal_mode=MEMORY",
    };
    
    for (int i = 0; i < 10; i++) {
        sqlite3_exec(ctx->db, crash_sqls[i], NULL, NULL, NULL);
    }
    
    /* 데이터 기반 악형 SQL 생성 */
    if (size >= 8) {
        char dynamic_sql[512];
        uint8_t pattern = data[0];
        uint16_t str_len = *(uint16_t*)(data + 1) % 200;
        
        switch (pattern % 4) {
            case 0:
                snprintf(dynamic_sql, sizeof(dynamic_sql),
                    "SELECT %.*s FROM sqlite_master", str_len, (char*)(data + 8));
                break;
            case 1:
                snprintf(dynamic_sql, sizeof(dynamic_sql),
                    "CREATE TABLE crash_%.*s (id INTEGER)", str_len, (char*)(data + 8));
                break;
            case 2:
                snprintf(dynamic_sql, sizeof(dynamic_sql),
                    "PRAGMA %.*s", str_len, (char*)(data + 8));
                break;
            case 3:
                snprintf(dynamic_sql, sizeof(dynamic_sql),
                    "SELECT CASE WHEN LENGTH('%.*s') > 1000000 THEN 1 END", 
                    str_len, (char*)(data + 8));
                break;
        }
        sqlite3_exec(ctx->db, dynamic_sql, NULL, NULL, NULL);
    }
    
    return 1;
}

/*
** 인덱스 손상 크래시 하니스
** 인덱스 구조 손상을 시뮬레이션해서 크래시 유발
*/
int fuzz_index_corruption_crash(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < 4) return 0;
    
    /* 복잡한 인덱스 시나리오 */
    sqlite3_exec(ctx->db, "CREATE TABLE IF NOT EXISTS idx_test (a TEXT, b INTEGER, c REAL)", NULL, NULL, NULL);
    sqlite3_exec(ctx->db, "CREATE INDEX IF NOT EXISTS idx_a ON idx_test(a)", NULL, NULL, NULL);
    sqlite3_exec(ctx->db, "CREATE INDEX IF NOT EXISTS idx_b ON idx_test(b)", NULL, NULL, NULL);
    sqlite3_exec(ctx->db, "CREATE UNIQUE INDEX IF NOT EXISTS idx_unique ON idx_test(c)", NULL, NULL, NULL);
    
    /* 대량 데이터 삽입 후 인덱스 조작 */
    uint32_t record_count = *(uint32_t*)data % 10000;
    for (uint32_t i = 0; i < record_count; i++) {
        char insert_sql[256];
        snprintf(insert_sql, sizeof(insert_sql),
            "INSERT OR IGNORE INTO idx_test VALUES ('test_%u', %u, %u.%u)",
            i, i, i, i % 1000);
        sqlite3_exec(ctx->db, insert_sql, NULL, NULL, NULL);
    }
    
    /* 인덱스 관련 크래시 시도 */
    const char *index_crash_sqls[] = {
        "REINDEX idx_test",
        "DROP INDEX idx_unique",
        "ANALYZE idx_test",
        "SELECT * FROM idx_test WHERE a > 'test_' || CHAR(0)",
        "UPDATE idx_test SET c = c + 0.1 WHERE b % 2 = 0",
    };
    
    for (int i = 0; i < 5; i++) {
        sqlite3_exec(ctx->db, index_crash_sqls[i], NULL, NULL, NULL);
    }
    
    return 1;
}

/*
** 트랜잭션 남용 크래시 하니스
** 트랜잭션 상태 조작으로 크래시 유발
*/
int fuzz_transaction_abuse_crash(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < 2) return 0;
    
    uint8_t pattern = data[0];
    uint8_t count = data[1] % 100;
    
    /* 중첩 트랜잭션 패턴 */
    switch (pattern % 4) {
        case 0: /* 다중 BEGIN */
            for (int i = 0; i < count; i++) {
                sqlite3_exec(ctx->db, "BEGIN", NULL, NULL, NULL);
            }
            sqlite3_exec(ctx->db, "COMMIT", NULL, NULL, NULL);
            break;
            
        case 1: /* 불일치 COMMIT/ROLLBACK */
            sqlite3_exec(ctx->db, "BEGIN", NULL, NULL, NULL);
            for (int i = 0; i < count; i++) {
                if (i % 2) {
                    sqlite3_exec(ctx->db, "COMMIT", NULL, NULL, NULL);
                } else {
                    sqlite3_exec(ctx->db, "ROLLBACK", NULL, NULL, NULL);
                }
            }
            break;
            
        case 2: /* SAVEPOINT 남용 */
            sqlite3_exec(ctx->db, "BEGIN", NULL, NULL, NULL);
            for (int i = 0; i < count; i++) {
                char savepoint_sql[64];
                snprintf(savepoint_sql, sizeof(savepoint_sql), "SAVEPOINT sp_%d", i);
                sqlite3_exec(ctx->db, savepoint_sql, NULL, NULL, NULL);
            }
            sqlite3_exec(ctx->db, "ROLLBACK", NULL, NULL, NULL);
            break;
            
        case 3: /* 트랜잭션 중 DDL */
            sqlite3_exec(ctx->db, "BEGIN", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "CREATE TABLE IF NOT EXISTS txn_test (id INTEGER)", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "DROP TABLE txn_test", NULL, NULL, NULL);
            sqlite3_exec(ctx->db, "COMMIT", NULL, NULL, NULL);
            break;
    }
    
    return 1;
}

/*
** 대량 저위험 함수 배치 하니스
** 간단한 함수들을 빠르게 커버하여 진척도 향상
*/
int fuzz_batch_low_risk_functions(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < 16) return 0;
    
    /* SQL 함수들 빠른 테스트 */
    const char *batch_sqls[] = {
        "SELECT ABS(-42), LENGTH('test'), UPPER('lower'), LOWER('UPPER')",
        "SELECT SUBSTR('hello', 2, 3), REPLACE('abc', 'b', 'x')",
        "SELECT ROUND(3.14159, 2), MAX(1,2,3), MIN(1,2,3)",
        "SELECT COALESCE(NULL, 'default'), IFNULL(NULL, 'null')",
        "SELECT TYPEOF(123), TYPEOF('text'), TYPEOF(3.14)",
        "SELECT HEX('ABC'), UNHEX('414243'), QUOTE('test')",
        "SELECT TRIM(' test '), LTRIM(' test'), RTRIM('test ')",
        "SELECT INSTR('hello', 'l'), GLOB('*test*', 'testing')",
        "SELECT DATE('now'), TIME('now'), DATETIME('now')",
        "SELECT RANDOM(), RANDOMBLOB(8), ZEROBLOB(16)",
    };
    
    for (int i = 0; i < 10; i++) {
        sqlite3_exec(ctx->db, batch_sqls[i], NULL, NULL, NULL);
    }
    
    /* PRAGMA 명령들 빠른 테스트 */
    const char *pragma_tests[] = {
        "PRAGMA compile_options",
        "PRAGMA database_list",
        "PRAGMA foreign_key_list(sqlite_master)",
        "PRAGMA function_list",
        "PRAGMA module_list",
        "PRAGMA pragma_list",
        "PRAGMA table_info(sqlite_master)",
        "PRAGMA index_list(sqlite_master)",
        "PRAGMA collation_list",
        "PRAGMA freelist_count",
    };
    
    for (int i = 0; i < 10; i++) {
        sqlite3_exec(ctx->db, pragma_tests[i], NULL, NULL, NULL);
    }
    
    /* 준비된 문장 빠른 테스트 */
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(ctx->db, "SELECT ?1, ?2, ?3", -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, *(int*)data);
        sqlite3_bind_text(stmt, 2, (char*)(data + 4), 8, SQLITE_STATIC);
        sqlite3_bind_double(stmt, 3, 3.14159);
        
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            sqlite3_column_int(stmt, 0);
            sqlite3_column_text(stmt, 1);
            sqlite3_column_double(stmt, 2);
        }
        sqlite3_finalize(stmt);
    }
    
    return 1;
}