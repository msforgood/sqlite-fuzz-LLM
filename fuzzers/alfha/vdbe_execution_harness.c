/*
** SQLite3 VDBE Execution Engine Harness Implementation
** 가상 데이터베이스 엔진의 복잡한 연산으로 크래시 유발 구현
*/

#include "vdbe_execution_harness.h"
#include <string.h>
#include <stdlib.h>
#include <math.h>

/* VDBE 연산코드 혼돈 - 복잡한 SQL로 내부 연산 스트레스 */
int fuzz_vdbe_opcode_chaos(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < sizeof(opcode_chaos_packet)) return 0;
    
    opcode_chaos_packet *packet = (opcode_chaos_packet*)data;
    sqlite3 *db = ctx->db;
    sqlite3_stmt *pStmt = NULL;
    int rc;
    
    /* 복잡한 연산을 유발하는 테이블 생성 */
    const char *create_sql = "CREATE TEMP TABLE opcode_test ("
                            "id INTEGER PRIMARY KEY, "
                            "num_col REAL, "
                            "text_col TEXT, "
                            "blob_col BLOB)";
    
    rc = sqlite3_exec(db, create_sql, NULL, NULL, NULL);
    if (rc != SQLITE_OK) return 0;
    
    /* 테스트 데이터 삽입 */
    const char *insert_sql = "INSERT INTO opcode_test (num_col, text_col, blob_col) VALUES (?, ?, ?)";
    rc = sqlite3_prepare_v2(db, insert_sql, -1, &pStmt, NULL);
    if (rc != SQLITE_OK) return 0;
    
    int data_count = packet->instruction_count % 50;
    for (int i = 0; i < data_count; i++) {
        double num_val = (double)(packet->execution_pattern ^ i) / 1000.0;
        sqlite3_bind_double(pStmt, 1, num_val);
        sqlite3_bind_text(pStmt, 2, packet->sql_template, 
                         (strlen(packet->sql_template) < 256) ? strlen(packet->sql_template) : 256, 
                         SQLITE_TRANSIENT);
        sqlite3_bind_blob(pStmt, 3, packet->param_data, 
                         (sizeof(packet->param_data) < 256) ? sizeof(packet->param_data) : 256, 
                         SQLITE_TRANSIENT);
        sqlite3_step(pStmt);
        sqlite3_reset(pStmt);
    }
    sqlite3_finalize(pStmt);
    
    /* 연산코드 패턴별 복잡한 쿼리 실행 */
    char complex_sql[2048];
    
    switch (packet->opcode_pattern % 8) {
        case 0: // 복잡한 수학 연산
            snprintf(complex_sql, sizeof(complex_sql),
                    "SELECT SUM(num_col * num_col), AVG(LENGTH(text_col)), "
                    "MAX(num_col + %d), MIN(num_col - %d) FROM opcode_test",
                    packet->chaos_seed, packet->chaos_seed);
            break;
            
        case 1: // 문자열 조작 연산
            snprintf(complex_sql, sizeof(complex_sql),
                    "SELECT SUBSTR(text_col, %d, %d), REPLACE(text_col, 'a', 'X'), "
                    "UPPER(LOWER(text_col)), LENGTH(text_col || text_col) FROM opcode_test",
                    packet->nesting_depth % 10 + 1, packet->complexity_level % 20 + 1);
            break;
            
        case 2: // 타입 변환 연산
            snprintf(complex_sql, sizeof(complex_sql),
                    "SELECT CAST(num_col AS TEXT), CAST(text_col AS REAL), "
                    "CAST(id AS BLOB), TYPEOF(num_col), TYPEOF(text_col) FROM opcode_test");
            break;
            
        case 3: // 집계 함수 중첩
            snprintf(complex_sql, sizeof(complex_sql),
                    "SELECT COUNT(DISTINCT text_col), GROUP_CONCAT(text_col, '|'), "
                    "SUM(CASE WHEN num_col > %f THEN 1 ELSE 0 END) FROM opcode_test",
                    (double)packet->chaos_seed / 100.0);
            break;
            
        case 4: // 윈도우 함수
            snprintf(complex_sql, sizeof(complex_sql),
                    "SELECT ROW_NUMBER() OVER (ORDER BY num_col), "
                    "LAG(num_col, %d) OVER (ORDER BY id), "
                    "DENSE_RANK() OVER (PARTITION BY LENGTH(text_col) ORDER BY num_col) FROM opcode_test",
                    packet->nesting_depth % 5 + 1);
            break;
            
        case 5: // 복잡한 조건부 표현식
            snprintf(complex_sql, sizeof(complex_sql),
                    "SELECT CASE "
                    "WHEN num_col > %f THEN 'HIGH' "
                    "WHEN num_col > %f THEN 'MED' "
                    "ELSE 'LOW' END, "
                    "IIF(LENGTH(text_col) > %d, 'LONG', 'SHORT') FROM opcode_test",
                    (double)packet->chaos_seed / 50.0,
                    (double)packet->chaos_seed / 100.0,
                    packet->complexity_level);
            break;
            
        case 6: // JSON 연산 (SQLite 3.51.0 지원)
            snprintf(complex_sql, sizeof(complex_sql),
                    "SELECT json_object('id', id, 'num', num_col, 'text', text_col), "
                    "json_extract(json_object('test', text_col), '$.test') FROM opcode_test");
            break;
            
        case 7: // 복합 서브쿼리
            snprintf(complex_sql, sizeof(complex_sql),
                    "SELECT * FROM opcode_test WHERE num_col > "
                    "(SELECT AVG(num_col) FROM opcode_test WHERE id < %d) "
                    "AND LENGTH(text_col) < "
                    "(SELECT MAX(LENGTH(text_col)) FROM opcode_test WHERE num_col > %f)",
                    packet->instruction_count % 20,
                    (double)packet->param_corruption / 1000.0);
            break;
    }
    
    /* 복잡한 쿼리 실행 */
    rc = sqlite3_prepare_v2(db, complex_sql, -1, &pStmt, NULL);
    if (rc == SQLITE_OK && pStmt) {
        while (sqlite3_step(pStmt) == SQLITE_ROW) {
            /* 결과 컬럼 액세스로 VDBE 연산 트리거 */
            int col_count = sqlite3_column_count(pStmt);
            for (int i = 0; i < col_count; i++) {
                sqlite3_column_text(pStmt, i);
                sqlite3_column_double(pStmt, i);
                sqlite3_column_type(pStmt, i);
            }
        }
        sqlite3_finalize(pStmt);
    }
    
    return 1;
}

/* VDBE 스택 오버플로우 - 깊은 재귀와 함수 호출 */
int fuzz_vdbe_stack_overflow(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < sizeof(stack_overflow_packet)) return 0;
    
    stack_overflow_packet *packet = (stack_overflow_packet*)data;
    sqlite3 *db = ctx->db;
    int rc;
    
    /* 재귀 CTE를 위한 테스트 테이블 */
    const char *create_sql = "CREATE TEMP TABLE recursive_test (n INTEGER)";
    rc = sqlite3_exec(db, create_sql, NULL, NULL, NULL);
    if (rc != SQLITE_OK) return 0;
    
    /* 초기 데이터 */
    sqlite3_exec(db, "INSERT INTO recursive_test VALUES (1)", NULL, NULL, NULL);
    
    /* 스택 연산 패턴별 재귀 쿼리 */
    char recursive_sql[4096];
    int recursion_limit = packet->recursion_depth % 100 + 10; // 10-109 제한
    
    switch (packet->stack_operation % 4) {
        case 0: // 단순 재귀 카운터
            snprintf(recursive_sql, sizeof(recursive_sql),
                    "WITH RECURSIVE counter(n) AS ("
                    "SELECT 1 "
                    "UNION ALL "
                    "SELECT n + 1 FROM counter WHERE n < %d"
                    ") SELECT COUNT(*) FROM counter", recursion_limit);
            break;
            
        case 1: // 재귀적 문자열 생성
            snprintf(recursive_sql, sizeof(recursive_sql),
                    "WITH RECURSIVE str_builder(level, str) AS ("
                    "SELECT 1, '%.*s' "
                    "UNION ALL "
                    "SELECT level + 1, str || '%.*s' FROM str_builder WHERE level < %d"
                    ") SELECT LENGTH(str) FROM str_builder ORDER BY level DESC LIMIT 1",
                    (int)(size % 20), (char*)data,
                    (int)(size % 20), (char*)data,
                    recursion_limit);
            break;
            
        case 2: // 재귀적 수학 계산 (피보나치 스타일)
            snprintf(recursive_sql, sizeof(recursive_sql),
                    "WITH RECURSIVE fib(n, a, b) AS ("
                    "SELECT 0, 0, 1 "
                    "UNION ALL "
                    "SELECT n + 1, b, a + b FROM fib WHERE n < %d"
                    ") SELECT MAX(b) FROM fib", recursion_limit);
            break;
            
        case 3: // 복잡한 재귀 조인
            snprintf(recursive_sql, sizeof(recursive_sql),
                    "WITH RECURSIVE complex_recursive(id, value, depth) AS ("
                    "SELECT 1, %d, 0 "
                    "UNION ALL "
                    "SELECT id + 1, value * 2 + %d, depth + 1 FROM complex_recursive "
                    "WHERE depth < %d AND value < %d"
                    ") SELECT COUNT(*), MAX(value), MAX(depth) FROM complex_recursive",
                    packet->stack_size % 1000,
                    packet->memory_pattern % 100,
                    recursion_limit,
                    packet->stack_size);
            break;
    }
    
    /* 재귀 쿼리 실행 */
    sqlite3_stmt *pStmt = NULL;
    rc = sqlite3_prepare_v2(db, recursive_sql, -1, &pStmt, NULL);
    if (rc == SQLITE_OK && pStmt) {
        while (sqlite3_step(pStmt) == SQLITE_ROW) {
            /* 결과 액세스 */
            int col_count = sqlite3_column_count(pStmt);
            for (int i = 0; i < col_count; i++) {
                sqlite3_column_int64(pStmt, i);
            }
        }
        sqlite3_finalize(pStmt);
    }
    
    /* 중첩된 함수 호출 스트레스 */
    if (packet->overflow_trigger & 0x01) {
        int nesting_depth = packet->function_calls % 20 + 5;
        char nested_func[2048] = "SELECT ";
        
        for (int i = 0; i < nesting_depth; i++) {
            strcat(nested_func, "UPPER(");
        }
        strcat(nested_func, "'test'");
        for (int i = 0; i < nesting_depth; i++) {
            strcat(nested_func, ")");
        }
        
        sqlite3_exec(db, nested_func, NULL, NULL, NULL);
    }
    
    return 1;
}

/* VDBE 타입 혼동 - 타입 시스템 취약점 */
int fuzz_vdbe_type_confusion(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < sizeof(type_confusion_packet)) return 0;
    
    type_confusion_packet *packet = (type_confusion_packet*)data;
    sqlite3 *db = ctx->db;
    sqlite3_stmt *pStmt = NULL;
    int rc;
    
    /* 타입 혼동 테스트용 테이블 */
    const char *create_sql = "CREATE TEMP TABLE type_test ("
                            "id INTEGER PRIMARY KEY, "
                            "mixed_col)"; // 타입 없는 컬럼
    
    rc = sqlite3_exec(db, create_sql, NULL, NULL, NULL);
    if (rc != SQLITE_OK) return 0;
    
    /* 다양한 타입으로 데이터 삽입 */
    const char *insert_sql = "INSERT INTO type_test (mixed_col) VALUES (?)";
    rc = sqlite3_prepare_v2(db, insert_sql, -1, &pStmt, NULL);
    if (rc != SQLITE_OK) return 0;
    
    /* 타입별 데이터 삽입 */
    for (int i = 0; i < 4; i++) {
        switch (i) {
            case 0: // INTEGER
                sqlite3_bind_int64(pStmt, 1, packet->numeric_value);
                break;
            case 1: // REAL
                sqlite3_bind_double(pStmt, 1, packet->real_value);
                break;
            case 2: // TEXT
                sqlite3_bind_text(pStmt, 1, packet->text_value, -1, SQLITE_TRANSIENT);
                break;
            case 3: // BLOB
                sqlite3_bind_blob(pStmt, 1, packet->blob_value, sizeof(packet->blob_value), SQLITE_TRANSIENT);
                break;
        }
        sqlite3_step(pStmt);
        sqlite3_reset(pStmt);
    }
    sqlite3_finalize(pStmt);
    
    /* 타입 혼동을 유발하는 복잡한 쿼리들 */
    const char *confusion_queries[] = {
        /* 타입 변환 강제 */
        "SELECT mixed_col + 0, mixed_col || '', CAST(mixed_col AS BLOB) FROM type_test",
        
        /* 비교 연산에서 타입 혼동 */
        "SELECT * FROM type_test WHERE mixed_col > 0 AND mixed_col < 'zzz'",
        
        /* 집계 함수에서 타입 변환 */
        "SELECT SUM(mixed_col), AVG(mixed_col), GROUP_CONCAT(mixed_col) FROM type_test",
        
        /* 함수 호출에서 타입 혼동 */
        "SELECT LENGTH(mixed_col), SUBSTR(mixed_col, 1, 5), ABS(mixed_col) FROM type_test",
        
        /* CASE 문에서 타입 혼동 */
        "SELECT CASE WHEN TYPEOF(mixed_col) = 'integer' THEN mixed_col + 1000 "
        "WHEN TYPEOF(mixed_col) = 'real' THEN mixed_col * 3.14 "
        "WHEN TYPEOF(mixed_col) = 'text' THEN LENGTH(mixed_col) "
        "ELSE 0 END FROM type_test"
    };
    
    for (size_t q = 0; q < sizeof(confusion_queries) / sizeof(confusion_queries[0]); q++) {
        rc = sqlite3_prepare_v2(db, confusion_queries[q], -1, &pStmt, NULL);
        if (rc == SQLITE_OK && pStmt) {
            while (sqlite3_step(pStmt) == SQLITE_ROW) {
                int col_count = sqlite3_column_count(pStmt);
                for (int i = 0; i < col_count; i++) {
                    /* 모든 타입으로 컬럼 액세스 시도 */
                    sqlite3_column_int64(pStmt, i);
                    sqlite3_column_double(pStmt, i);
                    sqlite3_column_text(pStmt, i);
                    sqlite3_column_blob(pStmt, i);
                    sqlite3_column_type(pStmt, i);
                }
            }
            sqlite3_finalize(pStmt);
        }
    }
    
    /* 친화성 조작 테스트 */
    if (packet->affinity_manipulation & 0x01) {
        sqlite3_exec(db, "CREATE TABLE affinity_test (num_col NUMERIC, int_col INTEGER, real_col REAL, text_col TEXT)", NULL, NULL, NULL);
        
        /* 각 컬럼에 타입 불일치 데이터 삽입 */
        const char *affinity_sql = "INSERT INTO affinity_test VALUES (?, ?, ?, ?)";
        rc = sqlite3_prepare_v2(db, affinity_sql, -1, &pStmt, NULL);
        if (rc == SQLITE_OK && pStmt) {
            sqlite3_bind_text(pStmt, 1, packet->text_value, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(pStmt, 2, packet->text_value, -1, SQLITE_TRANSIENT);
            sqlite3_bind_blob(pStmt, 3, packet->blob_value, 64, SQLITE_TRANSIENT);
            sqlite3_bind_int64(pStmt, 4, packet->numeric_value);
            sqlite3_step(pStmt);
            sqlite3_finalize(pStmt);
        }
    }
    
    return 1;
}

/* VDBE 레지스터 손상 */
int fuzz_vdbe_register_corruption(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < 32) return 0;
    
    sqlite3 *db = ctx->db;
    
    /* 대량의 바인드 변수로 레지스터 스트레스 */
    char sql[1024] = "SELECT ";
    for (int i = 0; i < 20; i++) {
        if (i > 0) strcat(sql, ", ");
        strcat(sql, "?");
    }
    
    sqlite3_stmt *pStmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &pStmt, NULL);
    if (rc == SQLITE_OK && pStmt) {
        /* 각 바인드 변수에 다른 타입 데이터 바인딩 */
        for (int i = 1; i <= 20; i++) {
            switch (i % 4) {
                case 0:
                    sqlite3_bind_int(pStmt, i, *(int*)(data + (i % size)));
                    break;
                case 1:
                    sqlite3_bind_double(pStmt, i, (double)(*(int*)(data + (i % size))) / 1000.0);
                    break;
                case 2:
                    sqlite3_bind_text(pStmt, i, (char*)(data + (i % size)), 8, SQLITE_TRANSIENT);
                    break;
                case 3:
                    sqlite3_bind_blob(pStmt, i, data + (i % size), 8, SQLITE_TRANSIENT);
                    break;
            }
        }
        
        sqlite3_step(pStmt);
        sqlite3_finalize(pStmt);
    }
    
    return 1;
}

/* VDBE 프로그램 조작 */
int fuzz_vdbe_program_manipulation(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < 16) return 0;
    
    sqlite3 *db = ctx->db;
    
    /* 동적 SQL 생성으로 프로그램 조작 */
    char dynamic_sql[512];
    snprintf(dynamic_sql, sizeof(dynamic_sql),
            "SELECT %.*s, %d + %d, '%.*s' || '%.*s'",
            (int)(size % 8), (char*)data,
            *(int*)data, *(int*)(data + 4),
            (int)(size % 8), (char*)data,
            (int)(size % 8), (char*)(data + 8));
    
    sqlite3_exec(db, dynamic_sql, NULL, NULL, NULL);
    
    return 1;
}

/* VDBE 집계 함수 혼돈 */
int fuzz_vdbe_aggregate_chaos(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < 32) return 0;
    
    sqlite3 *db = ctx->db;
    
    /* 집계 테스트용 임시 테이블 */
    sqlite3_exec(db, "CREATE TEMP TABLE agg_test (grp INTEGER, val REAL)", NULL, NULL, NULL);
    
    /* 테스트 데이터 */
    for (int i = 0; i < 50; i++) {
        char insert_sql[128];
        snprintf(insert_sql, sizeof(insert_sql),
                "INSERT INTO agg_test VALUES (%d, %f)",
                (*(int*)(data + (i % size))) % 10,
                (double)(*(int*)(data + ((i + 4) % size))) / 1000.0);
        sqlite3_exec(db, insert_sql, NULL, NULL, NULL);
    }
    
    /* 복잡한 집계 쿼리 */
    const char *agg_sql = "SELECT grp, COUNT(*), SUM(val), AVG(val), MIN(val), MAX(val), "
                         "GROUP_CONCAT(CAST(val AS TEXT)), "
                         "SUM(val * val), COUNT(DISTINCT CAST(val AS INTEGER)) "
                         "FROM agg_test GROUP BY grp HAVING COUNT(*) > 2";
    
    sqlite3_exec(db, agg_sql, NULL, NULL, NULL);
    
    return 1;
}

/* VDBE 재귀 폭발 */
int fuzz_vdbe_recursive_explosion(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < 16) return 0;
    
    sqlite3 *db = ctx->db;
    int recursion_limit = (*(int*)data) % 50 + 10; // 10-59 제한
    
    /* 트리거를 이용한 재귀 호출 */
    sqlite3_exec(db, "CREATE TEMP TABLE recursive_trigger_test (id INTEGER, data TEXT)", NULL, NULL, NULL);
    
    /* 재귀적 트리거 (제한된 깊이) */
    char trigger_sql[512];
    snprintf(trigger_sql, sizeof(trigger_sql),
            "CREATE TEMP TRIGGER recursive_trig AFTER INSERT ON recursive_trigger_test "
            "WHEN NEW.id < %d "
            "BEGIN "
            "INSERT INTO recursive_trigger_test VALUES (NEW.id + 1, NEW.data || 'X'); "
            "END", recursion_limit);
    
    sqlite3_exec(db, trigger_sql, NULL, NULL, NULL);
    
    /* 트리거 실행 */
    sqlite3_exec(db, "INSERT INTO recursive_trigger_test VALUES (1, 'start')", NULL, NULL, NULL);
    
    return 1;
}