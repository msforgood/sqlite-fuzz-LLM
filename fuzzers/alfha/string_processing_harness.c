/*
** SQLite3 String Processing and UTF-8 Conversion Harness Implementation
** 문자열 처리, 인코딩 변환, 패턴 매칭에서 크래시 유발 구현
*/

#include "string_processing_harness.h"
#include <string.h>
#include <stdlib.h>

/* UTF-8 경계 공격 - 잘못된 UTF-8 시퀀스로 크래시 유발 */
int fuzz_utf8_boundary_attack(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < sizeof(utf_boundary_packet)) return 0;
    
    utf_boundary_packet *packet = (utf_boundary_packet*)data;
    sqlite3 *db = ctx->db;
    sqlite3_stmt *pStmt = NULL;
    int rc;
    
    /* UTF-8 테스트용 테이블 생성 */
    const char *create_sql = "CREATE TEMP TABLE utf8_test ("
                            "id INTEGER PRIMARY KEY, "
                            "utf8_col TEXT, "
                            "utf16_col TEXT)";
    
    rc = sqlite3_exec(db, create_sql, NULL, NULL, NULL);
    if (rc != SQLITE_OK) return 0;
    
    /* 경계 타입별 악성 UTF-8 시퀀스 생성 */
    char *malformed_utf8 = (char*)sqlite3_malloc(1024);
    if (!malformed_utf8) return 0;
    
    size_t utf8_len = 0;
    
    switch (packet->boundary_type % 8) {
        case 0: // 잘린 다바이트 시퀀스
            malformed_utf8[utf8_len++] = 0xC2; // 2바이트 시작
            malformed_utf8[utf8_len++] = 0x00; // 잘못된 연속 바이트
            break;
            
        case 1: // 오버롱 인코딩
            malformed_utf8[utf8_len++] = 0xC0; // 오버롱 2바이트
            malformed_utf8[utf8_len++] = 0x80;
            break;
            
        case 2: // 잘못된 3바이트 시퀀스
            malformed_utf8[utf8_len++] = 0xE0; // 3바이트 시작
            malformed_utf8[utf8_len++] = 0x80; // 올바른 연속
            malformed_utf8[utf8_len++] = 0x00; // 잘못된 연속
            break;
            
        case 3: // 잘못된 4바이트 시퀀스
            malformed_utf8[utf8_len++] = 0xF0; // 4바이트 시작
            malformed_utf8[utf8_len++] = 0x80;
            malformed_utf8[utf8_len++] = 0x80;
            malformed_utf8[utf8_len++] = 0x00; // 잘못된 마지막 바이트
            break;
            
        case 4: // 고립된 연속 바이트
            malformed_utf8[utf8_len++] = 0x80; // 연속 바이트만
            malformed_utf8[utf8_len++] = 0x90;
            malformed_utf8[utf8_len++] = 0xA0;
            break;
            
        case 5: // 범위 초과 코드포인트
            malformed_utf8[utf8_len++] = 0xF4; // 4바이트
            malformed_utf8[utf8_len++] = 0x90; // 범위 초과
            malformed_utf8[utf8_len++] = 0x80;
            malformed_utf8[utf8_len++] = 0x80;
            break;
            
        case 6: // 서로게이트 반쪽
            malformed_utf8[utf8_len++] = 0xED; // 3바이트
            malformed_utf8[utf8_len++] = 0xA0; // 서로게이트 영역
            malformed_utf8[utf8_len++] = 0x80;
            break;
            
        case 7: // 패킷 데이터와 혼합
            memcpy(malformed_utf8, packet->utf8_data, 
                   (packet->string_length < 512) ? packet->string_length : 512);
            utf8_len = (packet->string_length < 512) ? packet->string_length : 512;
            
            /* 중간에 잘못된 바이트 삽입 */
            if (utf8_len > 10) {
                malformed_utf8[utf8_len / 2] = 0xFF; // 유효하지 않은 UTF-8
                malformed_utf8[utf8_len / 2 + 1] = 0xFE;
            }
            break;
    }
    
    malformed_utf8[utf8_len] = 0;
    
    /* UTF-8 데이터 삽입 및 처리 */
    const char *insert_sql = "INSERT INTO utf8_test (utf8_col, utf16_col) VALUES (?, ?)";
    rc = sqlite3_prepare_v2(db, insert_sql, -1, &pStmt, NULL);
    if (rc == SQLITE_OK && pStmt) {
        /* UTF-8로 바인딩 */
        sqlite3_bind_text(pStmt, 1, malformed_utf8, utf8_len, SQLITE_TRANSIENT);
        
        /* UTF-16으로 바인딩 (변환 스트레스) */
        sqlite3_bind_text16(pStmt, 2, packet->utf16_data, 
                           (packet->pattern_count < 256) ? packet->pattern_count * 2 : 512, 
                           SQLITE_TRANSIENT);
        
        sqlite3_step(pStmt);
        sqlite3_finalize(pStmt);
    }
    
    /* UTF-8 처리 함수들 스트레스 테스트 */
    const char *utf8_queries[] = {
        "SELECT LENGTH(utf8_col), LENGTH(utf16_col) FROM utf8_test",
        "SELECT UPPER(utf8_col), LOWER(utf16_col) FROM utf8_test",
        "SELECT SUBSTR(utf8_col, 1, 10), SUBSTR(utf16_col, 1, 10) FROM utf8_test",
        "SELECT utf8_col || utf16_col FROM utf8_test",
        "SELECT REPLACE(utf8_col, 'a', 'X'), REPLACE(utf16_col, 'a', 'Y') FROM utf8_test"
    };
    
    for (size_t q = 0; q < sizeof(utf8_queries) / sizeof(utf8_queries[0]); q++) {
        rc = sqlite3_prepare_v2(db, utf8_queries[q], -1, &pStmt, NULL);
        if (rc == SQLITE_OK && pStmt) {
            while (sqlite3_step(pStmt) == SQLITE_ROW) {
                /* UTF-8과 UTF-16으로 모두 접근 */
                sqlite3_column_text(pStmt, 0);
                sqlite3_column_text16(pStmt, 0);
                if (sqlite3_column_count(pStmt) > 1) {
                    sqlite3_column_text(pStmt, 1);
                    sqlite3_column_text16(pStmt, 1);
                }
            }
            sqlite3_finalize(pStmt);
        }
    }
    
    sqlite3_free(malformed_utf8);
    return 1;
}

/* 패턴 폭발 공격 - LIKE, GLOB 패턴으로 성능 저하 유발 */
int fuzz_pattern_explosion_attack(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < sizeof(pattern_explosion_packet)) return 0;
    
    pattern_explosion_packet *packet = (pattern_explosion_packet*)data;
    sqlite3 *db = ctx->db;
    sqlite3_stmt *pStmt = NULL;
    int rc;
    
    /* 패턴 테스트용 테이블 생성 */
    const char *create_sql = "CREATE TEMP TABLE pattern_test ("
                            "id INTEGER PRIMARY KEY, "
                            "text_data TEXT)";
    
    rc = sqlite3_exec(db, create_sql, NULL, NULL, NULL);
    if (rc != SQLITE_OK) return 0;
    
    /* 테스트 데이터 삽입 */
    const char *insert_sql = "INSERT INTO pattern_test (text_data) VALUES (?)";
    rc = sqlite3_prepare_v2(db, insert_sql, -1, &pStmt, NULL);
    if (rc != SQLITE_OK) return 0;
    
    for (int i = 0; i < 50; i++) {
        /* 패킷 데이터와 생성된 데이터 혼합 */
        char mixed_text[1024];
        snprintf(mixed_text, sizeof(mixed_text), "%.*s_%d_%.*s",
                 (int)(packet->text_length % 200), packet->match_text,
                 i,
                 (int)(size % 100), (char*)data);
        
        sqlite3_bind_text(pStmt, 1, mixed_text, -1, SQLITE_TRANSIENT);
        sqlite3_step(pStmt);
        sqlite3_reset(pStmt);
    }
    sqlite3_finalize(pStmt);
    
    /* 악성 LIKE 패턴 생성 */
    char evil_pattern[512];
    size_t pattern_pos = 0;
    
    switch (packet->pattern_type % 6) {
        case 0: // 중첩된 와일드카드 패턴
            strcpy(evil_pattern, "%");
            for (int i = 0; i < (packet->wildcard_density % 20); i++) {
                strcat(evil_pattern, "*%");
            }
            strcat(evil_pattern, "%");
            break;
            
        case 1: // 교대 패턴
            evil_pattern[0] = 0;
            for (int i = 0; i < (packet->nesting_level % 50); i++) {
                strcat(evil_pattern, (i % 2) ? "_" : "%");
            }
            break;
            
        case 2: // 이스케이프 혼란
            snprintf(evil_pattern, sizeof(evil_pattern), 
                    "%%%c%%%c%%%c%%", 
                    packet->escape_char, packet->escape_char, packet->escape_char);
            break;
            
        case 3: // 긴 리터럴 + 와일드카드
            for (int i = 0; i < (packet->pattern_length % 100); i++) {
                evil_pattern[i] = 'a' + (i % 26);
            }
            evil_pattern[packet->pattern_length % 100] = 0;
            strcat(evil_pattern, "%");
            break;
            
        case 4: // 패킷 데이터 기반 패턴
            snprintf(evil_pattern, sizeof(evil_pattern), 
                    "%%%.*s%%_%.*s%%",
                    (int)(packet->pattern_length % 50), packet->like_pattern,
                    (int)(packet->pattern_length % 50), packet->like_pattern + 50);
            break;
            
        case 5: // 극단적 와일드카드
            for (int i = 0; i < (packet->complexity_seed % 200) && i < 510; i++) {
                evil_pattern[i] = (i % 3 == 0) ? '%' : ((i % 3 == 1) ? '_' : 'x');
            }
            evil_pattern[packet->complexity_seed % 200] = 0;
            break;
    }
    
    /* 악성 패턴으로 쿼리 실행 */
    char pattern_query[1024];
    snprintf(pattern_query, sizeof(pattern_query),
            "SELECT COUNT(*) FROM pattern_test WHERE text_data LIKE '%s'",
            evil_pattern);
    
    rc = sqlite3_prepare_v2(db, pattern_query, -1, &pStmt, NULL);
    if (rc == SQLITE_OK && pStmt) {
        sqlite3_step(pStmt);
        sqlite3_finalize(pStmt);
    }
    
    /* GLOB 패턴도 테스트 */
    if (packet->escape_manipulation & 0x01) {
        snprintf(pattern_query, sizeof(pattern_query),
                "SELECT COUNT(*) FROM pattern_test WHERE text_data GLOB '%s'",
                evil_pattern);
        
        rc = sqlite3_prepare_v2(db, pattern_query, -1, &pStmt, NULL);
        if (rc == SQLITE_OK && pStmt) {
            sqlite3_step(pStmt);
            sqlite3_finalize(pStmt);
        }
    }
    
    /* ESCAPE 절 테스트 */
    if (packet->escape_manipulation & 0x02) {
        snprintf(pattern_query, sizeof(pattern_query),
                "SELECT COUNT(*) FROM pattern_test WHERE text_data LIKE '%s' ESCAPE '%c'",
                evil_pattern, packet->escape_char);
        
        rc = sqlite3_prepare_v2(db, pattern_query, -1, &pStmt, NULL);
        if (rc == SQLITE_OK && pStmt) {
            sqlite3_step(pStmt);
            sqlite3_finalize(pStmt);
        }
    }
    
    return 1;
}

/* 포맷 오버플로우 공격 - sqlite3_mprintf 계열 함수 타겟팅 */
int fuzz_format_overflow_attack(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < sizeof(format_overflow_packet)) return 0;
    
    format_overflow_packet *packet = (format_overflow_packet*)data;
    
    /* 포맷 타입별 공격 문자열 생성 */
    char *result = NULL;
    
    switch (packet->format_type % 8) {
        case 0: // 폭 지정자 오버플로우
            result = sqlite3_mprintf("%*s", 
                                   (int)(packet->overflow_pattern % 100000), 
                                   packet->format_string);
            break;
            
        case 1: // 정밀도 지정자 오버플로우
            result = sqlite3_mprintf("%.*s", 
                                   (int)(packet->overflow_pattern % 100000), 
                                   packet->format_string);
            break;
            
        case 2: // 다중 인수 오버플로우
            result = sqlite3_mprintf("%s %d %f %s %x", 
                                   packet->format_string,
                                   *(int*)packet->format_args,
                                   *(double*)(packet->format_args + 4),
                                   packet->format_string + 100,
                                   *(unsigned int*)(packet->format_args + 12));
            break;
            
        case 3: // 중첩된 포맷 지정자
            {
                char nested_format[256];
                snprintf(nested_format, sizeof(nested_format), 
                        "%%%d.%ds", 
                        packet->width_manipulation % 1000,
                        packet->precision_chaos % 1000);
                result = sqlite3_mprintf(nested_format, packet->format_string);
            }
            break;
            
        case 4: // 긴 문자열 포맷팅
            result = sqlite3_mprintf("%.*s", 
                                   (int)(packet->format_length % 10000), 
                                   packet->format_string);
            break;
            
        case 5: // 숫자 포맷 오버플로우
            result = sqlite3_mprintf("%*.*f", 
                                   packet->width_manipulation % 1000,
                                   packet->precision_chaos % 100,
                                   *(double*)packet->format_args);
            break;
            
        case 6: // 16진수 포맷 오버플로우
            result = sqlite3_mprintf("%*x %*X", 
                                   packet->width_manipulation % 1000,
                                   *(unsigned int*)packet->format_args,
                                   packet->precision_chaos % 1000,
                                   *(unsigned int*)(packet->format_args + 4));
            break;
            
        case 7: // 혼합 포맷 지정자
            result = sqlite3_mprintf("%*.*s_%d_%f_%x", 
                                   packet->width_manipulation % 100,
                                   packet->precision_chaos % 100,
                                   packet->format_string,
                                   *(int*)packet->format_args,
                                   *(double*)(packet->format_args + 4),
                                   packet->overflow_pattern);
            break;
    }
    
    if (result) {
        /* 결과 문자열 길이 체크 */
        size_t result_len = strlen(result);
        
        /* 추가 문자열 조작 */
        if (packet->argument_count & 0x01) {
            char *extended = sqlite3_mprintf("%s%s%s", result, result, result);
            sqlite3_free(result);
            result = extended;
        }
        
        sqlite3_free(result);
    }
    
    return 1;
}

/* UTF-16 변환 공격 */
int fuzz_utf16_conversion_attack(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < 32) return 0;
    
    sqlite3 *db = ctx->db;
    sqlite3_stmt *pStmt = NULL;
    
    /* UTF-16 테스트 */
    const char *sql = "SELECT ?1, UPPER(?1), LOWER(?1), LENGTH(?1)";
    int rc = sqlite3_prepare_v2(db, sql, -1, &pStmt, NULL);
    if (rc == SQLITE_OK && pStmt) {
        /* UTF-16 데이터 바인딩 */
        sqlite3_bind_text16(pStmt, 1, data, (size < 1000) ? size : 1000, SQLITE_TRANSIENT);
        
        while (sqlite3_step(pStmt) == SQLITE_ROW) {
            /* UTF-8과 UTF-16으로 모두 읽기 */
            sqlite3_column_text(pStmt, 0);
            sqlite3_column_text16(pStmt, 0);
            sqlite3_column_text(pStmt, 1);
            sqlite3_column_text16(pStmt, 1);
        }
        
        sqlite3_finalize(pStmt);
    }
    
    return 1;
}

/* 인코딩 혼동 공격 */
int fuzz_encoding_confusion_attack(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < 16) return 0;
    
    sqlite3 *db = ctx->db;
    
    /* 데이터베이스 인코딩 변경 시도 */
    sqlite3_exec(db, "PRAGMA encoding='UTF-8'", NULL, NULL, NULL);
    sqlite3_exec(db, "PRAGMA encoding='UTF-16'", NULL, NULL, NULL);
    sqlite3_exec(db, "PRAGMA encoding='UTF-16le'", NULL, NULL, NULL);
    sqlite3_exec(db, "PRAGMA encoding='UTF-16be'", NULL, NULL, NULL);
    
    /* 혼합 인코딩 테스트 */
    sqlite3_stmt *pStmt;
    const char *sql = "SELECT ?1 || ?2";
    
    int rc = sqlite3_prepare_v2(db, sql, -1, &pStmt, NULL);
    if (rc == SQLITE_OK && pStmt) {
        sqlite3_bind_text(pStmt, 1, (char*)data, size / 2, SQLITE_TRANSIENT);
        sqlite3_bind_text16(pStmt, 2, data + size / 2, size / 2, SQLITE_TRANSIENT);
        
        sqlite3_step(pStmt);
        sqlite3_finalize(pStmt);
    }
    
    return 1;
}

/* 조합(Collation) 혼돈 공격 */
int fuzz_collation_chaos_attack(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < 16) return 0;
    
    sqlite3 *db = ctx->db;
    
    /* 다양한 조합 시퀀스로 정렬/비교 테스트 */
    sqlite3_exec(db, "CREATE TEMP TABLE collation_test (data TEXT COLLATE BINARY)", NULL, NULL, NULL);
    sqlite3_exec(db, "CREATE INDEX idx_collate ON collation_test(data COLLATE NOCASE)", NULL, NULL, NULL);
    
    /* 데이터 삽입 */
    sqlite3_stmt *pStmt;
    const char *insert_sql = "INSERT INTO collation_test VALUES (?)";
    
    int rc = sqlite3_prepare_v2(db, insert_sql, -1, &pStmt, NULL);
    if (rc == SQLITE_OK && pStmt) {
        sqlite3_bind_text(pStmt, 1, (char*)data, (size < 100) ? size : 100, SQLITE_TRANSIENT);
        sqlite3_step(pStmt);
        sqlite3_finalize(pStmt);
    }
    
    /* 다양한 조합으로 쿼리 */
    const char *collation_queries[] = {
        "SELECT * FROM collation_test ORDER BY data COLLATE BINARY",
        "SELECT * FROM collation_test ORDER BY data COLLATE NOCASE",
        "SELECT * FROM collation_test ORDER BY data COLLATE RTRIM",
        "SELECT * FROM collation_test WHERE data = ? COLLATE BINARY",
        "SELECT * FROM collation_test WHERE data = ? COLLATE NOCASE"
    };
    
    for (size_t q = 0; q < 3; q++) { // 처음 3개만 실행
        sqlite3_prepare_v2(db, collation_queries[q], -1, &pStmt, NULL);
        if (pStmt) {
            sqlite3_step(pStmt);
            sqlite3_finalize(pStmt);
        }
    }
    
    return 1;
}

/* 정규식 재앙 공격 */
int fuzz_regex_catastrophe_attack(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < 16) return 0;
    
    sqlite3 *db = ctx->db;
    
    /* REGEXP 함수가 있는 경우 테스트 (SQLite 기본에는 없지만 확장에서 제공) */
    sqlite3_stmt *pStmt;
    const char *regexp_sql = "SELECT ?1 REGEXP ?2";
    
    int rc = sqlite3_prepare_v2(db, regexp_sql, -1, &pStmt, NULL);
    if (rc == SQLITE_OK && pStmt) {
        sqlite3_bind_text(pStmt, 1, (char*)data, size / 2, SQLITE_TRANSIENT);
        sqlite3_bind_text(pStmt, 2, (char*)(data + size / 2), size / 2, SQLITE_TRANSIENT);
        
        sqlite3_step(pStmt); // 실패할 수도 있지만 시도
        sqlite3_finalize(pStmt);
    }
    
    return 1;
}