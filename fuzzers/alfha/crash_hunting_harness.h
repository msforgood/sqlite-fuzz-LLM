/*
** SQLite3 Crash Hunting Harness Header
** 크래시 가능성이 높은 함수들을 집중적으로 타겟팅
** 메모리 관리, 파서, 경계 조건 등 취약한 영역 우선
*/

#ifndef CRASH_HUNTING_HARNESS_H
#define CRASH_HUNTING_HARNESS_H

#include "fuzz.h"
#include "sqlite3.h"

/* 크래시 가능성 높은 함수 모드 정의 */
#define CRASH_MODE_MEMORY_STRESS        0x90  /* 메모리 관리 스트레스 */
#define CRASH_MODE_PARSER_OVERFLOW      0x91  /* 파서 오버플로우 */
#define CRASH_MODE_BOUNDARY_VIOLATION   0x92  /* 경계 위반 */
#define CRASH_MODE_STRING_MANIPULATION  0x93  /* 문자열 조작 */
#define CRASH_MODE_RECURSIVE_CALLS      0x94  /* 재귀 호출 */
#define CRASH_MODE_MALFORMED_SQL        0x95  /* 악형 SQL */
#define CRASH_MODE_INDEX_CORRUPTION     0x96  /* 인덱스 손상 */
#define CRASH_MODE_TRANSACTION_ABUSE    0x97  /* 트랜잭션 남용 */

/* 크래시 유발 패킷 구조체들 */
typedef struct {
    uint8_t stress_type;        /* 메모리 스트레스 타입 */
    uint8_t alloc_pattern;      /* 할당 패턴 */
    uint8_t fragmentation_level; /* 파편화 수준 */
    uint8_t pressure_intensity; /* 압박 강도 */
    uint32_t alloc_count;       /* 할당 횟수 */
    uint32_t max_size;          /* 최대 크기 */
    uint32_t target_pattern;    /* 타겟 패턴 */
    uint8_t payload[64];        /* 스트레스 데이터 */
} memory_stress_packet;

typedef struct {
    uint8_t parser_target;      /* 파서 타겟 */
    uint8_t overflow_type;      /* 오버플로우 타입 */
    uint8_t nesting_depth;      /* 중첩 깊이 */
    uint8_t token_corruption;   /* 토큰 손상 */
    uint16_t sql_length;        /* SQL 길이 */
    uint16_t padding;
    char malformed_sql[512];    /* 악형 SQL */
} parser_overflow_packet;

typedef struct {
    uint8_t boundary_target;    /* 경계 타겟 */
    uint8_t violation_type;     /* 위반 타입 */
    uint8_t offset_corruption;  /* 오프셋 손상 */
    uint8_t size_manipulation; /* 크기 조작 */
    uint32_t target_index;      /* 타겟 인덱스 */
    uint32_t boundary_value;    /* 경계값 */
    int32_t signed_overflow;    /* 부호 오버플로우 */
    uint8_t crash_data[48];     /* 크래시 데이터 */
} boundary_violation_packet;

/* 함수 선언 */
int fuzz_memory_stress_crash(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_parser_overflow_crash(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_boundary_violation_crash(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_string_manipulation_crash(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_recursive_calls_crash(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_malformed_sql_crash(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_index_corruption_crash(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_transaction_abuse_crash(FuzzCtx *ctx, const uint8_t *data, size_t size);

/* 대량 저위험 함수 하니스 */
int fuzz_batch_low_risk_functions(FuzzCtx *ctx, const uint8_t *data, size_t size);

#endif /* CRASH_HUNTING_HARNESS_H */