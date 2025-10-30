/*
** SQLite3 VDBE Execution Engine Harness Header
** 가상 데이터베이스 엔진의 복잡한 연산으로 크래시 유발
** 연산 스택, 레지스터, 프로그램 카운터 조작을 통한 취약점 탐지
*/

#ifndef VDBE_EXECUTION_HARNESS_H
#define VDBE_EXECUTION_HARNESS_H

#include "fuzz.h"
#include "sqlite3.h"

/* VDBE 실행 공격 모드 정의 */
#define VDBE_MODE_OPCODE_CHAOS         0xC0  /* 연산코드 혼돈 */
#define VDBE_MODE_STACK_OVERFLOW       0xC1  /* 스택 오버플로우 */
#define VDBE_MODE_REGISTER_CORRUPTION  0xC2  /* 레지스터 손상 */
#define VDBE_MODE_PROGRAM_MANIPULATION 0xC3  /* 프로그램 조작 */
#define VDBE_MODE_TYPE_CONFUSION       0xC4  /* 타입 혼동 */
#define VDBE_MODE_AGGREGATE_CHAOS      0xC5  /* 집계 함수 혼돈 */
#define VDBE_MODE_RECURSIVE_EXPLOSION  0xC6  /* 재귀 폭발 */

/* VDBE 공격 패킷 구조체들 */
typedef struct {
    uint8_t opcode_pattern;     /* 연산코드 패턴 */
    uint8_t complexity_level;   /* 복잡도 수준 */
    uint8_t nesting_depth;      /* 중첩 깊이 */
    uint8_t chaos_seed;         /* 혼돈 시드 */
    uint16_t instruction_count; /* 명령어 수 */
    uint16_t param_corruption;  /* 매개변수 손상 */
    uint32_t execution_pattern; /* 실행 패턴 */
    char sql_template[1024];    /* SQL 템플릿 */
    uint8_t param_data[512];    /* 매개변수 데이터 */
} opcode_chaos_packet;

typedef struct {
    uint8_t stack_operation;    /* 스택 연산 */
    uint8_t overflow_trigger;   /* 오버플로우 트리거 */
    uint8_t recursion_depth;    /* 재귀 깊이 */
    uint8_t memory_pattern;     /* 메모리 패턴 */
    uint16_t stack_depth;       /* 스택 깊이 */
    uint16_t function_calls;    /* 함수 호출 수 */
    uint32_t stack_size;        /* 스택 크기 */
    char recursive_sql[2048];   /* 재귀 SQL */
} stack_overflow_packet;

typedef struct {
    uint8_t type_confusion;     /* 타입 혼동 */
    uint8_t conversion_pattern; /* 변환 패턴 */
    uint8_t affinity_manipulation; /* 친화성 조작 */
    uint8_t comparison_chaos;   /* 비교 혼돈 */
    uint32_t numeric_value;     /* 숫자 값 */
    double real_value;          /* 실수 값 */
    char text_value[256];       /* 텍스트 값 */
    uint8_t blob_value[256];    /* BLOB 값 */
} type_confusion_packet;

/* 함수 선언 */
int fuzz_vdbe_opcode_chaos(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_vdbe_stack_overflow(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_vdbe_register_corruption(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_vdbe_program_manipulation(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_vdbe_type_confusion(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_vdbe_aggregate_chaos(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_vdbe_recursive_explosion(FuzzCtx *ctx, const uint8_t *data, size_t size);

#endif /* VDBE_EXECUTION_HARNESS_H */