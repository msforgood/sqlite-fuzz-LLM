/*
** SQLite3 Utility Functions Batch Harness Header
** 저위험 유틸리티 함수들의 대량 배치 테스팅
** 개발 진척도 향상을 위한 간단한 함수들 커버리지 확장
*/

#ifndef UTILITY_BATCH_HARNESS_H
#define UTILITY_BATCH_HARNESS_H

#include "fuzz.h"
#include "sqlite3.h"

/* 유틸리티 배치 모드 정의 */
#define UTILITY_MODE_MATH_FUNCTIONS     0xE0  /* 수학 함수 배치 */
#define UTILITY_MODE_DATE_TIME          0xE1  /* 날짜/시간 함수 */
#define UTILITY_MODE_SYSTEM_INFO        0xE2  /* 시스템 정보 함수 */
#define UTILITY_MODE_TYPE_CONVERSION    0xE3  /* 타입 변환 함수 */
#define UTILITY_MODE_AGGREGATE_SIMPLE   0xE4  /* 단순 집계 함수 */
#define UTILITY_MODE_JSON_FUNCTIONS     0xE5  /* JSON 함수들 */
#define UTILITY_MODE_MISC_UTILITIES     0xE6  /* 기타 유틸리티 */

/* 유틸리티 배치 패킷 구조체 */
typedef struct {
    uint8_t function_group;     /* 함수 그룹 */
    uint8_t test_intensity;     /* 테스트 강도 */
    uint8_t param_variation;    /* 매개변수 변형 */
    uint8_t coverage_mode;      /* 커버리지 모드 */
    uint16_t iteration_count;   /* 반복 횟수 */
    uint16_t data_variety;      /* 데이터 다양성 */
    uint32_t seed_value;        /* 시드 값 */
    double numeric_params[8];   /* 숫자 매개변수들 */
    char string_params[256];    /* 문자열 매개변수들 */
    uint8_t binary_params[256]; /* 바이너리 매개변수들 */
} utility_batch_packet;

/* 함수 선언 */
int fuzz_math_functions_batch(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_datetime_functions_batch(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_system_info_batch(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_type_conversion_batch(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_aggregate_simple_batch(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_json_functions_batch(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_misc_utilities_batch(FuzzCtx *ctx, const uint8_t *data, size_t size);

#endif /* UTILITY_BATCH_HARNESS_H */