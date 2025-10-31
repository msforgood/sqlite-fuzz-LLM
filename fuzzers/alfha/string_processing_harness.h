/*
** SQLite3 String Processing and UTF-8 Conversion Harness Header
** 문자열 처리, 인코딩 변환, 패턴 매칭에서 크래시 유발
** UTF-8/UTF-16 경계 조건, 정규식, LIKE 패턴 등 문자열 취약점 타겟팅
*/

#ifndef STRING_PROCESSING_HARNESS_H
#define STRING_PROCESSING_HARNESS_H

#include "fuzz.h"
#include "sqlite3.h"

/* 문자열 처리 공격 모드 정의 */
#define STRING_MODE_UTF8_BOUNDARY       0xD0  /* UTF-8 경계 공격 */
#define STRING_MODE_UTF16_CONVERSION    0xD1  /* UTF-16 변환 공격 */
#define STRING_MODE_PATTERN_EXPLOSION   0xD2  /* 패턴 폭발 공격 */
#define STRING_MODE_ENCODING_CONFUSION  0xD3  /* 인코딩 혼동 */
#define STRING_MODE_COLLATION_CHAOS     0xD4  /* 조합 혼돈 */
#define STRING_MODE_REGEX_CATASTROPHE   0xD5  /* 정규식 재앙 */
#define STRING_MODE_FORMAT_OVERFLOW     0xD6  /* 포맷 오버플로우 */

/* 문자열 공격 패킷 구조체들 */
typedef struct {
    uint8_t boundary_type;      /* 경계 타입 */
    uint8_t encoding_pattern;   /* 인코딩 패턴 */
    uint8_t corruption_level;   /* 손상 수준 */
    uint8_t overflow_trigger;   /* 오버플로우 트리거 */
    uint16_t string_length;     /* 문자열 길이 */
    uint16_t pattern_count;     /* 패턴 수 */
    uint32_t encoding_seed;     /* 인코딩 시드 */
    char utf8_data[1024];       /* UTF-8 데이터 */
    uint16_t utf16_data[512];   /* UTF-16 데이터 */
} utf_boundary_packet;

typedef struct {
    uint8_t pattern_type;       /* 패턴 타입 */
    uint8_t wildcard_density;   /* 와일드카드 밀도 */
    uint8_t nesting_level;      /* 중첩 수준 */
    uint8_t escape_manipulation; /* 이스케이프 조작 */
    uint16_t pattern_length;    /* 패턴 길이 */
    uint16_t text_length;       /* 텍스트 길이 */
    uint32_t complexity_seed;   /* 복잡도 시드 */
    char like_pattern[256];     /* LIKE 패턴 */
    char match_text[1024];      /* 매칭 텍스트 */
    char escape_char;           /* 이스케이프 문자 */
} pattern_explosion_packet;

typedef struct {
    uint8_t format_type;        /* 포맷 타입 */
    uint8_t argument_count;     /* 인수 개수 */
    uint8_t width_manipulation; /* 폭 조작 */
    uint8_t precision_chaos;    /* 정밀도 혼돈 */
    uint16_t format_length;     /* 포맷 길이 */
    uint16_t arg_size;          /* 인수 크기 */
    uint32_t overflow_pattern;  /* 오버플로우 패턴 */
    char format_string[512];    /* 포맷 문자열 */
    uint8_t format_args[1024];  /* 포맷 인수들 */
} format_overflow_packet;

/* 함수 선언 */
int fuzz_utf8_boundary_attack(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_utf16_conversion_attack(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_pattern_explosion_attack(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_encoding_confusion_attack(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_collation_chaos_attack(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_regex_catastrophe_attack(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_format_overflow_attack(FuzzCtx *ctx, const uint8_t *data, size_t size);

#endif /* STRING_PROCESSING_HARNESS_H */