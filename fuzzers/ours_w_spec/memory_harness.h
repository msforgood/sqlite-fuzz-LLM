/*
** SQLite3 Memory Management Harness Header
** 메모리 할당/해제 함수들의 크래시 유발 테스팅
** 힙 파편화, 경계 오버플로우, 이중 해제 등 메모리 취약점 타겟팅
*/

#ifndef MEMORY_HARNESS_H
#define MEMORY_HARNESS_H

#include "fuzz.h"
#include "sqlite3.h"

/* 메모리 공격 모드 정의 */
#define MEMORY_MODE_HEAP_SPRAY          0xA0  /* 힙 스프레이 공격 */
#define MEMORY_MODE_DOUBLE_FREE         0xA1  /* 이중 해제 */
#define MEMORY_MODE_USE_AFTER_FREE      0xA2  /* 해제 후 사용 */
#define MEMORY_MODE_BUFFER_OVERFLOW     0xA3  /* 버퍼 오버플로우 */
#define MEMORY_MODE_INTEGER_OVERFLOW    0xA4  /* 정수 오버플로우 */
#define MEMORY_MODE_VDBE_MEMORY_STRESS  0xA5  /* VDBE 메모리 스트레스 */
#define MEMORY_MODE_PAGE_ALLOC_STRESS   0xA6  /* 페이지 할당 스트레스 */

/* 메모리 공격 패킷 구조체들 */
typedef struct {
    uint8_t spray_pattern;      /* 스프레이 패턴 */
    uint8_t alloc_size_class;   /* 할당 크기 클래스 */
    uint8_t fragmentation_level; /* 파편화 수준 */
    uint8_t poison_value;       /* 포이즌 값 */
    uint16_t spray_count;       /* 스프레이 횟수 */
    uint16_t target_size;       /* 타겟 크기 */
    uint32_t heap_pattern;      /* 힙 패턴 */
    uint8_t spray_data[256];    /* 스프레이 데이터 */
} heap_spray_packet;

typedef struct {
    uint8_t vdbe_op_type;       /* VDBE 연산 타입 */
    uint8_t mem_grow_pattern;   /* 메모리 증가 패턴 */
    uint8_t string_encoding;    /* 문자열 인코딩 */
    uint8_t preserve_flag;      /* 보존 플래그 */
    uint16_t initial_size;      /* 초기 크기 */
    uint16_t target_size;       /* 타겟 크기 */
    uint32_t corruption_offset; /* 손상 오프셋 */
    char mem_content[512];      /* 메모리 내용 */
} vdbe_memory_packet;

typedef struct {
    uint8_t page_type;          /* 페이지 타입 */
    uint8_t alloc_pattern;      /* 할당 패턴 */
    uint8_t corruption_type;    /* 손상 타입 */
    uint8_t write_flag;         /* 쓰기 플래그 */
    uint32_t page_number;       /* 페이지 번호 */
    uint32_t page_size;         /* 페이지 크기 */
    uint32_t corruption_mask;   /* 손상 마스크 */
    uint8_t page_data[1024];    /* 페이지 데이터 */
} page_alloc_packet;

/* 함수 선언 */
int fuzz_heap_spray_attack(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_double_free_attack(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_use_after_free_attack(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_buffer_overflow_attack(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_integer_overflow_attack(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_vdbe_memory_stress(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_page_alloc_stress(FuzzCtx *ctx, const uint8_t *data, size_t size);

#endif /* MEMORY_HARNESS_H */