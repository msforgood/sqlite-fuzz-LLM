/*
** SQLite3 B-Tree Intensive Operations Harness Header
** B-Tree 내부 구조 조작을 통한 크래시 유발 테스팅
** 페이지 분할, 병합, 재밸런싱 등 복잡한 B-Tree 연산 타겟팅
*/

#ifndef BTREE_INTENSIVE_HARNESS_H
#define BTREE_INTENSIVE_HARNESS_H

#include "fuzz.h"
#include "sqlite3.h"

/* B-Tree 집중 공격 모드 정의 */
#define BTREE_MODE_PAGE_SPLIT_STRESS    0xB0  /* 페이지 분할 스트레스 */
#define BTREE_MODE_MERGE_CORRUPTION     0xB1  /* 병합 손상 */
#define BTREE_MODE_REBALANCE_CHAOS      0xB2  /* 재밸런싱 혼돈 */
#define BTREE_MODE_CURSOR_MANIPULATION  0xB3  /* 커서 조작 */
#define BTREE_MODE_INDEX_CORRUPTION     0xB4  /* 인덱스 손상 */
#define BTREE_MODE_VACUUM_STRESS        0xB5  /* VACUUM 스트레스 */
#define BTREE_MODE_TRANSACTION_CHAOS    0xB6  /* 트랜잭션 혼돈 */

/* B-Tree 공격 패킷 구조체들 */
typedef struct {
    uint8_t split_pattern;      /* 분할 패턴 */
    uint8_t key_distribution;   /* 키 분포 */
    uint8_t payload_size_class; /* 페이로드 크기 클래스 */
    uint8_t split_trigger;      /* 분할 트리거 */
    uint16_t insert_count;      /* 삽입 횟수 */
    uint16_t key_size;          /* 키 크기 */
    uint32_t payload_pattern;   /* 페이로드 패턴 */
    char key_data[512];         /* 키 데이터 */
    uint8_t payload_data[1024]; /* 페이로드 데이터 */
} page_split_packet;

typedef struct {
    uint8_t cursor_movement;    /* 커서 이동 패턴 */
    uint8_t seek_pattern;       /* 탐색 패턴 */
    uint8_t boundary_test;      /* 경계 테스트 */
    uint8_t corruption_type;    /* 손상 타입 */
    uint32_t target_rowid;      /* 타겟 행 ID */
    uint32_t seek_key;          /* 탐색 키 */
    uint32_t movement_count;    /* 이동 횟수 */
    char seek_data[256];        /* 탐색 데이터 */
} cursor_manipulation_packet;

typedef struct {
    uint8_t vacuum_type;        /* VACUUM 타입 */
    uint8_t fragmentation_level; /* 파편화 수준 */
    uint8_t corruption_inject;  /* 손상 주입 */
    uint8_t interrupt_pattern;  /* 중단 패턴 */
    uint16_t page_count;        /* 페이지 수 */
    uint16_t record_size;       /* 레코드 크기 */
    uint32_t vacuum_trigger;    /* VACUUM 트리거 */
    uint8_t test_data[2048];    /* 테스트 데이터 */
} vacuum_stress_packet;

/* 함수 선언 */
int fuzz_page_split_stress(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_btree_merge_corruption(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_rebalance_chaos(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_cursor_manipulation(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_index_corruption(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_vacuum_stress(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_transaction_chaos(FuzzCtx *ctx, const uint8_t *data, size_t size);

#endif /* BTREE_INTENSIVE_HARNESS_H */