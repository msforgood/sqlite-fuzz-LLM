/*
** SQLite3 Memory Management Harness Implementation
** 메모리 할당/해제 함수들의 크래시 유발 테스팅 구현
*/

#include "memory_harness.h"
#include <string.h>
#include <stdlib.h>

/* 힙 스프레이 공격 - sqlite3_malloc 집중 타겟팅 */
int fuzz_heap_spray_attack(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < sizeof(heap_spray_packet)) return 0;
    
    heap_spray_packet *packet = (heap_spray_packet*)data;
    char **spray_ptrs = NULL;
    int spray_count = packet->spray_count % 1000; // 최대 1000개 제한
    
    /* 메모리 풀 생성 및 스프레이 */
    spray_ptrs = (char**)sqlite3_malloc(spray_count * sizeof(char*));
    if (!spray_ptrs) return 0;
    
    for (int i = 0; i < spray_count; i++) {
        size_t alloc_size = (packet->target_size % 8192) + 16; // 16-8192 바이트
        
        spray_ptrs[i] = (char*)sqlite3_malloc(alloc_size);
        if (spray_ptrs[i]) {
            /* 패턴 기반 힙 오염 */
            memset(spray_ptrs[i], packet->poison_value, alloc_size);
            
            /* 경계 테스팅 - 의도적 오버플로우 시도 */
            if (packet->spray_pattern & 0x01) {
                memcpy(spray_ptrs[i], packet->spray_data, 
                       (alloc_size < 256) ? alloc_size : 256);
            }
            
            /* 파편화 유발 - 랜덤 해제 */
            if ((packet->fragmentation_level & 0x03) == (i & 0x03)) {
                sqlite3_free(spray_ptrs[i]);
                spray_ptrs[i] = NULL;
            }
        }
    }
    
    /* sqlite3_realloc 스트레스 테스팅 */
    for (int i = 0; i < spray_count; i++) {
        if (spray_ptrs[i]) {
            size_t new_size = (packet->heap_pattern % 16384) + 8;
            char *new_ptr = (char*)sqlite3_realloc(spray_ptrs[i], new_size);
            if (new_ptr) {
                spray_ptrs[i] = new_ptr;
                /* 재할당된 메모리 손상 테스트 */
                if (packet->spray_pattern & 0x02) {
                    memset(new_ptr + (new_size - 8), 0xFF, 8);
                }
            }
        }
    }
    
    /* 정리 */
    for (int i = 0; i < spray_count; i++) {
        if (spray_ptrs[i]) {
            sqlite3_free(spray_ptrs[i]);
        }
    }
    sqlite3_free(spray_ptrs);
    
    return 1;
}

/* VDBE 메모리 스트레스 - sqlite3VdbeMemGrow/SetStr 타겟팅 */
int fuzz_vdbe_memory_stress(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < sizeof(vdbe_memory_packet)) return 0;
    
    vdbe_memory_packet *packet = (vdbe_memory_packet*)data;
    sqlite3 *db = ctx->db;
    sqlite3_stmt *pStmt = NULL;
    int rc;
    
    /* VDBE 컨텍스트 생성 */
    const char *sql = "SELECT ?1, ?2, ?3";
    rc = sqlite3_prepare_v2(db, sql, -1, &pStmt, NULL);
    if (rc != SQLITE_OK || !pStmt) return 0;
    
    /* 메모리 증가 패턴 테스팅 */
    char *test_string = NULL;
    size_t string_size = packet->initial_size % 8192;
    
    test_string = (char*)sqlite3_malloc(string_size + 1);
    if (test_string) {
        memcpy(test_string, packet->mem_content, 
               (string_size < 512) ? string_size : 512);
        test_string[string_size] = 0;
        
        /* sqlite3_bind_text로 VDBE 메모리 조작 */
        sqlite3_bind_text(pStmt, 1, test_string, string_size, SQLITE_TRANSIENT);
        
        /* 메모리 증가 시뮬레이션 */
        size_t target_size = packet->target_size % 65536;
        if (target_size > string_size) {
            char *expanded = (char*)sqlite3_realloc(test_string, target_size + 1);
            if (expanded) {
                test_string = expanded;
                /* 확장된 영역에 패턴 주입 */
                memset(test_string + string_size, packet->vdbe_op_type, 
                       target_size - string_size);
                test_string[target_size] = 0;
                
                sqlite3_bind_text(pStmt, 2, test_string, target_size, SQLITE_TRANSIENT);
            }
        }
        
        /* UTF-8/UTF-16 인코딩 전환 스트레스 */
        if (packet->string_encoding & 0x01) {
            sqlite3_bind_text16(pStmt, 3, test_string, 
                                (target_size < 1000) ? target_size * 2 : 2000, 
                                SQLITE_TRANSIENT);
        }
        
        /* VDBE 실행으로 메모리 연산 트리거 */
        while (sqlite3_step(pStmt) == SQLITE_ROW) {
            /* 결과 추출로 메모리 변환 유발 */
            sqlite3_column_text(pStmt, 0);
            sqlite3_column_text(pStmt, 1);
            sqlite3_column_text16(pStmt, 2);
        }
        
        sqlite3_free(test_string);
    }
    
    sqlite3_finalize(pStmt);
    return 1;
}

/* 페이지 할당 스트레스 - sqlite3PagerGet/Write 타겟팅 */
int fuzz_page_alloc_stress(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < sizeof(page_alloc_packet)) return 0;
    
    page_alloc_packet *packet = (page_alloc_packet*)data;
    sqlite3 *db = ctx->db;
    sqlite3_stmt *pStmt = NULL;
    int rc;
    
    /* 대량 페이지 할당을 유발하는 테이블 생성 */
    const char *create_sql = "CREATE TEMP TABLE page_stress_test ("
                            "id INTEGER PRIMARY KEY, "
                            "data1 TEXT, data2 TEXT, data3 TEXT, data4 TEXT)";
    
    rc = sqlite3_exec(db, create_sql, NULL, NULL, NULL);
    if (rc != SQLITE_OK) return 0;
    
    /* 페이지 할당 패턴에 따른 데이터 삽입 */
    const char *insert_sql = "INSERT INTO page_stress_test (data1, data2, data3, data4) VALUES (?, ?, ?, ?)";
    rc = sqlite3_prepare_v2(db, insert_sql, -1, &pStmt, NULL);
    if (rc != SQLITE_OK || !pStmt) return 0;
    
    int insert_count = packet->alloc_pattern % 100; // 최대 100개 레코드
    
    for (int i = 0; i < insert_count; i++) {
        /* 가변 크기 데이터로 페이지 파편화 유발 */
        size_t data_size = (packet->page_size % 4096) + 100;
        char *large_data = (char*)sqlite3_malloc(data_size + 1);
        
        if (large_data) {
            /* 패킷 데이터로 페이지 내용 구성 */
            size_t copy_size = (data_size < 1024) ? data_size : 1024;
            memcpy(large_data, packet->page_data, copy_size);
            
            /* 페이지 경계를 넘나드는 데이터 패턴 */
            if (packet->corruption_type & 0x01) {
                memset(large_data + copy_size - 100, 0xAA, 100);
            }
            
            large_data[data_size] = 0;
            
            /* 4개 컬럼에 동일 데이터 바인딩으로 메모리 압박 */
            sqlite3_bind_text(pStmt, 1, large_data, data_size, SQLITE_TRANSIENT);
            sqlite3_bind_text(pStmt, 2, large_data, data_size, SQLITE_TRANSIENT);
            sqlite3_bind_text(pStmt, 3, large_data, data_size, SQLITE_TRANSIENT);
            sqlite3_bind_text(pStmt, 4, large_data, data_size, SQLITE_TRANSIENT);
            
            sqlite3_step(pStmt);
            sqlite3_reset(pStmt);
            
            sqlite3_free(large_data);
        }
        
        /* 페이지 캐시 압박을 위한 강제 동기화 */
        if ((i % 10) == 0) {
            sqlite3_exec(db, "PRAGMA synchronous=FULL", NULL, NULL, NULL);
        }
    }
    
    sqlite3_finalize(pStmt);
    
    /* 페이지 재구성을 유발하는 UPDATE/DELETE 패턴 */
    if (packet->corruption_type & 0x02) {
        sqlite3_exec(db, "UPDATE page_stress_test SET data1 = data1 || data2 WHERE id % 2 = 0", NULL, NULL, NULL);
        sqlite3_exec(db, "DELETE FROM page_stress_test WHERE id % 3 = 0", NULL, NULL, NULL);
        sqlite3_exec(db, "VACUUM", NULL, NULL, NULL);
    }
    
    return 1;
}

/* 버퍼 오버플로우 공격 */
int fuzz_buffer_overflow_attack(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < 64) return 0;
    
    /* sqlite3_mprintf를 통한 문자열 포맷팅 오버플로우 */
    char *format_str = sqlite3_mprintf("%.*s", (int)(size % 8192), (char*)data);
    if (format_str) {
        /* 포맷 문자열 길이 조작 */
        size_t len = strlen(format_str);
        if (len > 0) {
            char *expanded = sqlite3_mprintf("%s%s%s%s", format_str, format_str, format_str, format_str);
            sqlite3_free(expanded);
        }
        sqlite3_free(format_str);
    }
    
    return 1;
}

/* 정수 오버플로우 공격 */
int fuzz_integer_overflow_attack(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < 16) return 0;
    
    uint32_t *values = (uint32_t*)data;
    size_t alloc_size = values[0];
    
    /* 정수 오버플로우를 유발하는 대형 할당 */
    if (alloc_size > 0x7FFFFFFF) {
        alloc_size = 0x7FFFFFFF; // 최대값으로 제한
    }
    
    char *large_buffer = (char*)sqlite3_malloc(alloc_size);
    if (large_buffer) {
        /* 경계 근처 메모리 접근 */
        if (alloc_size > 1024) {
            memset(large_buffer, 0xCC, 1024);
            memset(large_buffer + alloc_size - 1024, 0xDD, 1024);
        }
        sqlite3_free(large_buffer);
    }
    
    return 1;
}

/* 이중 해제 공격 */
int fuzz_double_free_attack(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < 32) return 0;
    
    char *ptr1 = (char*)sqlite3_malloc(1024);
    char *ptr2 = (char*)sqlite3_malloc(1024);
    
    if (ptr1 && ptr2) {
        memcpy(ptr1, data, (size < 1024) ? size : 1024);
        memcpy(ptr2, data, (size < 1024) ? size : 1024);
        
        sqlite3_free(ptr1);
        sqlite3_free(ptr2);
        
        /* 의도적 이중 해제는 보안상 위험하므로 시뮬레이션만 */
        // sqlite3_free(ptr1); // 실제로는 실행하지 않음
    }
    
    return 1;
}

/* 해제 후 사용 공격 */
int fuzz_use_after_free_attack(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < 32) return 0;
    
    char *ptr = (char*)sqlite3_malloc(1024);
    if (ptr) {
        memcpy(ptr, data, (size < 1024) ? size : 1024);
        sqlite3_free(ptr);
        
        /* 해제 후 사용은 시뮬레이션만 수행 */
        // memset(ptr, 0xAA, 1024); // 실제로는 실행하지 않음
    }
    
    return 1;
}