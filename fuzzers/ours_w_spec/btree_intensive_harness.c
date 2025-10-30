/*
** SQLite3 B-Tree Intensive Operations Harness Implementation
** B-Tree 내부 구조 조작을 통한 크래시 유발 테스팅 구현
*/

#include "btree_intensive_harness.h"
#include <string.h>
#include <stdlib.h>

/* 페이지 분할 스트레스 - allocateBtreePage, balance 함수들 타겟팅 */
int fuzz_page_split_stress(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < sizeof(page_split_packet)) return 0;
    
    page_split_packet *packet = (page_split_packet*)data;
    sqlite3 *db = ctx->db;
    sqlite3_stmt *pStmt = NULL;
    int rc;
    
    /* B-Tree 분할을 유발하는 테이블 생성 */
    const char *create_sql = "CREATE TABLE btree_split_test ("
                            "id INTEGER PRIMARY KEY, "
                            "key_col TEXT, "
                            "payload_col BLOB)";
    
    rc = sqlite3_exec(db, create_sql, NULL, NULL, NULL);
    if (rc != SQLITE_OK) return 0;
    
    /* 페이지 크기 설정으로 분할 조건 조정 */
    sqlite3_exec(db, "PRAGMA page_size=1024", NULL, NULL, NULL);
    
    /* 대량 삽입으로 페이지 분할 강제 유발 */
    const char *insert_sql = "INSERT INTO btree_split_test (key_col, payload_col) VALUES (?, ?)";
    rc = sqlite3_prepare_v2(db, insert_sql, -1, &pStmt, NULL);
    if (rc != SQLITE_OK || !pStmt) return 0;
    
    int insert_count = packet->insert_count % 500; // 최대 500개
    
    for (int i = 0; i < insert_count; i++) {
        /* 키 크기 조작으로 분할 패턴 제어 */
        size_t key_size = (packet->key_size % 256) + 8;
        char *key_buffer = (char*)sqlite3_malloc(key_size + 1);
        
        if (key_buffer) {
            /* 키 분포 패턴 적용 */
            switch (packet->key_distribution % 4) {
                case 0: // 순차적 키 (오른쪽 분할 유발)
                    snprintf(key_buffer, key_size, "key_%08d", i);
                    break;
                case 1: // 역순 키 (왼쪽 분할 유발)
                    snprintf(key_buffer, key_size, "key_%08d", insert_count - i);
                    break;
                case 2: // 랜덤 키 (중간 분할 유발)
                    snprintf(key_buffer, key_size, "key_%08x", packet->payload_pattern ^ i);
                    break;
                case 3: // 패킷 기반 키
                    memcpy(key_buffer, packet->key_data, 
                           (key_size < 512) ? key_size : 512);
                    key_buffer[key_size] = 0;
                    break;
            }
            
            /* 페이로드 크기 조작으로 페이지 채우기 패턴 제어 */
            size_t payload_size = (packet->payload_size_class % 8) * 128 + 64;
            uint8_t *payload_buffer = (uint8_t*)sqlite3_malloc(payload_size);
            
            if (payload_buffer) {
                /* 페이로드 패턴 생성 */
                for (size_t j = 0; j < payload_size; j++) {
                    payload_buffer[j] = packet->payload_data[j % 1024] ^ (j & 0xFF);
                }
                
                sqlite3_bind_text(pStmt, 1, key_buffer, key_size, SQLITE_TRANSIENT);
                sqlite3_bind_blob(pStmt, 2, payload_buffer, payload_size, SQLITE_TRANSIENT);
                
                sqlite3_step(pStmt);
                sqlite3_reset(pStmt);
                
                sqlite3_free(payload_buffer);
            }
            
            sqlite3_free(key_buffer);
        }
        
        /* 분할 트리거 조건 체크 */
        if ((i % 50) == 0 && (packet->split_trigger & 0x01)) {
            /* 강제 체크포인트로 페이지 쓰기 유발 */
            sqlite3_exec(db, "PRAGMA wal_checkpoint", NULL, NULL, NULL);
        }
    }
    
    sqlite3_finalize(pStmt);
    
    /* 분할된 페이지들에 대한 스트레스 연산 */
    if (packet->split_pattern & 0x02) {
        /* 범위 쿼리로 분할된 페이지 탐색 */
        sqlite3_exec(db, "SELECT COUNT(*) FROM btree_split_test WHERE key_col BETWEEN 'key_000' AND 'key_999'", 
                     NULL, NULL, NULL);
    }
    
    return 1;
}

/* 커서 조작 - 복잡한 커서 이동 패턴으로 크래시 유발 */
int fuzz_cursor_manipulation(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < sizeof(cursor_manipulation_packet)) return 0;
    
    cursor_manipulation_packet *packet = (cursor_manipulation_packet*)data;
    sqlite3 *db = ctx->db;
    sqlite3_stmt *pStmt = NULL;
    int rc;
    
    /* 커서 테스트용 테이블 준비 */
    const char *create_sql = "CREATE TABLE cursor_test ("
                            "id INTEGER PRIMARY KEY, "
                            "data TEXT)";
    
    rc = sqlite3_exec(db, create_sql, NULL, NULL, NULL);
    if (rc != SQLITE_OK) return 0;
    
    /* 테스트 데이터 삽입 */
    const char *insert_sql = "INSERT INTO cursor_test (id, data) VALUES (?, ?)";
    rc = sqlite3_prepare_v2(db, insert_sql, -1, &pStmt, NULL);
    if (rc != SQLITE_OK) return 0;
    
    for (int i = 0; i < 100; i++) {
        sqlite3_bind_int(pStmt, 1, i);
        sqlite3_bind_text(pStmt, 2, packet->seek_data, -1, SQLITE_STATIC);
        sqlite3_step(pStmt);
        sqlite3_reset(pStmt);
    }
    sqlite3_finalize(pStmt);
    
    /* 복잡한 커서 이동 패턴 실행 */
    const char *select_sql = "SELECT * FROM cursor_test WHERE id >= ? ORDER BY id";
    rc = sqlite3_prepare_v2(db, select_sql, -1, &pStmt, NULL);
    if (rc != SQLITE_OK) return 0;
    
    int movement_count = packet->movement_count % 200;
    
    for (int i = 0; i < movement_count; i++) {
        int seek_target = packet->target_rowid % 100;
        
        /* 커서 이동 패턴 적용 */
        switch (packet->cursor_movement % 8) {
            case 0: // First/Last 경계 테스트
                sqlite3_bind_int(pStmt, 1, 0);
                break;
            case 1: // 중간 지점 탐색
                sqlite3_bind_int(pStmt, 1, seek_target);
                break;
            case 2: // 존재하지 않는 키 탐색
                sqlite3_bind_int(pStmt, 1, 200 + seek_target);
                break;
            case 3: // 음수 키 탐색
                sqlite3_bind_int(pStmt, 1, -seek_target);
                break;
            case 4: // 최대값 탐색
                sqlite3_bind_int(pStmt, 1, 0x7FFFFFFF);
                break;
            case 5: // 최소값 탐색
                sqlite3_bind_int(pStmt, 1, 0x80000000);
                break;
            case 6: // 패킷 기반 탐색
                sqlite3_bind_int(pStmt, 1, packet->seek_key);
                break;
            case 7: // 0 탐색
                sqlite3_bind_int(pStmt, 1, 0);
                break;
        }
        
        /* 커서 이동 실행 */
        int step_count = 0;
        while (sqlite3_step(pStmt) == SQLITE_ROW && step_count < 10) {
            /* 경계 테스트 수행 */
            if (packet->boundary_test & 0x01) {
                sqlite3_column_int(pStmt, 0);
                sqlite3_column_text(pStmt, 1);
            }
            step_count++;
        }
        
        sqlite3_reset(pStmt);
        
        /* 손상 타입에 따른 추가 연산 */
        if ((packet->corruption_type & 0x03) == (i & 0x03)) {
            /* 동시 수정으로 커서 무효화 시도 */
            char update_sql[256];
            snprintf(update_sql, sizeof(update_sql), 
                    "UPDATE cursor_test SET data = '%.*s' WHERE id = %d", 
                    (int)(sizeof(packet->seek_data) - 1), packet->seek_data, seek_target);
            sqlite3_exec(db, update_sql, NULL, NULL, NULL);
        }
    }
    
    sqlite3_finalize(pStmt);
    return 1;
}

/* VACUUM 스트레스 - 페이지 재구성 중 크래시 유발 */
int fuzz_vacuum_stress(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < sizeof(vacuum_stress_packet)) return 0;
    
    vacuum_stress_packet *packet = (vacuum_stress_packet*)data;
    sqlite3 *db = ctx->db;
    int rc;
    
    /* VACUUM 스트레스용 테이블 생성 */
    const char *create_sql = "CREATE TABLE vacuum_stress ("
                            "id INTEGER PRIMARY KEY, "
                            "data BLOB)";
    
    rc = sqlite3_exec(db, create_sql, NULL, NULL, NULL);
    if (rc != SQLITE_OK) return 0;
    
    /* 파편화 유발을 위한 데이터 삽입/삭제 패턴 */
    sqlite3_stmt *pStmt = NULL;
    const char *insert_sql = "INSERT INTO vacuum_stress (data) VALUES (?)";
    rc = sqlite3_prepare_v2(db, insert_sql, -1, &pStmt, NULL);
    if (rc != SQLITE_OK) return 0;
    
    int record_count = packet->page_count % 1000;
    
    /* 첫 번째 라운드: 대량 삽입 */
    for (int i = 0; i < record_count; i++) {
        size_t data_size = (packet->record_size % 4096) + 100;
        
        sqlite3_bind_blob(pStmt, 1, packet->test_data, 
                         (data_size < 2048) ? data_size : 2048, SQLITE_STATIC);
        sqlite3_step(pStmt);
        sqlite3_reset(pStmt);
    }
    sqlite3_finalize(pStmt);
    
    /* 파편화 유발: 선택적 삭제 */
    switch (packet->fragmentation_level % 4) {
        case 0: // 홀수 ID 삭제
            sqlite3_exec(db, "DELETE FROM vacuum_stress WHERE id % 2 = 1", NULL, NULL, NULL);
            break;
        case 1: // 3의 배수 삭제
            sqlite3_exec(db, "DELETE FROM vacuum_stress WHERE id % 3 = 0", NULL, NULL, NULL);
            break;
        case 2: // 랜덤 50% 삭제
            sqlite3_exec(db, "DELETE FROM vacuum_stress WHERE id % 2 = 0", NULL, NULL, NULL);
            break;
        case 3: // 중간 범위 삭제
            sqlite3_exec(db, "DELETE FROM vacuum_stress WHERE id BETWEEN 100 AND 200", NULL, NULL, NULL);
            break;
    }
    
    /* VACUUM 타입별 실행 */
    switch (packet->vacuum_type % 4) {
        case 0: // 일반 VACUUM
            rc = sqlite3_exec(db, "VACUUM", NULL, NULL, NULL);
            break;
        case 1: // VACUUM INTO 임시 파일
            rc = sqlite3_exec(db, "VACUUM INTO '/tmp/vacuum_test.db'", NULL, NULL, NULL);
            break;
        case 2: // PRAGMA 기반 VACUUM
            sqlite3_exec(db, "PRAGMA auto_vacuum=FULL", NULL, NULL, NULL);
            rc = sqlite3_exec(db, "VACUUM", NULL, NULL, NULL);
            break;
        case 3: // 점진적 VACUUM
            sqlite3_exec(db, "PRAGMA auto_vacuum=INCREMENTAL", NULL, NULL, NULL);
            sqlite3_exec(db, "PRAGMA incremental_vacuum(10)", NULL, NULL, NULL);
            break;
    }
    
    /* 손상 주입 테스트 */
    if (packet->corruption_inject & 0x01) {
        /* VACUUM 중 추가 데이터 변경 시도 */
        const char *concurrent_sql = "INSERT INTO vacuum_stress (data) VALUES (?)";
        sqlite3_prepare_v2(db, concurrent_sql, -1, &pStmt, NULL);
        if (pStmt) {
            sqlite3_bind_blob(pStmt, 1, packet->test_data, 1024, SQLITE_STATIC);
            sqlite3_step(pStmt);
            sqlite3_finalize(pStmt);
        }
    }
    
    return 1;
}

/* B-Tree 병합 손상 */
int fuzz_btree_merge_corruption(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < 64) return 0;
    
    sqlite3 *db = ctx->db;
    
    /* 병합을 유발하는 작은 페이지 크기 설정 */
    sqlite3_exec(db, "PRAGMA page_size=512", NULL, NULL, NULL);
    
    /* 병합 테스트용 테이블 */
    const char *create_sql = "CREATE TABLE merge_test (id INTEGER PRIMARY KEY, data TEXT)";
    sqlite3_exec(db, create_sql, NULL, NULL, NULL);
    
    /* 작은 레코드들로 여러 페이지 생성 */
    for (int i = 0; i < 100; i++) {
        char sql[256];
        snprintf(sql, sizeof(sql), "INSERT INTO merge_test VALUES (%d, '%.*s')", 
                i, (int)(size % 32), (char*)data);
        sqlite3_exec(db, sql, NULL, NULL, NULL);
    }
    
    /* 병합을 유발하는 대량 삭제 */
    sqlite3_exec(db, "DELETE FROM merge_test WHERE id % 2 = 0", NULL, NULL, NULL);
    sqlite3_exec(db, "VACUUM", NULL, NULL, NULL);
    
    return 1;
}

/* 재밸런싱 혼돈 */
int fuzz_rebalance_chaos(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < 64) return 0;
    
    sqlite3 *db = ctx->db;
    
    /* 재밸런싱용 테이블 생성 */
    sqlite3_exec(db, "CREATE TABLE rebalance_test (key TEXT PRIMARY KEY, value BLOB)", NULL, NULL, NULL);
    
    /* 불균형 삽입 패턴으로 재밸런싱 유발 */
    for (int i = 0; i < 50; i++) {
        char key[64];
        snprintf(key, sizeof(key), "key_%08d", i * 1000); // 큰 간격으로 삽입
        
        sqlite3_stmt *pStmt;
        sqlite3_prepare_v2(db, "INSERT INTO rebalance_test VALUES (?, ?)", -1, &pStmt, NULL);
        sqlite3_bind_text(pStmt, 1, key, -1, SQLITE_STATIC);
        sqlite3_bind_blob(pStmt, 2, data, (size < 1024) ? size : 1024, SQLITE_STATIC);
        sqlite3_step(pStmt);
        sqlite3_finalize(pStmt);
    }
    
    /* 중간값 삽입으로 재밸런싱 강제 유발 */
    for (int i = 0; i < 25; i++) {
        char key[64];
        snprintf(key, sizeof(key), "key_%08d", i * 1000 + 500); // 중간값 삽입
        
        sqlite3_stmt *pStmt;
        sqlite3_prepare_v2(db, "INSERT INTO rebalance_test VALUES (?, ?)", -1, &pStmt, NULL);
        sqlite3_bind_text(pStmt, 1, key, -1, SQLITE_STATIC);
        sqlite3_bind_blob(pStmt, 2, data, (size < 512) ? size : 512, SQLITE_STATIC);
        sqlite3_step(pStmt);
        sqlite3_finalize(pStmt);
    }
    
    return 1;
}

/* 인덱스 손상 */
int fuzz_index_corruption(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < 32) return 0;
    
    sqlite3 *db = ctx->db;
    
    /* 복합 인덱스 테스트 */
    sqlite3_exec(db, "CREATE TABLE index_test (a INTEGER, b TEXT, c REAL)", NULL, NULL, NULL);
    sqlite3_exec(db, "CREATE INDEX idx_abc ON index_test(a, b, c)", NULL, NULL, NULL);
    sqlite3_exec(db, "CREATE INDEX idx_cb ON index_test(c, b)", NULL, NULL, NULL);
    
    /* 인덱스 손상을 유발하는 복잡한 삽입 패턴 */
    for (int i = 0; i < 50; i++) {
        char sql[512];
        snprintf(sql, sizeof(sql), 
                "INSERT INTO index_test VALUES (%d, '%.*s', %f)", 
                *(int*)data, (int)(size % 16), (char*)data, 
                (double)(*(float*)data));
        sqlite3_exec(db, sql, NULL, NULL, NULL);
    }
    
    /* 인덱스 무결성 검사 */
    sqlite3_exec(db, "PRAGMA integrity_check", NULL, NULL, NULL);
    
    return 1;
}

/* 트랜잭션 혼돈 */
int fuzz_transaction_chaos(FuzzCtx *ctx, const uint8_t *data, size_t size) {
    if (size < 32) return 0;
    
    sqlite3 *db = ctx->db;
    
    /* 중첩 트랜잭션 시뮬레이션 */
    sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL);
    sqlite3_exec(db, "SAVEPOINT sp1", NULL, NULL, NULL);
    
    /* 트랜잭션 내 복잡한 연산 */
    sqlite3_exec(db, "CREATE TEMP TABLE tx_test (data BLOB)", NULL, NULL, NULL);
    
    for (int i = 0; i < 20; i++) {
        sqlite3_stmt *pStmt;
        sqlite3_prepare_v2(db, "INSERT INTO tx_test VALUES (?)", -1, &pStmt, NULL);
        sqlite3_bind_blob(pStmt, 1, data, (size < 1024) ? size : 1024, SQLITE_STATIC);
        sqlite3_step(pStmt);
        sqlite3_finalize(pStmt);
        
        if (i % 5 == 0) {
            if (data[i % size] & 0x01) {
                sqlite3_exec(db, "ROLLBACK TO sp1", NULL, NULL, NULL);
                sqlite3_exec(db, "SAVEPOINT sp1", NULL, NULL, NULL);
            }
        }
    }
    
    /* 랜덤 커밋/롤백 */
    if (data[0] & 0x01) {
        sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
    } else {
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    }
    
    return 1;
}