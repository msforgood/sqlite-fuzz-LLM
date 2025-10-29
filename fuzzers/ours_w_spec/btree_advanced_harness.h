/*
** B-Tree Advanced Functions Fuzzing Harness Header
** Target: btreeInvokeBusyHandler, btreeRestoreCursorPosition, setSharedCacheTableLock
** Category: B-Tree subsystem Critical/High functions
*/
#ifndef BTREE_ADVANCED_HARNESS_H
#define BTREE_ADVANCED_HARNESS_H

#include "fuzz.h"

/* Fuzzing mode definitions for advanced B-Tree functions */
#define FUZZ_MODE_BTREE_BUSY_HANDLER        0x30
#define FUZZ_MODE_BTREE_RESTORE_CURSOR      0x31
#define FUZZ_MODE_BTREE_SHARED_CACHE_LOCK   0x32

/* Advanced B-Tree context structures for fuzzing */
typedef struct {
    uint8_t mode;
    uint8_t timeout_scenario;
    uint8_t busy_count;
    uint8_t flags;
    uint32_t timeout_ms;
    uint32_t retry_count;
} BtreeAdvancedFuzzHeader;

typedef struct {
    uint32_t timeout_ms;
    uint32_t retry_count;
    uint8_t handler_return;
    uint8_t simulate_busy;
    uint8_t concurrent_access;
    uint8_t stress_test;
} BusyHandlerData;

typedef struct {
    uint8_t initial_state;
    uint8_t fault_simulation;
    uint8_t key_preservation;
    uint8_t skip_next_scenario;
    uint32_t key_size;
    uint32_t fault_code;
    char saved_key[256];
} RestoreCursorData;

typedef struct {
    uint32_t table_id;
    uint8_t lock_type;
    uint8_t shared_cache_mode;
    uint8_t conflict_scenario;
    uint8_t read_uncommitted;
    uint32_t concurrent_tables;
} SharedCacheLockData;

/* Function declarations */
int fuzz_btreeInvokeBusyHandler(const uint8_t *data, size_t size);
int fuzz_btreeRestoreCursorPosition(const uint8_t *data, size_t size);
int fuzz_setSharedCacheTableLock(const uint8_t *data, size_t size);

/* Helper functions */
int setup_busy_handler_context(sqlite3 **db, int timeout_ms);
int setup_cursor_context(sqlite3 **db, sqlite3_stmt **stmt);
int setup_shared_cache_context(sqlite3 **db1, sqlite3 **db2);
void cleanup_advanced_context(sqlite3 *db, sqlite3_stmt *stmt);

#endif /* BTREE_ADVANCED_HARNESS_H */