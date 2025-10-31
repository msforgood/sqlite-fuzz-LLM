/*
** SQLite3 B-Tree Advanced API Harness Header
** Target functions: sqlite3BtreeBeginStmt, sqlite3BtreeCheckpoint, sqlite3BtreeCommit,
**                  sqlite3BtreeCount, sqlite3BtreeCreateTable, sqlite3BtreeCursor
** High-frequency public API functions for maximum crash discovery
*/
#ifndef BTREE_API_ADVANCED_HARNESS_H
#define BTREE_API_ADVANCED_HARNESS_H

#include "fuzz.h"

/* Packet structures for advanced B-Tree API fuzzing */
typedef struct {
    uint8_t stmtMode;
    uint8_t scenario;
    uint8_t flags;
    uint8_t padding;
    uint32_t iStatement;
    uint32_t transactionLevel;
    uint32_t testParams[4];
} btree_begin_stmt_packet;

typedef struct {
    uint8_t checkpointMode;
    uint8_t scenario;
    uint8_t flags;
    uint8_t walMode;
    uint32_t eMode;
    uint32_t logSize;
    uint32_t testParams[4];
} btree_checkpoint_packet;

typedef struct {
    uint8_t commitMode;
    uint8_t scenario;
    uint8_t flags;
    uint8_t journalMode;
    uint32_t changeCount;
    uint32_t transactionId;
    uint32_t testParams[4];
} btree_commit_packet;

typedef struct {
    uint8_t countMode;
    uint8_t scenario;
    uint8_t flags;
    uint8_t cursorType;
    uint32_t scanLimit;
    uint32_t estimateThreshold;
    uint32_t testParams[4];
} btree_count_packet;

typedef struct {
    uint8_t createMode;
    uint8_t scenario;
    uint8_t flags;
    uint8_t tableType;
    uint32_t createFlags;
    uint32_t pageSize;
    uint32_t testParams[4];
} btree_create_table_packet;

typedef struct {
    uint8_t cursorMode;
    uint8_t scenario;
    uint8_t flags;
    uint8_t writeFlag;
    uint32_t iTable;
    uint32_t keyInfoSize;
    uint32_t testParams[4];
} btree_cursor_api_packet;

/* Function declarations for B-Tree advanced API harnesses */
int fuzz_sqlite3_btree_begin_stmt(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_sqlite3_btree_checkpoint(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_sqlite3_btree_commit(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_sqlite3_btree_count(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_sqlite3_btree_create_table(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_sqlite3_btree_cursor_api(FuzzCtx *ctx, const uint8_t *data, size_t size);

#endif /* BTREE_API_ADVANCED_HARNESS_H */