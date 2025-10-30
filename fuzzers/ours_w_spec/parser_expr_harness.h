/*
** SQLite3 Parser Expression Functions Harness Header
** Target functions: sqlite3ExprAttachSubtrees, sqlite3NestedParse, sqlite3TableLock
*/

#ifndef PARSER_EXPR_HARNESS_H
#define PARSER_EXPR_HARNESS_H

#include "fuzz.h"

/* Packet structures for Parser expression functions */
typedef struct ExprAttachSubtreesPacket {
    uint32_t scenario;
    uint8_t  rootOp;
    uint8_t  leftOp;
    uint8_t  rightOp;
    uint8_t  treeDepth;
    uint32_t rootFlags;
    uint32_t leftFlags;
    uint32_t rightFlags;
    uint8_t  exprData[64];
} ExprAttachSubtreesPacket;

typedef struct NestedParsePacket {
    uint32_t scenario;
    uint32_t sqlLength;
    uint8_t  nestingDepth;
    uint8_t  argCount;
    uint8_t  formatType;
    uint8_t  padding;
    char     formatString[128];
    char     sqlTemplate[256];
} NestedParsePacket;

typedef struct TableLockPacket {
    uint32_t scenario;
    uint32_t pageNumber;
    uint8_t  databaseIndex;
    uint8_t  isWriteLock;
    uint8_t  nameLength;
    uint8_t  padding;
    char     tableName[64];
    uint8_t  lockData[32];
} TableLockPacket;

/* Function prototypes */
int fuzz_expr_attach_subtrees(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_nested_parse(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_table_lock(FuzzCtx *ctx, const uint8_t *data, size_t size);

#endif /* PARSER_EXPR_HARNESS_H */