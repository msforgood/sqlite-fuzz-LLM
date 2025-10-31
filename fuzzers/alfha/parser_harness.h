/*
** Parser Functions Fuzzing Harness Header
** Target: codeTableLocks, destroyRootPage, sqlite3CodeVerifySchema
** Category: Parser subsystem Critical functions
*/
#ifndef PARSER_HARNESS_H
#define PARSER_HARNESS_H

#include "fuzz.h"

/* Forward declarations for internal SQLite types */
typedef struct Parse Parse;
typedef struct Vdbe Vdbe;
typedef struct TableLock TableLock;

/* Fuzzing mode definitions for parser functions */
#define FUZZ_MODE_CODE_TABLE_LOCKS      0x20
#define FUZZ_MODE_DESTROY_ROOT_PAGE     0x21
#define FUZZ_MODE_CODE_VERIFY_SCHEMA    0x22

/* Parser context structures for fuzzing */
typedef struct {
    uint8_t mode;
    uint8_t db_index;
    uint8_t table_count;
    uint8_t flags;
    uint32_t table_id;
    uint32_t schema_cookie;
} ParserFuzzHeader;

typedef struct {
    uint32_t iDb;
    uint32_t iTab;
    uint8_t isWriteLock;
    uint8_t name_len;
    char zLockName[256];
} TableLockData;

typedef struct {
    uint32_t iTable;
    uint32_t iDb;
    uint8_t corruption_test;
    uint8_t autovacuum_enable;
} DestroyPageData;

typedef struct {
    uint32_t iDb;
    uint8_t temp_db_test;
    uint8_t schema_validation;
    uint16_t cookie_mask;
} VerifySchemaData;

/* Function declarations */
int fuzz_codeTableLocks(const uint8_t *data, size_t size);
int fuzz_destroyRootPage(const uint8_t *data, size_t size);
int fuzz_sqlite3CodeVerifySchema(const uint8_t *data, size_t size);

/* Helper functions */
int setup_parser_context(sqlite3 **db, Parse **pParse);
void cleanup_parser_context(sqlite3 *db, Parse *pParse);
int create_table_locks(Parse *pParse, const TableLockData *locks, int count);

#endif /* PARSER_HARNESS_H */