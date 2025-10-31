/*
** Parser Advanced Functions Harness Header
** Targets: sqlite3CodeVerifyNamedSchema, sqlite3CodeVerifySchemaAtToplevel, 
**          sqlite3CommitInternalChanges, sqlite3FreeIndex
** Specification-based fuzzing implementation for SQLite3 v3.51.0
*/

#ifndef PARSER_ADVANCED_HARNESS_H
#define PARSER_ADVANCED_HARNESS_H

#include "fuzz.h"

/* Function Code mappings for Parser Advanced functions */
#define FUZZ_MODE_PARSER_VERIFY_NAMED_SCHEMA      47
#define FUZZ_MODE_PARSER_VERIFY_SCHEMA_TOPLEVEL   48
#define FUZZ_MODE_PARSER_COMMIT_INTERNAL_CHANGES  49
#define FUZZ_MODE_PARSER_FREE_INDEX               50

/* Test scenario constants */
#define PARSER_ADV_SCENARIO_NORMAL     0
#define PARSER_ADV_SCENARIO_MULTI_DB   1
#define PARSER_ADV_SCENARIO_TEMP_DB    2
#define PARSER_ADV_SCENARIO_SCHEMA     3
#define PARSER_ADV_SCENARIO_ATTACH     4
#define PARSER_ADV_SCENARIO_MEMORY     5
#define PARSER_ADV_SCENARIO_INDEX      6
#define PARSER_ADV_SCENARIO_CORRUPT    7

/* Packet structures for each target function */

/*
** Packet for sqlite3CodeVerifyNamedSchema (FC: parser_001)
*/
typedef struct {
    uint32_t dbCount;           /* Number of databases to test */
    uint32_t nameLength;        /* Length of database name */
    uint32_t verifyFlags;       /* Verification control flags */
    uint32_t scenario;          /* Test scenario selector */
    uint32_t parseFlags;        /* Parse context flags */
    uint32_t cookieMask;        /* Schema cookie mask */
    uint32_t corruption_seed;   /* Corruption testing seed */
    uint8_t  reserved;          /* Padding */
    char     testData[32];      /* Test database name data */
} ParserVerifyNamedSchemaPacket;

/*
** Packet for sqlite3CodeVerifySchemaAtToplevel (FC: parser_002)
*/
typedef struct {
    uint32_t dbIndex;           /* Database index to verify */
    uint32_t cookieMask;        /* Current cookie mask state */
    uint32_t scenario;          /* Test scenario selector */
    uint32_t tempDbFlags;       /* Temporary database flags */
    uint32_t maskTest;          /* DbMask test patterns */
    uint32_t toplevelFlags;     /* Toplevel parse flags */
    uint32_t corruption_flags;  /* Corruption test flags */
    uint8_t  reserved;          /* Padding */
    char     testData[24];      /* Test context data */
} ParserVerifyToplevelPacket;

/*
** Packet for sqlite3CommitInternalChanges (FC: parser_003)
*/
typedef struct {
    uint32_t mDbFlags;          /* Database flags to modify */
    uint32_t flagMask;          /* Flag modification mask */
    uint32_t scenario;          /* Test scenario selector */
    uint32_t commitType;        /* Type of commit operation */
    uint32_t schemaChangeFlag;  /* Schema change flag state */
    uint32_t flagOperations;    /* Flag operation types */
    uint32_t corruption_test;   /* Corruption test selector */
    uint8_t  reserved;          /* Padding */
    char     testData[16];      /* Test operation data */
} ParserCommitChangesPacket;

/*
** Packet for sqlite3FreeIndex (FC: parser_004)
*/
typedef struct {
    uint32_t indexSize;         /* Size of index structure */
    uint32_t columnCount;       /* Number of columns in index */
    uint32_t scenario;          /* Test scenario selector */
    uint32_t memoryFlags;       /* Memory management flags */
    uint32_t resizeState;       /* Index resize state */
    uint32_t collationCount;    /* Number of collations */
    uint32_t analyzeFlags;      /* ANALYZE feature flags */
    uint32_t stat4Flags;        /* STAT4 feature flags */
    uint32_t corruption_mask;   /* Corruption testing mask */
    uint8_t  reserved;          /* Padding */
    char     testData[20];      /* Test index data */
} ParserFreeIndexPacket;

/* Function declarations */
int fuzz_parser_verify_named_schema(FuzzCtx *pCtx, const ParserVerifyNamedSchemaPacket *pPacket);
int fuzz_parser_verify_schema_toplevel(FuzzCtx *pCtx, const ParserVerifyToplevelPacket *pPacket);
int fuzz_parser_commit_internal_changes(FuzzCtx *pCtx, const ParserCommitChangesPacket *pPacket);
int fuzz_parser_free_index(FuzzCtx *pCtx, const ParserFreeIndexPacket *pPacket);

#endif /* PARSER_ADVANCED_HARNESS_H */