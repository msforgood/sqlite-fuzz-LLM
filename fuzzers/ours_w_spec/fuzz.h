/*
** Enhanced SQLite3 Fuzzer Header
** Target: allocateBtreePage function
** Specification-based fuzzing implementation
*/
#ifndef SQLITE3_ENHANCED_FUZZ_H
#define SQLITE3_ENHANCED_FUZZ_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "sqlite3.h"

/* Forward declarations for vulnerability detection harness */
struct btree_overflow_packet;
struct vdbe_uaf_packet;
struct format_string_packet;
struct wal_race_packet;
struct memory_pressure_packet;

/* Fuzzing mode selector values */
#define FUZZ_MODE_BTREE_ALLOC    0x01  /* Target allocateBtreePage specifically */
#define FUZZ_MODE_FREELIST_FULL  0x02  /* Test freelist scenarios */
#define FUZZ_MODE_CORRUPTION     0x03  /* Test corruption detection */
#define FUZZ_MODE_MEMORY_STRESS  0x04  /* Test memory pressure */
#define FUZZ_MODE_CONCURRENT     0x05  /* Test concurrent access */
#define FUZZ_MODE_AUTOVACUUM     0x06  /* Target autoVacuumCommit specifically */
#define FUZZ_MODE_FREESPACE      0x07  /* Target btreeComputeFreeSpace specifically */
#define FUZZ_MODE_PAGEMANAGEMENT 0x08  /* Target page management functions */
#define FUZZ_MODE_TABLECURSOR    0x09  /* Target table/cursor management functions */
#define FUZZ_MODE_BTREE_TRANS    0x0A  /* Target btreeBeginTrans */
#define FUZZ_MODE_CELL_CHECK     0x0B  /* Target btreeCellSizeCheck */
#define FUZZ_MODE_CREATE_TABLE   0x0C  /* Target btreeCreateTable */
#define FUZZ_MODE_CURSOR         0x0D  /* Target btreeCursor */
#define FUZZ_MODE_DROP_TABLE     0x0E  /* Target btreeDropTable */
#define FUZZ_MODE_FREE_PAGE      0x10  /* Target freePage specifically */
#define FUZZ_MODE_CLEAR_PAGE     0x11  /* Target clearDatabasePage specifically */
#define FUZZ_MODE_DEFRAG_PAGE    0x12  /* Target defragmentPage specifically */
#define FUZZ_MODE_CLOSE_CURSOR   0x13  /* Target sqlite3BtreeCloseCursor specifically */
#define FUZZ_MODE_DELETE_AUXDATA  0x14  /* Target sqlite3VdbeDeleteAuxData specifically */
#define FUZZ_MODE_SET_NUMCOLS     0x15  /* Target sqlite3VdbeSetNumCols specifically */
#define FUZZ_MODE_MEM_WRITEABLE   0x16  /* Target sqlite3VdbeMemMakeWriteable specifically */
#define FUZZ_MODE_VALUE_FREE      0x17  /* Target sqlite3_value_free specifically */
#define FUZZ_MODE_CODE_TABLE_LOCKS      0x20  /* Target codeTableLocks specifically */
#define FUZZ_MODE_DESTROY_ROOT_PAGE     0x21  /* Target destroyRootPage specifically */
#define FUZZ_MODE_CODE_VERIFY_SCHEMA    0x22  /* Target sqlite3CodeVerifySchema specifically */
#define FUZZ_MODE_BTREE_BUSY_HANDLER    0x30  /* Target btreeInvokeBusyHandler specifically */
#define FUZZ_MODE_BTREE_RESTORE_CURSOR  0x31  /* Target btreeRestoreCursorPosition specifically */

/* Advanced Memory Attack Modes (0xA0-0xA6) */
#define MEMORY_MODE_HEAP_SPRAY          0xA0  /* 힙 스프레이 공격 */
#define MEMORY_MODE_DOUBLE_FREE         0xA1  /* 이중 해제 */
#define MEMORY_MODE_USE_AFTER_FREE      0xA2  /* 해제 후 사용 */
#define MEMORY_MODE_BUFFER_OVERFLOW     0xA3  /* 버퍼 오버플로우 */
#define MEMORY_MODE_INTEGER_OVERFLOW    0xA4  /* 정수 오버플로우 */
#define MEMORY_MODE_VDBE_MEMORY_STRESS  0xA5  /* VDBE 메모리 스트레스 */
#define MEMORY_MODE_PAGE_ALLOC_STRESS   0xA6  /* 페이지 할당 스트레스 */

/* B-Tree Intensive Attack Modes (0xB0-0xB6) */
#define BTREE_MODE_PAGE_SPLIT_STRESS    0xB0  /* 페이지 분할 스트레스 */
#define BTREE_MODE_MERGE_CORRUPTION     0xB1  /* 병합 손상 */
#define BTREE_MODE_REBALANCE_CHAOS      0xB2  /* 재밸런싱 혼돈 */
#define BTREE_MODE_CURSOR_MANIPULATION  0xB3  /* 커서 조작 */
#define BTREE_MODE_INDEX_CORRUPTION     0xB4  /* 인덱스 손상 */
#define BTREE_MODE_VACUUM_STRESS        0xB5  /* VACUUM 스트레스 */
#define BTREE_MODE_TRANSACTION_CHAOS    0xB6  /* 트랜잭션 혼돈 */

/* VDBE Execution Attack Modes (0xC0-0xC6) */
#define VDBE_MODE_OPCODE_CHAOS         0xC0  /* 연산코드 혼돈 */
#define VDBE_MODE_STACK_OVERFLOW       0xC1  /* 스택 오버플로우 */
#define VDBE_MODE_REGISTER_CORRUPTION  0xC2  /* 레지스터 손상 */
#define VDBE_MODE_PROGRAM_MANIPULATION 0xC3  /* 프로그램 조작 */
#define VDBE_MODE_TYPE_CONFUSION       0xC4  /* 타입 혼동 */
#define VDBE_MODE_AGGREGATE_CHAOS      0xC5  /* 집계 함수 혼돈 */
#define VDBE_MODE_RECURSIVE_EXPLOSION  0xC6  /* 재귀 폭발 */

/* String Processing Attack Modes (0xD0-0xD6) */
#define STRING_MODE_UTF8_BOUNDARY       0xD0  /* UTF-8 경계 공격 */
#define STRING_MODE_UTF16_CONVERSION    0xD1  /* UTF-16 변환 공격 */
#define STRING_MODE_PATTERN_EXPLOSION   0xD2  /* 패턴 폭발 공격 */
#define STRING_MODE_ENCODING_CONFUSION  0xD3  /* 인코딩 혼동 */
#define STRING_MODE_COLLATION_CHAOS     0xD4  /* 조합 혼돈 */
#define STRING_MODE_REGEX_CATASTROPHE   0xD5  /* 정규식 재앙 */
#define STRING_MODE_FORMAT_OVERFLOW     0xD6  /* 포맷 오버플로우 */

/* Utility Batch Test Modes (0xE0-0xE6) */
#define UTILITY_MODE_MATH_FUNCTIONS     0xE0  /* 수학 함수 배치 */
#define UTILITY_MODE_DATE_TIME          0xE1  /* 날짜/시간 함수 */
#define UTILITY_MODE_SYSTEM_INFO        0xE2  /* 시스템 정보 함수 */
#define UTILITY_MODE_TYPE_CONVERSION    0xE3  /* 타입 변환 함수 */
#define UTILITY_MODE_AGGREGATE_SIMPLE   0xE4  /* 단순 집계 함수 */
#define UTILITY_MODE_JSON_FUNCTIONS     0xE5  /* JSON 함수들 */
#define UTILITY_MODE_MISC_UTILITIES     0xE6  /* 기타 유틸리티 */
#define FUZZ_MODE_BTREE_SHARED_CACHE_LOCK 0x32  /* Target setSharedCacheTableLock specifically */
#define FUZZ_MODE_BTREE_MOVETO          0x33  /* Target btreeMoveto specifically */
#define FUZZ_MODE_BTREE_OVERWRITE_CELL  0x34  /* Target btreeOverwriteCell specifically */
#define FUZZ_MODE_BTREE_OVERWRITE_CONTENT 0x35  /* Target btreeOverwriteContent specifically */
#define FUZZ_MODE_VDBE_COLUMN_MALLOC_FAILURE 0x36  /* Target columnMallocFailure specifically */
#define FUZZ_MODE_VDBE_FREE_P4          0x37  /* Target freeP4 specifically */
#define FUZZ_MODE_VDBE_ASSERT_FIELD_COUNT 0x38  /* Target vdbeAssertFieldCountWithinLimits specifically */
#define FUZZ_MODE_ASSERT_PAGER_STATE     0x39  /* Target assert_pager_state specifically */
#define FUZZ_MODE_CHECK_PAGE             0x3A  /* Target checkPage specifically */
#define FUZZ_MODE_PAGE_IN_JOURNAL        0x3B  /* Target pageInJournal specifically */
#define FUZZ_MODE_PAGER_FIX_MAPLIMIT     0x3C  /* Target pagerFixMaplimit specifically */
#define FUZZ_MODE_FREE_IDX_STR           0x3D  /* Target freeIdxStr specifically */
#define FUZZ_MODE_FREE_INDEX_INFO        0x3E  /* Target freeIndexInfo specifically */
#define FUZZ_MODE_WHERE_INFO_FREE        0x3F  /* Target whereInfoFree specifically */
#define FUZZ_MODE_WHERE_LOOP_ADD_BTREE_INDEX 0x40  /* Target whereLoopAddBtreeIndex specifically */
#define FUZZ_MODE_VDBE_RECORD_COMPARE_DEBUG 0x41  /* Target vdbeRecordCompareDebug specifically */
#define FUZZ_MODE_VDBE_RECORD_COMPARE_STRING 0x42  /* Target vdbeRecordCompareString specifically */
#define FUZZ_MODE_VDBE_RECORD_COMPARE_INT 0x43  /* Target vdbeRecordCompareInt specifically */
#define FUZZ_MODE_VDBE_RECORD_DECODE_INT 0x44  /* Target vdbeRecordDecodeInt specifically */
#define FUZZ_MODE_VDBE_MEM_SET_ZERO_BLOB 0x45  /* Target sqlite3VdbeMemSetZeroBlob specifically */
#define FUZZ_MODE_VDBE_MEM_SHALLOW_COPY 0x46  /* Target sqlite3VdbeMemShallowCopy specifically */
#define FUZZ_MODE_VDBE_MEM_STRINGIFY 0x47  /* Target sqlite3VdbeMemStringify specifically */
#define FUZZ_MODE_VDBE_MEM_VALID_STR_REP 0x48  /* Target sqlite3VdbeMemValidStrRep specifically */
#define FUZZ_MODE_BTREE_CURSOR_WITH_LOCK 0x49  /* Target btreeCursorWithLock specifically */
#define FUZZ_MODE_BTREE_LAST          0x4A  /* Target btreeLast specifically */
#define FUZZ_MODE_BTREE_NEXT          0x4B  /* Target btreeNext specifically */
#define FUZZ_MODE_BTREE_OVERWRITE_OVERFLOW_CELL 0x4C  /* Target btreeOverwriteOverflowCell specifically */
#define FUZZ_MODE_BTREE_PARSE_CELL_PTR_INDEX 0x4D  /* Target btreeParseCellPtrIndex specifically */
#define FUZZ_MODE_BTREE_PARSE_CELL_PTR_NO_PAYLOAD 0x4E  /* Target btreeParseCellPtrNoPayload specifically */
#define FUZZ_MODE_VDBE_ADD_DBLQUOTE_STR 0x4F  /* Target sqlite3VdbeAddDblquoteStr specifically */
#define FUZZ_MODE_VDBE_ADD_FUNCTION_CALL 0x50  /* Target sqlite3VdbeAddFunctionCall specifically */
#define FUZZ_MODE_VDBE_ADD_OP4_DUP8 0x51  /* Target sqlite3VdbeAddOp4Dup8 specifically */
#define FUZZ_MODE_EXPR_ATTACH_SUBTREES 0x52  /* Target sqlite3ExprAttachSubtrees specifically */
#define FUZZ_MODE_NESTED_PARSE 0x53  /* Target sqlite3NestedParse specifically */
#define FUZZ_MODE_TABLE_LOCK 0x54  /* Target sqlite3TableLock specifically */
#define FUZZ_MODE_VALUE_BYTES16 0x55  /* Target sqlite3_value_bytes16 specifically */
#define FUZZ_MODE_VALUE_NOCHANGE 0x56  /* Target sqlite3_value_nochange specifically */
#define FUZZ_MODE_VTAB_IN_FIRST 0x57  /* Target sqlite3_vtab_in_first specifically */
#define FUZZ_MODE_RESULT_TEXT16 0x58  /* Target sqlite3_result_text16 specifically */
#define FUZZ_MODE_RESULT_ZEROBLOB64 0x59  /* Target sqlite3_result_zeroblob64 specifically */
#define FUZZ_MODE_STMT_SCANSTATUS 0x5A  /* Target sqlite3_stmt_scanstatus specifically */
#define FUZZ_MODE_BTREE_BEGIN_TRANS 0x5B  /* Target sqlite3BtreeBeginTrans specifically */
#define FUZZ_MODE_BTREE_CLEAR_CURSOR 0x5C  /* Target sqlite3BtreeClearCursor specifically */
#define FUZZ_MODE_BTREE_RELEASE_PAGES 0x5D  /* Target btreeReleaseAllCursorPages specifically */
#define FUZZ_MODE_QUERY_SHARED_CACHE_LOCK 0x5E  /* Target querySharedCacheTableLock specifically */
#define FUZZ_MODE_BTREE_PARSE_CELL_PTR 0x5F  /* Target btreeParseCellPtr specifically */
#define FUZZ_MODE_CURSOR_ON_LAST_PAGE 0x60  /* Target cursorOnLastPage specifically */
#define FUZZ_MODE_BTREE_CURSOR_HAS_MOVED 0x61  /* Target sqlite3BtreeCursorHasMoved specifically */
#define FUZZ_MODE_BTREE_INSERT 0x62  /* Target sqlite3BtreeInsert specifically */
#define FUZZ_MODE_BTREE_INDEX_MOVETO 0x63  /* Target sqlite3BtreeIndexMoveto specifically */
#define FUZZ_MODE_CLEAR_SHARED_CACHE_LOCKS 0x64  /* Target clearAllSharedCacheTableLocks specifically */
#define FUZZ_MODE_SQLITE3_BTREE_CLEAR_TABLE 0x65  /* Target sqlite3BtreeClearTable specifically */
#define FUZZ_MODE_SQLITE3_VDBE_SORTER_INIT 0x66  /* Target sqlite3VdbeSorterInit specifically */
#define FUZZ_MODE_SQLITE3_WHERE_EXPR_ANALYZE 0x67  /* Target sqlite3WhereExprAnalyze specifically */
#define FUZZ_MODE_SQLITE3_VDBE_SORTER_WRITE 0x68  /* Target sqlite3VdbeSorterWrite specifically */
#define FUZZ_MODE_SQLITE3_DB_MALLOC_SIZE 0x69  /* Target sqlite3DbMallocSize specifically */
#define FUZZ_MODE_DOWNGRADE_SHARED_CACHE_LOCKS 0x6A  /* Target downgradeAllSharedCacheTableLocks specifically */

/* Crash Hunting Modes - High Priority for Crash Discovery */
#define CRASH_MODE_MEMORY_STRESS        0x90  /* 메모리 관리 스트레스 */
#define CRASH_MODE_PARSER_OVERFLOW      0x91  /* 파서 오버플로우 */
#define CRASH_MODE_BOUNDARY_VIOLATION   0x92  /* 경계 위반 */
#define CRASH_MODE_STRING_MANIPULATION  0x93  /* 문자열 조작 */
#define CRASH_MODE_RECURSIVE_CALLS      0x94  /* 재귀 호출 */
#define CRASH_MODE_MALFORMED_SQL        0x95  /* 악형 SQL */
#define CRASH_MODE_INDEX_CORRUPTION     0x96  /* 인덱스 손상 */
#define CRASH_MODE_TRANSACTION_ABUSE    0x97  /* 트랜잭션 남용 */
#define CRASH_MODE_BATCH_LOW_RISK       0x98  /* 대량 저위험 함수 */

/* B-Tree Core Operations Functions */
#define FUZZ_MODE_SQLITE3_BTREE_CURSOR_IS_VALID 0x6B  /* Target sqlite3BtreeCursorIsValid specifically */
#define FUZZ_MODE_SQLITE3_BTREE_CLEAR_CACHE 0x6C      /* Target sqlite3BtreeClearCache specifically */
#define FUZZ_MODE_SQLITE3_BTREE_CURSOR_PIN 0x6D       /* Target sqlite3BtreeCursorPin specifically */
#define FUZZ_MODE_HAS_SHARED_CACHE_TABLE_LOCK 0x6E    /* Target hasSharedCacheTableLock specifically */
#define FUZZ_MODE_SQLITE3_BTREE_CURSOR_SIZE 0x6F      /* Target sqlite3BtreeCursorSize specifically */
#define FUZZ_MODE_SQLITE3_BTREE_CLOSES_WITH_CURSOR 0x70 /* Target sqlite3BtreeClosesWithCursor specifically */

/* B-Tree Cursor Navigation Functions */
#define FUZZ_MODE_BTREE_CURSOR_WITH_LOCK_NAV 0x71     /* Target btreeCursorWithLock navigation specifically */
#define FUZZ_MODE_BTREE_LAST_NAV 0x72                 /* Target btreeLast navigation specifically */
#define FUZZ_MODE_BTREE_NEXT_NAV 0x73                 /* Target btreeNext navigation specifically */

/* B-Tree Advanced API Functions */
#define FUZZ_MODE_SQLITE3_BTREE_BEGIN_STMT 0x74       /* Target sqlite3BtreeBeginStmt specifically */
#define FUZZ_MODE_SQLITE3_BTREE_CHECKPOINT 0x75       /* Target sqlite3BtreeCheckpoint specifically */
#define FUZZ_MODE_SQLITE3_BTREE_COMMIT 0x76           /* Target sqlite3BtreeCommit specifically */
#define FUZZ_MODE_SQLITE3_BTREE_COUNT 0x77            /* Target sqlite3BtreeCount specifically */
#define FUZZ_MODE_SQLITE3_BTREE_CREATE_TABLE 0x78     /* Target sqlite3BtreeCreateTable specifically */
#define FUZZ_MODE_SQLITE3_BTREE_CURSOR_API 0x79       /* Target sqlite3BtreeCursor API specifically */

/* Vulnerability Detection Modes */
#define VULN_MODE_BTREE_INTEGER_OVERFLOW    0x80      /* B-Tree allocateBtreePage integer overflow */
#define VULN_MODE_VDBE_MEMORY_UAF          0x81       /* VDBE Memory Use-After-Free */
#define VULN_MODE_FORMAT_STRING_ATTACK     0x82       /* sqlite3_mprintf format string attack */
#define VULN_MODE_WAL_RACE_CONDITION       0x83       /* WAL checkpoint race condition */
#define VULN_MODE_ASSERT_BYPASS            0x84       /* Assert bypass in release builds */
#define VULN_MODE_MEMORY_PRESSURE          0x85       /* Memory allocation failure testing */
#define VULN_MODE_CORRUPTED_DB_FILE        0x86       /* Corrupted database file testing */
#define VULN_MODE_CHAINED_EXPLOIT          0x87       /* Multiple vulnerabilities chained */

/* Allocation mode values from btree.c */
#define BTALLOC_ANY    0   /* Allocate any page */
#define BTALLOC_EXACT  1   /* Allocate exact page if possible */
#define BTALLOC_LE     2   /* Allocate any page <= the parameter */

/* Enhanced fuzzing context */
typedef struct FuzzCtx {
  sqlite3 *db;               /* Database connection */
  sqlite3_int64 iCutoffTime; /* Stop processing at this time */
  sqlite3_int64 iLastCb;     /* Time recorded for previous progress callback */
  sqlite3_int64 mxInterval;  /* Longest interval between two progress calls */
  unsigned nCb;              /* Number of progress callbacks */
  unsigned execCnt;          /* Number of calls to sqlite3_exec callback */
  
  /* Enhanced fuzzing state */
  uint8_t fuzzMode;          /* Current fuzzing mode */
  uint32_t targetPgno;       /* Target page number for allocation */
  uint8_t allocMode;         /* Allocation mode (BTALLOC_*) */
  uint32_t corruptionSeed;   /* Seed for corruption scenarios */
  uint32_t memoryLimit;      /* Memory limit for stress testing */
} FuzzCtx;

/* Input packet structure for allocateBtreePage fuzzing */
typedef struct BtreeAllocPacket {
  uint8_t mode;              /* Fuzzing mode selector */
  uint8_t allocType;         /* BTALLOC_ANY/EXACT/LE */
  uint16_t flags;            /* Various test flags */
  uint32_t nearbyPgno;       /* Nearby page number hint */
  uint32_t corruptionMask;   /* Corruption pattern mask */
  uint32_t memoryPressure;   /* Memory pressure simulation */
  uint8_t payload[32];       /* Additional test data */
} BtreeAllocPacket;

/* Input packet structure for autoVacuumCommit fuzzing */
typedef struct AutoVacuumPacket {
  uint8_t vacuumMode;        /* Auto-vacuum mode (0=NONE, 1=FULL, 2=INCREMENTAL) */
  uint8_t pageSize;          /* Page size selector (512, 1024, 4096, etc.) */
  uint16_t scenario;         /* Test scenario selector */
  uint32_t dbPages;          /* Initial database size in pages */
  uint32_t freePages;        /* Number of pages to free before vacuum */
  uint32_t corruptionSeed;   /* Seed for corruption injection */
  uint32_t customVacFunc;    /* Custom vacuum function behavior */
  uint8_t testData[24];      /* Additional test parameters */
} AutoVacuumPacket;

/* Input packet for btreeBeginTrans fuzzing */
typedef struct BtreeTransPacket {
  uint8_t transType;         /* Transaction type (0=READ, 1=WRITE) */
  uint8_t flags;             /* Test flags */
  uint16_t scenario;         /* Test scenario selector */
  uint32_t schemaVersion;    /* Schema version number */
  uint32_t corruptionMask;   /* Corruption simulation mask */
  uint8_t testData[20];      /* Additional test parameters */
} BtreeTransPacket;

/* Input packet for btreeCellSizeCheck fuzzing */
typedef struct CellCheckPacket {
  uint8_t pageType;          /* Page type (leaf/interior/index) */
  uint8_t corruption;        /* Corruption scenario selector */
  uint16_t cellCount;        /* Number of cells on page */
  uint32_t pageSize;         /* Page size */
  uint32_t corruptOffset;    /* Offset for corruption injection */
  uint8_t cellData[20];      /* Cell data pattern */
} CellCheckPacket;

/* Input packet for btreeCreateTable fuzzing */
typedef struct CreateTablePacket {
  uint8_t createFlags;       /* Table creation flags */
  uint8_t pageType;          /* Initial page type */
  uint16_t scenario;         /* Test scenario */
  uint32_t initialPages;     /* Initial page allocation */
  uint32_t tableId;          /* Preferred table ID */
  uint8_t testData[20];      /* Additional parameters */
} CreateTablePacket;

/* Input packet for btreeCursor fuzzing */
typedef struct CursorPacket {
  uint8_t wrFlag;            /* Write flag (0=READ, 1=WRITE, 2=FORDELETE) */
  uint8_t keyType;           /* Key type selector */
  uint16_t scenario;         /* Test scenario */
  uint32_t tableRoot;        /* Root page number */
  uint32_t keyFields;        /* Number of key fields */
  uint8_t keyData[20];       /* Key pattern data */
} CursorPacket;

/* Input packet for btreeDropTable fuzzing */
typedef struct DropTablePacket {
  uint8_t dropMode;          /* Drop mode selector */
  uint8_t compactAfter;      /* Whether to compact after drop */
  uint16_t scenario;         /* Test scenario */
  uint32_t tableRoot;        /* Table root page to drop */
  uint32_t expectedMoved;    /* Expected moved page */
  uint8_t testData[20];      /* Additional parameters */
} DropTablePacket;

/* Input packet for btreeMoveto fuzzing */
typedef struct MovetoPacket {
  uint8_t keyType;           /* Key type (0=INTEGER, 1=BLOB, 2=TEXT, 3=NULL) */
  uint8_t bias;              /* Search bias (-1, 0, 1) */
  uint16_t scenario;         /* Test scenario selector */
  uint32_t nKey;             /* Key size for index searches */
  uint32_t cursorState;      /* Cursor state simulation */
  uint8_t keyData[16];       /* Key content data */
} MovetoPacket;

/* Input packet for btreeOverwriteCell fuzzing */
typedef struct OverwriteCellPacket {
  uint8_t cellType;          /* Cell type (leaf/interior) */
  uint8_t overflowMode;      /* Overflow handling mode */
  uint16_t scenario;         /* Test scenario selector */
  uint32_t nData;            /* Data size */
  uint32_t nZero;            /* Zero padding size */
  uint32_t localSize;        /* Local storage size */
  uint8_t payloadData[12];   /* Payload content */
} OverwriteCellPacket;

/* Input packet for btreeOverwriteContent fuzzing */
typedef struct OverwriteContentPacket {
  uint8_t writeMode;         /* Write mode (0=DATA, 1=ZERO, 2=MIXED) */
  uint8_t alignment;         /* Memory alignment test */
  uint16_t scenario;         /* Test scenario selector */
  uint32_t iOffset;          /* Write offset */
  uint32_t iAmt;             /* Amount to write */
  uint8_t contentData[16];   /* Content to write */
} OverwriteContentPacket;

/* Input packet for columnMallocFailure fuzzing */
typedef struct ColumnMallocFailurePacket {
  uint8_t errorCode;         /* Error code type (NOMEM, ERROR, etc.) */
  uint8_t encoding;          /* Text encoding type */
  uint16_t scenario;         /* Test scenario selector */
  uint32_t stmtState;        /* Statement state simulation */
  uint32_t mallocSize;       /* Failed allocation size */
  uint8_t testData[16];      /* Additional test parameters */
} ColumnMallocFailurePacket;

/* Input packet for freeP4 fuzzing */
typedef struct FreeP4Packet {
  uint8_t p4Type;            /* P4 parameter type */
  uint8_t freeMode;          /* Free operation mode */
  uint16_t scenario;         /* Test scenario selector */
  uint32_t allocSize;        /* Allocation size for testing */
  uint32_t refCount;         /* Reference count simulation */
  uint8_t p4Data[16];        /* P4 content data */
} FreeP4Packet;

/* Input packet for vdbeAssertFieldCountWithinLimits fuzzing */
typedef struct AssertFieldCountPacket {
  uint8_t fieldCount;        /* Number of fields in record */
  uint8_t encoding;          /* Record encoding */
  uint16_t scenario;         /* Test scenario selector */
  uint32_t keySize;          /* Record key size */
  uint32_t headerSize;       /* Record header size */
  uint8_t recordData[16];    /* Record content data */
} AssertFieldCountPacket;

/* Input packet for assert_pager_state fuzzing */
typedef struct AssertPagerStatePacket {
  uint8_t scenario;          /* Test scenario selector */
  uint8_t pagerState;        /* Expected pager state */
  uint8_t lockLevel;         /* Current lock level */
  uint8_t walEnabled;        /* WAL mode enabled */
  uint32_t dbSize;           /* Database size */
  uint32_t changeCounter;    /* Change counter value */
  uint32_t cacheSpill;       /* Cache spill threshold */
  uint32_t corruption_flags; /* Corruption pattern */
  uint8_t testData[12];      /* Test parameters */
} AssertPagerStatePacket;

/* Input packet for checkPage fuzzing */
typedef struct CheckPagePacket {
  uint8_t scenario;          /* Test scenario selector */
  uint8_t pageType;          /* Page type selector */
  uint8_t checkFlags;        /* Check operation flags */
  uint8_t corruptionType;    /* Type of corruption to test */
  uint32_t pgno;             /* Page number to check */
  uint32_t pageSize;         /* Page size */
  uint32_t headerOffset;     /* Header offset */
  uint32_t checksum;         /* Page checksum */
  uint8_t pageData[16];      /* Page content sample */
} CheckPagePacket;

/* Input packet for pageInJournal fuzzing */
typedef struct PageInJournalPacket {
  uint8_t scenario;          /* Test scenario selector */
  uint8_t journalMode;       /* Journal mode selector */
  uint8_t syncFlags;         /* Synchronization flags */
  uint8_t walEnabled;        /* WAL mode enabled */
  uint32_t pgno;             /* Page number to check */
  uint32_t journalSize;      /* Journal file size */
  uint32_t journalOffset;    /* Offset in journal */
  uint32_t pageSize;         /* Page size */
  uint8_t journalData[12];   /* Journal content sample */
} PageInJournalPacket;

/* Input packet for pagerFixMaplimit fuzzing */
typedef struct PagerFixMaplimitPacket {
  uint8_t scenario;          /* Test scenario selector */
  uint8_t mmapEnabled;       /* Memory mapping enabled */
  uint8_t sectorSize;        /* Sector size selector */
  uint8_t lockLevel;         /* Current lock level */
  uint32_t dbSize;           /* Database size */
  uint32_t mmapSize;         /* Memory map size limit */
  uint32_t pageSize;         /* Page size */
  uint32_t cacheSize;        /* Cache size */
  uint8_t testData[12];      /* Test parameters */
} PagerFixMaplimitPacket;

/* Input packet for btreeCursorWithLock fuzzing */
typedef struct BtreeCursorWithLockPacket {
  uint8_t scenario;          /* Test scenario selector */
  uint8_t wrFlag;            /* Write flag (0=READ, 1=WRITE) */
  uint8_t lockLevel;         /* Lock level simulation */
  uint8_t shareMode;         /* Share mode selector */
  uint32_t iTable;           /* Table root page number */
  uint32_t keyFields;        /* Number of key fields */
  uint32_t transactionState; /* Transaction state simulation */
  uint32_t btreeFlags;       /* Btree flags */
  uint8_t keyInfoData[12];   /* KeyInfo structure data */
} BtreeCursorWithLockPacket;

/* Input packet for btreeLast fuzzing */
typedef struct BtreeLastPacket {
  uint8_t scenario;          /* Test scenario selector */
  uint8_t cursorState;       /* Initial cursor state */
  uint8_t pageType;          /* Page type selector */
  uint8_t cursorFlags;       /* Cursor flags */
  uint32_t rootPage;         /* Root page number */
  uint32_t treeDepth;        /* Tree depth simulation */
  uint32_t pageCount;        /* Page count in tree */
  uint32_t corruptionMask;   /* Corruption pattern */
  uint8_t testData[12];      /* Additional test parameters */
} BtreeLastPacket;

/* Input packet for btreeNext fuzzing */
typedef struct BtreeNextPacket {
  uint8_t scenario;          /* Test scenario selector */
  uint8_t cursorState;       /* Initial cursor state */
  uint8_t pagePosition;      /* Position on page */
  uint8_t cursorFlags;       /* Cursor flags */
  uint32_t cellIndex;        /* Current cell index */
  uint32_t skipNext;         /* Skip next value */
  uint32_t pageLayout;       /* Page layout simulation */
  uint32_t leafInternal;     /* Leaf/internal page selector */
  uint8_t navigationData[12]; /* Navigation test data */
} BtreeNextPacket;

/* Core function declarations */
int progress_handler(void *pClientData);
int exec_handler(void *pClientData, int argc, char **argv, char **namev);
int block_debug_pragmas(void *Notused, int eCode, const char *zArg1, 
                        const char *zArg2, const char *zArg3, const char *zArg4);
sqlite3_int64 timeOfDay(void);


/* Include harness headers */
#include "parser_advanced_harness.h"
#include "btree_meta_harness.h"
#include "btree_cursor_ops_harness.h"
#include "vdbe_auxiliary_extended_harness.h"
#include "storage_pager_harness.h"
#include "query_where_harness.h"
#include "vdbe_record_harness.h"
#include "vdbe_memory_advanced_harness.h"
#include "btree_cursor_nav_harness.h"

/* Debug and utility functions */
void ossfuzz_set_debug_flags(unsigned x);

#endif /* SQLITE3_ENHANCED_FUZZ_H */