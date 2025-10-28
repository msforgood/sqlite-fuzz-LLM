/*
** Enhanced SQLite3 Fuzzer - Specification-based Implementation
** Target: allocateBtreePage function (btree.c:6475)
** Focus: B-Tree page allocation with deep coverage optimization
*/
#include "fuzz.h"

/* Global debugging settings */
static unsigned mDebug = 0;
#define FUZZ_SQL_TRACE       0x0001
#define FUZZ_SHOW_MAX_DELAY  0x0002
#define FUZZ_SHOW_ERRORS     0x0004
#define FUZZ_SHOW_BTREE      0x0008

/* Debug flag interface for ossshell utility */
void ossfuzz_set_debug_flags(unsigned x){
  mDebug = x;
}

/* Return current time in milliseconds since Julian epoch */
static sqlite3_int64 timeOfDay(void){
  static sqlite3_vfs *clockVfs = 0;
  sqlite3_int64 t;
  if( clockVfs==0 ){
    clockVfs = sqlite3_vfs_find(0);
    if( clockVfs==0 ) return 0;
  }
  if( clockVfs->iVersion>=2 && clockVfs->xCurrentTimeInt64!=0 ){
    clockVfs->xCurrentTimeInt64(clockVfs, &t);
  }else{
    double r;
    clockVfs->xCurrentTime(clockVfs, &r);
    t = (sqlite3_int64)(r*86400000.0);
  }
  return t;
}

/* Progress handler callback with timeout protection */
static int progress_handler(void *pClientData) {
  FuzzCtx *p = (FuzzCtx*)pClientData;
  sqlite3_int64 iNow = timeOfDay();
  int rc = iNow>=p->iCutoffTime;
  sqlite3_int64 iDiff = iNow - p->iLastCb;
  if( iDiff > p->mxInterval ) p->mxInterval = iDiff;
  p->nCb++;
  return rc;
}

/* Block debug pragmas to prevent excessive output */
static int block_debug_pragmas(
  void *Notused,
  int eCode,
  const char *zArg1,
  const char *zArg2,
  const char *zArg3,
  const char *zArg4
){
  if( eCode==SQLITE_PRAGMA
   && (sqlite3_strnicmp("vdbe_", zArg1, 5)==0
        || sqlite3_stricmp("parser_trace", zArg1)==0)
  ){
    return SQLITE_DENY;
  }
  return SQLITE_OK;
}

/* Exec callback for SQL execution */
static int exec_handler(void *pClientData, int argc, char **argv, char **namev){
  FuzzCtx *p = (FuzzCtx*)pClientData;
  int i;
  if( argv ){
    for(i=0; i<argc; i++) sqlite3_free(sqlite3_mprintf("%s", argv[i]));
  }
  return (p->execCnt--)<=0 || progress_handler(pClientData);
}

/* Generate B-Tree focused SQL commands based on fuzzing packet */
static void generate_btree_sql(char *zSql, size_t sqlSize, const BtreeAllocPacket *pPacket) {
  const char *templates[] = {
    /* Basic table operations that trigger page allocation */
    "CREATE TABLE IF NOT EXISTS test%u(id INTEGER PRIMARY KEY, data BLOB);",
    "INSERT INTO test%u VALUES(NULL, randomblob(%u));",
    "CREATE INDEX IF NOT EXISTS idx%u ON test%u(data);",
    
    /* Operations that stress freelist management */
    "DELETE FROM test%u WHERE id %% %u = 0;",
    "VACUUM;",
    "PRAGMA incremental_vacuum(%u);",
    
    /* Auto-vacuum operations */
    "PRAGMA auto_vacuum = %u;",
    "PRAGMA freelist_count;",
    "PRAGMA page_count;",
    
    /* Transactions that affect page allocation */
    "BEGIN IMMEDIATE;",
    "SAVEPOINT sp%u;",
    "ROLLBACK TO sp%u;",
    "COMMIT;",
  };
  
  int templateIdx = pPacket->corruptionMask % (sizeof(templates)/sizeof(templates[0]));
  uint32_t param1 = pPacket->nearbyPgno % 100;
  uint32_t param2 = (pPacket->memoryPressure % 1000) + 1;
  
  snprintf(zSql, sqlSize, templates[templateIdx], param1, param2, param1, param1, param2, param2, param1 % 3, param1, param1);
}

/* Setup B-Tree environment for targeted testing */
static int setup_btree_environment(FuzzCtx *pCtx, const BtreeAllocPacket *pPacket) {
  char *zErrMsg = 0;
  char zSql[512];
  int rc;
  
  /* Configure database for B-Tree testing */
  if( pPacket->flags & 0x01 ) {
    rc = sqlite3_exec(pCtx->db, "PRAGMA auto_vacuum = FULL;", 0, 0, &zErrMsg);
    if( rc && (mDebug & FUZZ_SHOW_ERRORS) ) {
      printf("Auto-vacuum setup error: %s\n", zErrMsg);
    }
    sqlite3_free(zErrMsg);
  }
  
  if( pPacket->flags & 0x02 ) {
    rc = sqlite3_exec(pCtx->db, "PRAGMA journal_mode = WAL;", 0, 0, &zErrMsg);
    sqlite3_free(zErrMsg);
  }
  
  /* Create initial table structure to populate B-Tree */
  snprintf(zSql, sizeof(zSql), 
    "CREATE TABLE IF NOT EXISTS btree_test("
    "id INTEGER PRIMARY KEY, "
    "data BLOB, "
    "extra TEXT DEFAULT 'padding_%u'"
    ");", pPacket->nearbyPgno % 1000);
  
  rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
  sqlite3_free(zErrMsg);
  
  return SQLITE_OK;
}

/* Test freelist scenarios that exercise allocateBtreePage */
static int test_freelist_scenarios(FuzzCtx *pCtx, const BtreeAllocPacket *pPacket) {
  char zSql[1024];
  char *zErrMsg = 0;
  int rc;
  uint32_t iterations = (pPacket->memoryPressure % 50) + 1;
  uint32_t i;
  
  /* Fill pages then delete to create freelist */
  for(i = 0; i < iterations; i++) {
    snprintf(zSql, sizeof(zSql),
      "INSERT INTO btree_test(data) VALUES(randomblob(%u));",
      (pPacket->payload[i % 32] % 1000) + 100);
    
    rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
    if( rc && rc != SQLITE_INTERRUPT ) break;
    sqlite3_free(zErrMsg);
    zErrMsg = 0;
  }
  
  /* Delete pattern to fragment freelist */
  uint32_t deletePattern = pPacket->corruptionMask % 7 + 1;
  snprintf(zSql, sizeof(zSql),
    "DELETE FROM btree_test WHERE id %% %u = 0;", deletePattern);
  
  rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
  sqlite3_free(zErrMsg);
  
  /* Force reallocation from freelist */
  for(i = 0; i < iterations/2; i++) {
    snprintf(zSql, sizeof(zSql),
      "INSERT INTO btree_test(data) VALUES(randomblob(%u));",
      (pPacket->payload[(i+16) % 32] % 500) + 50);
    
    rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
    if( rc && rc != SQLITE_INTERRUPT ) break;
    sqlite3_free(zErrMsg);
    zErrMsg = 0;
  }
  
  return SQLITE_OK;
}

/* Test memory stress conditions affecting page allocation */
static int test_memory_stress(FuzzCtx *pCtx, const BtreeAllocPacket *pPacket) {
  char zSql[512];
  char *zErrMsg = 0;
  int rc;
  
  /* Set lower memory limit based on packet */
  uint32_t memLimit = (pPacket->memoryPressure % 10000000) + 1000000; /* 1-10MB */
  sqlite3_hard_heap_limit64(memLimit);
  
  /* Try to allocate large amounts of data */
  uint32_t blobSize = (pPacket->nearbyPgno % 50000) + 1000;
  snprintf(zSql, sizeof(zSql),
    "INSERT INTO btree_test(data) VALUES(randomblob(%u));", blobSize);
  
  rc = sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
  sqlite3_free(zErrMsg);
  
  /* Reset to original limit */
  sqlite3_hard_heap_limit64(20000000);
  
  return SQLITE_OK;
}

/* Test corruption detection in page allocation */
static int test_corruption_detection(FuzzCtx *pCtx, const BtreeAllocPacket *pPacket) {
  char zSql[256];
  char *zErrMsg = 0;
  
  /* Trigger integrity check which exercises page allocation validation */
  snprintf(zSql, sizeof(zSql), "PRAGMA integrity_check(%u);", 
           (pPacket->corruptionMask % 100) + 1);
  
  sqlite3_exec(pCtx->db, zSql, exec_handler, (void*)pCtx, &zErrMsg);
  sqlite3_free(zErrMsg);
  
  /* Quick check that also validates B-Tree structure */
  sqlite3_exec(pCtx->db, "PRAGMA quick_check;", exec_handler, (void*)pCtx, &zErrMsg);
  sqlite3_free(zErrMsg);
  
  return SQLITE_OK;
}

/* Enhanced B-Tree allocation fuzzing */
static int fuzz_btree_allocation(FuzzCtx *pCtx, const BtreeAllocPacket *pPacket) {
  int rc = SQLITE_OK;
  
  /* Setup environment based on fuzzing mode */
  setup_btree_environment(pCtx, pPacket);
  
  switch(pCtx->fuzzMode) {
    case FUZZ_MODE_BTREE_ALLOC:
      /* Direct B-Tree allocation scenarios */
      test_freelist_scenarios(pCtx, pPacket);
      break;
      
    case FUZZ_MODE_FREELIST_FULL:
      /* Comprehensive freelist testing */
      test_freelist_scenarios(pCtx, pPacket);
      test_corruption_detection(pCtx, pPacket);
      break;
      
    case FUZZ_MODE_MEMORY_STRESS:
      /* Memory pressure testing */
      test_memory_stress(pCtx, pPacket);
      test_freelist_scenarios(pCtx, pPacket);
      break;
      
    case FUZZ_MODE_CORRUPTION:
      /* Corruption detection testing */
      test_corruption_detection(pCtx, pPacket);
      break;
      
    default:
      /* Multi-mode comprehensive testing */
      test_freelist_scenarios(pCtx, pPacket);
      test_memory_stress(pCtx, pPacket);
      test_corruption_detection(pCtx, pPacket);
      break;
  }
  
  return rc;
}

/* Main fuzzer entry point */
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  char *zErrMsg = 0;
  int rc;
  FuzzCtx cx;
  
  memset(&cx, 0, sizeof(cx));
  if( size < sizeof(BtreeAllocPacket) ) return 0;
  
  /* Parse fuzzing packet */
  const BtreeAllocPacket *pPacket = (const BtreeAllocPacket*)data;
  cx.fuzzMode = pPacket->mode % 6; /* 0-5 valid modes */
  cx.targetPgno = pPacket->nearbyPgno;
  cx.allocMode = pPacket->allocType % 3; /* 0-2 valid modes */
  cx.corruptionSeed = pPacket->corruptionMask;
  cx.memoryLimit = pPacket->memoryPressure;
  
  /* Initialize SQLite */
  if( sqlite3_initialize() ) return 0;
  
  /* Open in-memory database */
  rc = sqlite3_open_v2(":memory:", &cx.db,
           SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_MEMORY, 0);
  if( rc ) return 0;
  
  /* Setup timeout protection */
  cx.iLastCb = timeOfDay();
  cx.iCutoffTime = cx.iLastCb + 10000; /* 10 seconds timeout */
  
#ifndef SQLITE_OMIT_PROGRESS_CALLBACK
  sqlite3_progress_handler(cx.db, 10, progress_handler, (void*)&cx);
#endif
  
  /* Configure limits for fuzzing */
  sqlite3_limit(cx.db, SQLITE_LIMIT_VDBE_OP, 25000);
  sqlite3_limit(cx.db, SQLITE_LIMIT_LIKE_PATTERN_LENGTH, 250);
  sqlite3_limit(cx.db, SQLITE_LIMIT_LENGTH, 50000);
  sqlite3_hard_heap_limit64(20000000);
  
  /* Configure foreign keys based on packet */
  sqlite3_db_config(cx.db, SQLITE_DBCONFIG_ENABLE_FKEY, pPacket->flags & 1, &rc);
  
  /* Block debug pragmas */
  sqlite3_set_authorizer(cx.db, block_debug_pragmas, 0);
  
  /* Set execution limit */
  cx.execCnt = (pPacket->payload[0] % 50) + 1;
  
  /* Execute enhanced B-Tree allocation fuzzing */
  fuzz_btree_allocation(&cx, pPacket);
  
  /* If remaining data, treat as SQL */
  if( size > sizeof(BtreeAllocPacket) ) {
    size_t sqlLen = size - sizeof(BtreeAllocPacket);
    const uint8_t *sqlData = data + sizeof(BtreeAllocPacket);
    
    char *zSql = sqlite3_mprintf("%.*s", (int)sqlLen, sqlData);
    if( zSql ) {
#ifndef SQLITE_OMIT_COMPLETE
      sqlite3_complete(zSql);
#endif
      sqlite3_exec(cx.db, zSql, exec_handler, (void*)&cx, &zErrMsg);
      sqlite3_free(zSql);
    }
  }
  
  /* Show errors if debugging */
  if( (mDebug & FUZZ_SHOW_ERRORS) && zErrMsg ){
    printf("Error: %s\n", zErrMsg);
  }
  
  /* Cleanup */
  sqlite3_free(zErrMsg);
  sqlite3_exec(cx.db, "PRAGMA temp_store_directory=''", 0, 0, 0);
  sqlite3_close(cx.db);
  
  if( mDebug & FUZZ_SHOW_MAX_DELAY ){
    printf("Progress callback count....... %d\n", cx.nCb);
    printf("Max time between callbacks.... %d ms\n", (int)cx.mxInterval);
  }
  
  return 0;
}