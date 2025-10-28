/*
** Enhanced SQLite3 Fuzzer - Specification-based Implementation
** Target: allocateBtreePage function (btree.c:6475)
** Focus: B-Tree page allocation with deep coverage optimization
*/
#include "fuzz.h"
#include "btree_harness.h"
#include "autovacuum_harness.h"

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
sqlite3_int64 timeOfDay(void){
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
int progress_handler(void *pClientData) {
  FuzzCtx *p = (FuzzCtx*)pClientData;
  sqlite3_int64 iNow = timeOfDay();
  int rc = iNow>=p->iCutoffTime;
  sqlite3_int64 iDiff = iNow - p->iLastCb;
  if( iDiff > p->mxInterval ) p->mxInterval = iDiff;
  p->nCb++;
  return rc;
}

/* Block debug pragmas to prevent excessive output */
int block_debug_pragmas(
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
int exec_handler(void *pClientData, int argc, char **argv, char **namev){
  FuzzCtx *p = (FuzzCtx*)pClientData;
  int i;
  if( argv ){
    for(i=0; i<argc; i++) sqlite3_free(sqlite3_mprintf("%s", argv[i]));
  }
  return (p->execCnt--)<=0 || progress_handler(pClientData);
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