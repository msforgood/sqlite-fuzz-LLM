/*
** Enhanced SQLite3 Fuzzer - Specification-based Implementation
** Target: allocateBtreePage function (btree.c:6475)
** Focus: B-Tree page allocation with deep coverage optimization
*/
#include "fuzz.h"
#include "btree_harness.h"
#include "autovacuum_harness.h"
#include "freespace_harness.h"
#include "pagemanagement_harness.h"
#include "tablecursor_harness.h"
#include "btree_trans_harness.h"
#include "cell_check_harness.h"
#include "create_table_harness.h"
#include "cursor_harness.h"
#include "drop_table_harness.h"
#include "page_ops_harness.h"

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
  
  /* Check minimum size for any packet type */
  if( size < sizeof(BtreeAllocPacket) && size < sizeof(AutoVacuumPacket) && 
      size < sizeof(FreeSpacePacket) && size < sizeof(PageMgmtPacket) &&
      size < sizeof(TableCursorPacket) && size < sizeof(BtreeTransPacket) && 
      size < sizeof(CellCheckPacket) && size < sizeof(CreateTablePacket) &&
      size < sizeof(CursorPacket) && size < sizeof(DropTablePacket) &&
      size < sizeof(FreePagePacket) && size < sizeof(ClearPagePacket) &&
      size < sizeof(DefragPagePacket) && size < sizeof(CloseCursorPacket) ) return 0;
  
  /* Determine fuzzing mode based on first byte */
  uint8_t fuzzSelector = data[0];
  cx.fuzzMode = fuzzSelector % 20; /* 0-19 valid modes, added page operations harnesses */
  
  /* Parse appropriate packet based on mode */
  if( cx.fuzzMode == FUZZ_MODE_AUTOVACUUM && size >= sizeof(AutoVacuumPacket) ) {
    const AutoVacuumPacket *pAvPacket = (const AutoVacuumPacket*)data;
    cx.targetPgno = pAvPacket->dbPages;
    cx.allocMode = pAvPacket->vacuumMode % 3;
    cx.corruptionSeed = pAvPacket->corruptionSeed;
    cx.memoryLimit = pAvPacket->customVacFunc;
  } else if( cx.fuzzMode == FUZZ_MODE_FREESPACE && size >= sizeof(FreeSpacePacket) ) {
    const FreeSpacePacket *pFsPacket = (const FreeSpacePacket*)data;
    cx.targetPgno = pFsPacket->cellCount;
    cx.allocMode = pFsPacket->pageType % 4;
    cx.corruptionSeed = pFsPacket->corruptionMask;
    cx.memoryLimit = pFsPacket->freeblockCount;
  } else if( cx.fuzzMode == FUZZ_MODE_PAGEMANAGEMENT && size >= sizeof(PageMgmtPacket) ) {
    const PageMgmtPacket *pPmPacket = (const PageMgmtPacket*)data;
    cx.targetPgno = pPmPacket->pageCount;
    cx.allocMode = pPmPacket->operations % 16;
    cx.corruptionSeed = pPmPacket->corruptionMask;
    cx.memoryLimit = pPmPacket->bitvecSize;
  } else if( cx.fuzzMode == FUZZ_MODE_TABLECURSOR && size >= sizeof(TableCursorPacket) ) {
    const TableCursorPacket *pTcPacket = (const TableCursorPacket*)data;
    cx.targetPgno = pTcPacket->tableCount;
    cx.allocMode = pTcPacket->createFlags % 8;
    cx.corruptionSeed = pTcPacket->corruptionMask;
    cx.memoryLimit = pTcPacket->operationCount;
  } else if( cx.fuzzMode == FUZZ_MODE_BTREE_TRANS && size >= sizeof(BtreeTransPacket) ) {
    const BtreeTransPacket *pBtPacket = (const BtreeTransPacket*)data;
    cx.targetPgno = pBtPacket->schemaVersion;
    cx.allocMode = pBtPacket->transType;
    cx.corruptionSeed = pBtPacket->corruptionMask;
  } else if( cx.fuzzMode == FUZZ_MODE_CELL_CHECK && size >= sizeof(CellCheckPacket) ) {
    const CellCheckPacket *pCcPacket = (const CellCheckPacket*)data;
    cx.targetPgno = pCcPacket->pageSize;
    cx.allocMode = pCcPacket->pageType;
    cx.corruptionSeed = pCcPacket->corruptOffset;
  } else if( cx.fuzzMode == FUZZ_MODE_CREATE_TABLE && size >= sizeof(CreateTablePacket) ) {
    const CreateTablePacket *pCtPacket = (const CreateTablePacket*)data;
    cx.targetPgno = pCtPacket->tableId;
    cx.allocMode = pCtPacket->createFlags;
    cx.corruptionSeed = pCtPacket->initialPages;
  } else if( cx.fuzzMode == FUZZ_MODE_CURSOR && size >= sizeof(CursorPacket) ) {
    const CursorPacket *pCurPacket = (const CursorPacket*)data;
    cx.targetPgno = pCurPacket->tableRoot;
    cx.allocMode = pCurPacket->wrFlag;
    cx.corruptionSeed = pCurPacket->keyFields;
  } else if( cx.fuzzMode == FUZZ_MODE_DROP_TABLE && size >= sizeof(DropTablePacket) ) {
    const DropTablePacket *pDtPacket = (const DropTablePacket*)data;
    cx.targetPgno = pDtPacket->tableRoot;
    cx.allocMode = pDtPacket->dropMode;
    cx.corruptionSeed = pDtPacket->expectedMoved;
  } else if( cx.fuzzMode == FUZZ_MODE_FREE_PAGE && size >= sizeof(FreePagePacket) ) {
    const FreePagePacket *pFpPacket = (const FreePagePacket*)data;
    cx.targetPgno = pFpPacket->targetPgno;
    cx.allocMode = pFpPacket->errorScenario;
    cx.corruptionSeed = pFpPacket->corruptionMask;
  } else if( cx.fuzzMode == FUZZ_MODE_CLEAR_PAGE && size >= sizeof(ClearPagePacket) ) {
    const ClearPagePacket *pCpPacket = (const ClearPagePacket*)data;
    cx.targetPgno = pCpPacket->targetPgno;
    cx.allocMode = pCpPacket->freeFlag;
    cx.corruptionSeed = pCpPacket->corruptionOffset;
  } else if( cx.fuzzMode == FUZZ_MODE_DEFRAG_PAGE && size >= sizeof(DefragPagePacket) ) {
    const DefragPagePacket *pDpPacket = (const DefragPagePacket*)data;
    cx.targetPgno = pDpPacket->targetPgno;
    cx.allocMode = pDpPacket->fragmentation;
    cx.corruptionSeed = pDpPacket->cellPattern;
  } else if( cx.fuzzMode == FUZZ_MODE_CLOSE_CURSOR && size >= sizeof(CloseCursorPacket) ) {
    const CloseCursorPacket *pCcPacket = (const CloseCursorPacket*)data;
    cx.targetPgno = pCcPacket->rootPage;
    cx.allocMode = pCcPacket->cursorState;
    cx.corruptionSeed = pCcPacket->overflowPages;
  } else if( size >= sizeof(BtreeAllocPacket) ) {
    const BtreeAllocPacket *pPacket = (const BtreeAllocPacket*)data;
    cx.fuzzMode = pPacket->mode % 6; /* 0-5 valid modes */
    cx.targetPgno = pPacket->nearbyPgno;
    cx.allocMode = pPacket->allocType % 3; /* 0-2 valid modes */
    cx.corruptionSeed = pPacket->corruptionMask;
    cx.memoryLimit = pPacket->memoryPressure;
  } else {
    return 0;
  }
  
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
  uint32_t fkeyFlag = (cx.fuzzMode == FUZZ_MODE_AUTOVACUUM) ? 
    ((const AutoVacuumPacket*)data)->scenario & 1 :
    (cx.fuzzMode == FUZZ_MODE_FREESPACE) ? 
    ((const FreeSpacePacket*)data)->pageType & 1 :
    (cx.fuzzMode == FUZZ_MODE_PAGEMANAGEMENT) ?
    ((const PageMgmtPacket*)data)->operations & 1 :
    (cx.fuzzMode == FUZZ_MODE_TABLECURSOR) ?
    ((const TableCursorPacket*)data)->createFlags & 1 :
    (cx.fuzzMode == FUZZ_MODE_BTREE_TRANS) ?
    ((const BtreeTransPacket*)data)->flags & 1 :
    (cx.fuzzMode == FUZZ_MODE_CELL_CHECK) ?
    ((const CellCheckPacket*)data)->corruption & 1 :
    (cx.fuzzMode == FUZZ_MODE_CREATE_TABLE) ?
    ((const CreateTablePacket*)data)->createFlags & 1 :
    (cx.fuzzMode == FUZZ_MODE_CURSOR) ?
    ((const CursorPacket*)data)->wrFlag & 1 :
    (cx.fuzzMode == FUZZ_MODE_DROP_TABLE) ?
    ((const DropTablePacket*)data)->dropMode & 1 :
    (cx.fuzzMode == FUZZ_MODE_FREE_PAGE) ?
    ((const FreePagePacket*)data)->errorScenario & 1 :
    (cx.fuzzMode == FUZZ_MODE_CLEAR_PAGE) ?
    ((const ClearPagePacket*)data)->freeFlag & 1 :
    (cx.fuzzMode == FUZZ_MODE_DEFRAG_PAGE) ?
    ((const DefragPagePacket*)data)->fragmentation & 1 :
    (cx.fuzzMode == FUZZ_MODE_CLOSE_CURSOR) ?
    ((const CloseCursorPacket*)data)->cursorState & 1 :
    ((const BtreeAllocPacket*)data)->flags & 1;
  sqlite3_db_config(cx.db, SQLITE_DBCONFIG_ENABLE_FKEY, fkeyFlag, &rc);
  
  /* Block debug pragmas */
  sqlite3_set_authorizer(cx.db, block_debug_pragmas, 0);
  
  /* Set execution limit based on mode */
  if( cx.fuzzMode == FUZZ_MODE_AUTOVACUUM && size >= sizeof(AutoVacuumPacket) ) {
    const AutoVacuumPacket *pAvPacket = (const AutoVacuumPacket*)data;
    cx.execCnt = (pAvPacket->testData[0] % 50) + 1;
    
    /* Execute enhanced auto-vacuum commit fuzzing */
    fuzz_autovacuum_commit(&cx, pAvPacket);
  } else if( cx.fuzzMode == FUZZ_MODE_FREESPACE && size >= sizeof(FreeSpacePacket) ) {
    const FreeSpacePacket *pFsPacket = (const FreeSpacePacket*)data;
    cx.execCnt = (pFsPacket->testData[0] % 50) + 1;
    
    /* Execute enhanced free space computation fuzzing */
    fuzz_freespace_computation(&cx, pFsPacket);
  } else if( cx.fuzzMode == FUZZ_MODE_PAGEMANAGEMENT && size >= sizeof(PageMgmtPacket) ) {
    const PageMgmtPacket *pPmPacket = (const PageMgmtPacket*)data;
    cx.execCnt = (pPmPacket->testData[0] % 50) + 1;
    
    /* Execute enhanced page management fuzzing */
    fuzz_page_management(&cx, pPmPacket);
  } else if( cx.fuzzMode == FUZZ_MODE_TABLECURSOR && size >= sizeof(TableCursorPacket) ) {
    const TableCursorPacket *pTcPacket = (const TableCursorPacket*)data;
    cx.execCnt = (pTcPacket->testData[0] % 50) + 1;
    
    /* Execute enhanced table/cursor management fuzzing */
    fuzz_table_cursor_management(&cx, pTcPacket);
  } else if( cx.fuzzMode == FUZZ_MODE_BTREE_TRANS && size >= sizeof(BtreeTransPacket) ) {
    const BtreeTransPacket *pBtPacket = (const BtreeTransPacket*)data;
    cx.execCnt = (pBtPacket->testData[0] % 50) + 1;
    
    /* Execute B-Tree transaction fuzzing */
    fuzz_btree_transaction(&cx, pBtPacket);
  } else if( cx.fuzzMode == FUZZ_MODE_CELL_CHECK && size >= sizeof(CellCheckPacket) ) {
    const CellCheckPacket *pCcPacket = (const CellCheckPacket*)data;
    cx.execCnt = (pCcPacket->cellData[0] % 50) + 1;
    
    /* Execute cell size check fuzzing */
    fuzz_cell_size_check(&cx, pCcPacket);
  } else if( cx.fuzzMode == FUZZ_MODE_CREATE_TABLE && size >= sizeof(CreateTablePacket) ) {
    const CreateTablePacket *pCtPacket = (const CreateTablePacket*)data;
    cx.execCnt = (pCtPacket->testData[0] % 50) + 1;
    
    /* Execute table creation fuzzing */
    fuzz_create_table(&cx, pCtPacket);
  } else if( cx.fuzzMode == FUZZ_MODE_CURSOR && size >= sizeof(CursorPacket) ) {
    const CursorPacket *pCurPacket = (const CursorPacket*)data;
    cx.execCnt = (pCurPacket->keyData[0] % 50) + 1;
    
    /* Execute cursor operations fuzzing */
    fuzz_cursor_operations(&cx, pCurPacket);
  } else if( cx.fuzzMode == FUZZ_MODE_DROP_TABLE && size >= sizeof(DropTablePacket) ) {
    const DropTablePacket *pDtPacket = (const DropTablePacket*)data;
    cx.execCnt = (pDtPacket->testData[0] % 50) + 1;
    
    /* Execute drop table operations fuzzing */
    fuzz_drop_table_operations(&cx, pDtPacket);
  } else if( cx.fuzzMode == FUZZ_MODE_FREE_PAGE && size >= sizeof(FreePagePacket) ) {
    const FreePagePacket *pFpPacket = (const FreePagePacket*)data;
    cx.execCnt = (pFpPacket->testData[0] % 50) + 1;
    
    /* Execute free page operations fuzzing */
    fuzz_free_page(data, size);
  } else if( cx.fuzzMode == FUZZ_MODE_CLEAR_PAGE && size >= sizeof(ClearPagePacket) ) {
    const ClearPagePacket *pCpPacket = (const ClearPagePacket*)data;
    cx.execCnt = (pCpPacket->testData[0] % 50) + 1;
    
    /* Execute clear database page fuzzing */
    fuzz_clear_database_page(data, size);
  } else if( cx.fuzzMode == FUZZ_MODE_DEFRAG_PAGE && size >= sizeof(DefragPagePacket) ) {
    const DefragPagePacket *pDpPacket = (const DefragPagePacket*)data;
    cx.execCnt = (pDpPacket->testData[0] % 50) + 1;
    
    /* Execute defragment page fuzzing */
    fuzz_defragment_page(data, size);
  } else if( cx.fuzzMode == FUZZ_MODE_CLOSE_CURSOR && size >= sizeof(CloseCursorPacket) ) {
    const CloseCursorPacket *pCcPacket = (const CloseCursorPacket*)data;
    cx.execCnt = (pCcPacket->testData[0] % 50) + 1;
    
    /* Execute close cursor fuzzing */
    fuzz_close_cursor(data, size);
  } else if( size >= sizeof(BtreeAllocPacket) ) {
    const BtreeAllocPacket *pPacket = (const BtreeAllocPacket*)data;
    cx.execCnt = (pPacket->payload[0] % 50) + 1;
    
    /* Execute enhanced B-Tree allocation fuzzing */
    fuzz_btree_allocation(&cx, pPacket);
  }
  
  /* If remaining data, treat as SQL */
  size_t packetSize = sizeof(BtreeAllocPacket);
  if( cx.fuzzMode == FUZZ_MODE_AUTOVACUUM ) packetSize = sizeof(AutoVacuumPacket);
  else if( cx.fuzzMode == FUZZ_MODE_FREESPACE ) packetSize = sizeof(FreeSpacePacket);
  else if( cx.fuzzMode == FUZZ_MODE_PAGEMANAGEMENT ) packetSize = sizeof(PageMgmtPacket);
  else if( cx.fuzzMode == FUZZ_MODE_TABLECURSOR ) packetSize = sizeof(TableCursorPacket);
  else if( cx.fuzzMode == FUZZ_MODE_BTREE_TRANS ) packetSize = sizeof(BtreeTransPacket);
  else if( cx.fuzzMode == FUZZ_MODE_CELL_CHECK ) packetSize = sizeof(CellCheckPacket);
  else if( cx.fuzzMode == FUZZ_MODE_CREATE_TABLE ) packetSize = sizeof(CreateTablePacket);
  else if( cx.fuzzMode == FUZZ_MODE_CURSOR ) packetSize = sizeof(CursorPacket);
  else if( cx.fuzzMode == FUZZ_MODE_DROP_TABLE ) packetSize = sizeof(DropTablePacket);
  else if( cx.fuzzMode == FUZZ_MODE_FREE_PAGE ) packetSize = sizeof(FreePagePacket);
  else if( cx.fuzzMode == FUZZ_MODE_CLEAR_PAGE ) packetSize = sizeof(ClearPagePacket);
  else if( cx.fuzzMode == FUZZ_MODE_DEFRAG_PAGE ) packetSize = sizeof(DefragPagePacket);
  else if( cx.fuzzMode == FUZZ_MODE_CLOSE_CURSOR ) packetSize = sizeof(CloseCursorPacket);
  if( size > packetSize ) {
    size_t sqlLen = size - packetSize;
    const uint8_t *sqlData = data + packetSize;
    
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