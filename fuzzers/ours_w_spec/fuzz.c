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
#include "vdbe_ops_harness.h"
#include "parser_harness.h"
#include "btree_advanced_harness.h"
#include "btree_extended_harness.h"
#include "vdbe_memory_harness.h"
#include "storage_pager_harness.h"
#include "vdbe_auxiliary_harness.h"

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
      size < sizeof(DefragPagePacket) && size < sizeof(CloseCursorPacket) &&
      size < sizeof(DeleteAuxDataPacket) && size < sizeof(SetNumColsPacket) &&
      size < sizeof(MemWriteablePacket) && size < sizeof(ValueFreePacket) &&
      size < sizeof(ParserFuzzHeader) && size < sizeof(BtreeAdvancedFuzzHeader) &&
      size < sizeof(BtreeTransEndPacket) && size < sizeof(BtreeGetPagePacket) &&
      size < sizeof(BtreeUnusedPagePacket) && size < sizeof(BtreeHeapInsertPacket) &&
      size < sizeof(BtreeHeapPullPacket) && size < sizeof(VdbeExpireStmtPacket) &&
      size < sizeof(VdbeStat4ProbePacket) && size < sizeof(VdbeValueFreePacket) &&
      size < sizeof(VdbeEphemeralFuncPacket) ) return 0;
  
  /* Determine fuzzing mode based on first byte */
  uint8_t fuzzSelector = data[0];
  cx.fuzzMode = fuzzSelector % 51; /* 0-50 valid modes, added Parser Advanced harnesses */
  
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
  } else if( cx.fuzzMode == FUZZ_MODE_DELETE_AUXDATA && size >= sizeof(DeleteAuxDataPacket) ) {
    const DeleteAuxDataPacket *pDaPacket = (const DeleteAuxDataPacket*)data;
    cx.targetPgno = pDaPacket->opIndex;
    cx.allocMode = pDaPacket->deletionMode;
    cx.corruptionSeed = pDaPacket->corruptionSeed;
  } else if( cx.fuzzMode == FUZZ_MODE_SET_NUMCOLS && size >= sizeof(SetNumColsPacket) ) {
    const SetNumColsPacket *pSnPacket = (const SetNumColsPacket*)data;
    cx.targetPgno = pSnPacket->numCols;
    cx.allocMode = pSnPacket->encoding;
    cx.corruptionSeed = pSnPacket->namePattern;
  } else if( cx.fuzzMode == FUZZ_MODE_MEM_WRITEABLE && size >= sizeof(MemWriteablePacket) ) {
    const MemWriteablePacket *pMwPacket = (const MemWriteablePacket*)data;
    cx.targetPgno = pMwPacket->memSize;
    cx.allocMode = pMwPacket->memFlags;
    cx.corruptionSeed = pMwPacket->corruptionMask;
  } else if( cx.fuzzMode == FUZZ_MODE_VALUE_FREE && size >= sizeof(ValueFreePacket) ) {
    const ValueFreePacket *pVfPacket = (const ValueFreePacket*)data;
    cx.targetPgno = pVfPacket->valueSize;
    cx.allocMode = pVfPacket->valueType;
    cx.corruptionSeed = pVfPacket->allocPattern;
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
    (cx.fuzzMode == FUZZ_MODE_DELETE_AUXDATA) ?
    ((const DeleteAuxDataPacket*)data)->deletionMode & 1 :
    (cx.fuzzMode == FUZZ_MODE_SET_NUMCOLS) ?
    ((const SetNumColsPacket*)data)->encoding & 1 :
    (cx.fuzzMode == FUZZ_MODE_MEM_WRITEABLE) ?
    ((const MemWriteablePacket*)data)->memFlags & 1 :
    (cx.fuzzMode == FUZZ_MODE_VALUE_FREE) ?
    ((const ValueFreePacket*)data)->valueType & 1 :
    (cx.fuzzMode == FUZZ_MODE_CODE_TABLE_LOCKS) ?
    ((const ParserFuzzHeader*)data)->flags & 1 :
    (cx.fuzzMode == FUZZ_MODE_DESTROY_ROOT_PAGE) ?
    ((const ParserFuzzHeader*)data)->flags & 1 :
    (cx.fuzzMode == FUZZ_MODE_CODE_VERIFY_SCHEMA) ?
    ((const ParserFuzzHeader*)data)->flags & 1 :
    (cx.fuzzMode == FUZZ_MODE_BTREE_BUSY_HANDLER) ?
    ((const BtreeAdvancedFuzzHeader*)data)->flags & 1 :
    (cx.fuzzMode == FUZZ_MODE_BTREE_RESTORE_CURSOR) ?
    ((const BtreeAdvancedFuzzHeader*)data)->flags & 1 :
    (cx.fuzzMode == FUZZ_MODE_BTREE_SHARED_CACHE_LOCK) ?
    ((const BtreeAdvancedFuzzHeader*)data)->flags & 1 :
    (cx.fuzzMode == FUZZ_MODE_BTREE_END_TRANS) ?
    ((const BtreeTransEndPacket*)data)->flags & 1 :
    (cx.fuzzMode == FUZZ_MODE_BTREE_GET_PAGE) ?
    ((const BtreeGetPagePacket*)data)->flags & 1 :
    (cx.fuzzMode == FUZZ_MODE_BTREE_UNUSED_PAGE) ?
    ((const BtreeUnusedPagePacket*)data)->flags & 1 :
    (cx.fuzzMode == FUZZ_MODE_BTREE_HEAP_INSERT) ?
    ((const BtreeHeapInsertPacket*)data)->flags & 1 :
    (cx.fuzzMode == FUZZ_MODE_BTREE_HEAP_PULL) ?
    ((const BtreeHeapPullPacket*)data)->flags & 1 :
    (cx.fuzzMode == FUZZ_MODE_VDBE_EXPIRE_STMT) ?
    ((const VdbeExpireStmtPacket*)data)->flags & 1 :
    (cx.fuzzMode == FUZZ_MODE_VDBE_STAT4_PROBE) ?
    ((const VdbeStat4ProbePacket*)data)->flags & 1 :
    (cx.fuzzMode == FUZZ_MODE_VDBE_VALUE_FREE) ?
    ((const VdbeValueFreePacket*)data)->flags & 1 :
    (cx.fuzzMode == FUZZ_MODE_VDBE_EPHEMERAL_FUNC) ?
    ((const VdbeEphemeralFuncPacket*)data)->flags & 1 :
    (cx.fuzzMode == FUZZ_MODE_PAGER_ACQUIRE_MMAP) ?
    ((const PagerAcquireMapPacket*)data)->corruption_flags & 1 :
    (cx.fuzzMode == FUZZ_MODE_PAGER_BEGIN_READ_TXN) ?
    ((const PagerBeginReadTxnPacket*)data)->corruption_flags & 1 :
    (cx.fuzzMode == FUZZ_MODE_PAGER_EXCLUSIVE_LOCK) ?
    ((const PagerExclusiveLockPacket*)data)->corruption_flags & 1 :
    (cx.fuzzMode == FUZZ_MODE_PAGER_GET_PAGE_NORMAL) ?
    ((const GetPageNormalPacket*)data)->corruption_flags & 1 :
    (cx.fuzzMode == FUZZ_MODE_VDBE_CHECK_ACTIVE_CNT) ?
    ((const VdbeCheckActiveCntPacket*)data)->corruption_flags & 1 :
    (cx.fuzzMode == FUZZ_MODE_VDBE_ADD_FUNCTION_CALL) ?
    ((const VdbeAddFunctionCallPacket*)data)->corruption_flags & 1 :
    (cx.fuzzMode == FUZZ_MODE_VDBE_ADD_OP4) ?
    ((const VdbeAddOp4Packet*)data)->corruption_flags & 1 :
    (cx.fuzzMode == FUZZ_MODE_VDBE_ADD_OP4_DUP8) ?
    ((const VdbeAddOp4Dup8Packet*)data)->corruption_flags & 1 :
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
  } else if( cx.fuzzMode == FUZZ_MODE_DELETE_AUXDATA && size >= sizeof(DeleteAuxDataPacket) ) {
    const DeleteAuxDataPacket *pDaPacket = (const DeleteAuxDataPacket*)data;
    cx.execCnt = (pDaPacket->testData[0] % 50) + 1;
    
    /* Execute delete auxiliary data fuzzing */
    fuzz_delete_auxdata(data, size);
  } else if( cx.fuzzMode == FUZZ_MODE_SET_NUMCOLS && size >= sizeof(SetNumColsPacket) ) {
    const SetNumColsPacket *pSnPacket = (const SetNumColsPacket*)data;
    cx.execCnt = (pSnPacket->testData[0] % 50) + 1;
    
    /* Execute set number of columns fuzzing */
    fuzz_set_numcols(data, size);
  } else if( cx.fuzzMode == FUZZ_MODE_MEM_WRITEABLE && size >= sizeof(MemWriteablePacket) ) {
    const MemWriteablePacket *pMwPacket = (const MemWriteablePacket*)data;
    cx.execCnt = (pMwPacket->testData[0] % 50) + 1;
    
    /* Execute memory make writeable fuzzing */
    fuzz_mem_writeable(data, size);
  } else if( cx.fuzzMode == FUZZ_MODE_VALUE_FREE && size >= sizeof(ValueFreePacket) ) {
    const ValueFreePacket *pVfPacket = (const ValueFreePacket*)data;
    cx.execCnt = (pVfPacket->testData[0] % 50) + 1;
    
    /* Execute value free fuzzing */
    fuzz_value_free(data, size);
  } else if( cx.fuzzMode == FUZZ_MODE_CODE_TABLE_LOCKS && size >= sizeof(ParserFuzzHeader) ) {
    const ParserFuzzHeader *pParserHeader = (const ParserFuzzHeader*)data;
    cx.execCnt = (pParserHeader->flags % 50) + 1;
    
    /* Execute parser codeTableLocks fuzzing */
    fuzz_codeTableLocks(data, size);
  } else if( cx.fuzzMode == FUZZ_MODE_DESTROY_ROOT_PAGE && size >= sizeof(ParserFuzzHeader) ) {
    const ParserFuzzHeader *pParserHeader = (const ParserFuzzHeader*)data;
    cx.execCnt = (pParserHeader->flags % 50) + 1;
    
    /* Execute parser destroyRootPage fuzzing */
    fuzz_destroyRootPage(data, size);
  } else if( cx.fuzzMode == FUZZ_MODE_CODE_VERIFY_SCHEMA && size >= sizeof(ParserFuzzHeader) ) {
    const ParserFuzzHeader *pParserHeader = (const ParserFuzzHeader*)data;
    cx.execCnt = (pParserHeader->flags % 50) + 1;
    
    /* Execute parser sqlite3CodeVerifySchema fuzzing */
    fuzz_sqlite3CodeVerifySchema(data, size);
  } else if( cx.fuzzMode == FUZZ_MODE_BTREE_BUSY_HANDLER && size >= sizeof(BtreeAdvancedFuzzHeader) ) {
    const BtreeAdvancedFuzzHeader *pAdvHeader = (const BtreeAdvancedFuzzHeader*)data;
    cx.execCnt = (pAdvHeader->flags % 50) + 1;
    
    /* Execute advanced B-Tree busy handler fuzzing */
    fuzz_btreeInvokeBusyHandler(data, size);
  } else if( cx.fuzzMode == FUZZ_MODE_BTREE_RESTORE_CURSOR && size >= sizeof(BtreeAdvancedFuzzHeader) ) {
    const BtreeAdvancedFuzzHeader *pAdvHeader = (const BtreeAdvancedFuzzHeader*)data;
    cx.execCnt = (pAdvHeader->flags % 50) + 1;
    
    /* Execute advanced B-Tree cursor restore fuzzing */
    fuzz_btreeRestoreCursorPosition(data, size);
  } else if( cx.fuzzMode == FUZZ_MODE_BTREE_SHARED_CACHE_LOCK && size >= sizeof(BtreeAdvancedFuzzHeader) ) {
    const BtreeAdvancedFuzzHeader *pAdvHeader = (const BtreeAdvancedFuzzHeader*)data;
    cx.execCnt = (pAdvHeader->flags % 50) + 1;
    
    /* Execute advanced B-Tree shared cache lock fuzzing */
    fuzz_setSharedCacheTableLock(data, size);
  } else if( cx.fuzzMode == FUZZ_MODE_BTREE_END_TRANS && size >= sizeof(BtreeTransEndPacket) ) {
    const BtreeTransEndPacket *pExtHeader = (const BtreeTransEndPacket*)data;
    cx.execCnt = (pExtHeader->flags % 50) + 1;
    
    /* Execute extended B-Tree end transaction fuzzing */
    fuzz_btree_end_transaction(&cx, pExtHeader);
  } else if( cx.fuzzMode == FUZZ_MODE_BTREE_GET_PAGE && size >= sizeof(BtreeGetPagePacket) ) {
    const BtreeGetPagePacket *pExtHeader = (const BtreeGetPagePacket*)data;
    cx.execCnt = (pExtHeader->flags % 50) + 1;
    
    /* Execute extended B-Tree get page fuzzing */
    fuzz_btree_get_page(&cx, pExtHeader);
  } else if( cx.fuzzMode == FUZZ_MODE_BTREE_UNUSED_PAGE && size >= sizeof(BtreeUnusedPagePacket) ) {
    const BtreeUnusedPagePacket *pExtHeader = (const BtreeUnusedPagePacket*)data;
    cx.execCnt = (pExtHeader->flags % 50) + 1;
    
    /* Execute extended B-Tree unused page fuzzing */
    fuzz_btree_get_unused_page(&cx, pExtHeader);
  } else if( cx.fuzzMode == FUZZ_MODE_BTREE_HEAP_INSERT && size >= sizeof(BtreeHeapInsertPacket) ) {
    const BtreeHeapInsertPacket *pExtHeader = (const BtreeHeapInsertPacket*)data;
    cx.execCnt = (pExtHeader->flags % 50) + 1;
    
    /* Execute extended B-Tree heap insert fuzzing */
    fuzz_btree_heap_insert(&cx, pExtHeader);
  } else if( cx.fuzzMode == FUZZ_MODE_BTREE_HEAP_PULL && size >= sizeof(BtreeHeapPullPacket) ) {
    const BtreeHeapPullPacket *pExtHeader = (const BtreeHeapPullPacket*)data;
    cx.execCnt = (pExtHeader->flags % 50) + 1;
    
    /* Execute extended B-Tree heap pull fuzzing */
    fuzz_btree_heap_pull(&cx, pExtHeader);
  } else if( cx.fuzzMode == FUZZ_MODE_VDBE_EXPIRE_STMT && size >= sizeof(VdbeExpireStmtPacket) ) {
    const VdbeExpireStmtPacket *pVdbeHeader = (const VdbeExpireStmtPacket*)data;
    cx.execCnt = (pVdbeHeader->flags % 50) + 1;
    
    /* Execute VDBE expire statements fuzzing */
    fuzz_vdbe_expire_statements(&cx, pVdbeHeader);
  } else if( cx.fuzzMode == FUZZ_MODE_VDBE_STAT4_PROBE && size >= sizeof(VdbeStat4ProbePacket) ) {
    const VdbeStat4ProbePacket *pVdbeHeader = (const VdbeStat4ProbePacket*)data;
    cx.execCnt = (pVdbeHeader->flags % 50) + 1;
    
    /* Execute VDBE STAT4 probe fuzzing */
    fuzz_vdbe_stat4_probe_free(&cx, pVdbeHeader);
  } else if( cx.fuzzMode == FUZZ_MODE_VDBE_VALUE_FREE && size >= sizeof(VdbeValueFreePacket) ) {
    const VdbeValueFreePacket *pVdbeHeader = (const VdbeValueFreePacket*)data;
    cx.execCnt = (pVdbeHeader->flags % 50) + 1;
    
    /* Execute VDBE value free fuzzing */
    fuzz_vdbe_value_free(&cx, pVdbeHeader);
  } else if( cx.fuzzMode == FUZZ_MODE_VDBE_EPHEMERAL_FUNC && size >= sizeof(VdbeEphemeralFuncPacket) ) {
    const VdbeEphemeralFuncPacket *pVdbeHeader = (const VdbeEphemeralFuncPacket*)data;
    cx.execCnt = (pVdbeHeader->flags % 50) + 1;
    
    /* Execute VDBE ephemeral function fuzzing */
    fuzz_vdbe_ephemeral_function(&cx, pVdbeHeader);
  } else if( cx.fuzzMode == FUZZ_MODE_PAGER_ACQUIRE_MMAP && size >= sizeof(PagerAcquireMapPacket) ) {
    const PagerAcquireMapPacket *pPagerPacket = (const PagerAcquireMapPacket*)data;
    cx.execCnt = (pPagerPacket->testData[0] % 50) + 1;
    
    /* Execute Storage Pager acquire mmap fuzzing */
    fuzz_pager_acquire_mmap(&cx, pPagerPacket);
  } else if( cx.fuzzMode == FUZZ_MODE_PAGER_BEGIN_READ_TXN && size >= sizeof(PagerBeginReadTxnPacket) ) {
    const PagerBeginReadTxnPacket *pPagerPacket = (const PagerBeginReadTxnPacket*)data;
    cx.execCnt = (pPagerPacket->testData[0] % 50) + 1;
    
    /* Execute Storage Pager begin read transaction fuzzing */
    fuzz_pager_begin_read_txn(&cx, pPagerPacket);
  } else if( cx.fuzzMode == FUZZ_MODE_PAGER_EXCLUSIVE_LOCK && size >= sizeof(PagerExclusiveLockPacket) ) {
    const PagerExclusiveLockPacket *pPagerPacket = (const PagerExclusiveLockPacket*)data;
    cx.execCnt = (pPagerPacket->testData[0] % 50) + 1;
    
    /* Execute Storage Pager exclusive lock fuzzing */
    fuzz_pager_exclusive_lock(&cx, pPagerPacket);
  } else if( cx.fuzzMode == FUZZ_MODE_PAGER_GET_PAGE_NORMAL && size >= sizeof(GetPageNormalPacket) ) {
    const GetPageNormalPacket *pPagerPacket = (const GetPageNormalPacket*)data;
    cx.execCnt = (pPagerPacket->testData[0] % 50) + 1;
    
    /* Execute Storage Pager get page normal fuzzing */
    fuzz_get_page_normal(&cx, pPagerPacket);
  } else if( cx.fuzzMode == FUZZ_MODE_VDBE_CHECK_ACTIVE_CNT && size >= sizeof(VdbeCheckActiveCntPacket) ) {
    const VdbeCheckActiveCntPacket *pVdbePacket = (const VdbeCheckActiveCntPacket*)data;
    cx.execCnt = (pVdbePacket->testData[0] % 50) + 1;
    
    /* Execute VDBE check active count fuzzing */
    fuzz_vdbe_check_active_cnt(&cx, pVdbePacket);
  } else if( cx.fuzzMode == FUZZ_MODE_VDBE_ADD_FUNCTION_CALL && size >= sizeof(VdbeAddFunctionCallPacket) ) {
    const VdbeAddFunctionCallPacket *pVdbePacket = (const VdbeAddFunctionCallPacket*)data;
    cx.execCnt = (pVdbePacket->testData[0] % 50) + 1;
    
    /* Execute VDBE add function call fuzzing */
    fuzz_vdbe_add_function_call(&cx, pVdbePacket);
  } else if( cx.fuzzMode == FUZZ_MODE_VDBE_ADD_OP4 && size >= sizeof(VdbeAddOp4Packet) ) {
    const VdbeAddOp4Packet *pVdbePacket = (const VdbeAddOp4Packet*)data;
    cx.execCnt = (pVdbePacket->testData[0] % 50) + 1;
    
    /* Execute VDBE add op4 fuzzing */
    fuzz_vdbe_add_op4(&cx, pVdbePacket);
  } else if( cx.fuzzMode == FUZZ_MODE_VDBE_ADD_OP4_DUP8 && size >= sizeof(VdbeAddOp4Dup8Packet) ) {
    const VdbeAddOp4Dup8Packet *pVdbePacket = (const VdbeAddOp4Dup8Packet*)data;
    cx.execCnt = (pVdbePacket->testData[0] % 50) + 1;
    
    /* Execute VDBE add op4 dup8 fuzzing */
    fuzz_vdbe_add_op4_dup8(&cx, pVdbePacket);
  } else if( cx.fuzzMode == FUZZ_MODE_PARSER_VERIFY_NAMED_SCHEMA && size >= sizeof(ParserVerifyNamedSchemaPacket) ) {
    const ParserVerifyNamedSchemaPacket *pParserPacket = (const ParserVerifyNamedSchemaPacket*)data;
    cx.execCnt = (pParserPacket->scenario % 50) + 1;
    
    /* Execute Parser Advanced Operations fuzzing */
    fuzz_parser_verify_named_schema(&cx, pParserPacket);
  } else if( cx.fuzzMode == FUZZ_MODE_PARSER_VERIFY_SCHEMA_TOPLEVEL && size >= sizeof(ParserVerifyToplevelPacket) ) {
    const ParserVerifyToplevelPacket *pParserPacket = (const ParserVerifyToplevelPacket*)data;
    cx.execCnt = (pParserPacket->scenario % 50) + 1;
    
    /* Execute Parser Advanced Operations fuzzing */
    fuzz_parser_verify_schema_toplevel(&cx, pParserPacket);
  } else if( cx.fuzzMode == FUZZ_MODE_PARSER_COMMIT_INTERNAL_CHANGES && size >= sizeof(ParserCommitChangesPacket) ) {
    const ParserCommitChangesPacket *pParserPacket = (const ParserCommitChangesPacket*)data;
    cx.execCnt = (pParserPacket->scenario % 50) + 1;
    
    /* Execute Parser Advanced Operations fuzzing */
    fuzz_parser_commit_internal_changes(&cx, pParserPacket);
  } else if( cx.fuzzMode == FUZZ_MODE_PARSER_FREE_INDEX && size >= sizeof(ParserFreeIndexPacket) ) {
    const ParserFreeIndexPacket *pParserPacket = (const ParserFreeIndexPacket*)data;
    cx.execCnt = (pParserPacket->scenario % 50) + 1;
    
    /* Execute Parser Advanced Operations fuzzing */
    fuzz_parser_free_index(&cx, pParserPacket);
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
  else if( cx.fuzzMode == FUZZ_MODE_DELETE_AUXDATA ) packetSize = sizeof(DeleteAuxDataPacket);
  else if( cx.fuzzMode == FUZZ_MODE_SET_NUMCOLS ) packetSize = sizeof(SetNumColsPacket);
  else if( cx.fuzzMode == FUZZ_MODE_MEM_WRITEABLE ) packetSize = sizeof(MemWriteablePacket);
  else if( cx.fuzzMode == FUZZ_MODE_VALUE_FREE ) packetSize = sizeof(ValueFreePacket);
  else if( cx.fuzzMode == FUZZ_MODE_CODE_TABLE_LOCKS ) packetSize = sizeof(ParserFuzzHeader);
  else if( cx.fuzzMode == FUZZ_MODE_DESTROY_ROOT_PAGE ) packetSize = sizeof(ParserFuzzHeader);
  else if( cx.fuzzMode == FUZZ_MODE_CODE_VERIFY_SCHEMA ) packetSize = sizeof(ParserFuzzHeader);
  else if( cx.fuzzMode == FUZZ_MODE_BTREE_BUSY_HANDLER ) packetSize = sizeof(BtreeAdvancedFuzzHeader);
  else if( cx.fuzzMode == FUZZ_MODE_BTREE_RESTORE_CURSOR ) packetSize = sizeof(BtreeAdvancedFuzzHeader);
  else if( cx.fuzzMode == FUZZ_MODE_BTREE_SHARED_CACHE_LOCK ) packetSize = sizeof(BtreeAdvancedFuzzHeader);
  else if( cx.fuzzMode == FUZZ_MODE_BTREE_END_TRANS ) packetSize = sizeof(BtreeTransEndPacket);
  else if( cx.fuzzMode == FUZZ_MODE_BTREE_GET_PAGE ) packetSize = sizeof(BtreeGetPagePacket);
  else if( cx.fuzzMode == FUZZ_MODE_BTREE_UNUSED_PAGE ) packetSize = sizeof(BtreeUnusedPagePacket);
  else if( cx.fuzzMode == FUZZ_MODE_BTREE_HEAP_INSERT ) packetSize = sizeof(BtreeHeapInsertPacket);
  else if( cx.fuzzMode == FUZZ_MODE_BTREE_HEAP_PULL ) packetSize = sizeof(BtreeHeapPullPacket);
  else if( cx.fuzzMode == FUZZ_MODE_VDBE_EXPIRE_STMT ) packetSize = sizeof(VdbeExpireStmtPacket);
  else if( cx.fuzzMode == FUZZ_MODE_VDBE_STAT4_PROBE ) packetSize = sizeof(VdbeStat4ProbePacket);
  else if( cx.fuzzMode == FUZZ_MODE_VDBE_VALUE_FREE ) packetSize = sizeof(VdbeValueFreePacket);
  else if( cx.fuzzMode == FUZZ_MODE_VDBE_EPHEMERAL_FUNC ) packetSize = sizeof(VdbeEphemeralFuncPacket);
  else if( cx.fuzzMode == FUZZ_MODE_PAGER_ACQUIRE_MMAP ) packetSize = sizeof(PagerAcquireMapPacket);
  else if( cx.fuzzMode == FUZZ_MODE_PAGER_BEGIN_READ_TXN ) packetSize = sizeof(PagerBeginReadTxnPacket);
  else if( cx.fuzzMode == FUZZ_MODE_PAGER_EXCLUSIVE_LOCK ) packetSize = sizeof(PagerExclusiveLockPacket);
  else if( cx.fuzzMode == FUZZ_MODE_PAGER_GET_PAGE_NORMAL ) packetSize = sizeof(GetPageNormalPacket);
  else if( cx.fuzzMode == FUZZ_MODE_VDBE_CHECK_ACTIVE_CNT ) packetSize = sizeof(VdbeCheckActiveCntPacket);
  else if( cx.fuzzMode == FUZZ_MODE_VDBE_ADD_FUNCTION_CALL ) packetSize = sizeof(VdbeAddFunctionCallPacket);
  else if( cx.fuzzMode == FUZZ_MODE_VDBE_ADD_OP4 ) packetSize = sizeof(VdbeAddOp4Packet);
  else if( cx.fuzzMode == FUZZ_MODE_VDBE_ADD_OP4_DUP8 ) packetSize = sizeof(VdbeAddOp4Dup8Packet);
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