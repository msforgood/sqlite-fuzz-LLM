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
#include "btree_cursor_ops_harness.h"
#include "vdbe_auxiliary_extended_harness.h"
#include "btree_cursor_nav_harness.h"
#include "btree_overflow_harness.h"
#include "btree_meta_harness.h"
#include "vdbe_memory_advanced_harness.h"
#include "vdbe_record_harness.h"
#include "query_where_harness.h"
#include "parser_advanced_harness.h"

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
      size < sizeof(VdbeEphemeralFuncPacket) &&
      size < sizeof(MovetoPacket) && size < sizeof(OverwriteCellPacket) &&
      size < sizeof(OverwriteContentPacket) &&
      size < sizeof(ColumnMallocFailurePacket) && size < sizeof(FreeP4Packet) &&
      size < sizeof(AssertFieldCountPacket) ) return 0;
  
  /* Determine fuzzing mode based on first byte */
  uint8_t fuzzSelector = data[0];
  cx.fuzzMode = fuzzSelector % 77; /* 0-76 valid modes, added VDBE Memory Advanced harnesses */
  
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
  } else if( cx.fuzzMode == FUZZ_MODE_BTREE_MOVETO && size >= sizeof(MovetoPacket) ) {
    const MovetoPacket *pMvPacket = (const MovetoPacket*)data;
    cx.targetPgno = pMvPacket->nKey;
    cx.allocMode = pMvPacket->keyType;
    cx.corruptionSeed = pMvPacket->cursorState;
  } else if( cx.fuzzMode == FUZZ_MODE_BTREE_OVERWRITE_CELL && size >= sizeof(OverwriteCellPacket) ) {
    const OverwriteCellPacket *pOwcPacket = (const OverwriteCellPacket*)data;
    cx.targetPgno = pOwcPacket->nData;
    cx.allocMode = pOwcPacket->cellType;
    cx.corruptionSeed = pOwcPacket->localSize;
  } else if( cx.fuzzMode == FUZZ_MODE_BTREE_OVERWRITE_CONTENT && size >= sizeof(OverwriteContentPacket) ) {
    const OverwriteContentPacket *pOwCtPacket = (const OverwriteContentPacket*)data;
    cx.targetPgno = pOwCtPacket->iOffset;
    cx.allocMode = pOwCtPacket->writeMode;
    cx.corruptionSeed = pOwCtPacket->iAmt;
  } else if( cx.fuzzMode == FUZZ_MODE_VDBE_COLUMN_MALLOC_FAILURE && size >= sizeof(ColumnMallocFailurePacket) ) {
    const ColumnMallocFailurePacket *pCmfPacket = (const ColumnMallocFailurePacket*)data;
    cx.targetPgno = pCmfPacket->mallocSize;
    cx.allocMode = pCmfPacket->errorCode;
    cx.corruptionSeed = pCmfPacket->stmtState;
  } else if( cx.fuzzMode == FUZZ_MODE_VDBE_FREE_P4 && size >= sizeof(FreeP4Packet) ) {
    const FreeP4Packet *pFp4Packet = (const FreeP4Packet*)data;
    cx.targetPgno = pFp4Packet->allocSize;
    cx.allocMode = pFp4Packet->p4Type;
    cx.corruptionSeed = pFp4Packet->refCount;
  } else if( cx.fuzzMode == FUZZ_MODE_VDBE_ASSERT_FIELD_COUNT && size >= sizeof(AssertFieldCountPacket) ) {
    const AssertFieldCountPacket *pAfcPacket = (const AssertFieldCountPacket*)data;
    cx.targetPgno = pAfcPacket->keySize;
    cx.allocMode = pAfcPacket->fieldCount;
    cx.corruptionSeed = pAfcPacket->headerSize;
  } else if( cx.fuzzMode == FUZZ_MODE_ASSERT_PAGER_STATE && size >= sizeof(AssertPagerStatePacket) ) {
    const AssertPagerStatePacket *pApsPacket = (const AssertPagerStatePacket*)data;
    cx.targetPgno = pApsPacket->dbSize;
    cx.allocMode = pApsPacket->pagerState;
    cx.corruptionSeed = pApsPacket->corruption_flags;
  } else if( cx.fuzzMode == FUZZ_MODE_CHECK_PAGE && size >= sizeof(CheckPagePacket) ) {
    const CheckPagePacket *pCpPacket = (const CheckPagePacket*)data;
    cx.targetPgno = pCpPacket->pgno;
    cx.allocMode = pCpPacket->pageType;
    cx.corruptionSeed = pCpPacket->checksum;
  } else if( cx.fuzzMode == FUZZ_MODE_PAGE_IN_JOURNAL && size >= sizeof(PageInJournalPacket) ) {
    const PageInJournalPacket *pPjPacket = (const PageInJournalPacket*)data;
    cx.targetPgno = pPjPacket->pgno;
    cx.allocMode = pPjPacket->journalMode;
    cx.corruptionSeed = pPjPacket->journalSize;
  } else if( cx.fuzzMode == FUZZ_MODE_PAGER_FIX_MAPLIMIT && size >= sizeof(PagerFixMaplimitPacket) ) {
    const PagerFixMaplimitPacket *pPfmPacket = (const PagerFixMaplimitPacket*)data;
    cx.targetPgno = pPfmPacket->dbSize;
    cx.allocMode = pPfmPacket->scenario;
    cx.corruptionSeed = pPfmPacket->mmapSize;
  } else if( cx.fuzzMode == FUZZ_MODE_FREE_IDX_STR && size >= sizeof(FreeIdxStrPacket) ) {
    const FreeIdxStrPacket *pFisPacket = (const FreeIdxStrPacket*)data;
    cx.targetPgno = pFisPacket->constraintCount;
    cx.allocMode = pFisPacket->scenario;
    cx.corruptionSeed = pFisPacket->corruption_flags;
  } else if( cx.fuzzMode == FUZZ_MODE_FREE_INDEX_INFO && size >= sizeof(FreeIndexInfoPacket) ) {
    const FreeIndexInfoPacket *pFiiPacket = (const FreeIndexInfoPacket*)data;
    cx.targetPgno = pFiiPacket->constraintCount;
    cx.allocMode = pFiiPacket->scenario;
    cx.corruptionSeed = pFiiPacket->corruption_flags;
  } else if( cx.fuzzMode == FUZZ_MODE_WHERE_INFO_FREE && size >= sizeof(WhereInfoFreePacket) ) {
    const WhereInfoFreePacket *pWifPacket = (const WhereInfoFreePacket*)data;
    cx.targetPgno = pWifPacket->loopCount;
    cx.allocMode = pWifPacket->scenario;
    cx.corruptionSeed = pWifPacket->corruption_flags;
  } else if( cx.fuzzMode == FUZZ_MODE_WHERE_LOOP_ADD_BTREE_INDEX && size >= sizeof(WhereLoopAddBtreeIndexPacket) ) {
    const WhereLoopAddBtreeIndexPacket *pWlabiPacket = (const WhereLoopAddBtreeIndexPacket*)data;
    cx.targetPgno = pWlabiPacket->indexColumnCount;
    cx.allocMode = pWlabiPacket->scenario;
    cx.corruptionSeed = pWlabiPacket->corruption_flags;
  } else if( cx.fuzzMode == FUZZ_MODE_BTREE_CURSOR_WITH_LOCK && size >= sizeof(BtreeCursorWithLockPacket) ) {
    const BtreeCursorWithLockPacket *pBclPacket = (const BtreeCursorWithLockPacket*)data;
    cx.targetPgno = pBclPacket->iTable;
    cx.allocMode = pBclPacket->wrFlag;
    cx.corruptionSeed = pBclPacket->btreeFlags;
  } else if( cx.fuzzMode == FUZZ_MODE_BTREE_LAST && size >= sizeof(BtreeLastPacket) ) {
    const BtreeLastPacket *pBlPacket = (const BtreeLastPacket*)data;
    cx.targetPgno = pBlPacket->rootPage;
    cx.allocMode = pBlPacket->cursorState;
    cx.corruptionSeed = pBlPacket->corruptionMask;
  } else if( cx.fuzzMode == FUZZ_MODE_BTREE_NEXT && size >= sizeof(BtreeNextPacket) ) {
    const BtreeNextPacket *pBnPacket = (const BtreeNextPacket*)data;
    cx.targetPgno = pBnPacket->cellIndex;
    cx.allocMode = pBnPacket->cursorState;
    cx.corruptionSeed = pBnPacket->pageLayout;
  } else if( cx.fuzzMode == FUZZ_MODE_VDBE_RECORD_COMPARE_DEBUG && size >= sizeof(RecordCompareDebugPacket) ) {
    const RecordCompareDebugPacket *pRcdPacket = (const RecordCompareDebugPacket*)data;
    cx.targetPgno = pRcdPacket->nKey1;
    cx.allocMode = pRcdPacket->scenario;
    cx.corruptionSeed = pRcdPacket->corruption_flags;
  } else if( cx.fuzzMode == FUZZ_MODE_VDBE_RECORD_COMPARE_STRING && size >= sizeof(RecordCompareStringPacket) ) {
    const RecordCompareStringPacket *pRcsPacket = (const RecordCompareStringPacket*)data;
    cx.targetPgno = pRcsPacket->nKey1;
    cx.allocMode = pRcsPacket->scenario;
    cx.corruptionSeed = pRcsPacket->corruption_flags;
  } else if( cx.fuzzMode == FUZZ_MODE_VDBE_RECORD_COMPARE_INT && size >= sizeof(RecordCompareIntPacket) ) {
    const RecordCompareIntPacket *pRciPacket = (const RecordCompareIntPacket*)data;
    cx.targetPgno = pRciPacket->nKey1;
    cx.allocMode = pRciPacket->scenario;
    cx.corruptionSeed = pRciPacket->corruption_flags;
  } else if( cx.fuzzMode == FUZZ_MODE_VDBE_RECORD_DECODE_INT && size >= sizeof(RecordDecodeIntPacket) ) {
    const RecordDecodeIntPacket *pRdiPacket = (const RecordDecodeIntPacket*)data;
    cx.targetPgno = pRdiPacket->serialType;
    cx.allocMode = pRdiPacket->scenario;
    cx.corruptionSeed = pRdiPacket->corruption_flags;
  } else if( cx.fuzzMode == FUZZ_MODE_VDBE_MEM_SET_ZERO_BLOB && size >= sizeof(MemSetZeroBlobPacket) ) {
    const MemSetZeroBlobPacket *pMszbPacket = (const MemSetZeroBlobPacket*)data;
    cx.targetPgno = pMszbPacket->blob_size;
    cx.allocMode = pMszbPacket->scenario;
    cx.corruptionSeed = pMszbPacket->corruption_flags;
  } else if( cx.fuzzMode == FUZZ_MODE_VDBE_MEM_SHALLOW_COPY && size >= sizeof(MemShallowCopyPacket) ) {
    const MemShallowCopyPacket *pMscPacket = (const MemShallowCopyPacket*)data;
    cx.targetPgno = pMscPacket->data_size;
    cx.allocMode = pMscPacket->scenario;
    cx.corruptionSeed = pMscPacket->corruption_flags;
  } else if( cx.fuzzMode == FUZZ_MODE_VDBE_MEM_STRINGIFY && size >= sizeof(MemStringifyPacket) ) {
    const MemStringifyPacket *pMsPacket = (const MemStringifyPacket*)data;
    cx.targetPgno = pMsPacket->int_value;
    cx.allocMode = pMsPacket->scenario;
    cx.corruptionSeed = pMsPacket->corruption_flags;
  } else if( cx.fuzzMode == FUZZ_MODE_VDBE_MEM_VALID_STR_REP && size >= sizeof(MemValidStrRepPacket) ) {
    const MemValidStrRepPacket *pMvsrPacket = (const MemValidStrRepPacket*)data;
    cx.targetPgno = pMvsrPacket->str_length;
    cx.allocMode = pMvsrPacket->scenario;
    cx.corruptionSeed = pMvsrPacket->corruption_flags;
  } else if( cx.fuzzMode == FUZZ_MODE_BTREE_OVERWRITE_OVERFLOW_CELL && size >= sizeof(BtreeOverwriteOverflowCellPacket) ) {
    const BtreeOverwriteOverflowCellPacket *pBoocPacket = (const BtreeOverwriteOverflowCellPacket*)data;
    cx.targetPgno = pBoocPacket->dataSize;
    cx.allocMode = pBoocPacket->scenario;
    cx.corruptionSeed = pBoocPacket->zeroTail;
  } else if( cx.fuzzMode == FUZZ_MODE_BTREE_PARSE_CELL_PTR_INDEX && size >= sizeof(BtreeParseCellPtrIndexPacket) ) {
    const BtreeParseCellPtrIndexPacket *pBpcpiPacket = (const BtreeParseCellPtrIndexPacket*)data;
    cx.targetPgno = pBpcpiPacket->cellSize;
    cx.allocMode = pBpcpiPacket->scenario;
    cx.corruptionSeed = pBpcpiPacket->payloadSize;
  } else if( cx.fuzzMode == FUZZ_MODE_BTREE_PARSE_CELL_PTR_NO_PAYLOAD && size >= sizeof(BtreeParseCellPtrNoPayloadPacket) ) {
    const BtreeParseCellPtrNoPayloadPacket *pBpcpnpPacket = (const BtreeParseCellPtrNoPayloadPacket*)data;
    cx.targetPgno = pBpcpnpPacket->keyValue;
    cx.allocMode = pBpcpnpPacket->scenario;
    cx.corruptionSeed = pBpcpnpPacket->varintBytes;
  } else if( cx.fuzzMode == FUZZ_MODE_VDBE_ADD_DBLQUOTE_STR && size >= sizeof(VdbeAddDblquoteStrPacket) ) {
    const VdbeAddDblquoteStrPacket *pVadsPacket = (const VdbeAddDblquoteStrPacket*)data;
    cx.targetPgno = pVadsPacket->stringLength;
    cx.allocMode = pVadsPacket->scenario;
    cx.corruptionSeed = pVadsPacket->memoryPressure;
  } else if( cx.fuzzMode == FUZZ_MODE_VDBE_ADD_FUNCTION_CALL && size >= sizeof(VdbeAddFunctionCallPacket) ) {
    const VdbeAddFunctionCallPacket *pVafcPacket = (const VdbeAddFunctionCallPacket*)data;
    cx.targetPgno = pVafcPacket->constantMask;
    cx.allocMode = pVafcPacket->scenario;
    cx.corruptionSeed = pVafcPacket->argumentCount;
  } else if( cx.fuzzMode == FUZZ_MODE_VDBE_ADD_OP4_DUP8 && size >= sizeof(VdbeAddOp4Dup8Packet) ) {
    const VdbeAddOp4Dup8Packet *pVaodPacket = (const VdbeAddOp4Dup8Packet*)data;
    cx.targetPgno = pVaodPacket->opcode;
    cx.allocMode = pVaodPacket->scenario;
    cx.corruptionSeed = pVaodPacket->p4type;
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
    (cx.fuzzMode == FUZZ_MODE_ASSERT_PAGER_STATE) ?
    ((const AssertPagerStatePacket*)data)->corruption_flags & 1 :
    (cx.fuzzMode == FUZZ_MODE_CHECK_PAGE) ?
    ((const CheckPagePacket*)data)->corruptionType & 1 :
    (cx.fuzzMode == FUZZ_MODE_PAGE_IN_JOURNAL) ?
    ((const PageInJournalPacket*)data)->syncFlags & 1 :
    (cx.fuzzMode == FUZZ_MODE_PAGER_FIX_MAPLIMIT) ?
    ((const PagerFixMaplimitPacket*)data)->mmapEnabled & 1 :
    (cx.fuzzMode == FUZZ_MODE_FREE_IDX_STR) ?
    ((const FreeIdxStrPacket*)data)->needToFreeFlag & 1 :
    (cx.fuzzMode == FUZZ_MODE_FREE_INDEX_INFO) ?
    ((const FreeIndexInfoPacket*)data)->scenario & 1 :
    (cx.fuzzMode == FUZZ_MODE_WHERE_INFO_FREE) ?
    ((const WhereInfoFreePacket*)data)->sortedFlag & 1 :
    (cx.fuzzMode == FUZZ_MODE_WHERE_LOOP_ADD_BTREE_INDEX) ?
    ((const WhereLoopAddBtreeIndexPacket*)data)->whereFlags & 1 :
    (cx.fuzzMode == FUZZ_MODE_BTREE_CURSOR_WITH_LOCK) ?
    ((const BtreeCursorWithLockPacket*)data)->wrFlag == 0 :
    (cx.fuzzMode == FUZZ_MODE_BTREE_LAST) ?
    ((const BtreeLastPacket*)data)->cursorFlags & 1 :
    (cx.fuzzMode == FUZZ_MODE_BTREE_NEXT) ?
    ((const BtreeNextPacket*)data)->cursorFlags & 1 :
    (cx.fuzzMode == FUZZ_MODE_VDBE_CHECK_ACTIVE_CNT) ?
    ((const VdbeCheckActiveCntPacket*)data)->corruption_flags & 1 :
    (cx.fuzzMode == FUZZ_MODE_VDBE_ADD_FUNCTION_CALL) ?
    ((const VdbeAddFunctionCallPacket*)data)->corruption_flags & 1 :
    (cx.fuzzMode == FUZZ_MODE_VDBE_ADD_OP4) ?
    ((const VdbeAddOp4Packet*)data)->corruption_flags & 1 :
    (cx.fuzzMode == FUZZ_MODE_VDBE_ADD_OP4_DUP8) ?
    ((const VdbeAddOp4Dup8Packet*)data)->corruption_flags & 1 :
    (cx.fuzzMode == FUZZ_MODE_BTREE_MOVETO) ?
    ((const MovetoPacket*)data)->scenario & 1 :
    (cx.fuzzMode == FUZZ_MODE_BTREE_OVERWRITE_CELL) ?
    ((const OverwriteCellPacket*)data)->scenario & 1 :
    (cx.fuzzMode == FUZZ_MODE_BTREE_OVERWRITE_CONTENT) ?
    ((const OverwriteContentPacket*)data)->scenario & 1 :
    (cx.fuzzMode == FUZZ_MODE_VDBE_COLUMN_MALLOC_FAILURE) ?
    ((const ColumnMallocFailurePacket*)data)->scenario & 1 :
    (cx.fuzzMode == FUZZ_MODE_VDBE_FREE_P4) ?
    ((const FreeP4Packet*)data)->scenario & 1 :
    (cx.fuzzMode == FUZZ_MODE_VDBE_ASSERT_FIELD_COUNT) ?
    ((const AssertFieldCountPacket*)data)->scenario & 1 :
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
  } else if( cx.fuzzMode == FUZZ_MODE_BTREE_TRANSFER_ROW && size >= sizeof(BtreeTransferRowPacket) ) {
    const BtreeTransferRowPacket *pBtreePacket = (const BtreeTransferRowPacket*)data;
    cx.execCnt = (pBtreePacket->scenario % 50) + 1;
    
    /* Execute B-Tree Meta Operations fuzzing */
    fuzz_btree_transfer_row(&cx, pBtreePacket);
  } else if( cx.fuzzMode == FUZZ_MODE_BTREE_TRIP_ALL_CURSORS && size >= sizeof(BtreeTripAllCursorsPacket) ) {
    const BtreeTripAllCursorsPacket *pBtreePacket = (const BtreeTripAllCursorsPacket*)data;
    cx.execCnt = (pBtreePacket->scenario % 50) + 1;
    
    /* Execute B-Tree Meta Operations fuzzing */
    fuzz_btree_trip_all_cursors(&cx, pBtreePacket);
  } else if( cx.fuzzMode == FUZZ_MODE_BTREE_UPDATE_META && size >= sizeof(BtreeUpdateMetaPacket) ) {
    const BtreeUpdateMetaPacket *pBtreePacket = (const BtreeUpdateMetaPacket*)data;
    cx.execCnt = (pBtreePacket->scenario % 50) + 1;
    
    /* Execute B-Tree Meta Operations fuzzing */
    fuzz_btree_update_meta(&cx, pBtreePacket);
  } else if( cx.fuzzMode == FUZZ_MODE_BTREE_UNLOCK_IF_UNUSED && size >= sizeof(BtreeUnlockIfUnusedPacket) ) {
    const BtreeUnlockIfUnusedPacket *pBtreePacket = (const BtreeUnlockIfUnusedPacket*)data;
    cx.execCnt = (pBtreePacket->scenario % 50) + 1;
    
    /* Execute B-Tree Meta Operations fuzzing */
    fuzz_btree_unlock_if_unused(&cx, pBtreePacket);
  } else if( cx.fuzzMode == FUZZ_MODE_BTREE_MOVETO && size >= sizeof(MovetoPacket) ) {
    const MovetoPacket *pMvPacket = (const MovetoPacket*)data;
    cx.execCnt = (pMvPacket->keyData[0] % 50) + 1;
    
    /* Execute B-Tree moveto fuzzing */
    fuzz_btree_moveto(&cx, pMvPacket);
  } else if( cx.fuzzMode == FUZZ_MODE_BTREE_OVERWRITE_CELL && size >= sizeof(OverwriteCellPacket) ) {
    const OverwriteCellPacket *pOwcPacket = (const OverwriteCellPacket*)data;
    cx.execCnt = (pOwcPacket->payloadData[0] % 50) + 1;
    
    /* Execute B-Tree overwrite cell fuzzing */
    fuzz_btree_overwrite_cell(&cx, pOwcPacket);
  } else if( cx.fuzzMode == FUZZ_MODE_BTREE_OVERWRITE_CONTENT && size >= sizeof(OverwriteContentPacket) ) {
    const OverwriteContentPacket *pOwCtPacket = (const OverwriteContentPacket*)data;
    cx.execCnt = (pOwCtPacket->contentData[0] % 50) + 1;
    
    /* Execute B-Tree overwrite content fuzzing */
    fuzz_btree_overwrite_content(&cx, pOwCtPacket);
  } else if( cx.fuzzMode == FUZZ_MODE_VDBE_COLUMN_MALLOC_FAILURE && size >= sizeof(ColumnMallocFailurePacket) ) {
    const ColumnMallocFailurePacket *pCmfPacket = (const ColumnMallocFailurePacket*)data;
    cx.execCnt = (pCmfPacket->testData[0] % 50) + 1;
    
    /* Execute VDBE column malloc failure fuzzing */
    fuzz_column_malloc_failure(&cx, pCmfPacket);
  } else if( cx.fuzzMode == FUZZ_MODE_VDBE_FREE_P4 && size >= sizeof(FreeP4Packet) ) {
    const FreeP4Packet *pFp4Packet = (const FreeP4Packet*)data;
    cx.execCnt = (pFp4Packet->p4Data[0] % 50) + 1;
    
    /* Execute VDBE free P4 fuzzing */
    fuzz_free_p4(&cx, pFp4Packet);
  } else if( cx.fuzzMode == FUZZ_MODE_VDBE_ASSERT_FIELD_COUNT && size >= sizeof(AssertFieldCountPacket) ) {
    const AssertFieldCountPacket *pAfcPacket = (const AssertFieldCountPacket*)data;
    cx.execCnt = (pAfcPacket->recordData[0] % 50) + 1;
    
    /* Execute VDBE assert field count fuzzing */
    fuzz_assert_field_count(&cx, pAfcPacket);
  } else if( cx.fuzzMode == FUZZ_MODE_ASSERT_PAGER_STATE && size >= sizeof(AssertPagerStatePacket) ) {
    const AssertPagerStatePacket *pApsPacket = (const AssertPagerStatePacket*)data;
    cx.execCnt = (pApsPacket->testData[0] % 50) + 1;
    
    /* Execute assert pager state fuzzing */
    fuzz_assert_pager_state(&cx, pApsPacket);
  } else if( cx.fuzzMode == FUZZ_MODE_CHECK_PAGE && size >= sizeof(CheckPagePacket) ) {
    const CheckPagePacket *pCpPacket = (const CheckPagePacket*)data;
    cx.execCnt = (pCpPacket->pageData[0] % 50) + 1;
    
    /* Execute check page fuzzing */
    fuzz_check_page(&cx, pCpPacket);
  } else if( cx.fuzzMode == FUZZ_MODE_PAGE_IN_JOURNAL && size >= sizeof(PageInJournalPacket) ) {
    const PageInJournalPacket *pPjPacket = (const PageInJournalPacket*)data;
    cx.execCnt = (pPjPacket->journalData[0] % 50) + 1;
    
    /* Execute page in journal fuzzing */
    fuzz_page_in_journal(&cx, pPjPacket);
  } else if( cx.fuzzMode == FUZZ_MODE_PAGER_FIX_MAPLIMIT && size >= sizeof(PagerFixMaplimitPacket) ) {
    const PagerFixMaplimitPacket *pPfmPacket = (const PagerFixMaplimitPacket*)data;
    cx.execCnt = (pPfmPacket->testData[0] % 50) + 1;
    
    /* Execute pager fix maplimit fuzzing */
    fuzz_pager_fix_maplimit(&cx, pPfmPacket);
  } else if( cx.fuzzMode == FUZZ_MODE_FREE_IDX_STR && size >= sizeof(FreeIdxStrPacket) ) {
    const FreeIdxStrPacket *pFisPacket = (const FreeIdxStrPacket*)data;
    cx.execCnt = (pFisPacket->testData[0] % 50) + 1;
    
    /* Execute free index string fuzzing */
    fuzz_free_idx_str(&cx, pFisPacket);
  } else if( cx.fuzzMode == FUZZ_MODE_FREE_INDEX_INFO && size >= sizeof(FreeIndexInfoPacket) ) {
    const FreeIndexInfoPacket *pFiiPacket = (const FreeIndexInfoPacket*)data;
    cx.execCnt = (pFiiPacket->constraintData[0] % 50) + 1;
    
    /* Execute free index info fuzzing */
    fuzz_free_index_info(&cx, pFiiPacket);
  } else if( cx.fuzzMode == FUZZ_MODE_WHERE_INFO_FREE && size >= sizeof(WhereInfoFreePacket) ) {
    const WhereInfoFreePacket *pWifPacket = (const WhereInfoFreePacket*)data;
    cx.execCnt = (pWifPacket->whereData[0] % 50) + 1;
    
    /* Execute WHERE info free fuzzing */
    fuzz_where_info_free(&cx, pWifPacket);
  } else if( cx.fuzzMode == FUZZ_MODE_WHERE_LOOP_ADD_BTREE_INDEX && size >= sizeof(WhereLoopAddBtreeIndexPacket) ) {
    const WhereLoopAddBtreeIndexPacket *pWlabiPacket = (const WhereLoopAddBtreeIndexPacket*)data;
    cx.execCnt = (pWlabiPacket->indexData[0] % 50) + 1;
    
    /* Execute WHERE loop add B-Tree index fuzzing */
    fuzz_where_loop_add_btree_index(&cx, pWlabiPacket);
  } else if( cx.fuzzMode == FUZZ_MODE_BTREE_CURSOR_WITH_LOCK && size >= sizeof(BtreeCursorWithLockPacket) ) {
    const BtreeCursorWithLockPacket *pBclPacket = (const BtreeCursorWithLockPacket*)data;
    cx.execCnt = (pBclPacket->scenario % 30) + 1;
    
    /* Execute B-Tree cursor with lock fuzzing */
    fuzz_btree_cursor_with_lock(&cx, data, size);
  } else if( cx.fuzzMode == FUZZ_MODE_BTREE_LAST && size >= sizeof(BtreeLastPacket) ) {
    const BtreeLastPacket *pBlPacket = (const BtreeLastPacket*)data;
    cx.execCnt = (pBlPacket->scenario % 25) + 1;
    
    /* Execute B-Tree last record positioning fuzzing */
    fuzz_btree_last(&cx, data, size);
  } else if( cx.fuzzMode == FUZZ_MODE_BTREE_NEXT && size >= sizeof(BtreeNextPacket) ) {
    const BtreeNextPacket *pBnPacket = (const BtreeNextPacket*)data;
    cx.execCnt = (pBnPacket->scenario % 35) + 1;
    
    /* Execute B-Tree next record navigation fuzzing */
    fuzz_btree_next(&cx, data, size);
  } else if( cx.fuzzMode == FUZZ_MODE_VDBE_RECORD_COMPARE_DEBUG && size >= sizeof(RecordCompareDebugPacket) ) {
    const RecordCompareDebugPacket *pRcdPacket = (const RecordCompareDebugPacket*)data;
    cx.execCnt = (pRcdPacket->keyData[0] % 50) + 1;
    
    /* Execute VDBE record compare debug fuzzing */
    fuzz_vdbe_record_compare_debug(&cx, pRcdPacket);
  } else if( cx.fuzzMode == FUZZ_MODE_VDBE_RECORD_COMPARE_STRING && size >= sizeof(RecordCompareStringPacket) ) {
    const RecordCompareStringPacket *pRcsPacket = (const RecordCompareStringPacket*)data;
    cx.execCnt = (pRcsPacket->stringData[0] % 50) + 1;
    
    /* Execute VDBE record compare string fuzzing */
    fuzz_vdbe_record_compare_string(&cx, pRcsPacket);
  } else if( cx.fuzzMode == FUZZ_MODE_VDBE_RECORD_COMPARE_INT && size >= sizeof(RecordCompareIntPacket) ) {
    const RecordCompareIntPacket *pRciPacket = (const RecordCompareIntPacket*)data;
    cx.execCnt = (pRciPacket->intData[0] % 50) + 1;
    
    /* Execute VDBE record compare int fuzzing */
    fuzz_vdbe_record_compare_int(&cx, pRciPacket);
  } else if( cx.fuzzMode == FUZZ_MODE_VDBE_RECORD_DECODE_INT && size >= sizeof(RecordDecodeIntPacket) ) {
    const RecordDecodeIntPacket *pRdiPacket = (const RecordDecodeIntPacket*)data;
    cx.execCnt = (pRdiPacket->testData[0] % 50) + 1;
    
    /* Execute VDBE record decode int fuzzing */
    fuzz_vdbe_record_decode_int(&cx, pRdiPacket);
  } else if( cx.fuzzMode == FUZZ_MODE_VDBE_MEM_SET_ZERO_BLOB && size >= sizeof(MemSetZeroBlobPacket) ) {
    const MemSetZeroBlobPacket *pMszbPacket = (const MemSetZeroBlobPacket*)data;
    cx.execCnt = (pMszbPacket->testData[0] % 50) + 1;
    
    /* Execute VDBE memory set zero blob fuzzing */
    fuzz_vdbe_mem_set_zero_blob(&cx, pMszbPacket);
  } else if( cx.fuzzMode == FUZZ_MODE_VDBE_MEM_SHALLOW_COPY && size >= sizeof(MemShallowCopyPacket) ) {
    const MemShallowCopyPacket *pMscPacket = (const MemShallowCopyPacket*)data;
    cx.execCnt = (pMscPacket->testData[0] % 50) + 1;
    
    /* Execute VDBE memory shallow copy fuzzing */
    fuzz_vdbe_mem_shallow_copy(&cx, pMscPacket);
  } else if( cx.fuzzMode == FUZZ_MODE_VDBE_MEM_STRINGIFY && size >= sizeof(MemStringifyPacket) ) {
    const MemStringifyPacket *pMsPacket = (const MemStringifyPacket*)data;
    cx.execCnt = (pMsPacket->testData[0] % 50) + 1;
    
    /* Execute VDBE memory stringify fuzzing */
    fuzz_vdbe_mem_stringify(&cx, pMsPacket);
  } else if( cx.fuzzMode == FUZZ_MODE_VDBE_MEM_VALID_STR_REP && size >= sizeof(MemValidStrRepPacket) ) {
    const MemValidStrRepPacket *pMvsrPacket = (const MemValidStrRepPacket*)data;
    cx.execCnt = (pMvsrPacket->stringData[0] % 50) + 1;
    
    /* Execute VDBE memory valid string rep fuzzing */
    fuzz_vdbe_mem_valid_str_rep(&cx, pMvsrPacket);
  } else if( cx.fuzzMode == FUZZ_MODE_BTREE_OVERWRITE_OVERFLOW_CELL && size >= sizeof(BtreeOverwriteOverflowCellPacket) ) {
    const BtreeOverwriteOverflowCellPacket *pBoocPacket = (const BtreeOverwriteOverflowCellPacket*)data;
    cx.execCnt = (pBoocPacket->payloadData[0] % 30) + 1;
    
    /* Execute B-Tree overwrite overflow cell fuzzing */
    fuzz_btree_overwrite_overflow_cell(&cx, data, size);
  } else if( cx.fuzzMode == FUZZ_MODE_BTREE_PARSE_CELL_PTR_INDEX && size >= sizeof(BtreeParseCellPtrIndexPacket) ) {
    const BtreeParseCellPtrIndexPacket *pBpcpiPacket = (const BtreeParseCellPtrIndexPacket*)data;
    cx.execCnt = (pBpcpiPacket->cellData[0] % 25) + 1;
    
    /* Execute B-Tree parse cell ptr index fuzzing */
    fuzz_btree_parse_cell_ptr_index(&cx, data, size);
  } else if( cx.fuzzMode == FUZZ_MODE_BTREE_PARSE_CELL_PTR_NO_PAYLOAD && size >= sizeof(BtreeParseCellPtrNoPayloadPacket) ) {
    const BtreeParseCellPtrNoPayloadPacket *pBpcpnpPacket = (const BtreeParseCellPtrNoPayloadPacket*)data;
    cx.execCnt = (pBpcpnpPacket->cellData[0] % 20) + 1;
    
    /* Execute B-Tree parse cell ptr no payload fuzzing */
    fuzz_btree_parse_cell_ptr_no_payload(&cx, data, size);
  } else if( cx.fuzzMode == FUZZ_MODE_VDBE_ADD_DBLQUOTE_STR && size >= sizeof(VdbeAddDblquoteStrPacket) ) {
    const VdbeAddDblquoteStrPacket *pVadsPacket = (const VdbeAddDblquoteStrPacket*)data;
    cx.execCnt = (pVadsPacket->testString[0] % 25) + 1;
    
    /* Execute VDBE add dblquote string fuzzing */
    fuzz_vdbe_add_dblquote_str(&cx, data, size);
  } else if( cx.fuzzMode == FUZZ_MODE_VDBE_ADD_FUNCTION_CALL && size >= sizeof(VdbeAddFunctionCallPacket) ) {
    const VdbeAddFunctionCallPacket *pVafcPacket = (const VdbeAddFunctionCallPacket*)data;
    cx.execCnt = (pVafcPacket->scenario % 30) + 1;
    
    /* Execute VDBE add function call fuzzing */
    fuzz_vdbe_add_function_call(&cx, pVafcPacket);
  } else if( cx.fuzzMode == FUZZ_MODE_VDBE_ADD_OP4_DUP8 && size >= sizeof(VdbeAddOp4Dup8Packet) ) {
    const VdbeAddOp4Dup8Packet *pVaodPacket = (const VdbeAddOp4Dup8Packet*)data;
    cx.execCnt = (pVaodPacket->scenario % 20) + 1;
    
    /* Execute VDBE add op4 dup8 fuzzing */
    fuzz_vdbe_add_op4_dup8(&cx, pVaodPacket);
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
  else if( cx.fuzzMode == FUZZ_MODE_VDBE_CHECK_ACTIVE_CNT ) packetSize = sizeof(VdbeCheckActiveCntPacket);
  else if( cx.fuzzMode == FUZZ_MODE_VDBE_ADD_FUNCTION_CALL ) packetSize = sizeof(VdbeAddFunctionCallPacket);
  else if( cx.fuzzMode == FUZZ_MODE_VDBE_ADD_OP4 ) packetSize = sizeof(VdbeAddOp4Packet);
  else if( cx.fuzzMode == FUZZ_MODE_VDBE_ADD_OP4_DUP8 ) packetSize = sizeof(VdbeAddOp4Dup8Packet);
  else if( cx.fuzzMode == FUZZ_MODE_BTREE_MOVETO ) packetSize = sizeof(MovetoPacket);
  else if( cx.fuzzMode == FUZZ_MODE_BTREE_OVERWRITE_CELL ) packetSize = sizeof(OverwriteCellPacket);
  else if( cx.fuzzMode == FUZZ_MODE_BTREE_OVERWRITE_CONTENT ) packetSize = sizeof(OverwriteContentPacket);
  else if( cx.fuzzMode == FUZZ_MODE_VDBE_COLUMN_MALLOC_FAILURE ) packetSize = sizeof(ColumnMallocFailurePacket);
  else if( cx.fuzzMode == FUZZ_MODE_VDBE_FREE_P4 ) packetSize = sizeof(FreeP4Packet);
  else if( cx.fuzzMode == FUZZ_MODE_VDBE_ASSERT_FIELD_COUNT ) packetSize = sizeof(AssertFieldCountPacket);
  else if( cx.fuzzMode == FUZZ_MODE_ASSERT_PAGER_STATE ) packetSize = sizeof(AssertPagerStatePacket);
  else if( cx.fuzzMode == FUZZ_MODE_CHECK_PAGE ) packetSize = sizeof(CheckPagePacket);
  else if( cx.fuzzMode == FUZZ_MODE_PAGE_IN_JOURNAL ) packetSize = sizeof(PageInJournalPacket);
  else if( cx.fuzzMode == FUZZ_MODE_PAGER_FIX_MAPLIMIT ) packetSize = sizeof(PagerFixMaplimitPacket);
  else if( cx.fuzzMode == FUZZ_MODE_FREE_IDX_STR ) packetSize = sizeof(FreeIdxStrPacket);
  else if( cx.fuzzMode == FUZZ_MODE_FREE_INDEX_INFO ) packetSize = sizeof(FreeIndexInfoPacket);
  else if( cx.fuzzMode == FUZZ_MODE_WHERE_INFO_FREE ) packetSize = sizeof(WhereInfoFreePacket);
  else if( cx.fuzzMode == FUZZ_MODE_WHERE_LOOP_ADD_BTREE_INDEX ) packetSize = sizeof(WhereLoopAddBtreeIndexPacket);
  else if( cx.fuzzMode == FUZZ_MODE_BTREE_CURSOR_WITH_LOCK ) packetSize = sizeof(BtreeCursorWithLockPacket);
  else if( cx.fuzzMode == FUZZ_MODE_BTREE_LAST ) packetSize = sizeof(BtreeLastPacket);
  else if( cx.fuzzMode == FUZZ_MODE_BTREE_NEXT ) packetSize = sizeof(BtreeNextPacket);
  else if( cx.fuzzMode == FUZZ_MODE_BTREE_OVERWRITE_OVERFLOW_CELL ) packetSize = sizeof(BtreeOverwriteOverflowCellPacket);
  else if( cx.fuzzMode == FUZZ_MODE_BTREE_PARSE_CELL_PTR_INDEX ) packetSize = sizeof(BtreeParseCellPtrIndexPacket);
  else if( cx.fuzzMode == FUZZ_MODE_BTREE_PARSE_CELL_PTR_NO_PAYLOAD ) packetSize = sizeof(BtreeParseCellPtrNoPayloadPacket);
  else if( cx.fuzzMode == FUZZ_MODE_VDBE_ADD_DBLQUOTE_STR ) packetSize = sizeof(VdbeAddDblquoteStrPacket);
  else if( cx.fuzzMode == FUZZ_MODE_VDBE_ADD_FUNCTION_CALL ) packetSize = sizeof(VdbeAddFunctionCallPacket);
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