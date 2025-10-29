#ifndef BTREE_EXTENDED_HARNESS_H
#define BTREE_EXTENDED_HARNESS_H

#include "fuzz.h"

/* B-Tree Extended Operations Packet Headers */
typedef struct {
    uint8_t fuzzSelector;
    uint8_t transactionState;
    uint8_t nVdbeRead;
    uint8_t flags;
    uint32_t btSharedData;
    uint32_t corruptionMask;
    uint8_t testData[48];
} BtreeTransEndPacket;

typedef struct {
    uint8_t fuzzSelector;
    uint8_t pageFlag;
    uint8_t getMode;
    uint8_t flags;
    uint32_t targetPgno;
    uint32_t corruptionMask;
    uint8_t testData[48];
} BtreeGetPagePacket;

typedef struct {
    uint8_t fuzzSelector;
    uint8_t pageFlag;
    uint8_t refCountMode;
    uint8_t flags;
    uint32_t targetPgno;
    uint32_t corruptionMask;
    uint8_t testData[48];
} BtreeUnusedPagePacket;

typedef struct {
    uint8_t fuzzSelector;
    uint8_t heapSize;
    uint8_t insertMode;
    uint8_t flags;
    uint32_t heapElement;
    uint32_t corruptionMask;
    uint8_t testData[48];
} BtreeHeapInsertPacket;

typedef struct {
    uint8_t fuzzSelector;
    uint8_t heapSize;
    uint8_t pullMode;
    uint8_t flags;
    uint32_t heapState;
    uint32_t corruptionMask;
    uint8_t testData[48];
} BtreeHeapPullPacket;

/* Extended B-Tree Fuzzing Modes */
#define FUZZ_MODE_BTREE_END_TRANS     30
#define FUZZ_MODE_BTREE_GET_PAGE      31
#define FUZZ_MODE_BTREE_UNUSED_PAGE   32
#define FUZZ_MODE_BTREE_HEAP_INSERT   33
#define FUZZ_MODE_BTREE_HEAP_PULL     34

/* Function declarations */
void fuzz_btree_end_transaction(FuzzCtx *pCtx, const BtreeTransEndPacket *pPacket);
void fuzz_btree_get_page(FuzzCtx *pCtx, const BtreeGetPagePacket *pPacket);
void fuzz_btree_get_unused_page(FuzzCtx *pCtx, const BtreeUnusedPagePacket *pPacket);
void fuzz_btree_heap_insert(FuzzCtx *pCtx, const BtreeHeapInsertPacket *pPacket);
void fuzz_btree_heap_pull(FuzzCtx *pCtx, const BtreeHeapPullPacket *pPacket);

#endif /* BTREE_EXTENDED_HARNESS_H */