/*
** SQLite3 B-Tree Overflow Functions Harness Header
** Target functions: btreeOverwriteOverflowCell, btreeParseCellPtrIndex, btreeParseCellPtrNoPayload
*/

#ifndef BTREE_OVERFLOW_HARNESS_H
#define BTREE_OVERFLOW_HARNESS_H

#include "fuzz.h"

/* Packet structures for overflow functions */
typedef struct BtreeOverwriteOverflowCellPacket {
    uint32_t scenario;
    uint32_t dataSize;
    uint32_t zeroTail;
    uint32_t pageSize;
    uint8_t  wrFlag;
    uint8_t  useOverflow;
    uint8_t  padding[2];
    uint8_t  payloadData[1024];  /* Variable payload content */
} BtreeOverwriteOverflowCellPacket;

typedef struct BtreeParseCellPtrIndexPacket {
    uint32_t scenario;
    uint32_t cellSize;
    uint32_t payloadSize;
    uint16_t pageFlags;
    uint8_t  pageType;
    uint8_t  intKey;
    uint8_t  cellData[512];  /* Raw cell data to parse */
} BtreeParseCellPtrIndexPacket;

typedef struct BtreeParseCellPtrNoPayloadPacket {
    uint32_t scenario;
    uint32_t keyValue;
    uint8_t  varintBytes;
    uint8_t  pageLeaf;
    uint8_t  childPtrSize;
    uint8_t  padding;
    uint8_t  cellData[64];  /* Interior cell data */
} BtreeParseCellPtrNoPayloadPacket;

/* Function prototypes */
int fuzz_btree_overwrite_overflow_cell(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_btree_parse_cell_ptr_index(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_btree_parse_cell_ptr_no_payload(FuzzCtx *ctx, const uint8_t *data, size_t size);

#endif /* BTREE_OVERFLOW_HARNESS_H */