/*
** B-Tree Metadata Functions Harness Header
** Targets: sqlite3BtreeTransferRow, sqlite3BtreeTripAllCursors, 
**          sqlite3BtreeUpdateMeta, unlockBtreeIfUnused
** Specification-based fuzzing implementation for SQLite3 v3.51.0
*/

#ifndef BTREE_META_HARNESS_H
#define BTREE_META_HARNESS_H

#include "fuzz.h"

/* Function Code mappings for B-Tree Metadata functions */
#define FUZZ_MODE_BTREE_TRANSFER_ROW      51
#define FUZZ_MODE_BTREE_TRIP_ALL_CURSORS  52
#define FUZZ_MODE_BTREE_UPDATE_META       53
#define FUZZ_MODE_BTREE_UNLOCK_IF_UNUSED  54

/* Test scenario constants */
#define BTREE_META_SCENARIO_NORMAL     0
#define BTREE_META_SCENARIO_TRANSFER   1
#define BTREE_META_SCENARIO_CURSORS    2
#define BTREE_META_SCENARIO_METADATA   3
#define BTREE_META_SCENARIO_UNLOCK     4
#define BTREE_META_SCENARIO_OVERFLOW   5
#define BTREE_META_SCENARIO_CORRUPT    6
#define BTREE_META_SCENARIO_BOUNDARY   7

/* Packet structures for each target function */

/*
** Packet for sqlite3BtreeTransferRow (FC: btree_meta_001)
*/
typedef struct {
    uint64_t iKey;              /* Row key value */
    uint32_t nPayload;          /* Payload size */
    uint32_t nLocal;            /* Local payload size */
    uint32_t scenario;          /* Test scenario selector */
    uint16_t transferFlags;     /* Transfer operation flags */
    uint16_t cursorFlags;       /* Cursor state flags */
    uint32_t corruption_seed;   /* Corruption testing seed */
    uint8_t  reserved;          /* Padding */
    char     testData[24];      /* Test payload data */
} BtreeTransferRowPacket;

/*
** Packet for sqlite3BtreeTripAllCursors (FC: btree_meta_002)
*/
typedef struct {
    uint32_t errCode;           /* Error code to propagate */
    uint32_t writeOnly;         /* Write-only cursor flag */
    uint32_t scenario;          /* Test scenario selector */
    uint16_t cursorCount;       /* Number of cursors to create */
    uint16_t tripFlags;         /* Trip operation flags */
    uint32_t transactionState;  /* Transaction state */
    uint32_t corruption_flags;  /* Corruption test flags */
    uint8_t  reserved;          /* Padding */
    char     testData[16];      /* Test context data */
} BtreeTripAllCursorsPacket;

/*
** Packet for sqlite3BtreeUpdateMeta (FC: btree_meta_003)
*/
typedef struct {
    uint32_t idx;               /* Meta index (1-15) */
    uint32_t iMeta;             /* Meta value to set */
    uint32_t scenario;          /* Test scenario selector */
    uint16_t metaFlags;         /* Meta operation flags */
    uint16_t reserved1;         /* Padding */
    uint32_t transactionFlags;  /* Transaction setup flags */
    uint32_t corruption_test;   /* Corruption test selector */
    uint8_t  reserved;          /* Padding */
    char     testData[12];      /* Test meta data */
} BtreeUpdateMetaPacket;

/*
** Packet for unlockBtreeIfUnused (FC: btree_meta_004)
*/
typedef struct {
    uint32_t scenario;          /* Test scenario selector */
    uint16_t cursorCount;       /* Number of active cursors */
    uint16_t lockFlags;         /* Lock state flags */
    uint32_t transactionState;  /* Transaction state */
    uint32_t unlockFlags;       /* Unlock operation flags */
    uint32_t corruption_mask;   /* Corruption testing mask */
    uint8_t  reserved;          /* Padding */
    char     testData[8];       /* Test operation data */
} BtreeUnlockIfUnusedPacket;

/* Function declarations */
int fuzz_btree_transfer_row(FuzzCtx *pCtx, const BtreeTransferRowPacket *pPacket);
int fuzz_btree_trip_all_cursors(FuzzCtx *pCtx, const BtreeTripAllCursorsPacket *pPacket);
int fuzz_btree_update_meta(FuzzCtx *pCtx, const BtreeUpdateMetaPacket *pPacket);
int fuzz_btree_unlock_if_unused(FuzzCtx *pCtx, const BtreeUnlockIfUnusedPacket *pPacket);

#endif /* BTREE_META_HARNESS_H */