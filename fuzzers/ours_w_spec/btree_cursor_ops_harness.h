/*
** B-Tree Cursor Operations Harness Header
** Target functions: btreeMoveto, btreeOverwriteCell, btreeOverwriteContent
** Specification-based fuzzing for B-Tree cursor and content operations
*/
#ifndef BTREE_CURSOR_OPS_HARNESS_H
#define BTREE_CURSOR_OPS_HARNESS_H

#include "fuzz.h"

/* Function declarations for B-Tree cursor operations fuzzing */
void fuzz_btree_moveto(FuzzCtx *pCtx, const MovetoPacket *pPacket);
void fuzz_btree_overwrite_cell(FuzzCtx *pCtx, const OverwriteCellPacket *pPacket);
void fuzz_btree_overwrite_content(FuzzCtx *pCtx, const OverwriteContentPacket *pPacket);

#endif /* BTREE_CURSOR_OPS_HARNESS_H */