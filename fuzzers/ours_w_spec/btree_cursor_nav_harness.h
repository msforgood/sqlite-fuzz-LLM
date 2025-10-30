/*
** SQLite3 B-Tree Cursor Navigation Harness Header
** Target functions: btreeCursorWithLock, btreeLast, btreeNext
** Critical B-Tree cursor navigation and positioning functions
*/
#ifndef BTREE_CURSOR_NAV_HARNESS_H
#define BTREE_CURSOR_NAV_HARNESS_H

#include "fuzz.h"

/* Function declarations for B-Tree cursor navigation harnesses */
int fuzz_btree_cursor_with_lock(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_btree_last(FuzzCtx *ctx, const uint8_t *data, size_t size);
int fuzz_btree_next(FuzzCtx *ctx, const uint8_t *data, size_t size);

/* Utility functions for cursor navigation testing */
static int setup_test_btree_for_navigation(sqlite3 *db, uint32_t rootPage);
static int create_test_cursor_state(sqlite3 *db, uint32_t tableRoot, int wrFlag);
static int simulate_cursor_positioning(sqlite3 *db, uint32_t scenario);

#endif /* BTREE_CURSOR_NAV_HARNESS_H */