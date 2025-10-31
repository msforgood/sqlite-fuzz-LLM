// repro_no_free.c
// Build (recommended): clang -fsanitize=address,undefined -O1 -g repro_no_free.c build/dependencies/sqlite3.c -Ibuild/dependencies -o repro_no_free
// Run: ASAN_OPTIONS=malloc_context_size=50:fast_unwind_on_malloc=0 UBSAN_OPTIONS=print_stacktrace=1 ./repro_no_free < ./crash-e7c74034a2259aedcadf5507b1ea398e2bdb6e82

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sqlite3.h"

/* read stdin fully */
static unsigned char *read_all(size_t *out_len){
    size_t cap = 1<<16, len = 0;
    unsigned char *b = malloc(cap);
    if(!b) return NULL;
    for(;;){
        size_t n = fread(b + len, 1, cap - len, stdin);
        len += n;
        if(n == 0) break;
        if(len == cap){
            size_t nc = cap << 1;
            unsigned char *nb = realloc(b, nc);
            if(!nb){ free(b); return NULL; }
            b = nb; cap = nc;
        }
    }
    *out_len = len;
    return b;
}

int main(void){
    size_t in_len = 0;
    unsigned char *in = read_all(&in_len);
    if(!in) return 0;

    /* Prepare payload strings (nul-terminated) */
    char *payload = malloc(in_len + 1);
    if(!payload){ free(in); return 0; }
    memcpy(payload, in, in_len);
    payload[in_len] = '\0';

    /* Use the exact sqlite source from build/dependencies for best parity. */
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
        fprintf(stderr, "open fail\n");
        free(payload); free(in);
        return 0;
    }

    /* Create table similar to harness */
    sqlite3_exec(db, "CREATE TABLE t1(id INTEGER, data TEXT, blob_data BLOB)", NULL, NULL, NULL);

    /* 1) Use sqlite3_mprintf to create SQL using payload - INTENTIONALLY DO NOT FREE result.
       This mimics the harness bug where mprintf result is not freed and thus heap layout differs. */
    char *sql_leak = sqlite3_mprintf("INSERT INTO t1 VALUES(1, '%s', x'01020304')", payload);
    /* Note: we do NOT call sqlite3_free(sql_leak); */

    /* Prepare statement from that sql (this will exercise parsing & copying paths) */
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql_leak, -1, &stmt, NULL) == SQLITE_OK) {
        /* bind and step to ensure DB internal paths are exercised */
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
    /* Do NOT free sql_leak here */
    sqlite3_free(sql_leak);

    /* 2) Trigger vmprintf/strAccum append paths more aggressively:
       Build many concatenations using mprintf and also use %.*s style. Some intentionally not freed. */
    for (int i = 0; i < 200; ++i) {
        /* create some moderately sized strings and free some, but intentionally leak others */
        char *tmp = sqlite3_mprintf("%s_%d_%s", payload, i, payload);
        if (i % 7 == 0) {
            /* leak periodically */
            /* intentionally skip sqlite3_free(tmp); */
            sqlite3_free(tmp);

        } else {
            sqlite3_free(tmp);
        }
    }

    /* 3) Force a call path similar to vmprintf with precision formatting */
    for (int i = 0; i < 1000; ++i) {
        /* use a precision influenced by payload bytes (bounded) */
        int prec = (in_len > 0) ? (in[0] & 0xFF) : 10;
        if (prec <= 0) prec = 1;
        if (prec > 4096) prec = 4096;
        char *s = sqlite3_mprintf("%.*s_suffix", prec, payload);
        /* free only some to perturb heap */
        // if (i % 13 != 0) sqlite3_free(s);
        sqlite3_free(s);
    }

    /* 4) Execute some select queries that do string operations to hit the code path */
    if (sqlite3_prepare_v2(db, "SELECT data || '_modified', length(blob_data) FROM t1", -1, &stmt, NULL) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const unsigned char *text = sqlite3_column_text(stmt, 0);
            int len = sqlite3_column_int(stmt, 1);
            /* Additionally call mprintf on results and intentionally leak once */
            char *r = sqlite3_mprintf("%.*s", 10, text ? (const char*)text : "");
            /* sometimes free, sometimes not */
            // if (len % 2 == 0) sqlite3_free(r);
            sqlite3_free(r);
            /* else intentionally leak r */
        }
        sqlite3_finalize(stmt);
    }

    /* Keep program alive briefly to allow ASan to report; then cleanup */
    sqlite3_close(db);

    /* Intentionally leak sql_leak and some tmp's to mimic harness bug */
    free(payload);
    free(in);
    return 0;
}
