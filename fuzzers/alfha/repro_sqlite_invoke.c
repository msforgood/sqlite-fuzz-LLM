// Save as repro_sqlite_invoke.c
// Purpose: read stdin (artifact) and call sqlite3_mprintf/vmprintf paths
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sqlite3.h"

static unsigned char* read_all_stdin(size_t *out_len){
    size_t cap = 1<<16;
    size_t len = 0;
    unsigned char *buf = malloc(cap);
    if (!buf) return NULL;
    for (;;) {
        size_t n = fread(buf + len, 1, cap - len, stdin);
        len += n;
        if (n == 0) break;
        if (len == cap) {
            size_t ncap = cap << 1;
            unsigned char *nb = realloc(buf, ncap);
            if (!nb) { free(buf); return NULL; }
            buf = nb; cap = ncap;
        }
    }
    *out_len = len;
    return buf;
}

int main(void){
    size_t in_len=0;
    unsigned char *in = read_all_stdin(&in_len);
    if(!in) return 0;

    /* make nul-terminated string from input (may contain NULs but we'll treat as C-string) */
    char *s = malloc(in_len + 1);
    if(!s){ free(in); return 0; }
    memcpy(s, in, in_len);
    s[in_len] = '\0';

    /* 1) simple mprintf usage */
    char *a = sqlite3_mprintf("%s", s);
    if (a) sqlite3_free(a);

    /* 2) precision formatting (vmprintf path) */
    int prec = (in_len > 0) ? (int)(in[0] & 0xFF) : 10;
    if (prec <= 0) prec = 1;
    if (prec > 10000) prec = 10000;
    char *b = sqlite3_mprintf("%.*s", prec, s);
    if (b) sqlite3_free(b);

    /* 3) concatenation heavy path */
    for (int i=0;i<1000;i++){
        char *c = sqlite3_mprintf("%s%s%s%s%s", s, s, s, s, s);
        if (c) sqlite3_free(c);
    }

    /* 4) force vmprintf path with many format ops */
    for (int i=0;i<200;i++){
        char *d = sqlite3_mprintf("%s_%d_%.*s_suffix", s, i, prec, s);
        if (d) sqlite3_free(d);
    }

    free(s);
    free(in);
    return 0;
}
