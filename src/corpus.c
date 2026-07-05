#include "corpus.h"

#ifdef YAWT_ENABLE_FUZZ_CORPUS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <stdarg.h>
#include <errno.h>

static char s_base_dir[4096];
static int  s_base_dir_init = 0;

static void ensure_dir(void) {
    if (s_base_dir_init) return;

    const char *env = getenv("YAWT_CORPUS_DIR");
    const char *base = env ? env : "./corpus";
    snprintf(s_base_dir, sizeof(s_base_dir), "%s", base);

    /* Create directory if it doesn't exist */
    struct stat st;
    if (stat(s_base_dir, &st) != 0) {
        if (mkdir(s_base_dir, 0755) != 0 && errno != EEXIST) {
            fprintf(stderr, "YAWT_CORPUS: mkdir(%s): %s\n", s_base_dir, strerror(errno));
            return;
        }
    }
    s_base_dir_init = 1;
}

void _yawt_corpus_impl(const char *func, int num_pairs, ...) {
    if (num_pairs <= 0 || num_pairs > 64) return;

    ensure_dir();

    /* Get monotonic clock timestamp in nanoseconds */
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;

    /* Build filename: <__func__>_<ns>.bin */
    char path[5120];
    snprintf(path, sizeof(path), "%s/%s_%lu.bin", s_base_dir, func, (unsigned long)ns);

    FILE *f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "YAWT_CORPUS: fopen(%s): %s\n", path, strerror(errno));
        return;
    }

    /* Write header: number of pairs */
    uint8_t np = (uint8_t)num_pairs;
    fwrite(&np, 1, 1, f);

    /* Write each (data, len) pair */
    va_list ap;
    va_start(ap, num_pairs);
    for (int i = 0; i < num_pairs; i++) {
        const void *data = va_arg(ap, const void *);
        size_t len = va_arg(ap, size_t);

        /* Write length as 4-byte LE */
        uint32_t len32 = (uint32_t)len;
        fwrite(&len32, 1, 4, f);

        /* Write data */
        if (len > 0 && data) {
            fwrite(data, 1, len, f);
        }
    }
    va_end(ap);
    fclose(f);
}

#endif /* YAWT_ENABLE_FUZZ_CORPUS */
