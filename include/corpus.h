/**
 * @file corpus.h
 * @brief Fuzz corpus collection — write raw binary blobs to files for libFuzzer.
 *
 * When YAWT_ENABLE_FUZZ_CORPUS is defined, instrumented parse functions emit
 * the raw bytes they receive to $YAWT_CORPUS_DIR/<__func__>_<clock_ns>.bin.
 * Each file is a single invocation's input, directly usable as libFuzzer seed corpus.
 *
 * When the flag is undefined (the default), every call is a no-op with zero overhead.
 */

#pragma once
#include <stdint.h>
#include <stddef.h>

#ifdef YAWT_ENABLE_FUZZ_CORPUS

/**
 * @brief Emit raw binary data to a corpus file.
 *
 * File format:
 *   [num_pairs: 1 byte]
 *   [len_0: 4 bytes LE][data_0: len_0 bytes]
 *   [len_1: 4 bytes LE][data_1: len_1 bytes]
 *   ...
 *
 * @param func       Function name (captured by macro as __func__)
 * @param num_pairs  Number of (pointer, length) pairs following
 * @param ...        Pairs of (const void *data, size_t len)
 */
void _yawt_corpus_impl(const char *func, int num_pairs, ...);

/**
 * @brief Emit raw binary data to a corpus file.
 * @param num_pairs Number of (pointer, length) pairs following
 * @param ...       Pairs of (const void *data, size_t len)
 *
 * Filename: <__func__>_<CLOCK_MONOTONIC_ns>.bin
 */
#define YAWT_corpus_emit(num_pairs, ...) \
    _yawt_corpus_impl(__func__, (num_pairs), ##__VA_ARGS__)

#else /* !YAWT_ENABLE_FUZZ_CORPUS */

/* Zero-cost no-op when corpus collection is disabled */
#define YAWT_corpus_emit(num_pairs, ...) ((void)0)

#endif /* YAWT_ENABLE_FUZZ_CORPUS */
