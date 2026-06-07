#pragma once
#include <stdint.h>

// ---------------------------------------------------------------------------
// QPACK static table (RFC 9204 Appendix A) — 99 entries, index 0..98.
// Both sides ship with the same table; the encoder emits indexes, the decoder
// looks them up. No allocation, no destruction — compile-time constants.
// ---------------------------------------------------------------------------

#define YAWT_QPACK_STATIC_TABLE_SIZE 99

typedef struct {
  const char *name;
  const char *value;
} YAWT_QPACK_StaticEntry_t;

// Returns the static-table entry at `index`, or NULL if out of range.
const YAWT_QPACK_StaticEntry_t *YAWT_qpack_static_get(uint64_t index);

// Encoder helper: find the first static-table index whose name matches.
// Returns -1 if not found.
int YAWT_qpack_static_find_name(const char *name);

// Encoder helper: find the first static-table index whose name AND value match.
// Returns -1 if not found.
int YAWT_qpack_static_find_entry(const char *name, const char *value);
