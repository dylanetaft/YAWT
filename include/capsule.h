/**
 * @file capsule.h
 * @brief Generic RFC 9297 capsule protocol parser and encoder.
 *
 * @note Capsules are Type-Length-Value structures used by WebTransport and
 *       HTTP datagrams. This parser is reusable and not WT-specific.
 *
 * @note Buffering strategy:
 *       - Header phase: accumulate up to 16 bytes for Type + Length varints
 *       - Payload phase: buffer entire payload for control capsules that need
 *         atomic processing (CLOSE_SESSION, MAX_DATA, MAX_STREAMS_*, etc.)
 *       - Exception: DATAGRAM capsules (type 0x00) stream payload directly
 *         to callback without buffering, since datagram payloads can be large
 *         and the app can process them incrementally.
 *       - Unknown capsule types are logged and skipped (RFC 9297 §3.2).
 *
 * @note Minimum to start parsing: Once header is decoded (Type + Length),
 *       the parser knows the capsule type and can decide whether to buffer
 *       or stream the payload.
 */

#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "wt_types.h"
#include "allocnbuffer/blob.h"
/**
 * @ingroup Capsule
 * @brief Incremental capsule parser state.
 *
 * @note Handles partial chunks across calls. Modeled after H3 frame parser.
 *       One parser per stream direction — reset between capsules.
 */
typedef struct {
  uint8_t  hdr[16];           /**< Type+len decode scratch */
  uint8_t  hdr_size;          /**< Bytes consumed in header phase; 0 = not yet read */
  uint64_t accumulated;       /**< Bytes accumulated for current phase */
  uint64_t type;              /**< Decoded capsule type */
  uint64_t payload_len;       /**< Decoded capsule length */
  ANB_Blob_t *payload_blob;   /**< Buffered payload (NULL if streaming) */
  bool     stream_payload;    /**< True if payload should stream to callback without buffering */
} YAWT_Capsule_Parser_t;

/**
 * @ingroup Capsule
 * @brief Callback for completed capsules.
 *
 * @param ctx User context passed to YAWT_capsule_parse_feed()
 * @param type Capsule type (decoded varint)
 * @param value Pointer to capsule value data
 * @param len Length of value data
 *
 * @note For buffered capsules, value points into parser's malloc'd buffer —
 *       valid only for the duration of the callback.
 * @note For streamed capsules (DATAGRAM), value points into the input buffer
 *       passed to YAWT_capsule_parse_feed() — also valid only during callback.
 */
typedef void (*YAWT_Capsule_Callback_t)(void *ctx, uint64_t type,
                                         const uint8_t *value, size_t len);

/**
 * @ingroup Capsule
 * @brief Feed bytes into the parser.
 *
 * @param p Parser state
 * @param data Input bytes
 * @param len Number of input bytes
 * @param cb Callback invoked for each complete capsule
 * @param cb_ctx User context passed to callback
 * @return 0 on success, -1 on error (malformed capsule)
 *
 * @note Calls cb for each complete capsule. Handles partial capsules across
 *       multiple calls. For DATAGRAM capsules (type 0x00), cb may be called
 *       multiple times with partial payloads as data arrives.
 */
int YAWT_capsule_parse_feed(YAWT_Capsule_Parser_t *p,
                             const uint8_t *data, size_t len,
                             YAWT_Capsule_Callback_t cb, void *cb_ctx);

/**
 * @ingroup Capsule
 * @brief Reset parser state for reuse.
 *
 * @param p Parser state
 *
 * @note Frees any buffered payload and resets to initial state.
 *       Call between capsules if reusing the parser struct.
 */
void YAWT_capsule_parser_reset(YAWT_Capsule_Parser_t *p);

/**
 * @ingroup Capsule
 * @brief Encode a capsule into buf.
 *
 * @param type Capsule type
 * @param value Capsule value data
 * @param value_len Length of value data
 * @param buf Output buffer
 * @param buf_len Size of output buffer
 * @return Bytes written, 0 on error (buffer too small)
 *
 * @note buf must be large enough: varint_size(type) + varint_size(len) + value_len.
 *       Use YAWT_capsule_header_size() to compute the required size.
 */
size_t YAWT_capsule_encode(uint64_t type, const uint8_t *value, size_t value_len,
                            uint8_t *buf, size_t buf_len);

/**
 * @ingroup Capsule
 * @brief Get the number of bytes needed for a capsule header.
 *
 * @param type Capsule type
 * @param value_len Length of value data
 * @return Total header size (type varint + length varint)
 *
 * @note Use this to size the output buffer before calling YAWT_capsule_encode().
 */
size_t YAWT_capsule_header_size(uint64_t type, size_t value_len);

/**
 * @ingroup Capsule
 * @brief Check if a capsule type should be buffered.
 *
 * @param type Capsule type
 * @return true if the capsule payload should be buffered, false if streamed
 *
 * @note Buffered: CLOSE_SESSION, DRAIN_SESSION, MAX_DATA, MAX_STREAMS_BIDI,
 *       MAX_STREAMS_UNI, DATA_BLOCKED, STREAMS_BLOCKED_BIDI, STREAMS_BLOCKED_UNI.
 *       Streamed: DATAGRAM (0x00). Unknown types return false (logged, skipped).
 */
bool YAWT_capsule_should_buffer(uint64_t type);
