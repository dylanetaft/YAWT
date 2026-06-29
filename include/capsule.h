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
 *         without buffering, since datagram payloads can be large.
 *       - Unknown capsule types are logged and skipped (RFC 9297 §3.2).
 *
 * @note Synchronous API: parse_feed() returns status codes. When a capsule
 *       is complete, call get_current() to retrieve the data. The parser
 *       auto-resets when reaching the end of a capsule length.
 */

#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "wt_types.h"
#include "allocnbuffer/blob.h"

/**
 * @ingroup Capsule
 * @brief Return codes for capsule parser.
 */
#define YAWT_CAPSULE_OK          0
#define YAWT_CAPSULE_INCOMPLETE  1
#define YAWT_CAPSULE_ERROR      -1

/**
 * @ingroup Capsule
 * @brief Incremental capsule parser state.
 *
 * @note Handles partial chunks across calls. Modeled after H3 frame parser.
 *       One parser per stream direction. Auto-resets between capsules.
 */
typedef struct {
  uint8_t  hdr[16];
  uint8_t  hdr_size;
  uint64_t accumulated;
  uint64_t type;
  uint64_t payload_len;
  ANB_Blob_t *payload_blob;
  bool     stream_payload;
  bool     capsule_complete;
  const uint8_t *current_value;
  size_t   current_len;
  const uint8_t *stream_ref;
} YAWT_Capsule_Parser_t;

/**
 * @ingroup Capsule
 * @brief Feed bytes into the parser.
 *
 * @param p Parser state
 * @param data Input bytes
 * @param len Number of input bytes
 * @return YAWT_CAPSULE_OK when capsule complete (retrieve via get_current),
 *         YAWT_CAPSULE_INCOMPLETE if more data needed, YAWT_CAPSULE_ERROR on malformed input
 *
 * @note Parser auto-resets when reaching end of capsule length.
 *       For DATAGRAM capsules (type 0x00), get_current() returns pointer into input buffer.
 */
int YAWT_capsule_parse_feed(YAWT_Capsule_Parser_t *p, const uint8_t *data, size_t len);

/**
 * @ingroup Capsule
 * @brief Retrieve the completed capsule data.
 *
 * @param p Parser state
 * @param type Output: capsule type
 * @param value Output: pointer to capsule value data
 * @param value_len Output: length of value data
 * @return YAWT_CAPSULE_OK on success, YAWT_CAPSULE_ERROR if no complete capsule
 *
 * @note For buffered capsules, value points into parser's buffer — valid until next feed() call.
 *       For streamed capsules (DATAGRAM), value points into the input buffer from last feed() call.
 */
int YAWT_capsule_get_current(YAWT_Capsule_Parser_t *p, uint64_t *type,
                              const uint8_t **value, size_t *value_len);

/**
 * @ingroup Capsule
 * @brief Reset parser state for reuse.
 *
 * @param p Parser state
 *
 * @note Frees any buffered payload and resets to initial state.
 *       Normally not needed — parser auto-resets between capsules.
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
