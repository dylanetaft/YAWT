#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define H3_FRAME_MAX_HEADER_BYTES 16 // max varint size for Type + Length
#define H3_STREAM_TYPE_MAX_BYTES   8 // uni stream-type prefix is one varint (<=8 bytes)
// ---------------------------------------------------------------------------
// HTTP/3 data types (RFC 9114) — the YAWT_H3 analog of quic_types.h. Holds the
// enums and structs; the function API lives in h3.h. See docs/reference.md for
// the per-RFC mandatory/skip breakdown.
//
// Encapsulation: H3 has no packet concept. H3 frames live on the in-order byte
// stream of a QUIC stream (delivered by the QUIC layer via YAWT_Q_EVT_STREAM).
// A QUIC stream chunk may carry a partial H3 frame or several, so the frame
// parser has an INCOMPLETE outcome the QUIC frame parser never needed.
// ---------------------------------------------------------------------------

// HTTP/3 frame types (RFC 9114 §7.2). Named constants; YAWT_H3_Frame_t.type is
// kept as a raw uint64_t so unknown/reserved/greased types survive round-trip
// and are skipped generically rather than rejected.
typedef enum {
  YAWT_H3_FRAME_DATA         = 0x00,
  YAWT_H3_FRAME_HEADERS      = 0x01,
  YAWT_H3_FRAME_CANCEL_PUSH  = 0x03,
  YAWT_H3_FRAME_SETTINGS     = 0x04,
  YAWT_H3_FRAME_PUSH_PROMISE = 0x05,
  YAWT_H3_FRAME_GOAWAY       = 0x07,
  YAWT_H3_FRAME_MAX_PUSH_ID  = 0x0d,
} YAWT_H3_FrameType_t;

// Unidirectional wire format stream types (RFC 9114 §6.2, RFC 9204 §4.2, draft-15). The
// first varint on a client uni stream selects its role; we read it once into
// the per-stream slot. Bidi (request) streams have no such prefix.
typedef enum {
  YAWT_H3_STREAM_WIRE_CONTROL      = 0x00,
  YAWT_H3_STREAM_WIRE_PUSH         = 0x01,
  YAWT_H3_STREAM_WIRE_QPACK_ENCODER = 0x02,
  YAWT_H3_STREAM_WIRE_QPACK_DECODER = 0x03,
  YAWT_H3_STREAM_WIRE_WEBTRANSPORT  = 0x54,
} YAWT_H3_WireStreamType_t;


typedef enum {
  YAWT_H3_STREAM_UNASSIGNED = 0, //not yet assigned
  YAWT_H3_STREAM_FRAME,      // bidirectional stream carrying HTTP/3 frames (requests, responses, and DATA) 
  YAWT_H3_STREAM_PUSH,       // push stream (RFC 9114 §6.2.2)
  YAWT_H3_STREAM_CONTROL,    // control stream (RFC 9114 §6.2.1)
  YAWT_H3_STREAM_QPACK,
  YAWT_H3_STREAM_WEBTRANSPORT
} YAWT_H3_StreamType_t;

// SETTINGS identifiers (RFC 9114 §7.2.4.1, RFC 9204, RFC 9220, RFC 9297,
// draft-ietf-webtrans-http3-15). Values are the on-the-wire identifiers.
typedef enum {
  YAWT_H3_SETTING_QPACK_MAX_TABLE_CAPACITY = 0x01,
  YAWT_H3_SETTING_MAX_FIELD_SECTION_SIZE   = 0x06,
  YAWT_H3_SETTING_QPACK_BLOCKED_STREAMS    = 0x07,
  YAWT_H3_SETTING_ENABLE_CONNECT_PROTOCOL  = 0x08,
  YAWT_H3_SETTING_H3_DATAGRAM              = 0x33,
  YAWT_H3_SETTING_WT_ENABLED               = 0x2c7cf000,
} YAWT_H3_SettingId_t;

// Internal return status for H3 functions. Distinct from HTTP/3 *wire* error
// codes (RFC 9114 §8.1, e.g. H3_SETTINGS_ERROR) — those are added separately
// when GOAWAY / CONNECTION_CLOSE emission is built.
typedef enum {
  YAWT_H3_OK = 0,
  YAWT_H3_ERR_SHORT_BUFFER,   // output buffer too small to encode
  YAWT_H3_ERR_INCOMPLETE,     // not enough stream bytes yet — retry with more
  YAWT_H3_ERR_MALFORMED,      // structurally invalid (e.g. odd SETTINGS pairs)
  YAWT_H3_ERR_TOO_LARGE,      // frame exceeds the H3 buffer cap (security policy)
  YAWT_H3_ERR_INVALID_PARAM,
} YAWT_H3_Error_t;

static inline const char *YAWT_h3_err_str(YAWT_H3_Error_t err) {
  switch (err) {
    case YAWT_H3_OK:                return "OK";
    case YAWT_H3_ERR_SHORT_BUFFER:  return "SHORT_BUFFER";
    case YAWT_H3_ERR_INCOMPLETE:    return "INCOMPLETE";
    case YAWT_H3_ERR_MALFORMED:     return "MALFORMED";
    case YAWT_H3_ERR_TOO_LARGE:     return "TOO_LARGE";
    case YAWT_H3_ERR_INVALID_PARAM: return "INVALID_PARAM";
    default:                        return "UNKNOWN";
  }
}

// The one H3 frame currently in flight on a stream. Holds both the decoded
// result (type, payload_len, payload) and the byte-level decode scratch
// (hdr/hdr_size/accumulated) — only one frame parses at a time per stream, so a
// single embedded instance serves. READ-ONLY / NOT retained when handed to the
// app: `payload` points into transient stream bytes, and the whole struct is
// reset and reused for the next frame, so anything kept beyond the delivering
// call must be copied.
typedef struct {
  uint64_t type;          // decoded frame type (raw varint; unknown types survive)
  uint64_t payload_len;   // decoded Length
  uint8_t *payload; // Either malloced or pointing into the current stream chunk; caller must not mutate or retain

  uint8_t  hdr[H3_FRAME_MAX_HEADER_BYTES]; // header (type+len) decode scratch; dead once decoded
  uint8_t  hdr_size;      // bytes of header consumed; 0 == header not yet read
  uint64_t accumulated;   // raw stream bytes accumulated for the current frame (INCOMPLETE)
} YAWT_H3_Frame_t;


// Per-stream H3 parse state. Lives in a preallocated slot pool on the H3
// connection (slot index is NOT the stream id — ids are sparse and grow
// unbounded, so we store stream_id and linear-scan, like QUIC's stream_meta).
// A slot is claimed (in_use=true) when assigned to a stream id. A stream
// outlives any single frame and carries many of them, so the current frame is
// a union member, reset when advancing to the next frame.
typedef struct {
  bool     in_use;
  uint64_t id;
  YAWT_H3_StreamType_t type;  // ie frame, qpack, etc; UNASSIGNED until resolved
  // Uni streams begin with a stream-type varint (RFC 9114 §6.2). It may be split
  // across QUIC chunks, so accumulate it here until decoded. Bidi (request)
  // streams have no prefix and resolve straight to STREAM_FRAME; type ==
  // UNASSIGNED is the "prefix not yet read" signal. Unused once type is set.
  uint8_t  hdr[H3_STREAM_TYPE_MAX_BYTES];
  uint64_t accumulated;
  // Control and request streams both carry H3 frames, so both use `frame`.
  // (QPACK / WebTransport stream state will be added alongside as their own
  // members when those stream types are wired up.)
  YAWT_H3_Frame_t frame;
} YAWT_H3_Stream_t;

// Negotiated HTTP/3 settings. One instance holds the values we advertise;
// another holds what the peer sent.
typedef struct {
  uint64_t qpack_max_table_capacity;   // we send 0 (static-table-only QPACK)
  uint64_t qpack_blocked_streams;      // we send 0
  uint64_t max_field_section_size;     // inbound header cap; 0 = unset (omitted)
  uint8_t  enable_connect_protocol;    // 0/1 — extended CONNECT (RFC 9220)
  uint8_t  h3_datagram;                // 0/1 — HTTP datagrams (RFC 9297)
  uint8_t  wt_enabled;                 // 0/1 — WebTransport (draft-15)
} YAWT_H3_Settings_t;


// ---------------------------------------------------------------------------
// H3 connection object — hung off the QUIC connection's user_data. Allocated on
// EVT_CONNECTED, freed on EVT_CLOSE (which con_free guarantees fires once).
// ---------------------------------------------------------------------------
typedef struct {
  YAWT_H3_Settings_t local_settings;
  YAWT_H3_Settings_t peer_settings;
  bool peer_settings_seen;
  uint64_t nstreams;                  // slot pool size (concurrent stream cap)
  YAWT_H3_Stream_t *streams;   // preallocated slot pool, linear-scan by id
} YAWT_H3_Connection_t;

