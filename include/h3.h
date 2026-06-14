#pragma once
#include <stdint.h>
#include <stddef.h>
#include "h3_types.h"
#include "quic.h"   // YAWT_q_varint_*, YAWT_Q_ReadCursor_t, YAWT_Q_EventType_t, YAWT_Q_EventParam_t

// ---------------------------------------------------------------------------
// HTTP/3 (RFC 9114) function API — minimal subset for WebTransport. Data types
// live in h3_types.h.
// ---------------------------------------------------------------------------

// Assembles a frame from located metadata.  Will deliver partial frames
// but we can pull the header fields (Type, Length) out of metadata
YAWT_H3_Error_t YAWT_h3_parse_frame(YAWT_Q_Frame_Stream_t *stream, 
YAWT_H3_Stream_t *meta,
YAWT_H3_Frame_t *out);

// Encode an H3 frame header (type varint + length varint) into buf.
// buf must be at least H3_FRAME_MAX_HEADER_BYTES. Returns bytes written on
// success, 0 on error (safe — minimum valid header is 2 bytes).
size_t YAWT_h3_encode_frame_header(uint64_t frame_type, size_t payload_len, uint8_t *buf);

// Returns the number of bytes needed for an H3 frame header (type + length
// varints) given the payload length that will follow.
size_t YAWT_h3_frame_header_size(size_t payload_len);

// H3 event handler — register via YAWT_q_con_set_event_handler, or forward to it
// from the app's own handler. Manages the H3 connection object (allocated on
// CONNECTED, freed on CLOSE) and consumes stream events. Ignores TX (the app's
// concern). Connection state is stored in the QUIC connection's user_data.
//
// Returns:
//   YAWT_H3_OK              — event was processed successfully
//   YAWT_H3_IGNORED         — event is not an H3 concern (e.g. DATAGRAM)
//   YAWT_H3_ERR_NO_APP_HANDLER — event processed but app handler not installed
YAWT_H3_Error_t YAWT_h3_on_event(YAWT_Q_Connection_t *con, YAWT_Q_EventType_t event,
                                   YAWT_Q_EventParam_t param);

// Decode a SETTINGS frame *body* (the payload delimited by the frame Length).
// Operates on a `YAWT_Q_ReadCursor_t` whose `data`/`len` cover exactly the
// SETTINGS payload. The cursor advances as (id, value) pairs are consumed.
// Enforces: SETTINGS must appear first on the control stream and only once per
// connection (RFC 9114 §7.2.4).
YAWT_H3_Error_t YAWT_h3_settings_decode(YAWT_Q_ReadCursor_t *rc,
                                          YAWT_H3_Settings_t *out);

// Encode a SETTINGS frame body (id/value varint pairs) into buf, skipping
// settings with value 0. Sets *written to the number of bytes written.
YAWT_H3_Error_t YAWT_h3_settings_encode(const YAWT_H3_Settings_t *settings,
                                          uint8_t *buf, size_t len,
                                          size_t *written);

// Install an app-level event handler on an H3 connection. The handler receives
// H3-level events (HEADERS decoded, DATA chunks, SETTINGS, errors). Passing NULL
// clears any previously installed handler.
void YAWT_h3_set_event_handler(YAWT_H3_Connection_t *con,
                                YAWT_H3_EventHandler_t handler);

// Get the underlying QUIC connection from an H3 connection.
YAWT_Q_Connection_t *YAWT_h3_get_qcon(const YAWT_H3_Connection_t *con);

// Open the server control stream (if not already opened) and send a SETTINGS
// frame encoding local_settings. Must be called after the QUIC connection is
// established (typically from the EVT_CONNECTED handler).
YAWT_H3_Error_t YAWT_h3_send_settings(YAWT_H3_Connection_t *h3);

// Encode headers as a QPACK header block, wrap in an H3 HEADERS frame, and
// send on the given bidi stream. If fin is set, the QUIC stream is closed
// after this frame (no DATA follows).
YAWT_H3_Error_t YAWT_h3_send_headers(YAWT_H3_Connection_t *h3,
                                       uint64_t stream_id,
                                       const YAWT_H3_HeaderFields_t *headers,
                                       int fin);

// Wrap data in an H3 DATA frame and send on the given bidi stream. If fin is
// set, the QUIC stream is closed after this frame.
YAWT_H3_Error_t YAWT_h3_send_data(YAWT_H3_Connection_t *h3,
                                    uint64_t stream_id,
                                    const uint8_t *data, size_t data_len,
                                    int fin);
