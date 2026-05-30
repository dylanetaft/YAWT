#pragma once
#include <stdint.h>
#include <stddef.h>
#include "h3_types.h"
#include "events.h"   // YAWT_Q_Connection_t (fwd), YAWT_Q_EventType_t, YAWT_Q_EventParam_t

// ---------------------------------------------------------------------------
// HTTP/3 (RFC 9114) function API — minimal subset for WebTransport. Data types
// live in h3_types.h. Symbols use the YAWT_H3 prefix to distinguish this layer
// from the QUIC core (YAWT_Q).
// ---------------------------------------------------------------------------

// Parse one H3 frame (Type, Length, Payload) from rc. Returns:
//   YAWT_H3_OK             — complete frame; *out filled, cursor advanced past it.
//   YAWT_H3_ERR_INCOMPLETE — the type/length varints or full payload are not all
//                            present yet; cursor is left UNCHANGED so the caller
//                            can retry after more stream bytes arrive. Not an
//                            error unless the stream FINed with bytes pending.
// On INCOMPLETE rc->err stays OK (it is a flow condition, not corruption).
YAWT_H3_Error_t YAWT_h3_parse_frame(YAWT_H3_ReadCursor_t *rc, YAWT_H3_Frame_t *out);

// Encode an H3 frame wrapper (Type varint, Length varint, then payload bytes)
// into buf. `payload` may be NULL when payload_len is 0. Total bytes written
// via *written.
YAWT_H3_Error_t YAWT_h3_encode_frame(uint64_t type,
                                      const uint8_t *payload, size_t payload_len,
                                      uint8_t *buf, size_t len, size_t *written);

// H3 event handler — register via YAWT_q_con_set_event_handler, or forward to it
// from the app's own handler. Manages the H3 connection object (allocated on
// CONNECTED, freed on CLOSE) and consumes stream events. Ignores TX (the app's
// concern). Connection state is stored in the QUIC connection's user_data.
void YAWT_h3_on_event(YAWT_Q_Connection_t *con, YAWT_Q_EventType_t event,
                       YAWT_Q_EventParam_t param);

// TODO: settings codec — operates on a SETTINGS frame *body* (the payload that
// YAWT_h3_parse_frame delimits via Length). Implemented but parked until the
// control-stream slice wires it to YAWT_h3_parse_frame / YAWT_h3_encode_frame.
// See src/h3.c for the preserved implementation.
//
// YAWT_H3_Error_t YAWT_h3_settings_encode(const YAWT_H3_Settings_t *s,
//                                          uint8_t *buf, size_t len,
//                                          size_t *written);
// YAWT_H3_Error_t YAWT_h3_settings_decode(YAWT_H3_ReadCursor_t *rc,
//                                          YAWT_H3_Settings_t *out);
