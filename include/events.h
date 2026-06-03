#pragma once
#include <stdint.h>
#include <stddef.h>

// Forward declarations — consumers only include full headers for what they use
typedef struct YAWT_Q_Connection YAWT_Q_Connection_t;
typedef struct YAWT_Q_PeerAddr YAWT_Q_PeerAddr_t;
typedef struct YAWT_Q_Frame_Stream YAWT_Q_Frame_Stream_t;

// Event taxonomy. New events extend this enum AND add a matching
// `P_<eventtype>` substruct to YAWT_Q_EventParam_t below. The 1:1 mapping
// between enum suffix and union member name is part of the contract.
typedef enum {
  YAWT_Q_EVT_CONNECTED,   // handshake confirmed; no extra payload
  YAWT_Q_EVT_STREAM,      // reassembled, in-order stream bytes available
  YAWT_Q_EVT_DATAGRAM,    // unreliable datagram received (RFC 9221)
  YAWT_Q_EVT_CLOSE,       // connection ended (peer CC, idle, closing expired)
  YAWT_Q_EVT_TX,          // encrypted UDP packet ready to send
} YAWT_Q_EventType_t;

// Per-event parameters. Pure union: handler switches on event and reads the
// matching `P_EVT_<NAME>` member.
//
// Transience (applies to EVERY pointer in this union): all pointers are valid
// ONLY for the duration of the handler call. They reference internal/transient
// storage (the input datagram buffer, a slab item, or an encode scratch buffer)
// that the QUIC layer reuses immediately after the handler returns. Copy
// anything you need to retain. This is the single most important contract here.
typedef union YAWT_Q_EventParam {
  // Handshake confirmed. Fires exactly once, before any STREAM/DATAGRAM for the
  // connection. The natural place to allocate per-connection app state and
  // attach it via YAWT_q_con_set_user_data().
  struct { } P_EVT_CONNECTED;

  // A run of reassembled stream bytes.
  //   Transience: `frame` AND `frame->data` are call-scoped (see above) — copy
  //     what you keep. `frame->data` is the payload; `frame->data_len` its
  //     length; FIN is `frame->fin`.
  //   Ordering:   delivered gap-free and offset-ascending per stream (the QUIC
  //     layer buffers out-of-order frames and only emits the next contiguous
  //     run). `frame->offset == 0` marks the first bytes of a stream.
  struct {
    const YAWT_Q_Frame_Stream_t *frame;
  } P_EVT_STREAM;

  // One received DATAGRAM (RFC 9221). Unreliable, unordered, no reassembly.
  //   Transience: `data`/`len` are call-scoped (see above).
  struct {
    const uint8_t *data;
    size_t len;
  } P_EVT_DATAGRAM;

  // Connection ended.
  //   Lifetime: fires EXACTLY ONCE per connection, from YAWT_q_con_free(),
  //     regardless of how it died (peer CONNECTION_CLOSE, idle timeout, local
  //     close expiring). Emitted BEFORE teardown, so user_data is still valid:
  //     free per-connection app state in this handler.
  //   Transience: `reason` is call-scoped, null-terminated, bounded.
  struct {
    uint64_t error_code;
    const char *reason;           // null-terminated, bounded
  } P_EVT_CLOSE;

  // An encrypted packet ready for the wire.
  //   Transience: `buf`/`len`/`peer` are call-scoped — send synchronously to
  //     `peer` from within the handler; do not queue the pointer.
  struct {
    const uint8_t *buf;
    size_t len;
    const YAWT_Q_PeerAddr_t *peer;
  } P_EVT_TX;
} YAWT_Q_EventParam_t;

// Process-wide event handler.
//   Lifetime:  a single global, installed via YAWT_q_con_set_event_handler()
//     (NULL restores a built-in no-op; install replaces any previous handler).
//   Threading: the QUIC layer is single-threaded (one libev loop). The handler
//     is invoked synchronously from YAWT_q_con_rx() (CONNECTED/STREAM/DATAGRAM)
//     and YAWT_q_con_maintain() (TX/CLOSE). Nothing here is thread-safe.
typedef void (*YAWT_Q_EventHandler_t)(YAWT_Q_Connection_t *con,
                                       YAWT_Q_EventType_t event,
                                       YAWT_Q_EventParam_t param);
