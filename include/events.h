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
typedef union YAWT_Q_EventParam {
  struct { } P_EVT_CONNECTED;

  struct {
    const YAWT_Q_Frame_Stream_t *frame;
  } P_EVT_STREAM;

  struct {
    const uint8_t *data;
    size_t len;
  } P_EVT_DATAGRAM;

  struct {
    uint64_t error_code;
    const char *reason;           // null-terminated, bounded
  } P_EVT_CLOSE;

  struct {
    const uint8_t *buf;
    size_t len;
    const YAWT_Q_PeerAddr_t *peer;
  } P_EVT_TX;
} YAWT_Q_EventParam_t;

// Process-wide event handler. Installed via YAWT_q_con_set_event_handler.
typedef void (*YAWT_Q_EventHandler_t)(YAWT_Q_Connection_t *con,
                                       YAWT_Q_EventType_t event,
                                       YAWT_Q_EventParam_t param);
