#pragma once
#include <stdint.h>
#include <stddef.h>

// Forward declarations — consumers only include full headers for what they use
typedef struct YAWT_Q_Connection YAWT_Q_Connection_t;
typedef struct YAWT_Q_PeerAddr YAWT_Q_PeerAddr_t;
typedef struct YAWT_Q_Frame_Stream YAWT_Q_Frame_Stream_t;

typedef struct {
  // TX: encrypted packet ready to send over UDP
  void (*on_tx)(const uint8_t *buf, size_t len,
                const YAWT_Q_PeerAddr_t *peer, void *ctx);

  // RX: reassembled stream data delivered to application
  void (*on_stream)(YAWT_Q_Connection_t *con,
                    const YAWT_Q_Frame_Stream_t *frame, void *ctx);

  // Handshake complete, connection ready for application data
  void (*on_connected)(YAWT_Q_Connection_t *con, void *ctx);

  // RX: unreliable datagram received (RFC 9221)
  void (*on_datagram)(YAWT_Q_Connection_t *con,
                      const uint8_t *data, size_t len, void *ctx);

  // Peer sent CONNECTION_CLOSE
  void (*on_close)(YAWT_Q_Connection_t *con, uint64_t error_code,
                   const char *reason, void *ctx);

  void *ctx;
} YAWT_Q_Callbacks_t;
