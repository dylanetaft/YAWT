#pragma once
#include <stdint.h>

// Flow control limits — populated from transport params, updated by MAX_* frames
typedef struct {
  uint64_t max_idle_timeout;            // 0x01: milliseconds, 0 = disabled
  uint64_t max_data;                    // 0x04: connection-level byte limit
  uint64_t max_stream_data_bidi_local;  // 0x05: per-stream, sender-initiated bidi
  uint64_t max_stream_data_bidi_remote; // 0x06: per-stream, receiver-initiated bidi
  uint64_t max_stream_data_uni;         // 0x07: per-stream, unidirectional
  uint64_t max_streams_bidi;            // 0x08
  uint64_t max_streams_uni;             // 0x09
  uint64_t max_datagram_frame_size;     // 0x20: RFC 9221, 0 = datagrams not supported
} YAWT_Q_FlowControl_t;

typedef struct {
  uint64_t min_idle_timeout_ms;    // floor for effective idle timeout (ms), 0 = no floor
  uint64_t max_crypto_buffer_bytes; // max out-of-order CRYPTO buffering per connection, 0 = unlimited
} YAWT_Q_SecurityPolicy_t;

// Policy accessors. The getters return a const pointer to a STATIC GLOBAL — do
// not free it; it stays valid for the process lifetime. The pointed-to values
// are a snapshot: re-get after a set() to observe changes. set() copies *policy
// into the global, replacing it.
const YAWT_Q_SecurityPolicy_t *YAWT_q_security_get(void);
void YAWT_q_security_set(const YAWT_Q_SecurityPolicy_t *policy);

// Default flow-control limits (static global; same lifetime contract as above).
const YAWT_Q_FlowControl_t *YAWT_q_security_get_default_fc(void);

// HTTP/3 layer policy. Separate struct from the QUIC policy — the security
// module is centralized but each layer keeps its own layer-named config.
typedef struct {
  uint64_t max_frame_buffer_bytes; // max bytes the H3 layer accumulates for one
                                   // must-buffer frame (SETTINGS/HEADERS); a frame
                                   // whose Length exceeds this is rejected, not buffered
} YAWT_H3_SecurityPolicy_t;

// Same static-global lifetime contract as the QUIC accessors above.
const YAWT_H3_SecurityPolicy_t *YAWT_h3_security_get(void);
void YAWT_h3_security_set(const YAWT_H3_SecurityPolicy_t *policy);
