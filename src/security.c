#include "security.h"
#include "quic_types.h"

static YAWT_Q_SecurityPolicy_t _policy = {
  .min_idle_timeout_ms = 5000,
  .max_crypto_buffer_bytes = 65536,
};

static YAWT_Q_FlowControl_t _default_local_fc = {
  .max_idle_timeout = 30000,
  .max_data = 1048576,
  .max_stream_data_bidi_local = 1048576,
  .max_stream_data_bidi_remote = 1048576,
  .max_stream_data_uni = 1048576,
  .max_streams_bidi = 16,
  .max_streams_uni = 16,
  .max_datagram_frame_size = YAWT_Q_MAX_PKT_SIZE,
};

const YAWT_Q_SecurityPolicy_t *YAWT_q_security_get(void) {
  return &_policy;
}

void YAWT_q_security_set(const YAWT_Q_SecurityPolicy_t *policy) {
  if (!policy) return;
  _policy = *policy;
}

const YAWT_Q_FlowControl_t *YAWT_q_security_get_default_fc(void) {
  return &_default_local_fc;
}
