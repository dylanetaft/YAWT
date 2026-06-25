#include "security.h"

static YAWT_Q_SecurityPolicy_t _policy = {
  .min_idle_timeout_ms = 5000,
  .max_crypto_buffer_bytes = 65536,
  .max_stream_rx_buffer_bytes = 4 * 1024 * 1024,
  .fc_threshold_percent = 75,
  .fc_auto_increase_factor = 2,
};

static YAWT_Q_FlowControl_t _default_local_fc = {
  .max_idle_timeout = 30000,
  .max_data = 1048576,
  .max_stream_data_bidi_local = 1048576,
  .max_stream_data_bidi_remote = 1048576,
  .max_stream_data_uni = 1048576,
  .max_streams_bidi = 16,
  .max_streams_uni = 16,
  .max_datagram_frame_size = 1200,
};

static YAWT_H3_SecurityPolicy_t _h3_policy = {
  .max_frame_buffer_bytes = 32768,
  .max_header_name_len = 1024 * 1024,
  .max_header_value_len = 4 * 1024 * 1024,
  .max_capsule_buffer_bytes = 2048,
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
const YAWT_H3_SecurityPolicy_t *YAWT_h3_security_get(void) {
  return &_h3_policy;
}

void YAWT_h3_security_set(const YAWT_H3_SecurityPolicy_t *policy) {
  if (!policy) return;
  _h3_policy = *policy;
}

// WT disabled by default — enabling these may break connections to standard HTTP/3 servers
// that don't recognize WebTransport transport parameters or SETTINGS.
static YAWT_WT_SecurityPolicy_t _wt_policy = {
  .max_sessions = 0,
  .initial_max_streams_uni = 0,
  .initial_max_streams_bidi = 0,
  .initial_max_data = 0,
};

const YAWT_WT_SecurityPolicy_t *YAWT_wt_security_get(void) {
  return &_wt_policy;
}

void YAWT_wt_security_set(const YAWT_WT_SecurityPolicy_t *policy) {
  if (!policy) return;
  _wt_policy = *policy;
}
