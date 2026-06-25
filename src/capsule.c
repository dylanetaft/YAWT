#include "capsule.h"
#include "quic.h"
#include "security.h"
#include "logger.h"
#include <stdlib.h>
#include <string.h>

bool YAWT_capsule_should_buffer(uint64_t type) {
  switch (type) {
    case YAWT_WT_CAPSULE_CLOSE_SESSION:
    case YAWT_WT_CAPSULE_DRAIN_SESSION:
    case YAWT_WT_CAPSULE_MAX_DATA:
    case YAWT_WT_CAPSULE_MAX_STREAMS_BIDI:
    case YAWT_WT_CAPSULE_MAX_STREAMS_UNI:
    case YAWT_WT_CAPSULE_DATA_BLOCKED:
    case YAWT_WT_CAPSULE_STREAMS_BLOCKED_BIDI:
    case YAWT_WT_CAPSULE_STREAMS_BLOCKED_UNI:
      return true;
    case YAWT_WT_CAPSULE_DATAGRAM:
      return false;
    default:
      YAWT_LOG(YAWT_LOG_DEBUG, "capsule: unknown type 0x%lx, skipping without buffering", type);
      return false;
  }
}

void YAWT_capsule_parser_reset(YAWT_Capsule_Parser_t *p) {
  if (!p) return;
  if (p->payload_blob) {
    ANB_blob_destroy(p->payload_blob);
  }
  memset(p, 0, sizeof(*p));
}

size_t YAWT_capsule_header_size(uint64_t type, size_t value_len) {
  return YAWT_q_varint_size(type) + YAWT_q_varint_size(value_len);
}

size_t YAWT_capsule_encode(uint64_t type, const uint8_t *value, size_t value_len,
                            uint8_t *buf, size_t buf_len) {
  if (!buf) return 0;

  size_t hdr_size = YAWT_capsule_header_size(type, value_len);
  if (hdr_size + value_len > buf_len) {
    YAWT_LOG(YAWT_LOG_ERROR, "capsule: encode buffer too small (%zu < %zu)",
             buf_len, hdr_size + value_len);
    return 0;
  }

  size_t off = 0;
  uint64_t n;

  if (YAWT_q_varint_encode(type, buf + off, buf_len - off, &n) != YAWT_Q_OK) {
    return 0;
  }
  off += n;

  if (YAWT_q_varint_encode(value_len, buf + off, buf_len - off, &n) != YAWT_Q_OK) {
    return 0;
  }
  off += n;

  if (value_len > 0 && value) {
    memcpy(buf + off, value, value_len);
  }

  return hdr_size + value_len;
}

int YAWT_capsule_parse_feed(YAWT_Capsule_Parser_t *p,
                             const uint8_t *data, size_t len,
                             YAWT_Capsule_Callback_t cb, void *cb_ctx) {
  if (!p || !data || !cb) return -1;

  size_t cursor = 0;

  while (cursor < len) {
    // Header phase: accumulate bytes until Type + Length varints are decoded
    if (p->hdr_size == 0) {
      size_t remaining = len - cursor;
      size_t take = remaining;
      if (take > sizeof(p->hdr) - p->accumulated) {
        take = sizeof(p->hdr) - p->accumulated;
      }
      memcpy(p->hdr + p->accumulated, data + cursor, take);
      p->accumulated += take;

      YAWT_Q_ReadCursor_t rc = {0};
      rc.data = p->hdr;
      rc.len = p->accumulated;

      YAWT_q_varint_decode(&rc, &p->type);
      if (rc.err != YAWT_Q_OK) {
        if (p->accumulated == sizeof(p->hdr)) {
          YAWT_LOG(YAWT_LOG_ERROR, "capsule: header exceeds max size");
          return -1;
        }
        cursor += take;
        continue;
      }

      YAWT_q_varint_decode(&rc, &p->payload_len);
      if (rc.err != YAWT_Q_OK) {
        if (p->accumulated == sizeof(p->hdr)) {
          YAWT_LOG(YAWT_LOG_ERROR, "capsule: header exceeds max size");
          return -1;
        }
        cursor += take;
        continue;
      }

      p->hdr_size = (uint8_t)rc.cursor;
      cursor += (size_t)rc.cursor - p->accumulated;
      p->accumulated = 0;

      // Decide buffering strategy based on capsule type
      p->stream_payload = !YAWT_capsule_should_buffer(p->type);

      YAWT_LOG(YAWT_LOG_DEBUG, "capsule: decoded header type=0x%lx len=%lu stream=%d",
               p->type, p->payload_len, p->stream_payload);

      if (!p->stream_payload && p->payload_len > 0) {
        const YAWT_H3_SecurityPolicy_t *sec = YAWT_h3_security_get();
        if (sec->max_capsule_buffer_bytes &&
            p->payload_len > sec->max_capsule_buffer_bytes) {
          YAWT_LOG(YAWT_LOG_ERROR,
                   "capsule: payload %lu exceeds buffer cap %lu, type=0x%lx",
                   p->payload_len, sec->max_capsule_buffer_bytes, p->type);
          return -1;
        }
        p->payload_blob = ANB_blob_create(p->payload_len);
        if (!p->payload_blob) {
          YAWT_LOG(YAWT_LOG_ERROR, "capsule: OOM buffering %lu-byte payload", p->payload_len);
          return -1;
        }
      }
    }

    // Payload phase
    uint64_t need = p->payload_len - p->accumulated;
    size_t avail = len - cursor;
    size_t n = (need < avail) ? (size_t)need : avail;

    if (p->payload_blob) {
      // Buffered capsule: copy into malloc'd buffer
      ANB_blob_push(p->payload_blob, data + cursor, n);
      p->accumulated += n;
      cursor += n;
    } else if (p->stream_payload && p->payload_len > 0) {
      // Streamed capsule (DATAGRAM): deliver chunks directly to callback
      cb(cb_ctx, p->type, data + cursor, n);
      p->accumulated += n;
      cursor += n;
    } else {
      // Unknown type being skipped, or zero-length payload
      p->accumulated += n;
      cursor += n;
    }

    // Check if capsule is complete
    if (p->accumulated >= p->payload_len) {
      YAWT_LOG(YAWT_LOG_DEBUG, "capsule: complete type=0x%lx len=%lu",
               p->type, p->payload_len);

      // Deliver buffered capsule to callback
      if (p->payload_blob) {
        cb(cb_ctx, p->type, ANB_blob_data(p->payload_blob), ANB_blob_data_len(p->payload_blob));
      } else if (p->payload_len == 0 && !p->stream_payload) {
        // Zero-length buffered capsule (e.g., DRAIN_SESSION)
        cb(cb_ctx, p->type, NULL, 0);
      }
      // Streamed capsules already delivered during payload phase

      // Reset for next capsule
      if (p->payload_blob) {
        ANB_blob_destroy(p->payload_blob);
      }
      memset(p, 0, sizeof(*p));
    }
  }

  return 0;
}
