/**
 * @file err.h
 * @brief Unified error codes for QUIC, HTTP/3, and internal errors.
 */

/**
 * @defgroup Errors
 * @brief Error codes and utilities shared across all YAWT modules.
 */

#pragma once

/**
 * @ingroup Errors
 * @brief Unified error codes for QUIC and HTTP/3.
 * @note RFC-defined wire codes first (QUIC transport errors 0x00-0x10, H3 errors 0x0100-0x0110),
 *       then internal/application errors (0x10000+). YAWT_ERR_OK (0x00) serves as both success
 *       and the QUIC NO_ERROR wire code.
 */
typedef enum {
  // --- RFC 9000 §20.1 — QUIC transport error codes ---
  YAWT_Q_OK                              = 0x00,
  YAWT_Q_ERR_INTERNAL_ERROR              = 0x01,
  YAWT_Q_ERR_CONNECTION_REFUSED          = 0x02,
  YAWT_Q_ERR_FLOW_CONTROL_ERROR          = 0x03,
  YAWT_Q_ERR_STREAM_LIMIT_ERROR          = 0x04,
  YAWT_Q_ERR_STREAM_STATE_ERROR          = 0x05,
  YAWT_Q_ERR_FINAL_SIZE_ERROR            = 0x06,
  YAWT_Q_ERR_FRAME_ENCODING_ERROR        = 0x07,
  YAWT_Q_ERR_TRANSPORT_PARAMETER_ERROR   = 0x08,
  YAWT_Q_ERR_CONNECTION_ID_LIMIT_ERROR   = 0x09,
  YAWT_Q_ERR_PROTOCOL_VIOLATION          = 0x0a,
  YAWT_Q_ERR_INVALID_TOKEN               = 0x0b,
  YAWT_Q_ERR_APPLICATION_ERROR           = 0x0c,
  YAWT_Q_ERR_CRYPTO_BUFFER_EXCEEDED      = 0x0d,
  YAWT_Q_ERR_KEY_UPDATE_ERROR            = 0x0e,
  YAWT_Q_ERR_AEAD_LIMIT_REACHED          = 0x0f,
  YAWT_Q_ERR_NO_VIABLE_PATH              = 0x10,

  // --- RFC 9114 §8.1 — HTTP/3 error codes ---
  YAWT_ERR_H3_NO_ERROR                 = 0x0100,
  YAWT_ERR_H3_GENERAL_PROTOCOL         = 0x0101,
  YAWT_ERR_H3_INTERNAL_ERROR           = 0x0102,
  YAWT_ERR_H3_STREAM_CREATION_ERROR    = 0x0103,
  YAWT_ERR_H3_CLOSED_CRITICAL_STREAM   = 0x0104,
  YAWT_ERR_H3_FRAME_UNEXPECTED         = 0x0105,
  YAWT_ERR_H3_FRAME_ERROR              = 0x0106,
  YAWT_ERR_H3_EXCESSIVE_LOAD           = 0x0107,
  YAWT_ERR_H3_ID_ERROR                 = 0x0108,
  YAWT_ERR_H3_SETTINGS_ERROR           = 0x0109,
  YAWT_ERR_H3_MISSING_SETTINGS         = 0x010a,
  YAWT_ERR_H3_REQUEST_REJECTED         = 0x010b,
  YAWT_ERR_H3_REQUEST_CANCELLED        = 0x010c,
  YAWT_ERR_H3_REQUEST_INCOMPLETE       = 0x010d,
  YAWT_ERR_H3_MESSAGE_ERROR            = 0x010e,
  YAWT_ERR_H3_CONNECT_ERROR            = 0x010f,
  YAWT_ERR_H3_VERSION_FALLBACK         = 0x0110,

  // --- Internal / application errors (not wire values) ---
  YAWT_Q_ERR_SHORT_BUFFER                = 0x10000,
  YAWT_Q_ERR_INVALID_PACKET,
  YAWT_Q_ERR_VARINT_OVERFLOW,
  YAWT_Q_ERR_CID_TOO_LONG,
  YAWT_Q_ERR_INVALID_PARAM,
  YAWT_Q_ERR_ALLOC,
  YAWT_Q_ERR_FRAME_TOO_LARGE,
  YAWT_Q_ERR_TLS_ALERT,
  YAWT_Q_ERR_CERT_INVALID,
} YAWT_Err_t;

/**
 * @ingroup Errors
 * @brief Get a string representation of an error code.
 * @param err The error code.
 * @return A static string describing the error.
 */
static inline const char *YAWT_err_str(YAWT_Err_t err) {
  switch (err) {
    case YAWT_Q_OK:                              return "OK";
    case YAWT_Q_ERR_INTERNAL_ERROR:              return "INTERNAL_ERROR";
    case YAWT_Q_ERR_CONNECTION_REFUSED:          return "CONNECTION_REFUSED";
    case YAWT_Q_ERR_FLOW_CONTROL_ERROR:          return "FLOW_CONTROL_ERROR";
    case YAWT_Q_ERR_STREAM_LIMIT_ERROR:          return "STREAM_LIMIT_ERROR";
    case YAWT_Q_ERR_STREAM_STATE_ERROR:          return "STREAM_STATE_ERROR";
    case YAWT_Q_ERR_FINAL_SIZE_ERROR:            return "FINAL_SIZE_ERROR";
    case YAWT_Q_ERR_FRAME_ENCODING_ERROR:        return "FRAME_ENCODING_ERROR";
    case YAWT_Q_ERR_TRANSPORT_PARAMETER_ERROR:   return "TRANSPORT_PARAMETER_ERROR";
    case YAWT_Q_ERR_CONNECTION_ID_LIMIT_ERROR:   return "CONNECTION_ID_LIMIT_ERROR";
    case YAWT_Q_ERR_PROTOCOL_VIOLATION:          return "PROTOCOL_VIOLATION";
    case YAWT_Q_ERR_INVALID_TOKEN:               return "INVALID_TOKEN";
    case YAWT_Q_ERR_APPLICATION_ERROR:           return "APPLICATION_ERROR";
    case YAWT_Q_ERR_CRYPTO_BUFFER_EXCEEDED:      return "CRYPTO_BUFFER_EXCEEDED";
    case YAWT_Q_ERR_KEY_UPDATE_ERROR:            return "KEY_UPDATE_ERROR";
    case YAWT_Q_ERR_AEAD_LIMIT_REACHED:          return "AEAD_LIMIT_REACHED";
    case YAWT_Q_ERR_NO_VIABLE_PATH:              return "NO_VIABLE_PATH";
    case YAWT_ERR_H3_NO_ERROR:                 return "H3_NO_ERROR";
    case YAWT_ERR_H3_GENERAL_PROTOCOL:         return "H3_GENERAL_PROTOCOL";
    case YAWT_ERR_H3_INTERNAL_ERROR:           return "H3_INTERNAL_ERROR";
    case YAWT_ERR_H3_STREAM_CREATION_ERROR:    return "H3_STREAM_CREATION_ERROR";
    case YAWT_ERR_H3_CLOSED_CRITICAL_STREAM:   return "H3_CLOSED_CRITICAL_STREAM";
    case YAWT_ERR_H3_FRAME_UNEXPECTED:         return "H3_FRAME_UNEXPECTED";
    case YAWT_ERR_H3_FRAME_ERROR:              return "H3_FRAME_ERROR";
    case YAWT_ERR_H3_EXCESSIVE_LOAD:           return "H3_EXCESSIVE_LOAD";
    case YAWT_ERR_H3_ID_ERROR:                 return "H3_ID_ERROR";
    case YAWT_ERR_H3_SETTINGS_ERROR:           return "H3_SETTINGS_ERROR";
    case YAWT_ERR_H3_MISSING_SETTINGS:         return "H3_MISSING_SETTINGS";
    case YAWT_ERR_H3_REQUEST_REJECTED:         return "H3_REQUEST_REJECTED";
    case YAWT_ERR_H3_REQUEST_CANCELLED:        return "H3_REQUEST_CANCELLED";
    case YAWT_ERR_H3_REQUEST_INCOMPLETE:       return "H3_REQUEST_INCOMPLETE";
    case YAWT_ERR_H3_MESSAGE_ERROR:            return "H3_MESSAGE_ERROR";
    case YAWT_ERR_H3_CONNECT_ERROR:            return "H3_CONNECT_ERROR";
    case YAWT_ERR_H3_VERSION_FALLBACK:         return "H3_VERSION_FALLBACK";
    case YAWT_Q_ERR_SHORT_BUFFER:                return "SHORT_BUFFER";
    case YAWT_Q_ERR_INVALID_PACKET:              return "INVALID_PACKET";
    case YAWT_Q_ERR_VARINT_OVERFLOW:             return "VARINT_OVERFLOW";
    case YAWT_Q_ERR_CID_TOO_LONG:                return "CID_TOO_LONG";
    case YAWT_Q_ERR_INVALID_PARAM:               return "INVALID_PARAM";
    case YAWT_Q_ERR_ALLOC:                       return "ALLOC";
    case YAWT_Q_ERR_FRAME_TOO_LARGE:             return "FRAME_TOO_LARGE";
    case YAWT_Q_ERR_TLS_ALERT:                   return "TLS_ALERT";
    case YAWT_Q_ERR_CERT_INVALID:                return "CERT_INVALID";
    default:                                     return "UNKNOWN";
  }
}
