/**
 * @file logger.h
 * @brief Compile-time gated logging with level, file, line, and function context.
 */

/**
 * @defgroup Logging 
 * @brief Compile-time gated logging utilities.
 *
 * Enable logging by defining YAWT_ENABLE_LOGGING at compile time. Optionally set
 * YAWT_LOG_LEVEL to filter messages (defaults to YAWT_LOG_DEBUG when enabled).
 * When logging is disabled, YAWT_LOG() expands to a no-op.
 */

#pragma once

/**
 * @ingroup Logging
 * @brief Log levels for diagnostic messages.
 */
typedef enum {
  YAWT_LOG_DEBUG = 0, /**< Debug-level messages */
  YAWT_LOG_INFO,      /**< Informational messages */
  YAWT_LOG_WARN,      /**< Warning messages */
  YAWT_LOG_ERROR      /**< Error messages */
} YAWT_log_level_t;

#ifdef YAWT_ENABLE_LOGGING
#ifndef YAWT_LOG_LEVEL
#define YAWT_LOG_LEVEL YAWT_LOG_DEBUG
#endif
#endif

/**
 * @ingroup Logging
 * @brief Convert log level to string.
 * @param level Log level value
 * @return String representation of the log level
 */
static inline const char *YAWT_log_level_str(YAWT_log_level_t level) {
  switch (level) {
  case YAWT_LOG_DEBUG:
    return "DEBUG";
  case YAWT_LOG_INFO:
    return "INFO";
  case YAWT_LOG_WARN:
    return "WARN";
  case YAWT_LOG_ERROR:
    return "ERROR";
  default:
    return "UNKNOWN";
  }
}

/**
 * @ingroup Logging
 * @brief Log a message with level, file, line, and function context.
 * @param level Log level 
 * @param fmt Printf-style format string
 * @param ... Format arguments
 * @note When YAWT_ENABLE_LOGGING is not defined, this macro expands to a no-op.
 *       When enabled, messages below YAWT_LOG_LEVEL are filtered out.
 */
#ifdef YAWT_ENABLE_LOGGING
#define YAWT_LOG(level, fmt, ...)                                               \
  do {                                                                         \
    if ((level) >= YAWT_LOG_LEVEL) {                                            \
      fprintf(stdout, "[%s] %s:%d (%s): " fmt "\n", YAWT_log_level_str(level),  \
              __FILE__, __LINE__, __func__, ##__VA_ARGS__);                    \
    }                                                                          \
  } while (0)
#else
#define YAWT_LOG(level, fmt, ...)                                              \
  do {                                                                         \
  } while (0)
#endif
