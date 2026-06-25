# WebTransport Implementation Plan

## Architecture

### Layering & Event Flow

YAWT uses a strict layered architecture where **the app is the bridge between layers**. No layer knows about the layer above it.

```
UDP datagram
  -> YAWT_q_con_rx()                    [quic_connection.c]
    -> parse packets, decrypt, parse frames
    -> _event_handler(con, QUIC_EVENT, param)   [global callback]
      -> App's on_event() handler        [e.g., wt_server.c:114]
        -> YAWT_Q_EVT_TX: udp_send()
        -> default: YAWT_h3_on_event()   [h3.c:496]
          -> Creates H3 connection on CONNECTED
          -> Dispatches stream data to H3 frame parser
          -> _h3_emit_event() -> h3_app_handler()  [wt_server.c:50]
            -> YAWT_H3_EVT_SETTINGS
            -> YAWT_H3_EVT_HEADERS (CONNECT detection happens here)
            -> YAWT_H3_EVT_DATA
            -> YAWT_H3_EVT_CLOSE
```

The app manually forwards QUIC events to H3 via `YAWT_h3_on_event()`. H3 does NOT know about WT. The app will manually forward WT-related H3 events to the WT layer.

### Key Design Decisions

1. **Multiple sessions per H3 connection** — `YAWT_WT_Context_t` manages a pool of `YAWT_WT_Session_t`
2. **App-bridge pattern** — H3 emits raw WT data; app routes to WT layer. Mirrors existing QUIC->H3 pattern.
3. **Generic RFC 9297 capsule parser** — reusable, not WT-specific
4. **Defer 0x41 bidi stream handling** — start with uni streams (0x54) + capsules + datagrams

### Where WT Hooks In: H3 Layer, Not QUIC Layer

- 0x54 uni streams are already recognized by H3's `_gather_h3_stream_type()` (`h3.c:184`)
- Capsules flow on DATA frames of the CONNECT stream (an H3 concept, RFC 9297 section 3.2)
- Datagrams use Quarter Stream ID which maps to H3 CONNECT streams
- WT needs H3 settings context (SETTINGS_WT_ENABLED, etc.)

---

## What Already Exists

### Fully implemented:
- WT SETTINGS negotiation (encode/decode in H3 settings) — `h3_types.h:108-120`, `h3.c:40-85`
- WT security policy with defaults — `security.h:107-119`, `security.c:49-54`
- WT uni stream type recognition (0x54) — `h3.c:184-186` (but data is **discarded** at `h3.c:487`)
- `YAWT_UD_WT` user_data slot reserved — `quic_types.h:599`
- Extended CONNECT detection in wt_server.c example — `wt_server.c:62-83`
- Transport parameter for `reset_stream_at` — `crypt.c:378-384`
- `enable_connect_protocol` and `h3_datagram` auto-enabled when WT is on — `h3.c:513-517`

### What's missing (this plan):
- `YAWT_WT_Session_t` / `YAWT_WT_Context_t` struct definitions
- Capsule protocol implementation (RFC 9297)
- Capsule type enums and encode/decode
- WT stream header parsing (session ID extraction from 0x54 uni streams)
- WT session management (create, lookup, destroy)
- WT datagram demultiplexing (Quarter Stream ID parsing)
- WT flow control (WT_MAX_STREAMS, WT_MAX_DATA capsules) — deferred to Phase 5
- WT session termination (WT_CLOSE_SESSION, WT_DRAIN_SESSION)
- WT error codes
- WT bidi stream signal (0x41) detection — deferred to Phase 6
- Integration between H3 layer and WT layer for stream routing

---

## Phase 1: Types & Structs

### New files: `include/wt_types.h`, `include/impl/wt_types.h`

#### `include/wt_types.h` (public)

```c
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// Forward declarations
typedef struct YAWT_Q_Connection_t YAWT_Q_Connection_t;
typedef struct YAWT_H3_Connection_t YAWT_H3_Connection_t;
typedef struct YAWT_WT_Context_t YAWT_WT_Context_t;
typedef struct YAWT_WT_Session_t YAWT_WT_Session_t;

// ---- WT Error Codes (draft-15 section 9.5) ----
typedef enum {
  YAWT_WT_ERR_BUFFERED_STREAM_REJECTED = 0x3994bd84,
  YAWT_WT_ERR_SESSION_GONE             = 0x170d7b68,
  YAWT_WT_ERR_FLOW_CONTROL_ERROR       = 0x045d4487,
  YAWT_WT_ERR_ALPN_ERROR               = 0x0817b3dd,
  YAWT_WT_ERR_REQUIREMENTS_NOT_MET     = 0x212c0d48,
} YAWT_WT_ErrorCode_t;

// WT_APPLICATION_ERROR range: 0x52e4a40fa8db to 0x52e5ac983162
// (with codepoints of form 0x1f * N + 0x21 excluded)
#define YAWT_WT_ERR_APP_RANGE_FIRST  0x52e4a40fa8dbULL
#define YAWT_WT_ERR_APP_RANGE_LAST   0x52e5ac983162ULL

// ---- Capsule Types (draft-15 section 9.6, RFC 9297) ----
typedef enum {
  YAWT_WT_CAPSULE_DATAGRAM              = 0x00,         // RFC 9297 section 3.5
  YAWT_WT_CAPSULE_CLOSE_SESSION         = 0x2843,       // draft-15 section 6
  YAWT_WT_CAPSULE_DRAIN_SESSION         = 0x78ae,       // draft-15 section 4.7
  YAWT_WT_CAPSULE_MAX_DATA              = 0x190B4D3D,   // draft-15 section 5.6.4
  YAWT_WT_CAPSULE_MAX_STREAMS_BIDI      = 0x190B4D3F,   // draft-15 section 5.6.2
  YAWT_WT_CAPSULE_MAX_STREAMS_UNI       = 0x190B4D40,   // draft-15 section 5.6.2
  YAWT_WT_CAPSULE_DATA_BLOCKED          = 0x190B4D41,   // draft-15 section 5.6.5
  YAWT_WT_CAPSULE_STREAMS_BLOCKED_BIDI  = 0x190B4D43,   // draft-15 section 5.6.3
  YAWT_WT_CAPSULE_STREAMS_BLOCKED_UNI   = 0x190B4D44,   // draft-15 section 5.6.3
} YAWT_WT_CapsuleType_t;

// ---- WT Internal Return Status ----
typedef enum {
  YAWT_WT_OK = 0,
  YAWT_WT_ERR_SHORT_BUFFER,
  YAWT_WT_ERR_INCOMPLETE,
  YAWT_WT_ERR_MALFORMED,
  YAWT_WT_ERR_INVALID_PARAM,
  YAWT_WT_ERR_NO_APP_HANDLER,
  YAWT_WT_ERR_NO_SESSION,
  YAWT_WT_ERR_FLOW_CONTROL,
  YAWT_WT_ERR_SESSION_CLOSED,
} YAWT_WT_Error_t;

static inline const char *YAWT_wt_err_str(YAWT_WT_Error_t err) {
  switch (err) {
    case YAWT_WT_OK:                return "OK";
    case YAWT_WT_ERR_SHORT_BUFFER:  return "SHORT_BUFFER";
    case YAWT_WT_ERR_INCOMPLETE:    return "INCOMPLETE";
    case YAWT_WT_ERR_MALFORMED:     return "MALFORMED";
    case YAWT_WT_ERR_INVALID_PARAM: return "INVALID_PARAM";
    case YAWT_WT_ERR_NO_APP_HANDLER:return "NO_APP_HANDLER";
    case YAWT_WT_ERR_NO_SESSION:    return "NO_SESSION";
    case YAWT_WT_ERR_FLOW_CONTROL:  return "FLOW_CONTROL";
    case YAWT_WT_ERR_SESSION_CLOSED:return "SESSION_CLOSED";
    default:                        return "UNKNOWN";
  }
}

// ---- WT Events (app-facing) ----
typedef enum {
  YAWT_WT_EVT_SESSION_ESTABLISHED,  // session accepted/confirmed
  YAWT_WT_EVT_STREAM_DATA,          // data on a WT uni stream (after session ID parsed)
  YAWT_WT_EVT_STREAM_OPENED,        // new WT uni stream opened by peer (session_id + stream_id)
  YAWT_WT_EVT_STREAM_RESET,         // peer reset a WT stream
  YAWT_WT_EVT_DATAGRAM,             // datagram received (session_id + payload)
  YAWT_WT_EVT_SESSION_CLOSE,        // WT_CLOSE_SESSION received/sent
  YAWT_WT_EVT_SESSION_DRAIN,        // WT_DRAIN_SESSION or GOAWAY
} YAWT_WT_EventType_t;

// ---- WT Event Parameters ----
typedef union YAWT_WT_EventParam {
  struct {
    uint64_t session_id;
  } P_EVT_SESSION_ESTABLISHED;
  struct {
    uint64_t session_id;
    uint64_t stream_id;       // H3 stream ID
    const uint8_t *data;
    size_t len;
    int fin;
  } P_EVT_STREAM_DATA;
  struct {
    uint64_t session_id;
    uint64_t stream_id;       // H3 stream ID
  } P_EVT_STREAM_OPENED;
  struct {
    uint64_t session_id;
    uint64_t stream_id;
    uint64_t error_code;
  } P_EVT_STREAM_RESET;
  struct {
    uint64_t session_id;
    const uint8_t *data;
    size_t len;
  } P_EVT_DATAGRAM;
  struct {
    uint64_t session_id;
    uint32_t app_error_code;
    const char *app_error_message;
  } P_EVT_SESSION_CLOSE;
  struct {
    uint64_t session_id;
  } P_EVT_SESSION_DRAIN;
} YAWT_WT_EventParam_t;

// ---- WT Event Handler Callback ----
typedef void (*YAWT_WT_EventHandler_t)(YAWT_WT_Context_t *ctx,
                                        YAWT_WT_Session_t *session,
                                        YAWT_WT_EventType_t event,
                                        YAWT_WT_EventParam_t param);
```

#### `include/impl/wt_types.h` (internal)

```c
#pragma once
#include "../wt_types.h"
#include "../quic_connection.h"
#include "../h3_types.h"
#include <allocnbuffer/slab.h>

// Per-session WT state
struct YAWT_WT_Session_t {
  bool     in_use;
  uint64_t session_id;            // = CONNECT stream ID (draft-15 section 2.2)
  uint64_t connect_stream_id;     // same as session_id, kept for clarity

  // Flow control state (Phase 5)
  uint64_t max_streams_uni;       // cumulative, from WT_MAX_STREAMS or SETTINGS
  uint64_t max_streams_bidi;      // cumulative, from WT_MAX_STREAMS or SETTINGS
  uint64_t max_data;              // from WT_MAX_DATA or SETTINGS
  uint64_t sent_data;             // bytes sent (for data limit enforcement)
  uint64_t recv_data;             // bytes received (for data limit enforcement)
  uint64_t open_streams_uni;      // currently open
  uint64_t open_streams_bidi;     // currently open

  // Capsule parse state for the CONNECT stream
  // (capsules arrive as DATA frames on the CONNECT bidi stream)
  // Uses the generic capsule parser, stored per-session

  // State
  bool     draining;              // WT_DRAIN_SESSION sent/received
  bool     closed;                // session terminated
};

// Per-H3-connection WT manager
struct YAWT_WT_Context_t {
  YAWT_Q_Connection_t *qcon;
  YAWT_H3_Connection_t *h3con;
  YAWT_WT_EventHandler_t app_handler;
  uint64_t nsessions;
  YAWT_WT_Session_t *sessions;    // slot pool, linear-scan by session_id
};
```

---

## Phase 2: H3 Layer Changes (minimal)

### Modify `include/h3_types.h`

Add two new H3 event types and their event param structs:

```c
typedef enum {
  YAWT_H3_EVT_HEADERS,
  YAWT_H3_EVT_DATA,
  YAWT_H3_EVT_SETTINGS,
  YAWT_H3_EVT_CLOSE,
  YAWT_H3_EVT_WT_UNI_STREAM,  // NEW: data on 0x54 uni stream
  YAWT_H3_EVT_DATAGRAM,       // NEW: QUIC datagram received
} YAWT_H3_EventType_t;

// Add to YAWT_H3_EventParam_t union:
struct {
  uint64_t stream_id;       // H3 uni stream ID
  const uint8_t *data;
  size_t len;
} P_EVT_WT_UNI_STREAM;

struct {
  const uint8_t *data;
  size_t len;
} P_EVT_DATAGRAM;
```

### Modify `src/h3.c`

**Change 1**: `_handle_rx_stream_chunk()` at line 485-486 — don't drain 0x54 streams, emit to app:

```c
case YAWT_H3_STREAM_WEBTRANSPORT:
  // Emit raw bytes to app; WT layer will parse session ID + body
  _h3_emit_event(h3con, YAWT_H3_EVT_WT_UNI_STREAM, (YAWT_H3_EventParam_t){
    .P_EVT_WT_UNI_STREAM = {
      .stream_id = qf->stream_id,
      .data = rc.data + rc.cursor,
      .len = rc.len - rc.cursor,
    }
  });
  rc.cursor = rc.len;
  break;
```

**Change 2**: `YAWT_h3_on_event()` at line 549 — emit datagrams to app:

```c
case YAWT_Q_EVT_DATAGRAM: {
  YAWT_H3_Connection_t *h3 = YAWT_q_con_get_user_data(con, YAWT_UD_H3);
  if (h3 && h3->app_handler) {
    _h3_emit_event(h3, YAWT_H3_EVT_DATAGRAM, (YAWT_H3_EventParam_t){
      .P_EVT_DATAGRAM = {
        .data = param.P_EVT_DATAGRAM.data,
        .len = param.P_EVT_DATAGRAM.len,
      }
    });
    return YAWT_H3_OK;
  }
  return YAWT_H3_IGNORED;
}
```

---

## Phase 3: Generic Capsule Parser (RFC 9297)

### New files: `include/capsule.h`, `src/capsule.c`

Capsule wire format (RFC 9297 section 3.2):
```
Capsule {
  Capsule Type (varint),
  Capsule Length (varint),
  Capsule Value (..),
}
```

#### `include/capsule.h`

```c
#pragma once
#include <stdint.h>
#include <stddef.h>
#include "quic.h"  // YAWT_Q_ReadCursor_t, varint helpers

// Incremental capsule parser — handles partial chunks across calls.
// Modeled after H3 frame parser pattern.
typedef struct {
  uint8_t  hdr[16];           // type+len decode scratch
  uint8_t  hdr_size;          // bytes consumed in header phase; 0 = not yet read
  uint64_t accumulated;       // bytes accumulated for current phase
  uint64_t type;              // decoded capsule type
  uint64_t payload_len;       // decoded capsule length
  uint8_t *payload;           // malloc'd buffer for payload (NULL if not buffering)
} YAWT_Capsule_Parser_t;

// Callback for completed capsules.
// value points into parser's buffer — valid only for the duration of the callback.
typedef void (*YAWT_Capsule_Callback_t)(void *ctx, uint64_t type,
                                         const uint8_t *value, size_t len);

// Feed bytes into the parser. Calls cb for each complete capsule.
// Returns 0 on success, -1 on error (malformed).
int YAWT_capsule_parse_feed(YAWT_Capsule_Parser_t *p,
                              const uint8_t *data, size_t len,
                              YAWT_Capsule_Callback_t cb, void *cb_ctx);

// Reset parser state for reuse.
void YAWT_capsule_parser_reset(YAWT_Capsule_Parser_t *p);

// Encode a capsule into buf. Returns bytes written, 0 on error.
// buf must be large enough: varint_size(type) + varint_size(len) + len
size_t YAWT_capsule_encode(uint64_t type, const uint8_t *value, size_t value_len,
                            uint8_t *buf, size_t buf_len);

// Get the number of bytes needed for a capsule header (type + length varints).
size_t YAWT_capsule_header_size(uint64_t type, size_t value_len);
```

#### `src/capsule.c`

The parser follows the same incremental pattern as `_handle_rx_stream_frame()` in `h3.c`:
1. Header phase: accumulate bytes until type+length varints are decoded
2. Payload phase: accumulate payload_len bytes into malloc'd buffer
3. On completion: invoke callback, reset for next capsule

---

## Phase 4: WT API

### New files: `include/wt.h`, `src/wt.c`

#### `include/wt.h`

```c
#pragma once
#include "wt_types.h"
#include "h3_types.h"
#include "quic.h"

// ---- Context lifecycle ----

// Create a WT context for an H3 connection. Allocates session pool.
// Stores itself in the QUIC connection's YAWT_UD_WT slot.
YAWT_WT_Context_t *YAWT_wt_context_create(YAWT_H3_Connection_t *h3);

// Destroy WT context and all sessions. Clears YAWT_UD_WT slot.
void YAWT_wt_context_destroy(YAWT_WT_Context_t *ctx);

// Get the WT context from a QUIC connection (convenience accessor).
YAWT_WT_Context_t *YAWT_wt_context_get(YAWT_Q_Connection_t *con);

// ---- Event handler ----

void YAWT_wt_set_event_handler(YAWT_WT_Context_t *ctx,
                                 YAWT_WT_EventHandler_t handler);

// ---- Session management ----

// Accept a WT session. Called by app after sending 200 response to CONNECT.
// connect_stream_id is the H3 bidi stream ID of the CONNECT request (= session ID).
YAWT_WT_Session_t *YAWT_wt_session_accept(YAWT_WT_Context_t *ctx,
                                            uint64_t connect_stream_id);

// Look up a session by session ID.
YAWT_WT_Session_t *YAWT_wt_session_find(YAWT_WT_Context_t *ctx,
                                          uint64_t session_id);

// Close a session with an application error code and message.
// Sends WT_CLOSE_SESSION capsule, then FINs the CONNECT stream.
YAWT_WT_Error_t YAWT_wt_session_close(YAWT_WT_Context_t *ctx,
                                        uint64_t session_id,
                                        uint32_t app_error_code,
                                        const char *message);

// ---- Processing incoming data (called by app from its H3 handler) ----

// Process data from a 0x54 uni stream. Parses session ID varint from the
// stream header, looks up the session, emits YAWT_WT_EVT_STREAM_DATA.
// The first call for a given H3 stream ID must include the stream type (0x54)
// and session ID; subsequent calls are pure body data.
YAWT_WT_Error_t YAWT_wt_on_uni_stream(YAWT_WT_Context_t *ctx,
                                        uint64_t h3_stream_id,
                                        const uint8_t *data, size_t len,
                                        int fin);

// Process capsule data from a CONNECT stream's DATA frames.
// Feeds into the capsule parser; dispatches WT capsules to handlers.
YAWT_WT_Error_t YAWT_wt_on_capsule_data(YAWT_WT_Context_t *ctx,
                                          uint64_t session_id,
                                          const uint8_t *data, size_t len);

// Process a QUIC datagram. Parses Quarter Stream ID (RFC 9297 section 2.1),
// looks up the session, emits YAWT_WT_EVT_DATAGRAM.
YAWT_WT_Error_t YAWT_wt_on_datagram(YAWT_WT_Context_t *ctx,
                                      const uint8_t *data, size_t len);

// ---- Sending ----

// Open a uni stream for a session. Prepends 0x54 + session_id varint header.
YAWT_WT_Error_t YAWT_wt_send_uni_stream(YAWT_WT_Context_t *ctx,
                                          uint64_t session_id,
                                          const uint8_t *data, size_t len,
                                          int fin);

// Send a datagram for a session. Prepends Quarter Stream ID (RFC 9297 section 2.1).
YAWT_WT_Error_t YAWT_wt_send_datagram(YAWT_WT_Context_t *ctx,
                                        uint64_t session_id,
                                        const uint8_t *data, size_t len);

// Send a capsule on a CONNECT stream (for flow control, close, drain, etc.)
YAWT_WT_Error_t YAWT_wt_send_capsule(YAWT_WT_Context_t *ctx,
                                       uint64_t session_id,
                                       uint64_t capsule_type,
                                       const uint8_t *value, size_t value_len);
```

#### `src/wt.c` — Key Implementation Notes

**Session ID extraction from 0x54 uni streams** (draft-15 section 4.2):
```
Unidirectional Stream {
    Stream Type (i) = 0x54,    <-- already consumed by H3 layer
    Session ID (i),            <-- first thing in the data H3 emits
    User-Specified Stream Data (..)
}
```
The WT uni stream parser needs to accumulate bytes until the session ID varint is decoded (same pattern as `_gather_h3_stream_type()` in h3.c). Store per-H3-stream-ID state for this.

**Quarter Stream ID parsing for datagrams** (RFC 9297 section 2.1):
```
HTTP/3 Datagram {
  Quarter Stream ID (i),      <-- varint: connect_stream_id / 4
  HTTP Datagram Payload (..),
}
```
Decode the varint, multiply by 4 to get the session ID, look up the session.

**Capsule dispatch on CONNECT stream**:
The app knows which H3 bidi streams are WT CONNECT streams (it accepted them). When it receives `YAWT_H3_EVT_DATA` on a CONNECT stream, it calls `YAWT_wt_on_capsule_data()` which feeds the generic capsule parser and dispatches:
- `WT_CLOSE_SESSION` -> emit `YAWT_WT_EVT_SESSION_CLOSE`, FIN the stream
- `WT_DRAIN_SESSION` -> emit `YAWT_WT_EVT_SESSION_DRAIN`
- `WT_MAX_STREAMS` -> update session flow control limits (Phase 5)
- `WT_MAX_DATA` -> update session data limit (Phase 5)
- `DATAGRAM` (0x00) -> emit `YAWT_WT_EVT_DATAGRAM` (capsule-based datagrams)
- Unknown types -> silently skip (RFC 9297 section 3.2)

---

## Phase 5: Flow Control (deferred)

Per draft-15 section 5:
- Track per-session cumulative stream counts and data bytes
- Send `WT_MAX_STREAMS` / `WT_MAX_DATA` capsules as data is consumed
- Enforce limits: reject streams that exceed advertised Maximum Streams
- Handle `WT_STREAMS_BLOCKED` / `WT_DATA_BLOCKED` capsules (informational)
- `WT_FLOW_CONTROL_ERROR` on violations

---

## Phase 6: Bidi Stream Handling (deferred)

Per draft-15 section 4.3:
```
Bidirectional Stream {
    Signal Value (i) = 0x41,
    Session ID (i),
    Stream Body (..)
}
```
Requires peeking at the first bytes of every new bidi stream before H3 frame parsing. If first varint is 0x41, it's a WT bidi stream, not an H3 request. This is the trickiest integration point — may require H3 to expose a "pre-parse" hook or a new stream type.

---

## File Summary

| File | Action | Phase |
|------|--------|-------|
| `include/wt_types.h` | NEW | 1 |
| `include/impl/wt_types.h` | NEW | 1 |
| `include/h3_types.h` | MODIFY: add 2 event types + params | 2 |
| `src/h3.c` | MODIFY: don't drain 0x54, emit datagrams | 2 |
| `include/capsule.h` | NEW | 3 |
| `src/capsule.c` | NEW | 3 |
| `include/wt.h` | NEW | 4 |
| `src/wt.c` | NEW | 4 |
| `src/CMakeLists.txt` | MODIFY: add capsule.c, wt.c | 4 |
| `include/CMakeLists.txt` or build | MODIFY: add new headers | 4 |
| `examples/wt_server.c` | MODIFY: use WT API | 4 |

---

## Spec References

- **draft-ietf-webtrans-http3-15** — `docs/draft-ietf-webtrans-http3-15.txt`
  - Section 2.2: Protocol overview, session IDs
  - Section 3.1: WT-capable H3 connection (SETTINGS)
  - Section 3.2: Creating a new session (CONNECT)
  - Section 4.2: Unidirectional streams (0x54 + session ID)
  - Section 4.3: Bidirectional streams (0x41 signal) — deferred
  - Section 4.4: Resetting data streams (RESET_STREAM_AT)
  - Section 4.5: Datagrams (Quarter Stream ID)
  - Section 4.6: Buffering incoming streams/datagrams
  - Section 4.7: GOAWAY interaction (WT_DRAIN_SESSION)
  - Section 5: Flow control
  - Section 5.5: Flow control SETTINGS
  - Section 5.6: Flow control capsules
  - Section 6: Session termination (WT_CLOSE_SESSION)
  - Section 9: IANA registrations (error codes, capsule types, settings)

- **RFC 9297** — `docs/rfc9297.txt`
  - Section 2.1: HTTP/3 Datagram format (Quarter Stream ID)
  - Section 3.2: Capsule format (Type-Length-Value)
  - Section 3.5: DATAGRAM capsule (0x00)

- **RFC 9114** — `docs/rfc9114.txt` (H3)
- **RFC 9000** — `docs/rfc9000.txt` (QUIC)

---

## Naming Conventions (matching existing codebase)

| Prefix | Layer |
|--------|-------|
| `YAWT_q_` | QUIC wire-level |
| `YAWT_q_con_` | QUIC connection |
| `YAWT_h3_` | H3 |
| `YAWT_wt_` | WebTransport |
| `YAWT_capsule_` | Generic capsule protocol |

Types: `YAWT_WT_*` for WebTransport, `YAWT_Q_*` for QUIC, `YAWT_H3_*` for H3.
Functions: `YAWT_wt_*` for WT, `YAWT_h3_*` for H3, etc.
Error handling: return enum (`YAWT_WT_Error_t`). Output params via pointers.

---

## wt_server.c Example Flow (target state after Phase 4)

```c
// In h3_app_handler:
case YAWT_H3_EVT_SETTINGS:
  // Create WT context once settings arrive
  wt_ctx = YAWT_wt_context_create(h3con);
  YAWT_wt_set_event_handler(wt_ctx, wt_app_handler);
  break;

case YAWT_H3_EVT_HEADERS:
  if (CONNECT + webtransport-h3) {
    // Send 200 response (existing code)
    YAWT_h3_send_headers(h3con, sid, resp, 0);
    // Accept WT session
    YAWT_wt_session_accept(wt_ctx, sid);
    // Mark this stream as a WT CONNECT stream in app state
    // so we route DATA events to capsule parser
  }
  break;

case YAWT_H3_EVT_DATA:
  if (stream is a WT CONNECT stream) {
    // DATA frames on CONNECT stream = capsules
    YAWT_wt_on_capsule_data(wt_ctx, stream_id, data, len);
  }
  break;

case YAWT_H3_EVT_WT_UNI_STREAM:
  // 0x54 uni stream data — forward to WT layer
  YAWT_wt_on_uni_stream(wt_ctx, stream_id, data, len, fin);
  break;

case YAWT_H3_EVT_DATAGRAM:
  // QUIC datagram — forward to WT layer
  YAWT_wt_on_datagram(wt_ctx, data, len);
  break;

// Separate WT event handler:
static void wt_app_handler(YAWT_WT_Context_t *ctx,
                            YAWT_WT_Session_t *session,
                            YAWT_WT_EventType_t event,
                            YAWT_WT_EventParam_t param) {
  switch (event) {
    case YAWT_WT_EVT_STREAM_DATA:
      // Application payload from a WT uni stream
      break;
    case YAWT_WT_EVT_DATAGRAM:
      // Datagram payload for a session
      break;
    case YAWT_WT_EVT_SESSION_CLOSE:
      // Peer closed the session
      break;
    // ...
  }
}
```
