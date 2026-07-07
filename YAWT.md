# YAWT — Yet Another WebTransport Library

A C library providing a protocol stack:
- QUIC
- HTTP/3
- WebTransport

## What it does

YAWT provides a simple C API for creating services on top of QUIC, H3, or WebTransport. The library provides callback hooks for protocol events, and does not take over your event loop nor does it handle connectivity directly.
The API allows you to pump raw UDP packets into the library, they will be parsed and callbacks will be invoked for events such as new connections, streams, datagrams, etc. Functions are provided to send stream data or datagrams, the library will buffer what is needed, ie for streams, stream frames are held until ACK is received. The library also calls a user defined TX function with the raw UDP data to send.

## What is the goal

The goal of YAWT is to provide flexible low and high level APIs for building QUIC/H3/WebTransport services. It is not a full-featured framework, but rather a library that can be used to build your own service on top of the protocols. WebTransport is still in DRAFT with the IETF, thus I wanted the flexibility of owning my own stack to implement new features as they are supported.

## Features

### Performance
- Zero-copy "fast path" stream and datagram APIs - when possible and easy to offer without tradeoff
- QUIC RX Streams: the QUIC layer has a small bitfield for PN tracking, allowing for out of order packet RX and delivery without needing to retransmit
- QUIC connection CIDs tracked in a hash table for fast lookup - UTHASH

### Ease of Use
- All stream TX is buffered and sent in order, with automatic retransmission of lost frames based on ACK - application does not need to handle this
- Every protocol has ONE event callback, with a union of event types and parameters, with consistent naming and semantics across protocols
- QUIC: Stream and Connection level "slots" for you to implement your own protocols if desired
- Internal maintenance of connection state, including timers, retransmission, and flow control

## Implemented Protocol Features

### QUIC
- QUIC 1.0 (RFC 9000) - Server and Client
- Flow Control - Stream and Connection level (RFC 9000 §4)
- RX Packet coalescing
- Mandatory features allowing interoperability with other QUIC implementations
- RFC 9221 - Datagrams
- Most of the mandatory checks requiring connection termination

### HTTP/3
- HTTP/3 (RFC 9114) - Server and Client
- RFC 9204 - QPACK (Header Frame Decoder and Encoder Only, no dynamic table support, only open streams, no push)
- Enough features to interoperate with browsers and other HTTP/3 implementations
    - Send\receive headers and data frames
    - Download files via GET
    - Upload files via POST
    - Host a web server for static files
- Extended CONNECT (RFC 9220) - the HTTP/3 substrate WebTransport rides on (see WebTransport)
- Most of the mandatory checks requiring connection termination
- Unknown frames (GREASE) - anti-ossification measures for compatibility with other HTTP/3 implementations

### WebTransport
- WebTransport (draft 2 + draft 15) - Server and Client
    - Create\accept WebTransport sessions
    - Send\receive datagrams
    - Send\receive streams

## Partially Implemented Protocol Features

### HTTP/3
- RFC 9297 - Datagrams in capsules (untested)

## Unimplemented Protocol Features

### QUIC
- Congestion control (currently sends without a congestion window)
- TX Packet coalescing
- ACKs currently sent per PN, no ranges
- ECN
- Connection migration
- 0-RTT

### HTTP/3
- Push streams
- RFC 9204 - QPACK dynamic table support, Encoder\Decoder Streams

### WebTransport
- End to end draft 15 support (draft 2 is tested and working)
- Capsule framing is present but untested (browsers mostly support draft 2; IETF is on draft 15)
- Fewer sanity checks around protocol violations than QUIC or HTTP/3

## Building

```sh
cmake -B build
cmake --build build
```

With tests:
```sh
cmake -B build -DBUILD_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

With fuzzing (requires clang):
```sh
cmake -B build -DBUILD_FUZZ=ON
cmake --build build --target fuzz_slab
./build/fuzz_slab -max_total_time=60
```

## Internal Data Structures - Core Design

```c
struct YAWT_Q_Context_t { // QUIC context, contains all state for a single QUIC connection
    // ...
    // ...
    void *user_data[YAWT_UD_COUNT]; // Each implemented protocol stores an opaque pointer here for its own context
    // ...
    ANB_Slab_t *stream_userdata;      // YAWT_Q_StreamUserData_t per open stream
    // ...
};
```

```c
struct YAWT_Q_StreamUserData_t {
  uint64_t stream_id;
  void *user_data[YAWT_UD_COUNT];
};
```

```c
struct YAWT_H3_Context_t {
    YAWT_Q_Context_t *quic_ctx;
    // ...
}
```

Protocol contexts "hang off" the QUIC Ctx via the connection's `user_data[]` array, and each open
stream carries a parallel `user_data[]` array so every protocol can store its own per-stream state.
Both arrays are indexed by the same `YAWT_UD_*` slot enum (`YAWT_UD_APP`, `YAWT_UD_QUIC`,
`YAWT_UD_H3`, `YAWT_UD_WT`). Each protocol context keeps a back pointer to the QUIC Ctx; QUIC
functions are used across the board for all protocols. Each protocol is responsible for creating
and destroying its own context and stream user data, driven by the QUIC connection and close events.

There is one deliberate asymmetry between the two arrays: the `YAWT_UD_QUIC` slot holds a
`YAWT_Q_Stream_t` per stream, but is unused at the connection level — the `YAWT_Q_Context_t`
object *is* the QUIC connection state, so it has no reason to point back at itself.

Visually this looks like

```
 --------------
|   QUIC Ctx   |
|==============|
| user_data[0] | -> APP / your custom protocol context
| user_data[1] | -> (unused - the connection object IS the QUIC state)
| user_data[2] | -> YAWT_H3_Context_t
| user_data[3] | -> YAWT_WT_Context_t
|  ..........  |
|  ..........  |     ------------------
|  Stream[0]   | -> | Stream User Data |
|  ..........  |    |==================|
|  ..........  |    |  user_data[0]    | -> APP / your custom protocol stream
|  ..........  |    |  user_data[1]    | -> YAWT_Q_Stream_t
|  ..........  |    |  user_data[2]    | -> YAWT_H3_Stream_t
|  ..........  |    |  user_data[3]    | -> YAWT_WT_Stream_t
|  ..........  |     ------------------
|  Stream[1]   | -> | Stream User Data |
|  ..........  |    |==================|
|  ..........  |    |  user_data[0]    | -> APP / your custom protocol stream
|  ..........  |    |  user_data[1]    | -> YAWT_Q_Stream_t
|  ..........  |    |  user_data[2]    | -> YAWT_H3_Stream_t
|  ..........  |    |  user_data[3]    | -> YAWT_WT_Stream_t
|______________|     ------------------
```

### Quick start

```c
```
