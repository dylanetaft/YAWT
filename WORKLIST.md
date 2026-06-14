# YAWT QUIC Implementation Worklist

All work is tracked in this file. Check off items here as they are completed.

Excludes: ECN, 0-RTT, spin bit, congestion control (beyond basic), connection migration.

## 1. Datagram Processing Loop (RFC 9000 Section 12.2)
- [x] YAWT_q_con_rx() — loop over coalesced packets in a UDP datagram
- [x] Peek first byte to determine packet type (long vs short header)
- [x] For long header: use Length field to find packet boundary
- [x] For short header (1-RTT): consumes rest of datagram (always last)
- [x] Per-packet: parse header -> decrypt -> parse frames -> dispatch -> advance

## 2. Packet Protection (RFC 9001 Section 5)
- [x] Initial secret derivation from DCID using RFC-specified salt (not from GnuTLS)
- [x] HKDF-Expand-Label to derive key, IV, HP key from each level's secret
- [x] AEAD encrypt (AES-128-GCM)
- [x] AEAD decrypt
- [x] Header protection: apply packet number masking (AES-ECB)
- [x] Header protection: remove packet number masking
- [x] Packet number encoding (1-4 byte truncation)
- [x] Packet number decoding (reconstruct full PN from truncated)

## 3. Frame Parse/Encode
- [x] CRYPTO frame parse
- [x] CRYPTO frame encode
- [x] ACK frame parse
- [x] ACK frame encode
- [x] STREAM frame parse
- [x] STREAM frame encode
- [x] CONNECTION_CLOSE frame parse
- [x] CONNECTION_CLOSE frame encode (enqueue_frame_connection_close + con_close)
- [x] HANDSHAKE_DONE frame parse
- [x] HANDSHAKE_DONE frame encode
- [x] PING frame parse/encode (trivial, type byte only)
- [x] PADDING frame parse/encode (trivial, type byte only)
- [x] NEW_CONNECTION_ID frame parse
- [x] NEW_CONNECTION_ID frame handling (update peer CID, seq_num dedup)
- [x] MAX_DATA frame parse
- [x] MAX_STREAM_DATA frame parse
- [x] MAX_STREAMS frame parse (bidi + uni)
- [x] Frame dispatcher (read type byte, call correct parser)

## 4. Connection State Machine & Handshake Flow
- [x] Receive Initial packet -> decrypt -> parse frames -> extract CRYPTO
- [x] Feed CRYPTO data to GnuTLS via crypto_feed
- [x] Build response: take GnuTLS output -> wrap in CRYPTO frames -> build packet -> encrypt -> send
- [ ] Validate src_cid matches expected peer_cid (after header unprotect, before AEAD decrypt — avoids timing side channel on forged packets)
- [x] Server sends HANDSHAKE_DONE after handshake completes
- [ ] Drop Initial keys after Handshake keys are available
- [ ] Drop Handshake keys after handshake confirmed

## 5. Transport Parameters (RFC 9000 Section 18)
- [x] Define transport params struct (YAWT_Q_FlowControl_t in quic.h)
- [x] Encode transport params to wire format (_tp_send in crypt.c)
- [x] Decode transport params from wire format (_tp_recv in crypt.c)
- [x] Register TLS extension via gnutls_session_ext_register()
- [x] Exchange params during handshake
- [x] Copy peer flow control limits to connection after handshake (peer_fc)

## 6. ACK Generation & Basic Loss Detection (RFC 9002, simplified)
- [x] Track sent packets: pkt_num -> list of frames contained
- [x] Track received packet numbers (per packet number space)
- [x] Generate ACK frames from received PN set
- [x] Loss detection: time-based retransmit with backoff (retransmit_lost)
- [x] Retransmit lost CRYPTO frame data
- [x] Retransmit lost STREAM frame data
- [ ] PTO (probe timeout) — hardcoded timeout, send PING

## 7. Path Validation (RFC 9000 Section 8.2)
- [x] PATH_CHALLENGE frame parse (8-byte random data)
- [ ] PATH_CHALLENGE frame encode
- [ ] PATH_RESPONSE frame parse
- [x] PATH_RESPONSE frame encode
- [x] On receiving PATH_CHALLENGE, echo data back in PATH_RESPONSE
- [ ] Connection migration: update peer_addr on validated new path

## 8. Streams (RFC 9000 Section 2-3)
- [x] Stream map: stream_id -> stream state (slab-based stream_meta)
- [x] Per-stream send buffer with offset tracking (YAWT_q_con_send_stream)
- [x] Per-stream receive buffer with offset reassembly
- [ ] Stream state machine (open, half-closed, closed)
- [x] FIN handling (receive side)
- [x] FIN handling (send side — tx_fin_sent in StreamMeta)
- [x] Flow control: parse MAX_DATA / MAX_STREAM_DATA / MAX_STREAMS frames
- [x] Flow control: track peer limits (peer_fc on connection, tx_max_data on stream meta)
- [x] Flow control: enforce limits in send path (max_data + max_stream_data in _drain_tx, max_streams in send_stream)
- [ ] Send MAX_DATA / MAX_STREAM_DATA updates as data is consumed
- [x] MAX_STREAMS enforcement (checked in send_stream before stream creation)

## 10. DATAGRAM Extension (RFC 9221)
- [x] DATAGRAM frame types in enum (0x30, 0x31)
- [x] DATAGRAM frame parse (with/without length)
- [x] DATAGRAM frame encode (enqueue_frame_datagram)
- [x] Transport param: max_datagram_frame_size (0x20) decode
- [x] Transport param: max_datagram_frame_size (0x20) encode
- [x] on_datagram callback in vtable
- [ ] Wire on_datagram callback in frame handler
- [ ] Enforce peer's max_datagram_frame_size on send

## 11. Application Callback API
- [x] `YAWT_Q_Callbacks_t` vtable struct (`include/callbacks.h`)
- [x] Forward declarations for `YAWT_Q_Connection_t`, `YAWT_Q_PeerAddr_t`, `YAWT_Q_Frame_Stream_t`
- [x] `on_tx` — encrypted packet ready for UDP send
- [x] `on_stream` — reassembled stream data (takes `const YAWT_Q_Frame_Stream_t *`)
- [x] `on_connected` — handshake complete
- [x] `on_close` — peer CONNECTION_CLOSE
- [ ] Wire callbacks into `con_rx` / `con_tx` (replace current ad-hoc send callback)
- [ ] Per-connection vtable pointer (set at creation or on WT claim)
- [ ] WebTransport: `YAWT_WT_Callbacks_t` — WT-specific events (`on_session`, `on_wt_stream`, `on_wt_datagram`)
- [ ] WebTransport: WT layer consumes QUIC callbacks, swaps vtable on WT connections

## 9. Hardening / DoS Mitigation
- [ ] CRYPTO reassembly: cap max buffered out-of-order bytes per level (reject/close if exceeded)
- [ ] STREAM reassembly: cap max buffered out-of-order bytes per stream
- [ ] Connection-level cap on total buffered inbound data across all streams
- [ ] Max gap enforcement: reject frames with offset far ahead of expected (prevents memory exhaustion from fake high offsets with missing offset 0)
- [x] MAX_STREAMS enforcement: reject stream creation beyond advertised limit
- [x] Idle timeout: close connections with no activity (send PING to keep alive before expiry)
- [x] Maintenance API: `YAWT_q_con_maintain` — unified retransmit + idle timeout + keepalive PING
- [x] `YAWT_Q_MaintenanceConfig_t` — global config struct with retransmit/interval tunables
- [x] Security policy module: `security.h`/`security.c` — centralized policy with getter/setter API
- [x] Min idle timeout floor: clamp effective idle timeout via `YAWT_Q_SecurityPolicy_t.min_idle_timeout_ms`
- [ ] PN duplicate rejection (RFC 9000 §21.4): discard packets with already-seen PNs

## 9a. Error Handling / Cleanup
- [ ] H3: `_h3_stream_close(stream, error_code)` helper — reset frame state, free payload, null headers
- [ ] H3: `_h3_conn_close(h3con, error_code)` helper — send CONNECTION_CLOSE, tear down
- [ ] H3: close stream on frame header exceeds max len (`h3.c:219`)
- [ ] H3: close stream on frame Length exceeds buffer cap (`h3.c:251`)
- [ ] H3: close connection with H3_SETTINGS_ERROR on duplicate SETTINGS (`h3.c:284`)
- [ ] H3: close connection with H3_SETTINGS_ERROR on SETTINGS decode failure (`h3.c:300`)
- [ ] H3: close connection with H3_MISSING_SETTINGS on control stream violation (`h3.c:313`)
- [ ] H3: close connection when no stream slots available (`h3.c:350`)
- [ ] H3: close stream/session on stream type resolve error (`h3.c:374`)
- [ ] H3: close stream on unknown stream type (`h3.c:383`)
- [ ] H3: close stream on unhandled stream type (`h3.c:397`)
- [ ] QUIC: close connection on reassembly failure (`quic_connection.c:882`)
- [ ] CRYPTO: propagate TLS alert to connection layer (`crypt.c:194`)

## 12. HTTP/3 (RFC 9114) — RX path
- [x] H3 connection object (alloc on EVT_CONNECTED, free on EVT_CLOSE)
- [x] Per-stream meta slot pool + frame state (`YAWT_H3_StreamMeta_t.cur`)
- [x] Frame header gather (`_gather_h3_frame_head`) — Type/Length varints, split-chunk safe
- [x] Must-buffer frame path (SETTINGS/HEADERS): exact malloc(payload_len), capped by `security.max_frame_buffer_bytes`, buffer from chunk, free + reset on complete
- [x] **Uni stream-type prefix** — `_gather_h3_stream_type` reads the 1-varint role prefix on client uni streams once before framing (accumulates across chunks in `YAWT_H3_Stream_t.hdr`/`accumulated`), strips it into a forwarded body view, and resolves `type`. `type == UNASSIGNED` is the "prefix not yet read" signal (distinct from wire CONTROL==0). Maps CONTROL→STREAM_FRAME path, QPACK/WT to their types; rejects a server-side push stream (MALFORMED). Bidi resolves straight to STREAM_FRAME. TODO: silently drain unknown uni stream types instead of erroring.
- [x] **SETTINGS dispatch** — un-park `YAWT_h3_settings_decode` (adapt to `YAWT_Q_ReadCursor_t`/`YAWT_q_varint_decode`), call it on a complete control-stream SETTINGS frame, store into `peer_settings`; enforce SETTINGS-first + no-duplicate rules (RFC 9114 §7.2.4). `local_settings`/`peer_settings` are pointers (NULL = not set).
- [x] **Cursor-based frame handler** — `_handle_rx_stream_frame` takes `YAWT_Q_ReadCursor_t *` instead of copying `YAWT_Q_Frame_Stream_t`; `_gather_h3_frame_head` advances cursor directly.
- [x] **Stream-through + multi-frame-per-chunk** — consume non-buffered frames (DATA/unknown) by tracking remaining payload across chunks (no malloc), and loop the handler over a chunk that carries several sequential frames
- [x] **H3→app frame delivery callback** — `YAWT_H3_EventHandler_t` with HEADERS/DATA/SETTINGS/CLOSE events; `YAWT_h3_set_event_handler()` to install
- [x] **H3 event system** — `YAWT_H3_EventType_t`/`YAWT_H3_EventParam_t` in `h3_types.h`, handler API in `h3.h`
- [x] **QUIC event fold** — `YAWT_Q_EventType_t`/`YAWT_Q_EventParam_t` moved from `events.h` into `quic_types.h`; `YAWT_Q_EventHandler_t` in `quic.h`; `events.h` deleted
- [x] **Stream-type frame validation** — `_dispatch_buffered_frame()` switches on `stream->type`, rejects wrong-frame-on-wrong-stream (connection error)
- [ ] TX: open server control stream + advertise our SETTINGS (encoder still parked)
- [ ] QPACK/WEBTRANSPORT uni stream dispatch (silently drain)
- [x] H3: expose `YAWT_h3_get_qcon()` so app can reach QUIC layer from H3 callback

## 13. QPACK (RFC 9204) — Decoder
- [x] Static table (99 entries, RFC 9204 Appendix A) — `YAWT_qpack_static_get`, `YAWT_qpack_static_find_name`, `YAWT_qpack_static_find_entry`
- [x] Huffman encode/decode (RFC 7541 Appendix B / RFC 9204 §5.1) — `huff_encode_byte`, `huff_encode_string`, `huff_decode_byte`, `huff_decode_string`, tree-based decoder with EOS padding validation
- [x] Prefix integer encode/decode (RFC 7541 §5.1 / RFC 9204 §4.1.1) — `YAWT_H3_QPACK_decode_prefix_int`, `YAWT_H3_QPACK_encode_prefix_int`
- [x] Field line representation dispatcher (RFC 9204 §4.5) — `YAWT_H3_QPACK_decode_field_line_msb`: Indexed, Indexed Post-Base, Literal Name Ref, Literal Post-Base Name Ref, Literal Literal Name
- [x] Encoder instruction prefix decoder — `YAWT_H3_QPACK_decode_encoder_instruction_prefix`: Insert w/ Name Ref, Insert w/ Literal Name, Set Capacity, Duplicate
- [ ] Header block prefix decode (RFC 9204 §4.4) — Required Insert Count, Base index
- [ ] Field section decode (RFC 9204 §4.5) — full decode loop over field line representations, resolve static table refs, handle literals with Huffman string decode, populate `YAWT_H3_HeaderFields_t`
- [ ] Dynamic table support (RFC 9204 §3) — insert, evict, lookup by post-base index

## 14. QPACK (RFC 9204) — Encoder
- [ ] Header block prefix encode (RFC 9204 §4.4) — Required Insert Count, Base index
- [ ] Field line encode — Indexed (static table ref), Literal w/ Name Ref, Literal w/ Literal Name, with Huffman string encoding
- [ ] Field section encode — loop over `YAWT_H3_HeaderFields_t`, choose optimal representation (static table lookup via `YAWT_h3_header_resolve`), emit encoded block
- [ ] Encoder stream protocol (RFC 9204 §4.2) — encoder instructions on encoder uni stream (Insert w/ Name Ref, Insert w/ Literal Name, Set Capacity, Duplicate)
- [ ] Decoder stream protocol (RFC 9204 §4.3) — decoder acknowledgments on decoder uni stream (Section Ack, Stream Cancel, Insert Count Increment)

## 15. HTTP/3 (RFC 9114) — TX path
- [x] Open server control stream (uni, type=0x00) on EVT_CONNECTED
- [x] Encode + send SETTINGS frame on control stream from `local_settings`
- [x] Encode response: build HEADERS frame — resolve header fields via QPACK encoder, wrap in H3 frame, send on bidi stream
- [x] Encode DATA frames from body, send on bidi stream
- [x] Flow control: initialize stream tx_max_data from peer's transport parameters (initial_max_stream_data_bidi_remote/uni) per RFC 9000 §18.2
- [ ] GOAWAY frame encode/decode (RFC 9114 §7.2.6)
- [ ] MAX_PUSH_ID frame encode (RFC 9114 §7.2.5)
- [ ] Consider flushing TX buffer outside of maintenance window — currently `_drain_tx` runs after each `con_rx` packet batch and during `con_maintain`, which works for request/response patterns but may need explicit flush for proactive sends (e.g. server push, keepalive). Decide where/when later.
- [ ] Investigate unknown frame type 0x1d from curl after response — occurs during connection cleanup, not blocking functionality. RFC 9000 §12.4 requires FRAME_ENCODING_ERROR for unknown types (current behavior). May be extension frame or experimental feature.

## Done (foundational)
- [x] Packet parse/encode (all 5 types)
- [x] Frame structs (all 19 types defined)
- [x] Varint encode/decode (both public API)
- [x] Connection struct with packet number spaces
- [x] Connection stats struct (tx/rx byte counters, pkt_num tracking, cid_seq_num)
- [x] Connection hash table by local CID + HASH_ADD on create
- [x] YAWT_Q_Cid_t struct — consolidated CID fields across all structs
- [x] TLS 1.3 handshake via GnuTLS QUIC API (crypt.c)
- [x] Secret extraction per encryption level
- [x] Packet encrypt + header protect (outbound)
- [x] Packet decrypt + header unprotect (inbound)
- [x] Outbound packet packer (con_tx / _drain_tx: tx_buffer → encrypt → send)
- [x] UDP socket + libev event loop (test.c)
- [x] CRYPTO frame reassembly (ANB_Slab_t based, handles out-of-order)
- [x] ACK processing: remove acknowledged frames from tx_buffer (with gap ranges)
- [x] Retransmit timer with backoff (retransmit_lost)


Dylan
- [ ] Refactor _hande_frames - rename?  Its only for rx

