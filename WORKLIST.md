# YAWT QUIC Implementation Worklist

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
