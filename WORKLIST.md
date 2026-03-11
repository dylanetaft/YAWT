# YAWT QUIC Implementation Worklist

Excludes: ECN, 0-RTT, spin bit, congestion control (beyond basic), connection migration.

## 1. Datagram Processing Loop (RFC 9000 Section 12.2)
- [x] YAWT_q_process_datagram() — loop over coalesced packets in a UDP datagram
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
- [ ] Packet number decoding (reconstruct full PN from truncated)

## 3. Frame Parse/Encode
- [x] CRYPTO frame parse
- [x] CRYPTO frame encode
- [x] ACK frame parse
- [ ] ACK frame encode
- [ ] STREAM frame parse
- [ ] STREAM frame encode
- [x] CONNECTION_CLOSE frame parse
- [ ] CONNECTION_CLOSE frame encode
- [x] HANDSHAKE_DONE frame parse
- [ ] HANDSHAKE_DONE frame encode
- [x] PING frame parse/encode (trivial, type byte only)
- [x] PADDING frame parse/encode (trivial, type byte only)
- [x] NEW_CONNECTION_ID frame parse
- [x] Frame dispatcher (read type byte, call correct parser)

## 4. Connection State Machine & Handshake Flow
- [x] Receive Initial packet -> decrypt -> parse frames -> extract CRYPTO
- [x] Feed CRYPTO data to GnuTLS via crypto_feed
- [x] Build response: take GnuTLS output -> wrap in CRYPTO frames -> build packet -> encrypt -> send
- [ ] Validate src_cid matches expected peer_cid (after header unprotect, before AEAD decrypt — avoids timing side channel on forged packets)
- [ ] State transitions: Idle -> Initial -> Handshake -> Established
- [ ] Server sends HANDSHAKE_DONE after handshake completes
- [ ] Drop Initial keys after Handshake keys are available
- [ ] Drop Handshake keys after handshake confirmed

## 5. Transport Parameters (RFC 9000 Section 18)
- [ ] Define transport params struct (initial_max_data, initial_max_stream_data_bidi_local, initial_max_streams_bidi, max_idle_timeout)
- [ ] Encode transport params to wire format
- [ ] Decode transport params from wire format
- [ ] Register TLS extension via gnutls_session_ext_register()
- [ ] Exchange params during handshake

## 6. ACK Generation & Basic Loss Detection (RFC 9002, simplified)
- [ ] Track sent packets: pkt_num -> list of frames contained
- [ ] Track received packet numbers (per packet number space)
- [ ] Generate ACK frames from received PN set
- [ ] Threshold-based loss detection (3 packets past = lost)
- [ ] Retransmit lost CRYPTO frame data
- [ ] Retransmit lost STREAM frame data
- [ ] PTO (probe timeout) — hardcoded timeout, send PING

## 7. Streams (RFC 9000 Section 2-3)
- [ ] Stream map: stream_id -> stream state (hash table)
- [ ] Per-stream send buffer with offset tracking
- [ ] Per-stream receive buffer with offset reassembly
- [ ] Stream state machine (open, half-closed, closed)
- [ ] FIN handling
- [ ] Flow control: track and enforce MAX_DATA (connection-level)
- [ ] Flow control: track and enforce MAX_STREAM_DATA (per-stream)
- [ ] Send MAX_DATA / MAX_STREAM_DATA updates as data is consumed
- [ ] MAX_STREAMS enforcement

## Done (foundational)
- [x] Packet parse/encode (all 5 types)
- [x] Frame structs (all 19 types defined)
- [x] Varint encode/decode
- [x] Connection struct with packet number spaces
- [x] Connection hash table by local CID + HASH_ADD on create
- [x] YAWT_Q_Cid_t struct — consolidated CID fields across all structs
- [x] TLS 1.3 handshake via GnuTLS QUIC API (crypt.c)
- [x] Secret extraction per encryption level
- [x] Packet encrypt + header protect (outbound)
- [x] Packet decrypt + header unprotect (inbound)
- [x] Outbound packet packer (flush_send: tx_buffer → encrypt → send)
- [x] UDP socket + libev event loop (test.c)
