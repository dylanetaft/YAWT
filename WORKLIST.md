# YAWT QUIC Implementation Worklist

Excludes: ECN, 0-RTT, spin bit, congestion control (beyond basic), connection migration.

## 1. Datagram Processing Loop (RFC 9000 Section 12.2)
- [ ] YAWT_q_process_datagram() — loop over coalesced packets in a UDP datagram
- [ ] Peek first byte to determine packet type (long vs short header)
- [ ] For long header: use Length field to find packet boundary
- [ ] For short header (1-RTT): consumes rest of datagram (always last)
- [ ] Per-packet: parse header -> decrypt -> parse frames -> dispatch -> advance

## 2. Packet Protection (RFC 9001 Section 5)
- [ ] Initial secret derivation from DCID using RFC-specified salt (not from GnuTLS)
- [ ] HKDF-Expand-Label to derive key, IV, HP key from each level's secret
- [ ] AEAD encrypt (AES-128-GCM / AES-256-GCM based on cipher suite)
- [ ] AEAD decrypt
- [ ] Header protection: apply packet number masking (AES-ECB)
- [ ] Header protection: remove packet number masking
- [ ] Packet number encoding (1-4 byte truncation)
- [ ] Packet number decoding (reconstruct full PN from truncated)

## 2. Frame Parse/Encode
- [ ] CRYPTO frame parse
- [ ] CRYPTO frame encode
- [ ] ACK frame parse
- [ ] ACK frame encode
- [ ] STREAM frame parse
- [ ] STREAM frame encode
- [ ] CONNECTION_CLOSE frame parse
- [ ] CONNECTION_CLOSE frame encode
- [ ] HANDSHAKE_DONE frame parse
- [ ] HANDSHAKE_DONE frame encode
- [ ] PING frame parse/encode (trivial, type byte only)
- [ ] PADDING frame parse/encode (trivial, type byte only)
- [ ] Frame dispatcher (read type byte, call correct parser)

## 3. Connection State Machine & Handshake Flow
- [ ] Receive Initial packet -> decrypt -> parse frames -> extract CRYPTO
- [ ] Feed CRYPTO data to GnuTLS via crypto_feed
- [ ] Build response: take GnuTLS output -> wrap in CRYPTO frames -> build packet -> encrypt -> send
- [ ] State transitions: Idle -> Initial -> Handshake -> Established
- [ ] Server sends HANDSHAKE_DONE after handshake completes
- [ ] Drop Initial keys after Handshake keys are available
- [ ] Drop Handshake keys after handshake confirmed

## 4. Transport Parameters (RFC 9000 Section 18)
- [ ] Define transport params struct (initial_max_data, initial_max_stream_data_bidi_local, initial_max_streams_bidi, max_idle_timeout)
- [ ] Encode transport params to wire format
- [ ] Decode transport params from wire format
- [ ] Register TLS extension via gnutls_session_ext_register()
- [ ] Exchange params during handshake

## 5. ACK Generation & Basic Loss Detection (RFC 9002, simplified)
- [ ] Track sent packets: pkt_num -> list of frames contained
- [ ] Track received packet numbers (per packet number space)
- [ ] Generate ACK frames from received PN set
- [ ] Threshold-based loss detection (3 packets past = lost)
- [ ] Retransmit lost CRYPTO frame data
- [ ] Retransmit lost STREAM frame data
- [ ] PTO (probe timeout) — hardcoded timeout, send PING

## 6. Streams (RFC 9000 Section 2-3)
- [ ] Stream map: stream_id -> stream state (hash table)
- [ ] Per-stream send buffer with offset tracking
- [ ] Per-stream receive buffer with offset reassembly
- [ ] Stream state machine (open, half-closed, closed)
- [ ] FIN handling
- [ ] Flow control: track and enforce MAX_DATA (connection-level)
- [ ] Flow control: track and enforce MAX_STREAM_DATA (per-stream)
- [ ] Send MAX_DATA / MAX_STREAM_DATA updates as data is consumed
- [ ] MAX_STREAMS enforcement

## Done
- [x] Packet parse/encode (all 5 types)
- [x] Frame structs (all 19 types defined)
- [x] Varint encode/decode
- [x] Connection struct with packet number spaces
- [x] Connection hash tables (by CID, by addr)
- [x] TLS 1.3 handshake via GnuTLS QUIC API (crypt.c)
- [x] Secret extraction per encryption level
- [x] UDP socket + libev event loop (test.c)
