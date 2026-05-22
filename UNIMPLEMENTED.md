# YAWT Unimplemented Features

Intentionally excluded or receive-only features. YAWT is a minimal QUIC implementation.

## Excluded (not planned)
- **ECN** (Explicit Congestion Notification) — RFC 9000 §19.3, ACK-ECN frame type 0x03
- **0-RTT** — RFC 9001 §4.6, early data / session resumption
- **Spin bit** — RFC 9000 §17.4, latency measurement aid
- **Congestion control** — RFC 9002, beyond basic time-based retransmit with backoff
- **Connection migration** — RFC 9000 §9, changing peer address mid-connection
- **Stateless retry** — RFC 9000 §8.1, address validation via Retry packets
- **Preferred address** — RFC 9000 §18.2, server preferred address transport param

## Receive-only (parse + handle, no send)
- **PATH_CHALLENGE / PATH_RESPONSE** — we parse PATH_CHALLENGE and echo PATH_RESPONSE, but never initiate a challenge ourselves
- **NEW_CONNECTION_ID** — we process peer CID updates but don't send our own CID rotations
- **CONNECTION_CLOSE** — we parse it, but don't send it (no graceful shutdown yet)

## Partial / Stubbed
- **Flow control enforcement** — TX-side enforced (max_data + max_stream_data in _drain_tx, max_streams in send_stream); RX-side not yet sending MAX_* frames
- **MAX_DATA / MAX_STREAM_DATA send** — we never send these to raise the peer's limits (our 1MB initial limits are static)
- **Stream state machine** — no OPEN/HALF_CLOSED/CLOSED transitions, just offset tracking
- **RESET_STREAM / STOP_SENDING** — frame structs defined, no parse/encode/handling
- **Key dropping** — Initial and Handshake keys are never dropped after level transitions
- **Idle timeout** — no connection cleanup on inactivity
