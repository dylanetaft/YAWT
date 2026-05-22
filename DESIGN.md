# YAWT QUIC Design

## Frame Pipeline

### Outbound (TX)

Frames are the unit of reliability. A frame may need to be retransmitted if its
containing packet is never ACKed, so outbound frames live in a Slab
(`tx_buffer`) until acknowledged.

The generic `YAWT_Q_WireFrame_t` stores the minimum needed for retransmission:
- `type` and `level` — which packet type to send in
- `wire_data[YAWT_Q_MAX_PKT_SIZE]` / `wire_len` — pre-encoded wire bytes, self-contained
- `packet_num` / `last_sent` — tracking for loss detection

No frame-specific union or pointers — the wire bytes are the source of truth.
If a frame needs resending, the same `wire_data` goes into a new packet with a
new packet number.

**Encode vs Enqueue:**
- `YAWT_q_encode_frame_*` — writes wire format into a caller-provided buffer.
  Used for frames that are not tracked (e.g. PADDING).
- `YAWT_q_enqueue_frame_*` — encodes wire format into a `YAWT_Q_Frame_t`,
  pushes a `YAWT_Q_WireFrame_t` to a Slab queue. Used for frames that need ACK tracking
  (CRYPTO, STREAM, ACK, etc.).

### Inbound (RX)

Zero-copy. Parse functions return structs with pointers into the original
datagram buffer. The datagram buffer outlives the parsed structs — crypto
operates in-place on it:

1. `YAWT_q_parse_packet()` — parses header, `pkt->raw` and `pkt->payload`
   point into the datagram
2. `YAWT_q_crypto_unprotect_packet()` — decrypts in-place on the datagram
   buffer using `pkt->raw` for header AAD and writing plaintext back to
   `pkt->payload`
3. `YAWT_q_parse_frames()` — parses decrypted payload, passes frame structs
   (with data pointers into the datagram) to a handler callback

The callback processes each frame before returning. Once the callback returns,
the frame struct and its pointers are no longer referenced.

## Packet Pipeline

### Outbound

`YAWT_q_con_tx()` assembles packets from queued frames (via `_drain_tx` per connection):

1. For each encryption level, collect unsent frames' `wire_data` into a
   contiguous payload buffer
2. Build a `YAWT_Q_Packet_t` on the stack with that payload
3. `YAWT_q_encode_packet()` — single call that:
   - Encodes header + payload into a file-static `_encode_buf`
   - For Initial packets: adds PADDING frames inside the payload to meet
     the 1200-byte minimum (RFC 9000 §14.1)
   - Adds 16 bytes for AEAD tag space in the Length field
   - Encrypts in-place via `YAWT_q_crypto_protect_packet()`
   - Returns a pointer to the static buffer (valid until next encode call)
4. Send directly from the returned buffer pointer — one QUIC packet per UDP
   datagram

Packets are ephemeral — no Slab needed. The static `_encode_buf` is reused
each call.

### Inbound

`YAWT_q_con_rx()` handles coalesced packets in a single UDP datagram:

1. Loop: parse packet, find/create connection, derive keys if needed
2. Decrypt in-place on the datagram buffer
3. Parse frames from decrypted payload via callback

Multiple QUIC packets may be coalesced in one UDP datagram (by the remote peer).
The parse loop handles this via `YAWT_Q_ReadCursor_t` advancing through the
datagram.

## Crypto

Keys are organized by encryption level (Initial, Early, Handshake, Application)
in `YAWT_Q_Level_Keys_t level_keys[4]`.

- **Initial keys**: derived from client's DCID (min 8 bytes, RFC 9000 §7.2)
  plus a well-known salt. Both sides compute independently.
- **Handshake/Application keys**: delivered by GnuTLS via callbacks during the
  TLS handshake.

`YAWT_q_encode_packet()` selects keys internally based on packet type — the
caller just passes all 4 level keys.
