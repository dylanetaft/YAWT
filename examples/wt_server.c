#include <ev.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <gnutls/gnutls.h>
#include <quic_connection.h>
#include <quic_types.h>
#include <h3.h>
#include <h3_types.h>
#include <h3_header.h>
#include <wt.h>
#include <wt_types.h>
#include <security.h>

// Minimal WebTransport echo server: accept a WT session, echo back any
// stream data and datagrams the client sends.
// The point of this example is the layering — QUIC events pump down into H3,
// H3 events pump down into WT. You forward each event to the layer below
// before doing any work of your own, then hang your app logic off the
// highest layer (WT here) via its event handler.

#define DEFAULT_PORT 4433
#define BUF_SIZE 65535

static int sockfd;
static YAWT_Q_Crypto_Cred_t *server_cred;
static uint8_t recv_buf[BUF_SIZE];

// UDP send callback for QUIC.
// You can implement this with whichever socket library you want -
// this uses standard BSD sockets. https://beej.us/guide/bgnet/
// The address logging below is purely cosmetic.
static void udp_send(const uint8_t *buf, size_t len,
                       const YAWT_Q_PeerAddr_t *peer_addr) {
  ssize_t nsent = sendto(sockfd, buf, len, 0,
                         (const struct sockaddr *)peer_addr->addr, peer_addr->len);
  const struct sockaddr *sa = (const struct sockaddr *)peer_addr->addr;
  char addr_str[INET6_ADDRSTRLEN];
  uint16_t port;
  if (sa->sa_family == AF_INET) {
    const struct sockaddr_in *s4 = (const struct sockaddr_in *)sa;
    inet_ntop(AF_INET, &s4->sin_addr, addr_str, sizeof(addr_str));
    port = ntohs(s4->sin_port);
  } else {
    const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)sa;
    inet_ntop(AF_INET6, &s6->sin6_addr, addr_str, sizeof(addr_str));
    port = ntohs(s6->sin6_port);
  }
  YAWT_LOG(YAWT_LOG_DEBUG, "sent %zd bytes to %s:%d\n",
           nsent, addr_str, port);
}

// App-level WebTransport events. This is where your application lives:
// a session came up, bytes arrived on a stream, or a datagram arrived.
// This handler just echoes everything back to the client.
static void wt_app_handler(YAWT_WT_Context_t *ctx,
                              YAWT_WT_Session_t *session,
                              YAWT_WT_EventType_t event,
                              YAWT_WT_EventParam_t param) {
  switch (event) {
    case YAWT_WT_EVT_SESSION_ESTABLISHED:
      YAWT_LOG(YAWT_LOG_INFO, "wt app: SESSION_ESTABLISHED, session=%lu",
               param.P_EVT_SESSION_ESTABLISHED.session_id);
      break;
    case YAWT_WT_EVT_STREAM_DATA:
      YAWT_LOG(YAWT_LOG_INFO, "wt app: STREAM_DATA, session=%lu stream=%lu (%zu bytes), echoing",
                param.P_EVT_STREAM_DATA.session_id, param.P_EVT_STREAM_DATA.stream_id,
                param.P_EVT_STREAM_DATA.len);
      /* Echo the bytes back on the same (client-initiated bidi) stream.
       * WT owns the stream lifecycle; you just hand it session+stream ids. */
      YAWT_wt_send_data(ctx, param.P_EVT_STREAM_DATA.session_id,
                        param.P_EVT_STREAM_DATA.stream_id,
                        param.P_EVT_STREAM_DATA.data,
                        param.P_EVT_STREAM_DATA.len, 0);
      break;
    case YAWT_WT_EVT_DATAGRAM:
      YAWT_LOG(YAWT_LOG_INFO, "wt app: DATAGRAM, session=%lu (%zu bytes), echoing",
               param.P_EVT_DATAGRAM.session_id, param.P_EVT_DATAGRAM.len);
      YAWT_wt_send_datagram(ctx, param.P_EVT_DATAGRAM.session_id,
                            param.P_EVT_DATAGRAM.data,
                            param.P_EVT_DATAGRAM.len);
      break;
    case YAWT_WT_EVT_CAPSULE_RECEIVED:
      YAWT_LOG(YAWT_LOG_INFO, "wt app: CAPSULE, session=%lu, stream=%lu, type=0x%x",
               param.P_EVT_CAPSULE_RECEIVED.session_id,
               param.P_EVT_CAPSULE_RECEIVED.stream_id,
               param.P_EVT_CAPSULE_RECEIVED.type);
      break;
  }
}

// App-level H3 events. WebTransport rides on top of H3, so this handler is
// mostly plumbing: forward every H3 event down into WT, then handle the few
// things the app cares about (the CONNECT upgrade, and plain HTTP requests).
static void h3_app_handler(YAWT_H3_Context_t *h3con,
                              YAWT_H3_EventType_t event,
                              YAWT_H3_EventParam_t param) {

  /* Pump every H3 event into the WT layer first; WT keys off WT_UPGRADE (which
   * H3 fires post-accept) to create the session and emit SESSION_ESTABLISHED. */
  YAWT_wt_on_h3_event(h3con, event, param);

  switch (event) {
    case YAWT_H3_EVT_SETTINGS:
      YAWT_LOG(YAWT_LOG_INFO, "wt app: SETTINGS on stream %lu",
               param.P_EVT_SETTINGS.stream_id);
      break;
    case YAWT_H3_EVT_HEADERS: {
      uint64_t sid = param.P_EVT_HEADERS.stream_id;
      YAWT_H3_HeaderFields_t *headers = param.P_EVT_HEADERS.headers;

      YAWT_H3_Header_Field_t method = YAWT_h3_header_find_str(headers, ":method");

      if (method.name && strncmp(method.value, "CONNECT", method.value_len) == 0) {
        /* A CONNECT is the WebTransport handshake; the actual accept/reject
         * decision happens in WT_UPGRADE_REQUEST below, so nothing to do here. */
        YAWT_LOG(YAWT_LOG_INFO, "wt app: CONNECT request on stream %lu (handled by WT_UPGRADE event)", sid);
      } else {
        /* Any ordinary GET/POST — reply with a canned HTTP/3 response so the
         * same server answers a browser as well as a WebTransport client. */
        YAWT_LOG(YAWT_LOG_INFO, "wt app: non-CONNECT request on stream %lu", sid);
        const char *body = "Hello, HTTP/3!";
        size_t body_len = strlen(body);
        char cl_buf[16];
        snprintf(cl_buf, sizeof(cl_buf), "%zu", body_len);

        YAWT_H3_HeaderFields_t *resp = YAWT_h3_header_fields_create();
        YAWT_h3_header_add_str(resp, ":status", "200");
        YAWT_h3_header_add_str(resp, "content-type", "text/html");
        YAWT_h3_header_add_str(resp, "content-length", cl_buf);

        YAWT_h3_send_headers(h3con, sid, resp, 0);
        YAWT_h3_send_data(h3con, sid, (const uint8_t *)body, body_len, 1);
        YAWT_h3_header_fields_destroy(resp);
      }
      break;
    }
    case YAWT_H3_EVT_WT_UPGRADE_REQUEST: {
      uint64_t sid = param.P_EVT_WT_UPGRADE_REQUEST.stream_id;
      YAWT_LOG(YAWT_LOG_INFO, "wt app: WT_UPGRADE_REQUEST on stream %lu, accepting", sid);
      /* Accept the CONNECT (send 2xx). This fires YAWT_H3_EVT_WT_UPGRADE, which
       * the pump at the top of this handler turns into a WT session and a
       * YAWT_WT_EVT_SESSION_ESTABLISHED event. */
      YAWT_h3_webtrans_accept(h3con, sid);
      break;
    }
    case YAWT_H3_EVT_WT_UPGRADE:
      /* Session established (post-accept) — already handled by the pump above. */
      break;
    case YAWT_H3_EVT_DATA: {
      uint64_t sid = param.P_EVT_DATA.stream_id;
      /* WT stream/datagram payloads surface as WT events (handled in
       * wt_app_handler); the only H3 DATA we care about here is capsules.
       * If the stream is a WT_CONNECT, feed DATA bytes to the per-session
       * capsule parser. Capsule types (CLOSE_SESSION, DRAIN_SESSION, etc.)
       * flow on the CONNECT stream per draft-15 §6. */
      uint64_t stype = YAWT_h3_stream_get_type(h3con, sid);
      if (stype == YAWT_H3_STREAM_WT_CONNECT) {
        YAWT_WT_Context_t *wt_ctx = YAWT_q_con_get_user_data(
            YAWT_h3_get_qcon(h3con), YAWT_UD_WT);
        if (wt_ctx) {
          YAWT_wt_receive_capsule(wt_ctx, sid,
                                  param.P_EVT_DATA.data,
                                  param.P_EVT_DATA.len);
        }
      } else {
        YAWT_LOG(YAWT_LOG_INFO, "wt app: DATA on stream %lu (%zu bytes, fin=%d) type=%lu",
                 sid, param.P_EVT_DATA.len, param.P_EVT_DATA.fin, stype);
      }
      break;
    }
    case YAWT_H3_EVT_CLOSE:
      YAWT_LOG(YAWT_LOG_INFO, "wt app: CLOSE (code=%lu, reason=%s)",
               param.P_EVT_CLOSE.error_code, param.P_EVT_CLOSE.reason);
      break;
    case YAWT_H3_EVT_DATAGRAM:
      YAWT_LOG(YAWT_LOG_INFO, "wt app: DATAGRAM (%zu bytes)",
               param.P_EVT_DATAGRAM.len);
      break;
  }
}

// QUIC-level events. This is the top of the pump: forward each event to the
// H3 and WT layers, then wire up our app handlers once the connection is up.
static void on_event(YAWT_Q_Context_t *con,
                       YAWT_Q_EventType_t event,
                       YAWT_Q_EventParam_t param) {
  // Pass every QUIC event to the downstream protocols first. H3 bootstraps its
  // context on CONNECTED; WT bootstraps off H3, so order matters here.
  YAWT_H3_Error_t rc = YAWT_h3_on_event(con, event, param);
  YAWT_wt_on_event(con, event, param);

  if (event == YAWT_Q_EVT_CONNECTED && rc == YAWT_H3_OK) {
    // The layers created their contexts while handling CONNECTED above, so we
    // can now fetch them and attach our own handlers to receive app events.
    YAWT_H3_Context_t *h3 = YAWT_q_con_get_user_data(con, YAWT_UD_H3);
    YAWT_WT_Context_t *wt = YAWT_q_con_get_user_data(con, YAWT_UD_WT);
    if (h3) {
      YAWT_h3_set_event_handler(h3, h3_app_handler);
    }
    if (wt) {
      YAWT_wt_set_event_handler(wt, wt_app_handler);
    }
  }
  if (rc == YAWT_H3_ERR_NO_APP_HANDLER) {
    YAWT_LOG(YAWT_LOG_WARN, "h3: event %d processed but no app handler set", event);
  } else if (rc == YAWT_H3_IGNORED) {
    YAWT_LOG(YAWT_LOG_DEBUG, "h3: event %d ignored", event);
  }

  // The library hands us fully-formed QUIC packets to put on the wire.
  switch (event) {
    case YAWT_Q_EVT_TX:
      udp_send(param.P_EVT_TX.buf, param.P_EVT_TX.len, param.P_EVT_TX.peer);
      break;
    default:
      break;
  }
}

static void udp_read_cb(EV_P_ ev_io *w, int revents) {
  (void)w;
  (void)revents;

  struct sockaddr_storage from_addr;
  socklen_t from_len = sizeof(from_addr);
  ssize_t nread = recvfrom(sockfd, recv_buf, sizeof(recv_buf), 0,
                           (struct sockaddr *)&from_addr, &from_len);
  if (nread < 0) {
    perror("recvfrom");
    return;
  }

  char addr_str[INET6_ADDRSTRLEN];
  uint16_t port;
  if (from_addr.ss_family == AF_INET) {
    struct sockaddr_in *sa = (struct sockaddr_in *)&from_addr;
    inet_ntop(AF_INET, &sa->sin_addr, addr_str, sizeof(addr_str));
    port = ntohs(sa->sin_port);
  } else {
    struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&from_addr;
    inet_ntop(AF_INET6, &sa6->sin6_addr, addr_str, sizeof(addr_str));
    port = ntohs(sa6->sin6_port);
  }
  printf("recv %zd bytes from %s:%d\n", nread, addr_str, port);

  YAWT_Q_PeerAddr_t peer = { .addr = &from_addr, .len = from_len };
  double now = ev_now(loop);
  YAWT_q_con_rx(recv_buf, (size_t)nread, server_cred, &peer, now);
}

// QUIC connections need periodic maintenance for retransmissions, timeouts,
// and other protocol-level bookkeeping. Call YAWT_q_con_maintain() on a timer;
// the library tells us how soon it needs to run again via the maint config.
static void maintain_cb(EV_P_ ev_timer *w, int revents) {
  (void)w;
  (void)revents;

  double now = ev_now(loop);
  YAWT_q_con_maintain(now);
  const YAWT_Q_MaintenanceConfig_t *mcfg = YAWT_q_con_get_maint_config();
  w->repeat = mcfg->min_maint_interval;
  ev_timer_again(loop, w);
}

int main(int argc, char *argv[]) {
  const char *cert_file = "cert.pem";
  const char *key_file = "key.pem";
  uint16_t port = DEFAULT_PORT;

  if (argc >= 3) {
    cert_file = argv[1];
    key_file = argv[2];
  }
  if (argc >= 4) {
    port = (uint16_t)atoi(argv[3]);
  }

  gnutls_global_init();

  // WebTransport resource limits advertised to clients. These bound how many
  // sessions/streams a peer may open and how much data it may send.
  YAWT_WT_SecurityPolicy_t wt_policy = {
    .max_sessions = 8,
    .initial_max_streams_uni = 100,
    .initial_max_streams_bidi = 100,
    .initial_max_data = 0x100000,
  };
  YAWT_wt_security_set(&wt_policy);

  // Load the server cert + key. A server needs both; there's no system trust
  // store fallback like the client has.
  server_cred = YAWT_q_crypto_cred_new(cert_file, key_file, NULL);
  if (!server_cred) {
    YAWT_LOG(YAWT_LOG_ERROR, "failed to load cert %s / key %s", cert_file, key_file);
    return 1;
  }

  if (YAWT_q_crypto_cert_validate(server_cred, "localhost") != YAWT_Q_OK) {
    YAWT_LOG(YAWT_LOG_WARN, "certificate validation failed");
  }

  // Register the QUIC event handler. On the server side there's no connect
  // call — the library spins up a connection context when the first packet of
  // a new connection arrives via YAWT_q_con_rx().
  YAWT_q_con_set_event_handler(on_event);

  YAWT_LOG(YAWT_LOG_INFO, "Starting WebTransport server...");
  // Standard BSD sockets again - a dual-stack IPv6 socket (v6only off below)
  // so it accepts both IPv4 and IPv6 clients. https://beej.us/guide/bgnet/
  sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    perror("socket");
    return 1;
  }

  int reuse = 1;
  setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

  int v6only = 0;
  setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));

  struct sockaddr_in6 bind_addr = {
    .sin6_family = AF_INET6,
    .sin6_port = htons(port),
    .sin6_addr = in6addr_any,
  };

  if (bind(sockfd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
    perror("bind");
    close(sockfd);
    return 1;
  }

  printf("WebTransport server listening on udp [::]:%d\n", port);

  // We use libev for this example, but any async I/O library works: the
  // library is driven purely by feeding it received bytes (YAWT_q_con_rx)
  // and ticking maintenance (YAWT_q_con_maintain). https://github.com/enki/libev
  struct ev_loop *loop = ev_default_loop(0);
  ev_io udp_watcher;
  ev_io_init(&udp_watcher, udp_read_cb, sockfd, EV_READ);
  ev_io_start(loop, &udp_watcher);

  ev_timer maintain_watcher;
  ev_timer_init(&maintain_watcher, maintain_cb, 0.5, 0);
  ev_timer_start(loop, &maintain_watcher);

  ev_run(loop, 0);

  YAWT_q_crypto_cred_free(&server_cred);
  gnutls_global_deinit();
  close(sockfd);
  return 0;
}
