#include <ev.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
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

// Minimal WebTransport client: open a session, send one datagram, print the
// server's echo, exit. Mirrors minimal_h3_client.c's bring-up but drives the
// WT layer in parallel with H3, like wt_server.c does.

#define DEFAULT_PORT "4433"
#define BUF_SIZE 65535
#define WT_PAYLOAD "Hello from wt_client!"
#define WT_STREAM_PAYLOAD "Stream hello from wt_client!"

static int sockfd;
static YAWT_Q_Crypto_Cred_t *client_cred;
static uint8_t recv_buf[BUF_SIZE];
static struct ev_loop *main_loop;

static char req_host[256];
static char req_path[2048];
static char req_port[16];

static struct sockaddr_in server_addr;
static int echo_received = 0;
static int stream_echo_received = 0;

static void udp_send(const uint8_t *buf, size_t len,
                      const YAWT_Q_PeerAddr_t *peer_addr) {
  ssize_t nsent = sendto(sockfd, buf, len, 0,
                         (const struct sockaddr *)peer_addr->addr, peer_addr->len);
  YAWT_LOG(YAWT_LOG_DEBUG, "sent %zd bytes", nsent);
}

// App-level WT events: the server echoes our datagram back to us.
static void wt_app_handler(YAWT_WT_Context_t *ctx,
                            YAWT_WT_Session_t *session,
                            YAWT_WT_EventType_t event,
                            YAWT_WT_EventParam_t param) {
  (void)ctx;
  (void)session;
  switch (event) {
    case YAWT_WT_EVT_SESSION_ESTABLISHED: {
      // The WT layer signals the session is ready; now we can send. (The H3
      // WT_UPGRADE event only tells us whether the CONNECT was accepted.)
      uint64_t sid = param.P_EVT_SESSION_ESTABLISHED.session_id;
      YAWT_wt_send_datagram(ctx, sid, (const uint8_t *)WT_PAYLOAD, strlen(WT_PAYLOAD));
      printf("wt: session %lu established, sent datagram\n", sid);
      /* Also open a bidirectional WT stream and send on it; the server echoes it
       * back on the same stream (draft-15 §4.3). */
      uint64_t stream_id;
      if (YAWT_wt_open_stream(ctx, sid, YAWT_WT_DIR_BIDI, &stream_id) == YAWT_WT_OK) {
        YAWT_wt_send_data(ctx, sid, stream_id,
                          (const uint8_t *)WT_STREAM_PAYLOAD, strlen(WT_STREAM_PAYLOAD), 1);
        printf("wt: opened bidi stream %lu, sent data\n", stream_id);
      } else {
        fprintf(stderr, "wt: failed to open bidi stream\n");
      }
      fflush(stdout);
      break;
    }
    case YAWT_WT_EVT_DATAGRAM:
      printf("wt: echo %.*s\n",
             (int)param.P_EVT_DATAGRAM.len, param.P_EVT_DATAGRAM.data);
      fflush(stdout);
      echo_received = 1;
      if (echo_received && stream_echo_received) ev_break(main_loop, EVBREAK_ALL);
      break;
    case YAWT_WT_EVT_STREAM_DATA:
      printf("wt: stream echo %.*s\n",
             (int)param.P_EVT_STREAM_DATA.len, param.P_EVT_STREAM_DATA.data);
      fflush(stdout);
      stream_echo_received = 1;
      if (echo_received && stream_echo_received) ev_break(main_loop, EVBREAK_ALL);
      break;
    case YAWT_WT_EVT_CAPSULE_RECEIVED:
      break;
  }
}

// App-level H3 events. On the client, WT_UPGRADE fires when the server's
// response to our CONNECT arrives (src/h3.c). The stream type tells us whether
// the session was accepted (2xx -> WT_CONNECT) or rejected.
static void h3_app_handler(YAWT_H3_Context_t *h3con,
                            YAWT_H3_EventType_t event,
                            YAWT_H3_EventParam_t param) {
  /* Pump every H3 event into the WT layer first; on WT_UPGRADE (2xx accepted)
   * WT creates the session and emits YAWT_WT_EVT_SESSION_ESTABLISHED. */
  YAWT_wt_on_h3_event(h3con, event, param);

  switch (event) {
    case YAWT_H3_EVT_WT_UPGRADE: {
      // Client-side WT_UPGRADE fires when the server's CONNECT response arrives.
      // We only detect rejection here — on acceptance the WT layer (pumped
      // above) creates the session and fires YAWT_WT_EVT_SESSION_ESTABLISHED,
      // where we do the actual sending.
      uint64_t sid = param.P_EVT_WT_UPGRADE.stream_id;
      uint64_t stype = YAWT_h3_stream_get_type(h3con, sid);
      if (stype != YAWT_H3_STREAM_WT_CONNECT) {
        fprintf(stderr, "wt: CONNECT rejected on stream %lu (type=%lu)\n", sid, stype);
        ev_break(main_loop, EVBREAK_ALL);
      }
      break;
    }
    case YAWT_H3_EVT_CLOSE:
      ev_break(main_loop, EVBREAK_ALL);
      break;
    default:
      break;
  }
}

static void on_event(YAWT_Q_Context_t *con,
                      YAWT_Q_EventType_t event,
                      YAWT_Q_EventParam_t param) {
  YAWT_H3_Error_t rc = YAWT_h3_on_event(con, event, param);
  YAWT_wt_on_event(con, event, param);

  if (event == YAWT_Q_EVT_CONNECTED && rc == YAWT_H3_OK) {
    YAWT_H3_Context_t *h3 = YAWT_q_con_get_user_data(con, YAWT_UD_H3);
    YAWT_WT_Context_t *wt = YAWT_q_con_get_user_data(con, YAWT_UD_WT);
    if (wt) {
      YAWT_wt_set_event_handler(wt, wt_app_handler);
    }
    if (h3) {
      YAWT_h3_set_event_handler(h3, h3_app_handler);
      char authority[280];
      snprintf(authority, sizeof(authority), "%s:%s", req_host, req_port);
      uint64_t stream_id = YAWT_q_con_next_stream_id(con, true);
      YAWT_h3_webtrans_upgrade(h3, stream_id, "https", authority, req_path);
      YAWT_LOG(YAWT_LOG_INFO, "sent WT CONNECT to %s%s", authority, req_path);
    }
  }

  switch (event) {
    case YAWT_Q_EVT_TX:
      udp_send(param.P_EVT_TX.buf, param.P_EVT_TX.len, param.P_EVT_TX.peer);
      break;
    case YAWT_Q_EVT_CLOSE:
      ev_break(main_loop, EVBREAK_ALL);
      break;
    default:
      break;
  }
}

static void udp_read_cb(EV_P_ ev_io *w, int revents) {
  (void)w;
  (void)revents;

  struct sockaddr_in from_addr;
  socklen_t from_len = sizeof(from_addr);
  ssize_t nread = recvfrom(sockfd, recv_buf, sizeof(recv_buf), 0,
                           (struct sockaddr *)&from_addr, &from_len);
  if (nread < 0) {
    perror("recvfrom");
    return;
  }

  YAWT_Q_PeerAddr_t peer = { .addr = &from_addr, .len = from_len };
  double now = ev_now(loop);
  YAWT_q_con_rx(recv_buf, (size_t)nread, client_cred, &peer, now);
}

static void maintain_cb(EV_P_ ev_timer *w, int revents) {
  (void)w;
  (void)revents;

  double now = ev_now(loop);
  YAWT_q_con_maintain(now);
  const YAWT_Q_MaintenanceConfig_t *mcfg = YAWT_q_con_get_maint_config();
  w->repeat = mcfg->min_maint_interval;
  ev_timer_again(loop, w);
}

// Hard timeout guard so the process can never hang if the handshake or the
// echo never completes.
static void timeout_cb(EV_P_ ev_timer *w, int revents) {
  (void)w;
  (void)revents;
  fprintf(stderr, "wt: timeout waiting for echo\n");
  ev_break(loop, EVBREAK_ALL);
}

static int parse_url(const char *url) {
  const char *p = url;
  if (strncmp(p, "https://", 8) == 0) p += 8;
  else if (strncmp(p, "http://", 7) == 0) p += 7;

  const char *slash = strchr(p, '/');
  const char *colon = strchr(p, ':');

  size_t host_len;
  if (colon && (!slash || colon < slash)) {
    host_len = colon - p;
    if (host_len >= sizeof(req_host)) host_len = sizeof(req_host) - 1;
    memcpy(req_host, p, host_len);
    req_host[host_len] = '\0';
    const char *port_start = colon + 1;
    const char *port_end = slash ? slash : port_start + strlen(port_start);
    size_t port_len = port_end - port_start;
    if (port_len >= sizeof(req_port)) port_len = sizeof(req_port) - 1;
    memcpy(req_port, port_start, port_len);
    req_port[port_len] = '\0';
  } else {
    host_len = slash ? (size_t)(slash - p) : strlen(p);
    if (host_len >= sizeof(req_host)) host_len = sizeof(req_host) - 1;
    memcpy(req_host, p, host_len);
    req_host[host_len] = '\0';
    snprintf(req_port, sizeof(req_port), "%s", DEFAULT_PORT);
  }

  if (slash) {
    snprintf(req_path, sizeof(req_path), "%s", slash);
  } else {
    snprintf(req_path, sizeof(req_path), "/");
  }
  return 0;
}

int main(int argc, char *argv[]) {
  const char *url = "https://localhost:4433/";
  const char *ca_file = NULL;

  if (argc >= 2) url = argv[1];
  if (argc >= 3) ca_file = argv[2];

  if (parse_url(url) != 0) {
    fprintf(stderr, "failed to parse URL: %s\n", url);
    return 1;
  }
  printf("connecting to %s:%s%s\n", req_host, req_port, req_path);

  gnutls_global_init();

  YAWT_WT_SecurityPolicy_t wt_policy = {
    .max_sessions = 8,
    .initial_max_streams_uni = 100,
    .initial_max_streams_bidi = 100,
    .initial_max_data = 0x100000,
  };
  YAWT_wt_security_set(&wt_policy);

  client_cred = YAWT_q_crypto_cred_new(NULL, NULL, ca_file);
  if (!client_cred) {
    fprintf(stderr, "failed to create credentials\n");
    return 1;
  }

  struct addrinfo hints = {0}, *res = NULL;
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  int gai_err = getaddrinfo(req_host, req_port, &hints, &res);
  if (gai_err != 0) {
    fprintf(stderr, "DNS resolution failed for %s: %s\n", req_host, gai_strerror(gai_err));
    return 1;
  }

  memcpy(&server_addr, res->ai_addr, sizeof(server_addr));

  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    perror("socket");
    freeaddrinfo(res);
    return 1;
  }

  YAWT_q_con_set_event_handler(on_event);

  YAWT_Q_Con_Create_Info_t info;
  memset(&info, 0, sizeof(info));
  info.is_server = 0;
  info.cred = client_cred;
  info.peer_addr = (YAWT_Q_PeerAddr_t){ .addr = &server_addr, .len = sizeof(server_addr) };
  info.hostname = req_host;

  main_loop = ev_default_loop(0);
  double now = ev_now(main_loop);

  YAWT_Q_Context_t *con = YAWT_q_con_connect(&info, now);
  if (!con) {
    fprintf(stderr, "failed to initiate QUIC connection\n");
    freeaddrinfo(res);
    close(sockfd);
    return 1;
  }

  freeaddrinfo(res);

  ev_io udp_watcher;
  ev_io_init(&udp_watcher, udp_read_cb, sockfd, EV_READ);
  ev_io_start(main_loop, &udp_watcher);

  ev_timer maintain_watcher;
  ev_timer_init(&maintain_watcher, maintain_cb, 0.1, 0);
  ev_timer_start(main_loop, &maintain_watcher);

  ev_timer timeout_watcher;
  ev_timer_init(&timeout_watcher, timeout_cb, 5.0, 0.0);
  ev_timer_start(main_loop, &timeout_watcher);

  ev_run(main_loop, 0);

  YAWT_q_crypto_cred_free(&client_cred);
  gnutls_global_deinit();
  close(sockfd);
  return (echo_received && stream_echo_received) ? 0 : 1;
}
