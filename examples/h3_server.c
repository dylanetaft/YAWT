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

#define DEFAULT_PORT 4433
#define BUF_SIZE 65535

static int sockfd;
static YAWT_Q_Crypto_Cred_t *server_cred;
static uint8_t recv_buf[BUF_SIZE];


static YAWT_Q_PeerAddr_t _sockaddr_to_peer(const struct sockaddr_storage *ss) {
  YAWT_Q_PeerAddr_t pa;
  memset(&pa, 0, sizeof(pa));
  if (ss->ss_family == AF_INET) {
    const struct sockaddr_in *sa = (const struct sockaddr_in *)ss;
    pa.addr[10] = 0xff;
    pa.addr[11] = 0xff;
    memcpy(&pa.addr[12], &sa->sin_addr.s_addr, 4);
    pa.port = sa->sin_port;
  } else {
    const struct sockaddr_in6 *sa6 = (const struct sockaddr_in6 *)ss;
    memcpy(pa.addr, &sa6->sin6_addr, 16);
    pa.port = sa6->sin6_port;
  }
  return pa;
}

static int _is_ipv4_mapped(const YAWT_Q_PeerAddr_t *pa) {
  for (int i = 0; i < 10; i++) {
    if (pa->addr[i] != 0) return 0;
  }
  return pa->addr[10] == 0xff && pa->addr[11] == 0xff;
}


static socklen_t _peer_to_sockaddr(const YAWT_Q_PeerAddr_t *pa,
                                    struct sockaddr_storage *ss) {
  memset(ss, 0, sizeof(*ss));
  if (_is_ipv4_mapped(pa)) {
    struct sockaddr_in *sa = (struct sockaddr_in *)ss;
    sa->sin_family = AF_INET;
    sa->sin_port = pa->port;
    memcpy(&sa->sin_addr.s_addr, &pa->addr[12], 4);
    return sizeof(*sa);
  } else {
    struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)ss;
    sa6->sin6_family = AF_INET6;
    sa6->sin6_port = pa->port;
    memcpy(&sa6->sin6_addr, pa->addr, 16);
    return sizeof(*sa6);
  }
}
static void udp_send(const uint8_t *buf, size_t len,
                       const YAWT_Q_PeerAddr_t *peer_addr) {
  struct sockaddr_storage ss;
  socklen_t ss_len = _peer_to_sockaddr(peer_addr, &ss);
  ssize_t nsent = sendto(sockfd, buf, len, 0,
                         (struct sockaddr *)&ss, ss_len);
  if (nsent < 0) {
    perror("sendto");
    return;
  }
  char addr_str[INET6_ADDRSTRLEN];
  uint16_t port;
  if (ss.ss_family == AF_INET) {
    struct sockaddr_in *sa = (struct sockaddr_in *)&ss;
    inet_ntop(AF_INET, &sa->sin_addr, addr_str, sizeof(addr_str));
    port = ntohs(sa->sin_port);
  } else {
    struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&ss;
    inet_ntop(AF_INET6, &sa6->sin6_addr, addr_str, sizeof(addr_str));
    port = ntohs(sa6->sin6_port);
  }
  YAWT_LOG(YAWT_LOG_DEBUG, "sent %zd bytes to %s:%d\n",
           nsent, addr_str, port);
}

static void h3_app_handler(YAWT_H3_Context_t *h3con,
                             YAWT_H3_EventType_t event,
                             YAWT_H3_EventParam_t param) {
  switch (event) {
    case YAWT_H3_EVT_SETTINGS:
      YAWT_LOG(YAWT_LOG_INFO, "h3 app: SETTINGS on stream %lu",
               param.P_EVT_SETTINGS.stream_id);
      break;
    case YAWT_H3_EVT_HEADERS: {
      uint64_t sid = param.P_EVT_HEADERS.stream_id;
      YAWT_LOG(YAWT_LOG_INFO, "h3 app: HEADERS on stream %lu", sid);

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
      break;
    }
    case YAWT_H3_EVT_DATA:
      YAWT_LOG(YAWT_LOG_INFO, "h3 app: DATA on stream %lu (%zu bytes, fin=%d)",
               param.P_EVT_DATA.stream_id, param.P_EVT_DATA.len,
               param.P_EVT_DATA.fin);
      break;
    case YAWT_H3_EVT_CLOSE:
      YAWT_LOG(YAWT_LOG_INFO, "h3 app: CLOSE (code=%lu, reason=%s)",
               param.P_EVT_CLOSE.error_code, param.P_EVT_CLOSE.reason);
      break;
    // case YAWT_H3_EVT_WT_UNI_STREAM:
    case YAWT_H3_EVT_DATAGRAM:
      break;
    default:
      YAWT_LOG(YAWT_LOG_INFO, "h3 app: unhandled event %d", event);
      break;
  }
}

// App's single event handler: owns transport glue (TX -> UDP write) and forwards
// the application-facing events to the H3 layer.
static void on_event(YAWT_Q_Context_t *con,
                       YAWT_Q_EventType_t event,
                       YAWT_Q_EventParam_t param) {
  switch (event) {
    case YAWT_Q_EVT_TX:
      udp_send(param.P_EVT_TX.buf, param.P_EVT_TX.len, param.P_EVT_TX.peer);
      break;

    default: {
      YAWT_H3_Error_t rc = YAWT_h3_on_event(con, event, param);
      if (event == YAWT_Q_EVT_CONNECTED && rc == YAWT_H3_OK) {
        YAWT_H3_Context_t *h3 = YAWT_q_con_get_user_data(con, YAWT_UD_H3);
        if (h3) {
          YAWT_h3_set_event_handler(h3, h3_app_handler);
        }
      }
      if (rc == YAWT_H3_ERR_NO_APP_HANDLER) {
        YAWT_LOG(YAWT_LOG_WARN, "h3: event %d processed but no app handler set", event);
      } else if (rc == YAWT_H3_IGNORED) {
        YAWT_LOG(YAWT_LOG_DEBUG, "h3: event %d ignored", event);
      }
      break;
    }
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

  YAWT_Q_PeerAddr_t peer = _sockaddr_to_peer(&from_addr);
  double now = ev_now(loop);
  YAWT_q_con_rx(recv_buf, (size_t)nread, server_cred, &peer, now);
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

  server_cred = YAWT_q_crypto_cred_new(cert_file, key_file, NULL);
  if (!server_cred) {
    YAWT_LOG(YAWT_LOG_ERROR, "failed to load cert %s / key %s", cert_file, key_file);
    return 1;
  }

  if (YAWT_q_crypto_cert_validate(server_cred, "localhost") != YAWT_Q_OK) {
    YAWT_LOG(YAWT_LOG_WARN, "certificate validation failed");
  }

  YAWT_q_con_set_event_handler(on_event);

  YAWT_LOG(YAWT_LOG_INFO, "Starting QUIC server...");



  sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    perror("socket");
    return 1;
  }

  int reuse = 1;
  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
    perror("setsockopt SO_REUSEADDR");
  }

  int v6only = 0;
  if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only)) < 0) {
    perror("setsockopt IPV6_V6ONLY");
  }

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

  printf("listening on udp [::]:%d\n", port);

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
