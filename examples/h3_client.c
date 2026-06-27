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

#define DEFAULT_PORT "443"
#define BUF_SIZE 65535

static int sockfd;
static YAWT_Q_Crypto_Cred_t *client_cred;
static uint8_t recv_buf[BUF_SIZE];
static struct ev_loop *main_loop;

static char req_host[256];
static char req_path[2048];
static char req_port[16];

static YAWT_Q_PeerAddr_t server_addr;
static ANB_Blob_t *recv_blob;

static YAWT_Q_PeerAddr_t _sockaddr_to_peer(const struct sockaddr_in *sa) {
  YAWT_Q_PeerAddr_t pa;
  memset(&pa, 0, sizeof(pa));
  pa.addr[10] = 0xff;
  pa.addr[11] = 0xff;
  memcpy(&pa.addr[12], &sa->sin_addr.s_addr, 4);
  pa.port = sa->sin_port;
  return pa;
}

static struct sockaddr_in _peer_to_sockaddr(const YAWT_Q_PeerAddr_t *pa) {
  struct sockaddr_in sa;
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_port = pa->port;
  memcpy(&sa.sin_addr.s_addr, &pa->addr[12], 4);
  return sa;
}

static void udp_send(const uint8_t *buf, size_t len,
                      const YAWT_Q_PeerAddr_t *peer_addr) {
  struct sockaddr_in sa = _peer_to_sockaddr(peer_addr);
  ssize_t nsent = sendto(sockfd, buf, len, 0,
                         (struct sockaddr *)&sa, sizeof(sa));
  YAWT_LOG(YAWT_LOG_DEBUG, "sent %zd bytes to %s:%d\n",
           nsent, inet_ntoa(sa.sin_addr), ntohs(sa.sin_port));
}

static void h3_app_handler(YAWT_H3_Connection_t *h3con,
                            YAWT_H3_EventType_t event,
                            YAWT_H3_EventParam_t param) {
  switch (event) {
    case YAWT_H3_EVT_SETTINGS:
      YAWT_LOG(YAWT_LOG_INFO, "received SETTINGS");
      break;
    case YAWT_H3_EVT_HEADERS: {
      YAWT_H3_HeaderFields_t *hdrs = param.P_EVT_HEADERS.headers;
      YAWT_H3_Header_Field_t status = YAWT_h3_header_find_str(hdrs, ":status");
      if (status.name) {
        printf("HTTP/3 %.*s\n", (int)status.value_len, status.value);
      }
      ANB_SlabIter_t iter = {0};
      YAWT_H3_Header_Field_t f;
      while ((f = YAWT_h3_header_iter(hdrs, &iter)).name != NULL) {
        if (f.name[0] == ':') continue;
        printf("%.*s: %.*s\n",
               (int)f.name_len, f.name,
               (int)f.value_len, f.value);
      }
      printf("\n");
      fflush(stdout);
      break;
    }
    case YAWT_H3_EVT_DATA:
      ANB_blob_push(recv_blob, param.P_EVT_DATA.data, param.P_EVT_DATA.len);
      YAWT_LOG(YAWT_LOG_INFO, "received DATA len %lu, fin=%d",
               param.P_EVT_DATA.len, param.P_EVT_DATA.fin);  
      if (param.P_EVT_DATA.fin) 
      {
        YAWT_LOG(YAWT_LOG_INFO, "%.*s", (int)ANB_blob_data_len(recv_blob), ANB_blob_data(recv_blob));
        ev_break(main_loop, EVBREAK_ALL);
        //theres no way to close e3 or quic c here TODO
      }
      break;
    case YAWT_H3_EVT_CLOSE:
      YAWT_LOG(YAWT_LOG_INFO, "h3 close: code=%lu, reason=%s",
               param.P_EVT_CLOSE.error_code, param.P_EVT_CLOSE.reason);
      ev_break(main_loop, EVBREAK_ALL);
      break;
    case YAWT_H3_EVT_WT_UNI_STREAM:
    case YAWT_H3_EVT_DATAGRAM:
      break;
  }
}

static void on_event(YAWT_Q_Connection_t *con,
                      YAWT_Q_EventType_t event,
                      YAWT_Q_EventParam_t param) {
  switch (event) {
    case YAWT_Q_EVT_TX:
      udp_send(param.P_EVT_TX.buf, param.P_EVT_TX.len, param.P_EVT_TX.peer);
      break;

    case YAWT_Q_EVT_CONNECTED: {
      YAWT_H3_Error_t rc = YAWT_h3_on_event(con, event, param);
      if (rc != YAWT_H3_OK) break;
      YAWT_H3_Connection_t *h3 = YAWT_q_con_get_user_data(con, YAWT_UD_H3);
      if (!h3) break;
      YAWT_h3_set_event_handler(h3, h3_app_handler);

      YAWT_H3_HeaderFields_t *req = YAWT_h3_header_fields_create();
      YAWT_h3_header_add_str(req, ":method", "GET");
      YAWT_h3_header_add_str(req, ":scheme", "https");
      YAWT_h3_header_add_str(req, ":authority", req_host);
      YAWT_h3_header_add_str(req, ":path", req_path);
      YAWT_h3_header_add_str(req, "user-agent", "yawt-h3-client/0.1");
      YAWT_h3_header_add_str(req, "accept", "*/*");

      uint64_t stream_id = 0;
      YAWT_h3_send_headers(h3, stream_id, req, 1);
      YAWT_h3_header_fields_destroy(req);

      YAWT_LOG(YAWT_LOG_INFO, "sent GET %s to %s", req_path, req_host);
      break;
    }

    case YAWT_Q_EVT_CLOSE: {
      YAWT_h3_on_event(con, event, param);
      ev_break(main_loop, EVBREAK_ALL);
      break;
    }

    default: {
      YAWT_H3_Error_t rc = YAWT_h3_on_event(con, event, param);
      if (rc == YAWT_H3_ERR_NO_APP_HANDLER) {
        YAWT_LOG(YAWT_LOG_DEBUG, "h3: no app handler yet for event %d", event);
      }
      break;
    }
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

  YAWT_Q_PeerAddr_t peer = _sockaddr_to_peer(&from_addr);
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
  const char *url = "https://www.rfc-editor.org/rfc/rfc9114.txt";
  const char *ca_file = NULL;

  if (argc >= 2) url = argv[1];
  if (argc >= 3) ca_file = argv[2];

  if (parse_url(url) != 0) {
    fprintf(stderr, "failed to parse URL: %s\n", url);
    return 1;
  }
  recv_blob = ANB_blob_create(4096);
  printf("connecting to %s:%s%s\n", req_host, req_port, req_path);

  gnutls_global_init();

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

  server_addr = _sockaddr_to_peer((struct sockaddr_in *)res->ai_addr);

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
  info.peer_addr = server_addr;
  info.hostname = req_host;

  main_loop = ev_default_loop(0);
  double now = ev_now(main_loop);

  YAWT_Q_Connection_t *con = YAWT_q_con_connect(&info, now);
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

  ev_run(main_loop, 0);

  YAWT_q_crypto_cred_free(&client_cred);
  gnutls_global_deinit();
  close(sockfd);
  return 0;
}
