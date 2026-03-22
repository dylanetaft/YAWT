#include <ev.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <gnutls/gnutls.h>
#include "../include/quic_connection.h"
#include "logger.h"

#define LISTEN_PORT 4433
#define BUF_SIZE 65535

static int sockfd;
static YAWT_Q_Crypto_Cred_t *server_cred;
static uint8_t recv_buf[BUF_SIZE];

// Convert sockaddr_in to YAWT_Q_PeerAddr_t (IPv4-mapped IPv6)
static YAWT_Q_PeerAddr_t _sockaddr_to_peer(const struct sockaddr_in *sa) {
  YAWT_Q_PeerAddr_t pa;
  memset(&pa, 0, sizeof(pa));
  // ::ffff:x.x.x.x
  pa.addr[10] = 0xff;
  pa.addr[11] = 0xff;
  memcpy(&pa.addr[12], &sa->sin_addr.s_addr, 4);
  pa.port = sa->sin_port;
  return pa;
}

// Reconstruct sockaddr_in from YAWT_Q_PeerAddr_t
static struct sockaddr_in _peer_to_sockaddr(const YAWT_Q_PeerAddr_t *pa) {
  struct sockaddr_in sa;
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_port = pa->port;
  memcpy(&sa.sin_addr.s_addr, &pa->addr[12], 4);
  return sa;
}

static void udp_send(const uint8_t *buf, size_t len,
                      const YAWT_Q_PeerAddr_t *peer_addr, void *ctx) {
  (void)ctx;
  struct sockaddr_in sa = _peer_to_sockaddr(peer_addr);
  ssize_t nsent = sendto(sockfd, buf, len, 0,
                         (struct sockaddr *)&sa, sizeof(sa));
  if (nsent < 0) {
    perror("sendto");
  }
}

// How often to check for retransmits (seconds)
#define RETRANSMIT_INTERVAL 0.25

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

  printf("recv %zd bytes from %s:%d\n",
         nread, inet_ntoa(from_addr.sin_addr), ntohs(from_addr.sin_port));

  YAWT_Q_PeerAddr_t peer = _sockaddr_to_peer(&from_addr);
  YAWT_q_con_rx(recv_buf, (size_t)nread, server_cred, &peer);
  YAWT_q_con_tx(udp_send, NULL, ev_now(loop));
}

static void retransmit_cb(EV_P_ ev_timer *w, int revents) {
  (void)w;
  (void)revents;

  double now = ev_now(loop);
  YAWT_q_con_retransmit_lost(now);
  YAWT_q_con_tx(udp_send, NULL, now);
}

int main(int argc, char *argv[]) {
  const char *cert_file = "cert.pem";
  const char *key_file = "key.pem";

  if (argc >= 3) {
    cert_file = argv[1];
    key_file = argv[2];
  }

  gnutls_global_init();

  server_cred = YAWT_q_crypto_cred_new(cert_file, key_file, NULL);
  if (!server_cred) {
    fprintf(stderr, "failed to load cert %s / key %s\n", cert_file, key_file);
    return 1;
  }

  YAWT_LOG(YAWT_LOG_INFO, "Starting QUIC server...");
  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    perror("socket");
    return 1;
  }

  int reuse = 1;
  setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

  struct sockaddr_in bind_addr = {
    .sin_family = AF_INET,
    .sin_port = htons(LISTEN_PORT),
    .sin_addr.s_addr = INADDR_ANY,
  };

  if (bind(sockfd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
    perror("bind");
    close(sockfd);
    return 1;
  }

  printf("listening on udp :%d\n", LISTEN_PORT);

  struct ev_loop *loop = ev_default_loop(0);
  ev_io udp_watcher;
  ev_io_init(&udp_watcher, udp_read_cb, sockfd, EV_READ);
  ev_io_start(loop, &udp_watcher);

  ev_timer retransmit_watcher;
  ev_timer_init(&retransmit_watcher, retransmit_cb, RETRANSMIT_INTERVAL, RETRANSMIT_INTERVAL);
  ev_timer_start(loop, &retransmit_watcher);

  ev_run(loop, 0);

  YAWT_q_crypto_cred_free(&server_cred);
  gnutls_global_deinit();
  close(sockfd);
  return 0;
}
