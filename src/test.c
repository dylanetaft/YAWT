#include <ev.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include "../include/quic.h"
#include "../include/quic_connection.h"
#include "logger.h"


#define LISTEN_PORT 4433
#define BUF_SIZE 65535

static int sockfd;
static struct sockaddr_in peer_addr;
static socklen_t peer_addr_len;

static uint8_t recv_buf[BUF_SIZE];

static void udp_read_cb(EV_P_ ev_io *w, int revents) {
  (void)loop;
  (void)w;
  (void)revents;

  peer_addr_len = sizeof(peer_addr);
  ssize_t nread = recvfrom(sockfd, recv_buf, sizeof(recv_buf), 0,
                           (struct sockaddr *)&peer_addr, &peer_addr_len);
  if (nread < 0) {
    perror("recvfrom");
    return;
  }

  printf("recv %zd bytes from %s:%d\n",
         nread, inet_ntoa(peer_addr.sin_addr), ntohs(peer_addr.sin_port));

  YAWT_q_process_datagram(recv_buf, (size_t)nread, NULL);
}

// Send buf to the last-seen peer address
static void udp_send(const uint8_t *buf, size_t len) {
  if (peer_addr_len == 0) {
    fprintf(stderr, "no peer address yet\n");
    return;
  }
  ssize_t nsent = sendto(sockfd, buf, len, 0,
                         (struct sockaddr *)&peer_addr, peer_addr_len);
  if (nsent < 0) {
    perror("sendto");
  }
}

int main(void) {
  YAWT_LOG(YAWT_LOG_INFO, "Starting QUIC server...");
  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    perror("socket");
    return 1;
  }

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

  gnutls_global_init();

  ev_run(loop, 0);

  gnutls_global_deinit();

  close(sockfd);
  return 0;
}
