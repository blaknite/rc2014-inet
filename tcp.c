#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "slip.h"
#include "ip.h"
#include "tcp.h"

struct tcp_listener *tcp_listen_table;
struct tcp_sock *tcp_sock_table;
static uint8_t next_conn_id = 0;

void tcp_init(void) {
  tcp_listen_table = calloc(TCP_MAX_LISTENERS, sizeof(struct tcp_listener));
  tcp_sock_table = calloc(TCP_MAX_SOCKETS, sizeof(struct tcp_sock));
}

void tcp_debug(struct ip_hdr *iph) {
  struct tcp_hdr *tcph = (struct tcp_hdr *)ip_data(iph);
  uint8_t *raw = (uint8_t *)tcph;

  printf(" sport=%u dport=%u flags=%x", ntohs(tcph->sport), ntohs(tcph->dport), tcph->flags);
}

uint8_t *tcp_data(struct tcp_hdr *tcph) {
  return (uint8_t *)tcph + tcp_hl(tcph);
}

uint16_t tcp_data_len(struct ip_hdr *iph, struct tcp_hdr *tcph) {
  return iph->len - ip_hl(iph) - tcp_hl(tcph);
}

struct tcp_sock *tcp_sock_init(struct ip_hdr *iph) {
  struct tcp_hdr *tcph = (struct tcp_hdr *)ip_data(iph);
  struct tcp_listener *l = NULL;
  struct tcp_sock *s = NULL;
  uint8_t i;
  uint16_t dport_host = ntohs(tcph->dport);
  uint16_t sport_host = ntohs(tcph->sport);

  for (i = 0; i < TCP_MAX_LISTENERS; i++) {
    if (tcp_listen_table[i].port == dport_host) {
      l = &tcp_listen_table[i];
      break;
    }
  }

  if (i == TCP_MAX_LISTENERS) {
    return NULL;
  }

  for (i = 0; i < TCP_MAX_SOCKETS; i++) {
    if (tcp_sock_table[i].state == TCP_CLOSED) {
      s = &tcp_sock_table[i];
      break;
    }
  }

  // No free socket - evict the oldest one
  if (!s) {
    s = &tcp_sock_table[0];

    for (i = 1; i < TCP_MAX_SOCKETS; i++) {
      if (tcp_sock_table[i].ticks > s->ticks) {
        s = &tcp_sock_table[i];
      }
    }
  }

  // Silently evict the socket if it was in use
  if (s->state != TCP_CLOSED) {
    if (s->close) {
      (*(s->close))(s);
    }
  }

  memset(s, 0, sizeof(struct tcp_sock));

  s->state = TCP_LISTEN;
  s->conn_id = ++next_conn_id;

  s->sport = dport_host;
  s->dport = sport_host;

  s->open = l->open;
  s->send = l->send;
  s->recv = l->recv;
  s->close = l->close;

  memcpy(s->saddr, iph->daddr, 4);
  memcpy(s->daddr, iph->saddr, 4);

  return s;
}

uint8_t tcp_sock_matches_conn_id(struct tcp_sock *s, uint32_t ack_seq) {
  uint32_t seq_offset = s->local_seq - s->local_isn;
  uint8_t pkt_conn_id = (ack_seq - seq_offset) >> 24;
  return pkt_conn_id == s->conn_id;
}

struct tcp_sock *tcp_sock_get(struct ip_hdr *iph) {
  struct tcp_hdr *tcph = (struct tcp_hdr *)ip_data(iph);
  uint8_t i;
  uint16_t sport_host = ntohs(tcph->sport);
  uint16_t dport_host = ntohs(tcph->dport);
  uint32_t ack_seq_host = ntohl(tcph->ack_seq);

  for (i = 0; i < TCP_MAX_SOCKETS; i++) {
    if (tcp_sock_table[i].state == TCP_CLOSED) {
      continue;
    }

    if (tcp_sock_table[i].sport != dport_host) {
      continue;
    }

    if (memcmp(tcp_sock_table[i].daddr, iph->saddr, 4)) {
      continue;
    }

    if (tcp_sock_table[i].dport != sport_host) {
      continue;
    }

    // Verify conn_id to reject old packets from a previous connections.
    if (tcp_sock_table[i].state >= TCP_SYN_RCVD && (tcph->flags & TCP_ACK)) {
      if (!tcp_sock_matches_conn_id(&tcp_sock_table[i], ack_seq_host)) {
        continue;
      }
    }

    return &tcp_sock_table[i];
  }

  return tcp_sock_init(iph);
}

void tcp_sock_close(struct tcp_sock *s) {
  s->state = TCP_CLOSED;

  if (s->close) {
    (*s->close)(s);
  }
}

void tcp_tick(void) {
  uint8_t i;

  for (i = 0; i < TCP_MAX_SOCKETS; i++) {
    if (tcp_sock_table[i].state == TCP_CLOSED) {
      continue;
    }

    tcp_sock_table[i].ticks++;

    if (tcp_sock_table[i].state != TCP_ESTABLISHED) {
      continue;
    }

    if (tcp_sock_table[i].ticks >= TCP_TIMEOUT_TICKS) {
      tcp_sock_close(&tcp_sock_table[i]);
    }
  }
}

uint16_t tcp_checksum(struct ip_hdr *iph, uint8_t *data, uint16_t len) {
  struct tcp_psuedo_hdr hdr;
  uint16_t sum;

  memset(&hdr, 0, sizeof(struct tcp_psuedo_hdr));

  memcpy(hdr.saddr, iph->saddr, 4);
  memcpy(hdr.daddr, iph->daddr, 4);

  hdr.proto = iph->proto;
  hdr.len = htons(len);

  sum = ~checksum((uint16_t *)&hdr, 12, 0);

  return checksum((uint16_t *)data, len, sum);
}

void tcp_rx(struct ip_hdr *iph) {
  struct tcp_hdr *tcph = (struct tcp_hdr *)ip_data(iph);
  uint8_t *tcpd = tcp_data(tcph);
  uint16_t tcp_len = ip_data_len(iph);
  uint16_t tcpd_len = tcp_data_len(iph, tcph);
  struct tcp_sock *s;
  uint16_t csum;

  csum = tcp_checksum(iph, (uint8_t *)tcph, tcp_len);
  if (csum != 0) {
    return;
  }

  s = tcp_sock_get(iph);

  tcph->sport = ntohs(tcph->sport);
  tcph->dport = ntohs(tcph->dport);
  tcph->seq = ntohl(tcph->seq);
  tcph->ack_seq = ntohl(tcph->ack_seq);
  tcph->win = ntohs(tcph->win);
  tcph->csum = ntohs(tcph->csum);
  tcph->urp = ntohs(tcph->urp);

  if (tcph->flags & TCP_RST) {
    tcp_sock_close(s);
    return;
  }

  if (!s) {
    struct tcp_sock temp_sock;
    memset(&temp_sock, 0, sizeof(struct tcp_sock));

    temp_sock.sport = tcph->dport;
    temp_sock.dport = tcph->sport;
    temp_sock.local_seq = tcph->ack_seq;
    temp_sock.remote_seq = tcph->seq + tcpd_len;

    if (tcph->flags & TCP_FIN) {
      temp_sock.remote_seq++;
    }

    memcpy(temp_sock.saddr, iph->daddr, 4);
    memcpy(temp_sock.daddr, iph->saddr, 4);

    tcp_tx_rst(&temp_sock);

    return;
  }

  s->ticks = 0;

  // Retransmission - already processed, drop silently
  if (s->state != TCP_LISTEN && tcph->seq < s->remote_seq) {
    return;
  }

  // Out of order packet
  if (s->state != TCP_LISTEN && tcph->seq != s->remote_seq) {
    tcp_tx_rst(s);
    tcp_sock_close(s);
    return;
  }

  switch (s->state) {
    case TCP_LISTEN:
      if (tcph->flags & TCP_SYN) {
        s->local_seq = rand();
        s->local_seq |= ((uint32_t)rand()) << 16;
        s->local_seq = (s->local_seq & 0x00FFFFFF) | ((uint32_t)s->conn_id << 24);
        s->local_isn = s->local_seq;
        s->remote_seq = tcph->seq + 1;

        tcp_tx_synack(s);

        s->local_seq++;
        s->state = TCP_SYN_RCVD;
      }
      break;

    case TCP_SYN_RCVD:
      if (tcph->flags & TCP_ACK) {
        s->state = TCP_ESTABLISHED;

        if (s->open) {
          (*s->open)(s);
        }
      }
      break;

    case TCP_SYN_SENT:
      if (tcph->flags & (TCP_SYN|TCP_ACK)) {
        tcp_tx_ack(s);

        s->local_seq++;
        s->state = TCP_ESTABLISHED;

        if (s->open) {
          (*s->open)(s);
        }
      }
      break;

    case TCP_ESTABLISHED:
      s->remote_seq += tcpd_len;

      if (tcph->flags & TCP_FIN) {
        s->remote_seq++;

        if (tcpd_len > 0 && s->recv) {
          (*s->recv)(s, tcpd, tcpd_len);
        }

        tcp_tx_fin(s);

        s->local_seq++;
        s->state = TCP_LAST_ACK;

        if (s->close) {
          (*s->close)(s);
        }
      } else if (tcpd_len > 0) {
        if (s->recv) {
          (*s->recv)(s, tcpd, tcpd_len);
        }

        if (s->send) {
          (*s->send)(s, tcph->win);
        } else {
          tcp_tx_ack(s);
        }
      } else if (tcph->flags & TCP_ACK) {
        if (s->send) {
          (*s->send)(s, tcph->win);
        }
      }
      break;

    case TCP_LAST_ACK:
      if (tcph->flags & TCP_ACK) {
        s->state = TCP_CLOSED;
      }
      break;

    case TCP_FIN_WAIT_1:
      if (tcph->flags & (TCP_FIN|TCP_ACK)) {
        s->remote_seq++;
        tcp_tx_ack(s);
        s->state = TCP_CLOSED;
      } else if (tcph->flags & TCP_FIN) {
        s->remote_seq++;
        tcp_tx_ack(s);
        s->state = TCP_CLOSING;
      } else if (tcph->flags & TCP_ACK) {
        s->state = TCP_FIN_WAIT_2;
      }
      break;

    case TCP_FIN_WAIT_2:
      if (tcph->flags & TCP_FIN) {
        s->remote_seq++;
        tcp_tx_ack(s);
        s->state = TCP_CLOSED;
      }
      break;

    case TCP_CLOSING:
      if (tcph->flags & TCP_ACK) {
        s->state = TCP_CLOSED;
      }
      break;
  }
}

struct ip_hdr *tcp_packet_init(struct tcp_sock *s) {
  struct ip_hdr *iph = ip_hdr_init();
  struct tcp_hdr *tcph = (struct tcp_hdr *)ip_data(iph);

  iph->len = 20 + 20;
  iph->proto = TCP;

  tcph->sport = s->sport;
  tcph->dport = s->dport;
  tcph->seq = s->local_seq;
  tcph->ack_seq = s->remote_seq;
  tcph->offset_reserved = (5 << 4);  // offset 5 (20 bytes), reserved 0
  tcph->win = TCP_PACKET_LEN;

  memcpy(iph->daddr, s->daddr, 4);

  return iph;
}

void tcp_tx(struct ip_hdr *iph) {
  struct tcp_hdr *tcph = (struct tcp_hdr *)ip_data(iph);
  uint16_t tcp_len = ip_data_len(iph);

  tcph->sport = htons(tcph->sport);
  tcph->dport = htons(tcph->dport);
  tcph->seq = htonl(tcph->seq);
  tcph->ack_seq = htonl(tcph->ack_seq);
  tcph->win = htons(tcph->win);
  tcph->urp = htons(tcph->urp);

  tcph->csum = tcp_checksum(iph, (uint8_t *)tcph, tcp_len);

  ip_tx(iph);
}

void tcp_tx_data(struct tcp_sock *s, uint8_t *data, uint16_t len) {
  struct ip_hdr *iph = tcp_packet_init(s);
  struct tcp_hdr *tcph = (struct tcp_hdr *)ip_data(iph);
  uint8_t *tcpd = tcp_data(tcph);

  iph->len = iph->len + len;

  tcph->flags |= TCP_ACK;
  tcph->flags |= TCP_PSH;

  memcpy(tcpd, data, len);

  s->local_seq += len;

  tcp_tx(iph);
}

void tcp_tx_ack(struct tcp_sock *s) {
  struct ip_hdr *iph = tcp_packet_init(s);
  struct tcp_hdr *tcph = (struct tcp_hdr *)ip_data(iph);

  tcph->flags |= TCP_ACK;

  tcp_tx(iph);
}

void tcp_tx_synack(struct tcp_sock *s) {
  struct ip_hdr *iph = tcp_packet_init(s);
  struct tcp_hdr *tcph = (struct tcp_hdr *)ip_data(iph);

  tcph->flags |= TCP_SYN;
  tcph->flags |= TCP_ACK;

  tcp_tx(iph);
}

void tcp_tx_fin(struct tcp_sock *s) {
  struct ip_hdr *iph = tcp_packet_init(s);
  struct tcp_hdr *tcph = (struct tcp_hdr *)ip_data(iph);

  tcph->flags |= TCP_FIN;
  tcph->flags |= TCP_ACK;

  tcp_tx(iph);
}

void tcp_tx_rst(struct tcp_sock *s) {
  struct ip_hdr *iph = tcp_packet_init(s);
  struct tcp_hdr *tcph = (struct tcp_hdr *)ip_data(iph);

  tcph->flags |= TCP_RST;

  tcp_tx(iph);
}

void tcp_close(struct tcp_sock *s) {
  if (s->state == TCP_ESTABLISHED) {
    tcp_tx_fin(s);

    s->local_seq++;
    s->state = TCP_FIN_WAIT_1;

    if (s->close) {
      (*s->close)(s);
    }
  }
}

void tcp_listen(
  uint16_t port,
  void (*open)(struct tcp_sock *),
  void (*recv)(struct tcp_sock *, uint8_t *, uint16_t),
  void (*send)(struct tcp_sock *, uint16_t),
  void (*close)(struct tcp_sock *)
) {
  uint8_t i;

  for (i = 0; i < TCP_MAX_LISTENERS; i++) {
    if (tcp_listen_table[i].port == 0) {
      tcp_listen_table[i].port = port;
      tcp_listen_table[i].open = open;
      tcp_listen_table[i].recv = recv;
      tcp_listen_table[i].send = send;
      tcp_listen_table[i].close = close;
      break;
    }
  }
}

void tcp_unlisten(uint16_t port) {
  uint8_t i;

  for (i = 0; i < TCP_MAX_LISTENERS; i++) {
    if (tcp_listen_table[i].port == port) {
      tcp_listen_table[i].port = 0;
    }
  }
}
