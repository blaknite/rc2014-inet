#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "slip.h"
#include "ip.h"
#include "tcp.h"

struct tcp_listener *tcp_listen_table;
struct tcp_sock *tcp_sock_table;

void tcp_init(void) {
  tcp_listen_table = calloc(TCP_MAX_LISTENERS, sizeof(struct tcp_listener));
  tcp_sock_table = calloc(TCP_MAX_SOCKETS, sizeof(struct tcp_sock));
}

void tcp_debug(struct ip_hdr *iph) {
  struct tcp_hdr *tcph = ip_data(iph);

  printf(" sport=%u dport=%u flags=%x",
    ntohs(tcph->sport), ntohs(tcph->dport), tcph->flags, ntohs(tcph->win));
}

uint8_t *tcp_data(struct tcp_hdr *tcph) {
  return *tcph + tcp_hl(tcph);
}

uint16_t tcp_data_len(struct ip_hdr *iph, struct tcp_hdr *tcph) {
  return iph->len - ip_hl(iph) - tcp_hl(tcph);
}

struct tcp_sock *tcp_sock_init(struct ip_hdr *iph) {
  struct tcp_hdr *tcph = ip_data(iph);
  struct tcp_listener *l;
  struct tcp_sock *s;
  uint8_t i;

  for (i = 0; i < TCP_MAX_LISTENERS; i++) {
    if (tcp_listen_table[i].port == tcph->dport) {
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

  if (!s) {
    s = tcp_sock_table;

    for (i = 1; i < TCP_MAX_SOCKETS; i++) {
      if (tcp_sock_table[i].ticks > s->ticks) {
        s = &tcp_sock_table[i];
      }
    }

    tcp_tx_rst(s);

    if (s->close) {
      (*(s->close))(s);
    }
  }

  memset(s, 0, sizeof(struct tcp_sock));

  s->state = TCP_LISTEN;

  s->sport = tcph->dport;
  s->dport = tcph->sport;

  s->open = l->open;
  s->send = l->send;
  s->recv = l->recv;
  s->close = l->close;

  memcpy(s->saddr, iph->daddr, 4);
  memcpy(s->daddr, iph->saddr, 4);

  return s;
}

struct tcp_sock *tcp_sock_get(struct ip_hdr *iph) {
  struct tcp_hdr *tcph = ip_data(iph);
  uint8_t i;

  for (i = 0; i < TCP_MAX_SOCKETS; i++) {
    if (tcp_sock_table[i].state == TCP_CLOSED) {
      continue;
    }

    if (tcp_sock_table[i].sport != tcph->dport) {
      continue;
    }

    if (memcmp(tcp_sock_table[i].daddr, iph->saddr, 4)) {
      continue;
    }

    if (tcp_sock_table[i].dport != tcph->sport) {
      continue;
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
    tcp_sock_table[i].ticks++;
  }
}

uint16_t tcp_checksum(struct ip_hdr *iph, uint8_t *data, uint16_t len) {
  struct tcp_psuedo_hdr hdr;
  uint16_t sum;

  memset(hdr, 0, sizeof(struct tcp_psuedo_hdr));

  memcpy(hdr.saddr, iph->saddr, 4);
  memcpy(hdr.daddr, iph->daddr, 4);

  hdr.proto = iph->proto;
  hdr.len = htons(len);

  sum = ~checksum(&hdr, 12, 0);

  return checksum(data, len, sum);
}

void tcp_rx(struct ip_hdr *iph) {
  struct tcp_hdr *tcph = ip_data(iph);
  uint8_t *tcpd = tcp_data(tcph);
  uint16_t tcp_len = ip_data_len(iph);
  uint16_t tcpd_len = tcp_data_len(iph, tcph);
  struct tcp_sock *s;
  uint16_t csum;

  csum = tcp_checksum(iph, tcph, tcp_len);
  if (csum != 0) {
    // printf("> Invalid checksum: %u\n", csum);
    tcp_sock_close(s);
    tcp_tx_rst(s);
    return;
  }

  if (tcph->flags & TCP_RST) {
    // puts("> Connection reset");
    tcp_sock_close(s);
    return;
  }

  tcp_tick();

  tcph->sport = ntohs(tcph->sport);
  tcph->dport = ntohs(tcph->dport);
  tcph->seq = ntohl(tcph->seq);
  tcph->ack_seq = ntohl(tcph->ack_seq);
  tcph->win = ntohs(tcph->win);
  tcph->csum = ntohs(tcph->csum);
  tcph->urp = ntohs(tcph->urp);

  s = tcp_sock_get(iph);

  if (!s) {
    // puts("> No socket");
    return;
  }

  if (s->state != TCP_LISTEN && tcph->seq != s->remote_seq) {
    // printf("> Invalid sequence: seq=%lu remote_seq=%lu\n", tcph->seq, s->remote_seq);
    tcp_sock_close(s);
    tcp_tx_rst(s);
    return;
  }

  s->ticks = 0;

  switch (s->state) {
    case TCP_LISTEN:
      if (tcph->flags & TCP_SYN) {
        s->local_seq = rand();
        s->local_seq |= ((uint32_t)rand()) << 16;
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

      if (tcpd_len > 0) {
        tcp_tx_ack(s);

        if (s->recv) {
          (*s->recv)(s, tcpd, tcpd_len);
        }
      }

      if (s->send) {
        (*s->send)(s, tcph->win);
      }

      if (tcph->flags & TCP_FIN) {
        s->remote_seq++;

        tcp_tx_fin(s);

        s->state = TCP_LAST_ACK;

        if (s->close) {
          (*s->close)(s);
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
        tcp_tx_ack(s);
        s->state = TCP_CLOSED;
      } else if (tcph->flags & TCP_FIN) {
        tcp_tx_ack(s);
        s->state = TCP_CLOSING;
      } else if (tcph->flags & TCP_ACK) {
        s->state = TCP_FIN_WAIT_2;
      }
      break;

    case TCP_FIN_WAIT_2:
      if (tcph->flags & TCP_FIN) {
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
  struct tcp_hdr *tcph = ip_data(iph);

  iph->len = 20 + 20;
  iph->proto = TCP;

  tcph->sport = s->sport;
  tcph->dport = s->dport;
  tcph->seq = s->local_seq;
  tcph->ack_seq = s->remote_seq;
  tcph->offset = 5;
  tcph->win = TCP_PACKET_LEN;

  memcpy(iph->daddr, s->daddr, 4);

  return iph;
}

void tcp_tx(struct ip_hdr *iph) {
  struct tcp_hdr *tcph = ip_data(iph);
  uint16_t tcp_len = ip_data_len(iph);

  tcph->sport = htons(tcph->sport);
  tcph->dport = htons(tcph->dport);
  tcph->seq = htonl(tcph->seq);
  tcph->ack_seq = htonl(tcph->ack_seq);
  tcph->win = htons(tcph->win);
  tcph->urp = htons(tcph->urp);

  tcph->csum = tcp_checksum(iph, tcph, tcp_len);

  ip_tx(iph);
}

void tcp_tx_data(struct tcp_sock *s, uint8_t *data, uint16_t len) {
  struct ip_hdr *iph = tcp_packet_init(s);
  struct tcp_hdr *tcph = ip_data(iph);
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
  struct tcp_hdr *tcph = ip_data(iph);

  tcph->flags |= TCP_ACK;

  tcp_tx(iph);
}

void tcp_tx_synack(struct tcp_sock *s) {
  struct ip_hdr *iph = tcp_packet_init(s);
  struct tcp_hdr *tcph = ip_data(iph);

  tcph->flags |= TCP_SYN;
  tcph->flags |= TCP_ACK;

  tcp_tx(iph);
}

void tcp_tx_fin(struct tcp_sock *s) {
  struct ip_hdr *iph = tcp_packet_init(s);
  struct tcp_hdr *tcph = ip_data(iph);

  tcph->flags |= TCP_FIN;
  tcph->flags |= TCP_ACK;

  tcp_tx(iph);
}

void tcp_tx_rst(struct tcp_sock *s) {
  struct ip_hdr *iph = tcp_packet_init(s);
  struct tcp_hdr *tcph = ip_data(iph);

  tcph->flags |= TCP_RST;

  tcp_tx(iph);
}

void tcp_listen(uint16_t port, void (*open)(), void (*recv)(), void (*send)(), void (*close)()) {
  uint8_t i;

  for (i = 0; i < TCP_MAX_LISTENERS; i++) {
    if (tcp_listen_table[i].port == 0) {
      tcp_listen_table[i].port = port;
      tcp_listen_table[i].open = open;
      tcp_listen_table[i].recv = recv;
      tcp_listen_table[i].send = send;
      tcp_listen_table[i].close = close;
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
