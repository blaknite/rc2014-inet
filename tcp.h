#ifndef __TCP_H__
#define __TCP_H__

#define TCP_MAX_LISTENERS 4
#define TCP_MAX_SOCKETS 16

#define TCP_PACKET_LEN 536 // 576 MTU - 20 (IP header) - 20 (TCP header)

#define TCP_TIMEOUT_TICKS 200

#define TCP_CLOSED 0
#define TCP_LISTEN 1
#define TCP_SYN_RCVD 2
#define TCP_SYN_SENT 3
#define TCP_ESTABLISHED 4
// #define TCP_CLOSE_WAIT 5
#define TCP_LAST_ACK 6
#define TCP_FIN_WAIT_1 7
#define TCP_FIN_WAIT_2 8
#define TCP_CLOSING 9
// #define TCP_TIME_WAIT 10

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20
#define TCP_ECN 0x40
#define TCP_WIN 0x80

#define tcp_hl(tcph) (tcph->offset * 4)

struct tcp_hdr {
  uint16_t sport;
  uint16_t dport;
  uint32_t seq;
  uint32_t ack_seq;
  uint8_t reserved : 4;
  uint8_t offset : 4;
  uint8_t flags;
  uint16_t win;
  uint16_t csum;
  uint16_t urp;
};

struct tcp_psuedo_hdr {
  uint8_t saddr[4];
  uint8_t daddr[4];
  uint8_t reserved;
  uint8_t proto;
  uint16_t len;
};

struct tcp_listener {
  uint16_t port;
  void (*open)(struct tcp_sock *);
  void (*recv)(struct tcp_sock *, uint8_t *, uint16_t);
  void (*send)(struct tcp_sock *, uint16_t);
  void (*close)(struct tcp_sock *);
};

struct tcp_sock {
  uint8_t saddr[4];
  uint8_t daddr[4];
  uint16_t sport;
  uint16_t dport;
  uint8_t state;
  uint8_t conn_id;
  uint32_t local_isn;
  uint32_t local_seq;
  uint32_t remote_seq;
  uint16_t ticks;
  void (*open)(struct tcp_sock *);
  void (*recv)(struct tcp_sock *, uint8_t *, uint16_t);
  void (*send)(struct tcp_sock *, uint16_t);
  void (*close)(struct tcp_sock *);
};

void tcp_debug(struct ip_hdr *iph);
uint8_t *tcp_data(struct tcp_hdr *tcph);
uint16_t tcp_data_len(struct ip_hdr *iph, struct tcp_hdr *tcph);
void tcp_init(void);
struct tcp_sock *tcp_sock_init(struct ip_hdr *iph);
struct tcp_sock *tcp_sock_get(struct ip_hdr *iph);
void tcp_tick(void);
struct ip_hdr *tcp_packet_init(struct tcp_sock *s);
void tcp_sock_close(struct tcp_sock *s);
void tcp_rx(struct ip_hdr *iph);
void tcp_tx(struct ip_hdr *iph);
void tcp_tx_data(struct tcp_sock *s, uint8_t *data, uint16_t len);
void tcp_tx_data_fin(struct tcp_sock *s, uint8_t *data, uint16_t len);
void tcp_tx_syn(struct tcp_sock *s);
void tcp_tx_ack(struct tcp_sock *s);
void tcp_tx_synack(struct tcp_sock *s);
void tcp_tx_fin(struct tcp_sock *s);
void tcp_tx_rst(struct tcp_sock *s);
void tcp_reject(struct ip_hdr *in_iph);
void tcp_close(struct tcp_sock *s);
void tcp_listen(
  uint16_t port,
  void (*open)(struct tcp_sock *),
  void (*recv)(struct tcp_sock *, uint8_t *, uint16_t),
  void (*send)(struct tcp_sock *, uint16_t),
  void (*close)(struct tcp_sock *)
);
void tcp_unlisten(uint16_t port);
struct tcp_sock *tcp_connect(
  uint8_t *addr,
  uint16_t port,
  void (*open)(struct tcp_sock *),
  void (*recv)(struct tcp_sock *, uint8_t *, uint16_t),
  void (*send)(struct tcp_sock *, uint16_t),
  void (*close)(struct tcp_sock *)
);

#endif
