#ifndef __UDP_H__
#define __UDP_H__

#define UDP_MAX_BINDINGS 4

#define UDP_PACKET_LEN 536 // 576 MTU - 20 (IP header) - 20 (UDP header)

struct udp_hdr {
  uint16_t sport;
  uint16_t dport;
  uint16_t len;
  uint16_t csum;
};

struct udp_pseudo_hdr {
  uint8_t saddr[4];
  uint8_t daddr[4];
  uint8_t reserved;
  uint8_t proto;
  uint16_t len;
};

struct udp_binding {
  uint16_t port;
  void (*recv)(struct ip_hdr *);
};

void udp_init(void);
void udp_debug(struct ip_hdr *iph);
uint8_t *udp_data(struct udp_hdr *udph);
uint16_t udp_checksum(struct ip_hdr *iph, uint8_t *data, uint16_t len);
void udp_rx(struct ip_hdr *iph);
void udp_tx(uint8_t *dest_ip, uint16_t sport, uint16_t dport, uint8_t *data, uint16_t len);
void udp_bind(uint16_t port, void (*recv)(struct ip_hdr *));
void udp_unbind(uint16_t port);

#endif
