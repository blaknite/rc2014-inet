#ifndef __ICMP_H__
#define __ICMP_H__

#define ICMP_ECHO_REPLY       0x00
#define ICMP_DST_UNREACHABLE  0x03
// #define ICMP_SRC_QUENCH      0x04
// #define ICMP_REDIRECT        0x05
#define ICMP_ECHO_REQUEST     0x08
// #define ICMP_ROUTER_ADV      0x09
// #define ICMP_ROUTER_SOL      0x0a
// #define ICMP_TIMEOUT         0x0b
// #define ICMP_MALFORMED       0x0c

struct icmp_hdr {
  uint8_t type;
  uint8_t code;
  uint16_t csum;
  uint16_t id;
  uint16_t seq;
};

void icmp_debug(struct ip_hdr *iph);
void icmp_rx(struct ip_hdr *iph);
void icmp_tx_reply(struct ip_hdr *rx_iph);
void icmp_tx_request(uint8_t *daddr, uint16_t seq);
void icmp_listen(void (*callback)(struct ip_hdr *iph, struct icmp_hdr *icmph));

#endif
