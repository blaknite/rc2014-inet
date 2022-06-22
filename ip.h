#ifndef __IP_H__
#define __IP_H__

#define IPV4 4
#define ICMP 1
#define TCP 6
#define UDP 17

struct ip_hdr {
  uint8_t ihl : 4;
  uint8_t version : 4;
  uint8_t tos;
  uint16_t len;
  uint16_t id;
  uint16_t frag_offset;
  uint8_t ttl;
  uint8_t proto;
  uint16_t csum;
  uint8_t saddr[4];
  uint8_t daddr[4];
};

extern uint8_t local_address[4];

extern uint32_t __LIB__ htonl(uint32_t x) __smallc __z88dk_fastcall;
extern uint16_t __LIB__ htons(uint16_t x) __smallc __z88dk_fastcall;

#define ntohs(x) htons(x)
#define ntohl(x) htonl(x)

#define ip_hl(iph) (iph->ihl * 4)

uint8_t *ip_data(struct ip_hdr *iph);
uint16_t ip_data_len(struct ip_hdr *iph);
uint16_t checksum(uint16_t *addr, uint16_t count, uint32_t offset);
uint8_t *ip_proto_s(uint8_t proto);
void ip_debug_enable(void);
void ip_debug_disable(void);
void ip_debug(struct ip_hdr *iph);
struct ip_hdr *ip_hdr_init(void);
void ip_rx(struct ip_hdr *iph);
void ip_tx(struct ip_hdr *iph);

#endif
