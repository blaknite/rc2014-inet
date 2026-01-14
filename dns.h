#ifndef __DNS_H__
#define __DNS_H__

#define DNS_PORT 53
#define DNS_MAX_NAME_LEN 255

#define DNS_QUERY_TIMEOUT 2000 // 2 seconds

#define DNS_TYPE_A 1
#define DNS_TYPE_NS 2
#define DNS_TYPE_CNAME 5
#define DNS_TYPE_SOA 6
#define DNS_TYPE_PTR 12
#define DNS_TYPE_MX 15
#define DNS_TYPE_TXT 16
#define DNS_TYPE_AAAA 28

#define DNS_CLASS_IN 1

#define DNS_FLAG_QR 0x8000
#define DNS_FLAG_OPCODE 0x7800
#define DNS_FLAG_AA 0x0400
#define DNS_FLAG_TC 0x0200
#define DNS_FLAG_RD 0x0100
#define DNS_FLAG_RA 0x0080
#define DNS_FLAG_RCODE 0x000F

#define DNS_RCODE_OK 0
#define DNS_RCODE_FORMAT_ERROR 1
#define DNS_RCODE_SERVER_FAILURE 2
#define DNS_RCODE_NAME_ERROR 3
#define DNS_RCODE_NOT_IMPLEMENTED 4
#define DNS_RCODE_REFUSED 5

struct dns_hdr {
  uint16_t id;
  uint16_t flags;
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
};

struct dns_question {
  uint16_t qtype;
  uint16_t qclass;
};

struct dns_answer {
  uint16_t type;
  uint16_t class;
  uint32_t ttl;
  uint16_t rdlength;
};

struct dns_parse_result {
  uint16_t consumed;
  uint8_t success;
};

void dns_init(uint8_t *server);
uint8_t dns_resolve(const char *hostname, uint8_t *ip);
void dns_rx(struct ip_hdr *iph);

#endif
