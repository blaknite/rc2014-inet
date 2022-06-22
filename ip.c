#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "ip.h"
#include "icmp.h"
#include "slip.h"
#include "tcp.h"

uint8_t local_address[4] = {192, 168, 1, 51};
uint16_t packet_id = 0;
uint8_t debug_enabled = 0;

uint8_t *ip_data(struct ip_hdr *iph) {
  return *iph + ip_hl(iph);
}

uint16_t ip_data_len(struct ip_hdr *iph) {
  return iph->len - ip_hl(iph);
}

// Compute Internet Checksum for "count" bytes beginning at location "addr".
// Taken from https://tools.ietf.org/html/rfc1071
uint16_t checksum(uint16_t *addr, uint16_t count, uint32_t offset) {
  uint32_t sum = offset;
  uint16_t *ptr = addr;

  while ( count > 1 )  {
    sum += *ptr++;
    count -= 2;
  }

  if ( count > 0 ) {
    sum += *(uint8_t *) ptr;
  }

  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  return ~sum;
}

uint8_t *ip_proto_s(uint8_t proto) {
  switch (proto) {
    case ICMP: return "ICMP";
    case TCP: return "TCP";
    case UDP: return "UDP";
    default: return "UNKNOWN";
  }
}

void ip_debug_enable(void) {
  debug_enabled = 1;
}

void ip_debug_disable(void) {
  debug_enabled = 0;
}

void ip_debug(struct ip_hdr *iph) {
  if (debug_enabled == 0) {
    return;
  }

  printf("%u.%u.%u.%u > %u.%u.%u.%u: %s (%u) length=%u",
    iph->saddr[0], iph->saddr[1], iph->saddr[2], iph->saddr[3],
    iph->daddr[0], iph->daddr[1], iph->daddr[2], iph->daddr[3],
    ip_proto_s(iph->proto), iph->proto, ntohs(iph->len));

  switch (iph->proto) {
    case ICMP:
      icmp_debug(iph);
      break;

    case TCP:
      tcp_debug(iph);
      break;
  }

  printf("\n");
}

struct ip_hdr *ip_hdr_init(void) {
  struct ip_hdr *iph = slip_tx_buffer;

  memset(iph, 0, SLIP_MAX);

  iph->version = IPV4;
  iph->ihl = 5;
  iph->id = htons(packet_id++);
  iph->frag_offset = 0x0040;
  iph->ttl = 64;

  memcpy(iph->saddr, local_address, 4);

  return iph;
}

void ip_rx(struct ip_hdr *iph) {
  uint16_t csum = checksum(iph, iph->ihl * 4, 0);

  ip_debug(iph);

  if (iph->version != IPV4) return;
  if (iph->ihl < 5) return;
  if (iph->ttl == 0) return;
  if (csum != 0) return;

  iph->len = ntohs(iph->len);

  if (iph->len > SLIP_MTU) return;

  switch (iph->proto) {
    case ICMP:
      icmp_rx(iph);
      break;

    case TCP:
      tcp_rx(iph);
      break;
  }
}

void ip_tx(struct ip_hdr *iph) {
  uint16_t len = iph->len;

  iph->len = htons(len);
  iph->csum = checksum(iph, 20, 0);

  ip_debug(iph);

  slip_tx(iph, len);
}
