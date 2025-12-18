#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "ip.h"
#include "icmp.h"
#include "slip.h"
#include "tcp.h"

uint8_t local_address[4] = {192, 168, 1, 51};
uint8_t gateway_address[4] = {192, 168, 1, 1};
uint16_t packet_id = 0;
uint8_t debug_enabled = 0;
uint8_t debug_verbose = 0;

uint8_t *ip_data(struct ip_hdr *iph) {
  return (uint8_t *)iph + ip_hl(iph);
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

void ip_debug_enable(uint8_t verbose) {
  debug_enabled = 1;
  debug_verbose = verbose;
}

void ip_debug_disable(void) {
  debug_enabled = 0;
  debug_verbose = 0;
}

void ip_debug(struct ip_hdr *iph) {
  uint16_t i;
  uint16_t len;

  if (debug_enabled == 0) {
    return;
  }

  printf("%u.%u.%u.%u > %u.%u.%u.%u: %s (%u) length=%u",
    iph->saddr[0], iph->saddr[1], iph->saddr[2], iph->saddr[3],
    iph->daddr[0], iph->daddr[1], iph->daddr[2], iph->daddr[3],
    ip_proto_s(iph->proto), iph->proto, iph->len);

  switch (iph->proto) {
    case ICMP:
      icmp_debug(iph);
      break;
    case TCP:
      tcp_debug(iph);
      break;
  }

  printf("\n");

  if (debug_verbose) {
    len = iph->len;

    printf("Packet (%u bytes):\n", len);

    for (i = 0; i < len && i < 128; i++) {
      printf("%02x ", ((uint8_t *)iph)[i]);
      if ((i + 1) % 16 == 0) printf("\n");
    }

    if (i % 16 != 0) printf("\n");
  }
}

struct ip_hdr *ip_hdr_init(void) {
  struct ip_hdr *iph = slip_tx_buffer;

  memset(iph, 0, SLIP_MAX);

  iph->version_ihl = (IPV4 << 4) | 5;  // version 4, header length 5 (20 bytes)
  iph->id = htons(packet_id++);
  iph->frag_offset = 0x0040;
  iph->ttl = 64;

  memcpy(iph->saddr, local_address, 4);

  return iph;
}

void ip_rx(struct ip_hdr *iph) {
  uint16_t csum = checksum((uint16_t *)iph, ip_ihl(iph) * 4, 0);

  if (ip_version(iph) != IPV4) return;
  if (ip_ihl(iph) < 5) return;
  if (iph->ttl == 0) return;
  if (csum != 0) return;

  iph->len = ntohs(iph->len);

  if (iph->len > SLIP_MTU) return;

  ip_debug(iph);

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

  ip_debug(iph);

  iph->len = htons(len);
  iph->csum = checksum((uint16_t *)iph, 20, 0);

  slip_tx((uint8_t *)iph, len);
}
