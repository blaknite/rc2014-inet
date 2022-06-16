#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "slip.h"
#include "ip.h"
#include "icmp.h"

void icmp_debug(struct ip_hdr *iph) {
  struct icmp_hdr *icmph = ip_data(iph);

  printf(" type=%u code=%u", icmph->type, icmph->code);

  switch (icmph->type) {
    case ICMP_ECHO_REQUEST:
    case ICMP_ECHO_REPLY:
      printf(" id=%u seq=%u", ntohs(icmph->id), ntohs(icmph->seq));
      break;
  }
}

void icmp_rx(struct ip_hdr *iph) {
  struct icmp_hdr *icmph = ip_data(iph);
  uint16_t icmp_len = ip_data_len(iph);
  uint16_t csum = checksum(icmph, icmp_len, 0);

  if (csum != 0) return;

  switch (icmph->type) {
    case ICMP_ECHO_REQUEST:
      icmp_tx_reply(iph);
      break;

    case ICMP_ECHO_REPLY:
      break;

    case ICMP_DST_UNREACHABLE:
      break;
  }
}

void icmp_tx_reply(struct ip_hdr *rx_iph) {
  struct icmp_hdr *rx_icmph = ip_data(rx_iph);

  struct ip_hdr *tx_iph = ip_hdr_init();
  struct icmp_hdr *tx_icmph = ip_data(tx_iph);

  uint16_t icmp_dlen = ip_data_len(rx_iph) - 8;

  tx_iph->len = 28 + icmp_dlen;
  tx_iph->proto = ICMP;

  memcpy(tx_iph->daddr, rx_iph->saddr, 4);

  tx_icmph->type = ICMP_ECHO_REPLY;
  tx_icmph->id = rx_icmph->id;
  tx_icmph->seq = rx_icmph->seq;

  memcpy(*tx_icmph + 8, *rx_icmph + 8, icmp_dlen);

  tx_icmph->csum = checksum(tx_icmph, icmp_dlen + 8, 0);

  ip_tx(tx_iph);
}

void icmp_tx_request(uint8_t *daddr) {
  struct ip_hdr *iph = ip_hdr_init();
  struct icmp_hdr *icmph = ip_data(iph);

  uint16_t icmp_len = 0;

  iph->len = 28 + icmp_len;
  iph->proto = ICMP;

  memcpy(iph->daddr, daddr, 4);

  icmph->type = ICMP_ECHO_REQUEST;
  icmph->id = 0;
  icmph->seq = 0;

  icmph->csum = checksum(icmph, icmp_len + 8, 0);

  ip_tx(iph);
}
