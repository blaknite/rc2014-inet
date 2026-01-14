#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "slip.h"
#include "ip.h"
#include "udp.h"

struct udp_binding *udp_binding_table;

void udp_init(void) {
  udp_binding_table = calloc(UDP_MAX_BINDINGS, sizeof(struct udp_binding));
}

struct udp_binding *udp_binding_get(uint16_t port) {
  struct udp_binding *binding;
  uint8_t i;

  for (i = 0; i < UDP_MAX_BINDINGS; i++) {
    binding = &udp_binding_table[i];
    if (binding->port == port) {
      return binding;
    }
  }

  return NULL;
}

void udp_debug(struct ip_hdr *iph) {
  struct udp_hdr *udph = (struct udp_hdr *)ip_data(iph);

  printf(" sport=%u dport=%u", ntohs(udph->sport), ntohs(udph->dport));
}

uint8_t *udp_data(struct udp_hdr *udph) {
  return (uint8_t *)udph + sizeof(struct udp_hdr);
}

uint16_t udp_checksum(struct ip_hdr *iph, uint8_t *data, uint16_t len) {
  struct udp_pseudo_hdr hdr;
  uint16_t sum;

  memset(&hdr, 0, sizeof(struct udp_pseudo_hdr));

  memcpy(hdr.saddr, iph->saddr, 4);
  memcpy(hdr.daddr, iph->daddr, 4);

  hdr.proto = iph->proto;
  hdr.len = htons(len);

  sum = ~checksum((uint16_t *)&hdr, sizeof(struct udp_pseudo_hdr), 0);

  return checksum((uint16_t *)data, len, sum);
}

void udp_rx(struct ip_hdr *iph) {
  struct udp_hdr *udph = (struct udp_hdr *)ip_data(iph);
  uint8_t *udpd = udp_data(udph);
  uint16_t udp_len;
  uint16_t csum;
  struct udp_binding *binding;

  udp_len = ntohs(udph->len);

  if (udp_len < 8 || udp_len > ip_data_len(iph)) {
    return;
  }

  if (udph->csum != 0) {
    csum = udp_checksum(iph, (uint8_t *)udph, udp_len);
    if (csum != 0) {
      return;
    }
  }

  udph->sport = ntohs(udph->sport);
  udph->dport = ntohs(udph->dport);
  udph->len = udp_len;

  binding = udp_binding_get(udph->dport);

  if (binding && binding->recv) {
    (*binding->recv)(iph);
  }
}

void udp_tx(uint8_t *dest_ip, uint16_t sport, uint16_t dport, uint8_t *data, uint16_t len) {
  struct ip_hdr *iph = ip_hdr_init();
  struct udp_hdr *udph;
  uint8_t *udpd;
  uint16_t udp_len = 20 + len;

  iph->proto = UDP;
  iph->len = 20 + udp_len;

  memcpy(iph->daddr, dest_ip, 4);

  udph = (struct udp_hdr *)ip_data(iph);

  udph->sport = htons(sport);
  udph->dport = htons(dport);
  udph->len = htons(udp_len);

  udpd = udp_data(udph);
  memcpy(udpd, data, len);

  udph->csum = udp_checksum(iph, (uint8_t *)udph, udp_len);

  ip_tx(iph);
}

void udp_bind(uint16_t port, void (*recv)(struct ip_hdr *)) {
  struct udp_binding *binding;
  uint8_t i;

  for (i = 0; i < UDP_MAX_BINDINGS; i++) {
    binding = &udp_binding_table[i];

    if (binding->port == 0) {
      binding->port = port;
      binding->recv = recv;
      return;
    }
  }
}

void udp_unbind(uint16_t port) {
  struct udp_binding *binding;
  uint8_t i;

  for (i = 0; i < UDP_MAX_BINDINGS; i++) {
    binding = &udp_binding_table[i];

    if (binding->port == port) {
      binding->port = 0;
      binding->recv = NULL;
      return;
    }
  }
}
