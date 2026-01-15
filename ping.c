#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "slip.h"
#include "ip.h"
#include "icmp.h"
#include "dns.h"

static uint8_t is_ip_address(char *str) {
  unsigned int a, b, c, d;
  return (sscanf(str, "%u.%u.%u.%u", &a, &b, &c, &d) == 4);
}

static uint8_t response_received = 0;
static uint16_t response_ms;
static uint16_t expected_seq = 0;

static void ping_rx(struct ip_hdr *iph, struct icmp_hdr *icmph) {
  uint16_t seq = ntohs(icmph->seq);
  uint16_t ttl = iph->ttl;
  uint16_t size = ip_data_len(iph);

  if (seq != expected_seq) {
    return;
  }

  response_received = 1;

  printf("%u bytes from %u.%u.%u.%u: icmp_seq=%u ttl=%u\n",
    size,
    iph->saddr[0], iph->saddr[1], iph->saddr[2], iph->saddr[3],
    seq, ttl);
}

int main(int argc, char *argv[]) {
  uint8_t ping_addr[4];
  uint8_t dns_server[4] = {8, 8, 8, 8};
  uint16_t seq = 0;
  uint8_t i = 10;
  unsigned int a, b, c, d;
  char *host;

  const uint16_t timeout_ms = 2000;

  if (argc != 2 || !argv[1]) {
    puts("Usage: ping host");
    return 1;
  }

  host = argv[1];

  ip_init();

  icmp_listen(ping_rx);

  if (is_ip_address(host)) {
    sscanf(host, "%u.%u.%u.%u", &a, &b, &c, &d);
    ping_addr[0] = a;
    ping_addr[1] = b;
    ping_addr[2] = c;
    ping_addr[3] = d;

    printf("PING %u.%u.%u.%u...\n\n", ping_addr[0], ping_addr[1], ping_addr[2], ping_addr[3]);
  } else {
    dns_init(dns_server);

    if (!dns_resolve(host, ping_addr)) {
      printf("Error: Failed to resolve %s\n", host);
      return 0;
    }

    printf("PING %s (%u.%u.%u.%u)...\n\n", host, ping_addr[0], ping_addr[1], ping_addr[2], ping_addr[3]);
  }

  while (i--) {
    response_received = 0;
    expected_seq = seq;

    icmp_tx_request(ping_addr, seq++);

    while (!response_received) {
      slip_rx();
    }

    sleep(2);
  }

  return 0;
}
