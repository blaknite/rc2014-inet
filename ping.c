#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "slip.h"
#include "ip.h"
#include "tcp.h"
#include "icmp.h"

void main(int argc, char *argv[]) {
  uint8_t ping_addr[4];
  uint8_t i = 10;

  if (argc == 2) {
    sscanf(argv[1], "%u.%u.%u.%u", &ping_addr[0], &ping_addr[1], &ping_addr[2], &ping_addr[3]);
  } else {
    puts("Usage: ping host");
    return;
  }

  slip_init();
  tcp_init();

  ip_debug_enable();

  printf("Pinging %u.%u.%u.%u...\n\n", ping_addr[0], ping_addr[1], ping_addr[2], ping_addr[3]);

  while (i--) {
    icmp_tx_request(ping_addr);
    slip_rx();
    printf("\n");
    sleep(2);
  }
}
