#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <conio.h>
#include "slip.h"
#include "ip.h"
#include "tcp.h"
#include "icmp.h"

int main(int argc, char *argv[]) {
  uint8_t ping_addr[4];
  uint8_t i = 10;
  unsigned int a, b, c, d;

  if (argc != 2 || !argv[1]) {
    puts("Usage: ping host");
    return 1;
  }

  if (sscanf(argv[1], "%u.%u.%u.%u", &a, &b, &c, &d) != 4) {
    puts("Error: Invalid IP address format");
    return 1;
  }

  ping_addr[0] = a;
  ping_addr[1] = b;
  ping_addr[2] = c;
  ping_addr[3] = d;

  slip_init();
  tcp_init();

  ip_debug_enable(0);

  printf("Pinging %u.%u.%u.%u...\n\n", ping_addr[0], ping_addr[1], ping_addr[2], ping_addr[3]);
  printf("Press 'q' to quit...\n\n");

  while (i--) {
    icmp_tx_request(ping_addr);
    slip_rx();

    printf("\n");

    if (kbhit()) {
      int ch = getch();
      if (ch == 'q' || ch == 'Q') {
        printf("Stopped.\n");
        break;
      }
    }

    sleep(2);
  }

  return 0;
}
