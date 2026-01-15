#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "slip.h"
#include "ip.h"
#include "udp.h"
#include "dns.h"

int main(int argc, char *argv[]) {
  uint8_t dns_server[4];
  uint8_t result_ip[4];
  unsigned int a, b, c, d;
  char *hostname;
  uint8_t success = 0;

  if (argc < 2 || argc > 3) {
    puts("Usage: nslookup hostname [dns_server]");
    puts("Examples:");
    puts("  nslookup example.com");
    puts("  nslookup example.com 8.8.8.8");
    return 1;
  }

  hostname = argv[1];

  for (char *p = hostname; *p; p++) {
    *p = tolower(*p);
  }

  if (argc == 3) {
    if (sscanf(argv[2], "%u.%u.%u.%u", &a, &b, &c, &d) != 4) {
      puts("Error: Invalid DNS server IP address format");
      return 1;
    }
    dns_server[0] = a;
    dns_server[1] = b;
    dns_server[2] = c;
    dns_server[3] = d;
  } else {
    dns_server[0] = 8;
    dns_server[1] = 8;
    dns_server[2] = 8;
    dns_server[3] = 8;
  }

  ip_init();

  printf("DNS Server: %u.%u.%u.%u\n", dns_server[0], dns_server[1], dns_server[2], dns_server[3]);

  dns_init(dns_server);

  printf("Resolving %s...\n", hostname);

  success = dns_resolve(hostname, result_ip);

  if (success) {
    printf("\nName: %s\n", hostname);
    printf("Address: %u.%u.%u.%u\n", result_ip[0], result_ip[1], result_ip[2], result_ip[3]);
  } else {
    printf("\nFailed to resolve %s\n", hostname);
  }

  return 0;
}
