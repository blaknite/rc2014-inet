#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "slip.h"
#include "ip.h"
#include "tcp.h"
#include "http.h"

#define ARG_ADDR "-A"
#define ARG_PORT "-P"

void main(int argc, char *argv[]) {
  uint8_t i;
  int8_t *key;
  int8_t *value;
  uint16_t port = 80;

  for (i = 0; i < argc; i++) {
    key = strtok(argv[i], "=");
    value = strtok(NULL, "=");

    if (strcmp(ARG_ADDR, key) == 0) {
      sscanf(value, "%u.%u.%u.%u", &local_address[0], &local_address[1], &local_address[2], &local_address[3]);
    } else if (strcmp(ARG_PORT, key) == 0) {
      sscanf(value, "%u", &port);
    }
  }

  slip_init();
  tcp_init();
  http_init();

  tcp_listen(port, http_open, http_recv, http_send, http_close);

  printf("Listening on %u.%u.%u.%u:%u...\n\n",
    local_address[0], local_address[1], local_address[2], local_address[3], port);

  while (1) {
    slip_rx();
  }
}
