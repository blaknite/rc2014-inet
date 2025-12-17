#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "slip.h"
#include "ip.h"
#include "tcp.h"
#include "http.h"

// Set max open files to 12 (8 HTTP clients + 3 std streams + margin)
#pragma output CLIB_OPEN_MAX = 12

#define ARG_ADDR "-A"
#define ARG_PORT "-P"
#define ARG_DEBUG "-D"
#define ARG_VERBOSE "-V"

int main(int argc, char *argv[]) {
  uint8_t i;
  int8_t *key;
  int8_t *value;
  uint16_t port = 80;
  uint8_t debug = 0;
  uint8_t verbose = 0;
  unsigned int a, b, c, d;

  for (i = 0; i < argc; i++) {
    if (!argv[i]) {
      continue;
    }

    key = strtok(argv[i], "=");
    if (!key) {
      continue;
    }

    value = strtok(NULL, "=");

    if (strcmp(ARG_ADDR, key) == 0) {
      if (value && sscanf(value, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
        local_address[0] = a;
        local_address[1] = b;
        local_address[2] = c;
        local_address[3] = d;
      }
    } else if (strcmp(ARG_PORT, key) == 0) {
      if (value) {
        sscanf(value, "%u", &port);
      }
    } else if (strcmp(ARG_DEBUG, key) == 0) {
      debug = 1;
    } else if (strcmp(ARG_VERBOSE, key) == 0) {
      verbose = 1;
    }
  }

  slip_init();
  tcp_init();
  http_init();

  if (debug) {
    ip_debug_enable(verbose);
  }

  tcp_listen(port, http_open, http_recv, http_send, http_close);

  printf("Listening on %u.%u.%u.%u:%u...\n\n",
    local_address[0], local_address[1], local_address[2], local_address[3], port);

  while (1) {
    slip_rx();
  }

  return 0;
}
