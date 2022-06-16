#include <stdlib.h>
#include <stdio.h>
#include "slip.h"
#include "ip.h"
#include "tcp.h"
#include "http.h"

void main(void) {
  slip_init();
  tcp_init();
  http_init();

  tcp_listen(80, http_open, http_recv, http_send, http_close);

  printf("Listening on %u.%u.%u.%u:80...\n\n",
    local_address[0], local_address[1], local_address[2], local_address[3]);

  while (1) {
    slip_rx();
  }
}
