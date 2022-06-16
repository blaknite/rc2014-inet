#include <stdlib.h>
#include <stdio.h>
#include "slip.h"
#include "ip.h"

uint8_t *slip_rx_buffer;
uint8_t *slip_tx_buffer;

void slip_init(void) {
  slip_rx_buffer = slip_buffer_alloc();
  slip_tx_buffer = slip_buffer_alloc();
}

void slip_rx(void) {
  uint16_t i = 0;
  uint8_t c;

  while (1) {
    c = bdos(CPM_RRDR, 0);

    if (c == SLIP_END && i == 0) {
      // printf("%2x:", c);
      continue;
    } else if (c == SLIP_END) {
      // printf("%2x\n", c);
      break;
    }

    if (c == SLIP_ESC) {
      c = bdos(CPM_RRDR, 0);

      switch (c) {
        case SLIP_ESC_END:
          c = SLIP_END;
          break;

        case SLIP_ESC_ESC:
          c = SLIP_ESC;
          break;
      }
    }

    slip_rx_buffer[i++] = c;
    // printf("%2x:", c);

    if (i == SLIP_MAX) break;
  }

  ip_rx(slip_rx_buffer);
}

void slip_tx(uint8_t *buffer, uint16_t len) {
  uint16_t i;

  bdos(CPM_WPUN, SLIP_END);
  // printf("%2x:", SLIP_END);

  for (i = 0; i < len; i++) {
    switch (buffer[i]) {
      case SLIP_END:
        bdos(CPM_WPUN, SLIP_ESC);
        bdos(CPM_WPUN, SLIP_ESC_END);
        break;

      case SLIP_ESC:
        bdos(CPM_WPUN, SLIP_ESC);
        bdos(CPM_WPUN, SLIP_ESC_ESC);
        break;

      default:
        bdos(CPM_WPUN, buffer[i]);
    }

    // printf("%2x:", buffer[i]);
  }

  bdos(CPM_WPUN, SLIP_END);
  // printf("%2x\n", SLIP_END);
}
