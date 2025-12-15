#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "slip.h"
#include "ip.h"

uint8_t *slip_rx_buffer;
uint8_t *slip_tx_buffer;
slip_decoder_t slip_decoder;

void slip_init(void) {
  slip_rx_buffer = slip_buffer_alloc();
  slip_tx_buffer = slip_buffer_alloc();

  slip_decoder.buffer = slip_rx_buffer;
  slip_decoder.length = 0;
  slip_decoder.escaped = 0;
}

void slip_reset(void) {
  slip_decoder.length = 0;
  slip_decoder.escaped = 0;
}

uint8_t slip_rx_byte(uint8_t b) {
  if (b == SLIP_END) {
    if (slip_decoder.length > 0) {
      return 1; // Packet complete
    }

    slip_reset();

    return 0;
  }

  if (b == SLIP_ESC) {
    slip_decoder.escaped = 1;
    return 0;
  }

  if (slip_decoder.escaped) {
    if (b == SLIP_ESC_END) b = SLIP_END;
    if (b == SLIP_ESC_ESC) b = SLIP_ESC;

    slip_decoder.escaped = 0;
  }

  slip_decoder.buffer[slip_decoder.length++] = b;

  // Buffer overflow - discard packet
  if (slip_decoder.length >= SLIP_MAX) {
    printf("SLIP frame too large: >= %u bytes, discarding\n", SLIP_MAX);
    slip_reset();
  }

  return 0;
}

void slip_rx(void) {
  uint8_t c;

  while (1) {
    c = bdos(CPM_RRDR, 0);

    if (slip_rx_byte(c)) {
      // Packet complete
      ip_rx((struct ip_hdr *)slip_decoder.buffer);
      slip_reset();
      return;
    }
  }
}

void slip_tx(uint8_t *buffer, uint16_t len) {
  uint16_t i;

  bdos(CPM_WPUN, SLIP_END);

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
  }

  bdos(CPM_WPUN, SLIP_END);
}
