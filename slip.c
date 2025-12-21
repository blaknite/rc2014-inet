#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "slip.h"
#include "ip.h"

uint8_t *slip_rx_buffer;
uint8_t *slip_tx_buffer;
slip_decoder_t slip_decoder;
uint8_t slip_tx_sent;

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

uint8_t slip_rx_decode(uint8_t b) {
  if (b == SLIP_END) {
    if (slip_decoder.length > 0) {
      return SLIP_DECODE_DONE;
    }

    return SLIP_DECODE_SKIP;
  }

  if (b == SLIP_ESC) {
    slip_decoder.escaped = 1;
    return SLIP_DECODE_OK;
  }

  if (slip_decoder.escaped) {
    if (b == SLIP_ESC_END) {
      b = SLIP_END;
    } else if (b == SLIP_ESC_ESC) {
      b = SLIP_ESC;
    }

    slip_decoder.escaped = 0;
  }

  slip_decoder.buffer[slip_decoder.length++] = b;

  if (slip_decoder.length >= SLIP_MAX) {
    return SLIP_DECODE_RST;
  }

  return SLIP_DECODE_OK;
}

void slip_rx(void) {
  uint8_t c;
  uint8_t status;

  while (1) {
    c = bdos(CPM_RRDR, 0);
    status = slip_rx_decode(c);

    if (status == SLIP_DECODE_DONE) {
      slip_tx_sent = 0;

      ip_rx((struct ip_hdr *)slip_decoder.buffer);

      if (!slip_tx_sent) {
        slip_tx(NULL, 0);
      }

      slip_reset();

      return;
    } else if (status == SLIP_DECODE_RST) {
      slip_reset();
    }
  }
}

void slip_tx(uint8_t *buffer, uint16_t len) {
  uint16_t i;

  slip_tx_sent = 1;

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
