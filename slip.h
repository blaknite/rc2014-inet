#ifndef __SLIP_H__
#define __SLIP_H__

#define SLIP_MTU 576 // Internet minimum MTU (RFC 791)
#define SLIP_MAX 1154 // SLIP_MTU * 2 + SLIP_END * 2

#define SLIP_END 0xc0
#define SLIP_ESC 0xdb
#define SLIP_ESC_END 0xdc
#define SLIP_ESC_ESC 0xdd

#define slip_buffer_alloc() (calloc(SLIP_MAX, 1))

typedef struct {
  uint8_t *buffer;
  uint16_t length;
  uint8_t escaped;
} slip_decoder_t;

extern uint8_t *slip_rx_buffer;
extern uint8_t *slip_tx_buffer;
extern slip_decoder_t slip_decoder;

void slip_init(void);
void slip_decoder_reset(void);
uint8_t slip_process_byte(uint8_t b);
void slip_rx(void);
void slip_tx(uint8_t *buffer, uint16_t len);

#endif
