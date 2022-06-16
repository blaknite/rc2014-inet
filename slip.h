#ifndef __SLIP_H__
#define __SLIP_H__

#define SLIP_MTU 296 // TCP_PACKET_LEN plus headers
#define SLIP_MAX 594 // SLIP_MTU * 2 + SLIP_END * 2

#define SLIP_END 0xc0
#define SLIP_ESC 0xdb
#define SLIP_ESC_END 0xdc
#define SLIP_ESC_ESC 0xdd

#define slip_buffer_alloc() (calloc(SLIP_MAX, 1))

extern uint8_t *slip_rx_buffer;
extern uint8_t *slip_tx_buffer;

void slip_init(void);
void slip_rx(void);
void slip_tx(uint8_t *buffer, uint16_t len);

#endif
