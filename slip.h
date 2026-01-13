#ifndef __SLIP_H__
#define __SLIP_H__

#define SLIP_MTU 576 // Internet minimum MTU (RFC 791)
#define SLIP_MAX 1154 // SLIP_MTU * 2 + SLIP_END * 2

#define SLIP_END 0xc0
#define SLIP_ESC 0xdb
#define SLIP_ESC_END 0xdc
#define SLIP_ESC_ESC 0xdd

// #define BIOS_SERB_BUF 0xFF83
// #define BIOS_SERB_BUFUSED 0xFFBE
// #define BIOS_SERB_RDPTR 0xFFBF
// #define BIOS_SERB_BUFSIZE 60

#define SLIP_DECODE_OK 0
#define SLIP_DECODE_SKIP 1
#define SLIP_DECODE_DONE 2
#define SLIP_DECODE_RST 3

#define slip_buffer_alloc() (calloc(SLIP_MAX, 1))
// #define slip_rx_ready() (*(uint8_t *)BIOS_SERB_BUFUSED > 0)

extern uint8_t *slip_rx_buffer;
extern uint8_t *slip_tx_buffer;

void slip_init(void);
void slip_rx(void);
void slip_tx(uint8_t *buffer, uint16_t len);

#endif
