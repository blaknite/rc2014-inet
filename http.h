#ifndef __HTTP_H__
#define __HTTP_H__

#define HTTP_MAX_CLIENTS 16
#define HTTP_RX_LEN 1024

#define HTTP_RX_REQ 0
#define HTTP_TX_HDR 1
#define HTTP_TX_BODY 2

#define HTTP_FILE_MODE_TEXT 0
#define HTTP_FILE_MODE_BINARY 1

struct http_client {
  struct tcp_sock *s;
  uint8_t state;
  uint8_t rx_buff[HTTP_RX_LEN];
  uint16_t rx_cur;
  uint8_t req_method[8];
  uint8_t req_file[14];
  uint8_t file_mode;
  uint32_t tx_len;
  uint32_t tx_cur;
};

void http_init(void);
struct http_client *http_get_client(struct tcp_sock *s);
void http_parse_request(struct http_client *c);
void http_open(struct tcp_sock *s);
void http_recv(struct tcp_sock *s, uint8_t *data, uint16_t len);
void http_send(struct tcp_sock *s, uint16_t len);
void http_close(struct tcp_sock *s);

#endif
