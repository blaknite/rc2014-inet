#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "http.h"
#include "tcp.h"

struct http_client *http_client_table;

uint8_t *mime_types[] = {
  "htm", "text/html",
  "txt", "text/plain",
  "png", "image/png",
  "jpg", "image/jpeg",
  NULL
};

uint8_t *text_types[] = { "htm", "txt", NULL };

uint8_t *http_tx_buffer;

void http_init(void) {
  http_client_table = calloc(HTTP_MAX_CLIENTS, sizeof(struct http_client));
  http_tx_buffer = malloc(TCP_PACKET_LEN);
}

struct http_client *http_get_client(struct tcp_sock *s) {
  uint8_t i;

  for (i = 0; i < HTTP_MAX_CLIENTS; i++) {
    if (http_client_table[i].s == s) {
      return &http_client_table[i];
    }
  }

  return NULL;
}

void http_log(struct http_client *c, uint16_t code) {
  printf("%u.%u.%u.%u %s %s %u\n",
    c->s->daddr[0], c->s->daddr[1], c->s->daddr[2], c->s->daddr[3],
    c->req_method, c->req_file, code);
}

void http_system_response(struct http_client *c, uint16_t code, uint8_t *message) {
  uint8_t *ptr;

  ptr = &http_tx_buffer[0];
  ptr += sprintf((char *)ptr, "HTTP/1.0 %u %s\r\n", code, (char *)message);
  ptr += sprintf((char *)ptr, "Content-Type: text/html\r\n");
  ptr += sprintf((char *)ptr, "Content-Length: %u\r\n", 4 + strlen((char *)message) + 2);
  ptr += sprintf((char *)ptr, "\r\n");
  ptr += sprintf((char *)ptr, "%u %s\r\n", code, (char *)message);

  c->tx_cur = ptr - http_tx_buffer;  // Store response length

  http_log(c, code);

  c->state = HTTP_TX_HDR;
}

uint8_t *http_content_type(struct http_client *c) {
  uint8_t ext[4];
  uint8_t i;
  uint16_t len = strlen((char *)c->req_file);

  if (len < 4) {
    return (uint8_t *)"application/octet-stream";
  }

  strncpy((char *)ext, (char *)&c->req_file[len - 3], 4);

  for (i = 0; mime_types[i]; i += 2) {
    if (strcasecmp((char *)ext, (char *)mime_types[i]) == 0) {
      return mime_types[i + 1];
    }
  }

  return (uint8_t *)"application/octet-stream";
}

uint8_t http_file_mode(struct http_client *c) {
  uint8_t ext[4];
  uint8_t i;
  uint16_t len = strlen((char *)c->req_file);

  if (len < 4) {
    return HTTP_FILE_MODE_BINARY;
  }

  strncpy((char *)ext, (char *)&c->req_file[len - 3], 4);

  for (i = 0; text_types[i]; i++) {
    if (strcasecmp((char *)ext, (char *)text_types[i]) == 0) {
      return HTTP_FILE_MODE_TEXT;
    }
  }

  return HTTP_FILE_MODE_BINARY;
}

int16_t http_file_open(struct http_client *c) {
  if (c->file_mode == HTTP_FILE_MODE_TEXT) {
    return open((char *)&c->req_file[1], O_RDONLY, _IOTEXT);
  } else {
    return open((char *)&c->req_file[1], O_RDONLY, 0);
  }
}

uint32_t http_content_length(struct http_client *c, int16_t fd) {
  uint32_t pos;

  _fcb[fd].mode = 0;

  lseek(fd, 0, SEEK_END);
  pos = fdtell(fd);

  if (c->file_mode == HTTP_FILE_MODE_TEXT) {
    if (pos >= SECSIZE) {
      lseek(fd, pos - SECSIZE, SEEK_SET);
    }

    _fcb[fd].mode = _IOTEXT;

    lseek(fd, 0, SEEK_END);
    pos = fdtell(fd);
  }

  return pos;
}

void http_response(struct http_client *c) {
  uint8_t *ptr;

  c->file_mode = http_file_mode(c);

  c->fd = http_file_open(c);

  if (c->fd >= 0) {
    c->tx_len = http_content_length(c, c->fd);
    c->tx_cur = 0;

    ptr = &http_tx_buffer[0];
    ptr += sprintf((char *)ptr, "HTTP/1.0 200 OK\r\n");
    ptr += sprintf((char *)ptr, "Content-Type: %s\r\n", (char *)http_content_type(c));
    ptr += sprintf((char *)ptr, "Content-Length: %lu\r\n", c->tx_len);
    ptr += sprintf((char *)ptr, "\r\n");

    c->tx_cur = ptr - http_tx_buffer;  // Store header length

    http_log(c, 200);

    // For HEAD requests, close file since we won't send the body
    if (strncmp((char *)c->req_method, "HEAD", 4) == 0) {
      close(c->fd);
      c->fd = -1;
    }

    c->state = HTTP_TX_HDR;
  } else {
    http_system_response(c, 404, (uint8_t *)"Not Found");
  }
}

void http_parse_request(struct http_client *c) {
  int8_t *req_method;
  int8_t *req_file;

  if (c->rx_cur < 9) {
    return;
  }

  if (strncmp((char *)&c->rx_buff[c->rx_cur - 4], "\r\n\r\n", 4) != 0) {
    return;
  }

  req_method = (int8_t *)strtok((char *)c->rx_buff, " ");
  if (!req_method) {
    http_system_response(c, 400, (uint8_t *)"Bad Request");
    return;
  }

  if (strlen((char *)req_method) > 7) {
    http_system_response(c, 400, (uint8_t *)"Bad Request");
    return;
  }

  req_file = (int8_t *)strtok(NULL, " ");
  if (!req_file) {
    http_system_response(c, 400, (uint8_t *)"Bad Request");
    return;
  }

  if (strlen((char *)req_file) >= 14) {
    http_system_response(c, 414, (uint8_t *)"URI Too Long");
    return;
  }

  if (req_file[0] != '/') {
    http_system_response(c, 400, (uint8_t *)"Bad Request");
    return;
  }

  if (strchr((char *)req_file, ':')) {
    http_system_response(c, 400, (uint8_t *)"Bad Request");
    return;
  }

  strcpy((char *)c->req_method, (char *)req_method);

  if (strlen((char *)req_file) == 1) {
    strcpy((char *)c->req_file, "/INDEX.HTM");
  } else {
    strcpy((char *)c->req_file, (char *)req_file);
  }

  if (strncmp((char *)c->req_method, "GET", 3) == 0 || strncmp((char *)c->req_method, "HEAD", 4) == 0) {
    http_response(c);
  } else {
    http_system_response(c, 404, (uint8_t *)"Not Found");
  }
}

void http_open(struct tcp_sock *s) {
  uint8_t i;

  for (i = 0; i < HTTP_MAX_CLIENTS; i++) {
    if (!http_client_table[i].s) {
      memset(&http_client_table[i], 0, sizeof(struct http_client));

      http_client_table[i].s = s;
      http_client_table[i].state = HTTP_RX_REQ;
      http_client_table[i].fd = -1;

      return;
    }
  }

  // No free HTTP client - reject the connection
  printf("ERROR: Client limit reached, rejecting %u.%u.%u.%u\n",
    s->daddr[0], s->daddr[1], s->daddr[2], s->daddr[3]);
  tcp_tx_rst(s);
  tcp_sock_close(s);
}

void http_recv(struct tcp_sock *s, uint8_t *data, uint16_t len) {
  struct http_client *c = http_get_client(s);

  if (!c) {
    return;
  }

  if (c->state != HTTP_RX_REQ) {
    return;
  }

  if (c->rx_cur + len > HTTP_RX_LEN) {
    http_system_response(c, 431, (uint8_t *)"Request Header Fields Too Large");
    return;
  }

  memcpy(&c->rx_buff[c->rx_cur], data, len);

  c->rx_cur += len;

  http_parse_request(c);
}

void http_send(struct tcp_sock *s, uint16_t len) {
  struct http_client *c = http_get_client(s);

  if (!c) {
    return;
  }

  switch (c->state) {
    case HTTP_TX_HDR:
      if (c->fd == -1) {
        tcp_tx_data_fin(c->s, http_tx_buffer, (uint16_t)c->tx_cur);
        c->state = HTTP_TX_DONE;
        c->tx_cur = 0;
      } else {
        tcp_tx_data(c->s, http_tx_buffer, (uint16_t)c->tx_cur);
        c->state = HTTP_TX_BODY;
        c->tx_cur = 0;
      }
      break;

    case HTTP_TX_BODY:
      if (len > TCP_PACKET_LEN) {
        len = TCP_PACKET_LEN;
      }

      lseek(c->fd, c->tx_cur, SEEK_SET);

      len = read(c->fd, http_tx_buffer, len);

      if (len > 0) {
        c->tx_cur += len;

        if (c->tx_cur >= c->tx_len) {
          tcp_tx_data_fin(c->s, http_tx_buffer, len);
          close(c->fd);
          c->fd = -1;
          c->state = HTTP_TX_DONE;
        } else {
          tcp_tx_data(c->s, http_tx_buffer, len);
        }
      } else {
        // EOF or read error - abort the connection
        close(c->fd);
        c->fd = -1;
        tcp_tx_rst(c->s);
        tcp_sock_close(c->s);
      }
      break;

    case HTTP_TX_DONE:
      // nothing to do, connection already closed
      break;
  }
}

void http_close(struct tcp_sock *s) {
  struct http_client *c = http_get_client(s);

  if (!c) {
    return;
  }

  if (c->fd >= 0) {
    close(c->fd);
  }

  memset(c, 0, sizeof(struct http_client));
  c->fd = -1;
}
