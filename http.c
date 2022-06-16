#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "http.h"
#include "tcp.h"

struct http_client *http_client_table;

uint8_t *mime_types[] = {
  "htm", "text/html",
  "txt", "text/plain",
  "png", "image/png"
};

uint8_t *text_types[] = { "htm", "txt" };

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
  ptr += sprintf(ptr, "HTTP/1.0 %u %s\r\n", code, message);
  ptr += sprintf(ptr, "Content-Type: text/html\r\n");
  ptr += sprintf(ptr, "Content-Length: %u\r\n", 4 + strlen(message) + 2);
  ptr += sprintf(ptr, "\r\n");
  ptr += sprintf(ptr, "%u %s\r\n", code, message);

  http_log(c, code);

  c->state = HTTP_TX_HDR;
}

void http_content_type(struct http_client *c) {
  uint8_t ext[4];
  uint8_t i;

  strncpy(ext, &c->req_file[strlen(c->req_file) - 3], 4);

  for (i = 0; mime_types[i]; i += 2) {
    if (strcasecmp(ext, mime_types[i]) == 0) {
      return mime_types[i + 1];
    }
  }

  return "application/octet-stream";
}

uint8_t http_file_mode(struct http_client *c) {
  uint8_t ext[4];
  uint8_t i;

  strncpy(ext, &c->req_file[strlen(c->req_file) - 3], 4);

  for (i = 0; text_types[i]; i++) {
    if (strcasecmp(ext, text_types[i]) == 0) {
      return HTTP_FILE_MODE_TEXT;
    }
  }

  return HTTP_FILE_MODE_BINARY;
}

int16_t http_file_open(struct http_client *c) {
  if (c->file_mode == HTTP_FILE_MODE_TEXT) {
    return open(&c->req_file[1], O_RDONLY, _IOTEXT);
  } else {
    return open(&c->req_file[1], O_RDONLY, 0);
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
  int16_t fd;

  c->file_mode = http_file_mode(c);

  fd = http_file_open(c);

  if (fd >= 0) {
    c->tx_len = http_content_length(c, fd);

    ptr = &http_tx_buffer[0];
    ptr += sprintf(ptr, "HTTP/1.0 200 OK\r\n");
    ptr += sprintf(ptr, "Content-Type: %s\r\n", http_content_type(c));
    ptr += sprintf(ptr, "Content-Length: %lu\r\n", c->tx_len);
    ptr += sprintf(ptr, "\r\n");

    http_log(c, 200);

    c->state = HTTP_TX_HDR;

    close(fd);
  } else {
    http_system_response(c, 404, "Not Found");
  }
}

void http_parse_request(struct http_client *c) {
  int8_t *req_file;

  if (c->rx_cur < 9) {
    return;
  }

  if (strncmp(&c->rx_buff[c->rx_cur - 4], "\r\n\r\n", 4) != 0) {
    return;
  }

  strcpy(c->req_method, strtok(c->rx_buff, " "));
  req_file = strtok(NULL, " ");

  if (strlen(req_file) > 14) {
    http_system_response(c, 400, "Bad Request");
    return;
  }

  if (req_file[0] != '/') {
    http_system_response(c, 400, "Bad Request");
    return;
  }

  if (strchr(req_file, ":")) {
    http_system_response(c, 400, "Bad Request");
    return;
  }

  if (strlen(req_file) == 1) {
    strcpy(c->req_file, "/INDEX.HTM");
  } else {
    strcpy(c->req_file, req_file);
  }

  if (strncmp(c->req_method, "GET", 3) == 0 || strncmp(c->req_method, "HEAD", 4) == 0) {
    http_response(c);
  } else {
    http_system_response(c, 400, "Bad Request");
  }
}

void http_open(struct tcp_sock *s) {
  uint8_t i;

  for (i = 0; i < HTTP_MAX_CLIENTS; i++) {
    if (!http_client_table[i].s) {
      memset(&http_client_table[i], 0, sizeof(struct http_client));

      http_client_table[i].s = s;
      http_client_table[i].state = HTTP_RX_REQ;

      return;
    }
  }
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
    http_system_response(c, 431, "Request Header Fields Too Large");
    return;
  }

  memcpy(&c->rx_buff[c->rx_cur], data, len);

  c->rx_cur += len;

  http_parse_request(c);
}

void http_send(struct tcp_sock *s, uint16_t len) {
  struct http_client *c = http_get_client(s);
  int16_t fd;

  if (!c) {
    return;
  }

  switch (c->state) {
    case HTTP_TX_HDR:
      tcp_tx_data(c->s, http_tx_buffer, strlen(http_tx_buffer));
      c->state = HTTP_TX_BODY;
      break;

    case HTTP_TX_BODY:
      if (strncmp(c->req_method, "GET", 3) != 0) {
        break;
      }

      fd = http_file_open(c);

      if (fd == -1) {
        break;
      }

      if (len > TCP_PACKET_LEN) {
        len = TCP_PACKET_LEN;
      }

      lseek(fd, c->tx_cur, SEEK_SET);

      len = read(fd, http_tx_buffer, len);

      if (len > 0) {
        tcp_tx_data(c->s, http_tx_buffer, len);
      }

      c->tx_cur = fdtell(fd);

      close(fd);
      break;
  }
}

void http_close(struct tcp_sock *s) {
  struct http_client *c = http_get_client(s);

  if (!c) {
    return;
  }

  c->s = NULL;
}
