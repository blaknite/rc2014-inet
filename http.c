#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "http.h"
#include "tcp.h"

struct http_client *http_client_table;

const char * const mime_types[] = {
  "htm", "text/html",
  "txt", "text/plain",
  "css", "text/css",
  "js", "text/javascript",
  "jsn", "application/json",
  "xml", "text/xml",
  "jpg", "image/jpeg",
  "png", "image/png",
  "gif", "image/gif",
  "ico", "image/x-icon",
  "svg", "image/svg+xml",
  NULL
};

const char * const text_types[] = { "htm", "txt", "css", "js", "jsn", "xml", "svg", NULL };

uint8_t *http_tx_buffer;

const char *http_system_response_fmt = "\
HTTP/1.0 %u %s\r\n\
Content-Type: text/html\r\n\
Content-Length: %u\r\n\
\r\n\
%u %s\r\n";

const char *http_response_fmt = "\
HTTP/1.0 200 OK\r\n\
Content-Type: %s\r\n\
Content-Length: %lu\r\n\
\r\n";

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

void http_system_response(struct http_client *c, uint16_t code, char *message) {
  sprintf((char *)http_tx_buffer, http_system_response_fmt, code, message, 4 + strlen(message) + 2, code, message);

  c->tx_cur = strlen((char *)http_tx_buffer);

  http_log(c, code);

  c->state = HTTP_TX_HDR;
}

char *http_content_type(struct http_client *c) {
  char ext[4];
  uint8_t i;
  uint16_t len = strlen(c->req_file);

  if (len < 4) {
    return "application/octet-stream";
  }

  strncpy(ext, &c->req_file[len - 3], 4);

  for (i = 0; mime_types[i]; i += 2) {
    if (strcasecmp(ext, mime_types[i]) == 0) {
      return mime_types[i + 1];
    }
  }

  return "application/octet-stream";
}

uint8_t http_file_mode(struct http_client *c) {
  char ext[4];
  uint8_t i;
  uint16_t len = strlen(c->req_file);

  if (len < 4) {
    return HTTP_FILE_MODE_BINARY;
  }

  strncpy(ext, &c->req_file[len - 3], 4);

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
  c->file_mode = http_file_mode(c);

  c->fd = http_file_open(c);

  if (c->fd >= 0) {
    c->tx_len = http_content_length(c, c->fd);

    sprintf((char *)http_tx_buffer, http_response_fmt, http_content_type(c), c->tx_len);

    http_log(c, 200);

    // For HEAD requests, close file since we won't send the body
    if (strncmp(c->req_method, "HEAD", 4) == 0) {
      close(c->fd);
      c->fd = -1;
    }

    c->state = HTTP_TX_HDR;
  } else {
    http_system_response(c, 404, "Not Found");
  }
}

void http_parse_request(struct http_client *c) {
  char *req_method;
  char *req_file;

  if (c->rx_cur < 9) {
    return;
  }

  if (strncmp(&c->rx_buff[c->rx_cur - 4], "\r\n\r\n", 4) != 0) {
    return;
  }

  req_method = strtok(c->rx_buff, " ");
  if (!req_method) {
    http_system_response(c, 400, "Bad Request");
    return;
  }

  if (strlen(req_method) > 7) {
    http_system_response(c, 400, "Bad Request");
    return;
  }

  req_file = strtok(NULL, " ");
  if (!req_file) {
    http_system_response(c, 400, "Bad Request");
    return;
  }

  if (strlen(req_file) >= 14) {
    http_system_response(c, 414, "URI Too Long");
    return;
  }

  if (req_file[0] != '/') {
    http_system_response(c, 400, "Bad Request");
    return;
  }

  if (strchr(req_file, ':')) {
    http_system_response(c, 400, "Bad Request");
    return;
  }

  strcpy(c->req_method, req_method);

  if (strlen(req_file) == 1) {
    strcpy(c->req_file, "/INDEX.HTM");
  } else {
    strcpy(c->req_file, req_file);
  }

  if (strncmp(c->req_method, "GET", 3) == 0 || strncmp(c->req_method, "HEAD", 4) == 0) {
    http_response(c);
  } else {
    http_system_response(c, 404, "Not Found");
  }
}

void http_open(struct tcp_sock *s) {
  uint8_t i;
  struct http_client *c = &http_client_table[0];

  for (i = 0; i < HTTP_MAX_CLIENTS; i++) {
    if (!http_client_table[i].s) {
      c = &http_client_table[i];
      break;
    }

    if (http_client_table[i].s->ticks > c->s->ticks) {
      c = &http_client_table[i];
    }
  }

  if (c->s) {
    printf("Client limit reached: evicting %u.%u.%u.%u\n",
      c->s->daddr[0], c->s->daddr[1], c->s->daddr[2], c->s->daddr[3]);

    tcp_sock_close(c->s);
  }

  memset(c, 0, sizeof(struct http_client));

  c->s = s;
  c->state = HTTP_RX_REQ;
  c->fd = -1;
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

  if (!c) {
    return;
  }

  switch (c->state) {
    case HTTP_TX_HDR:
      if (c->fd < 0) {
        tcp_tx_data_fin(c->s, http_tx_buffer, strlen((char *)http_tx_buffer));
      } else {
        tcp_tx_data(c->s, http_tx_buffer, strlen((char *)http_tx_buffer));
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
}
