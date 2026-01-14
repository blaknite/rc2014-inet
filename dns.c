#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "slip.h"
#include "ip.h"
#include "udp.h"
#include "dns.h"

static uint8_t dns_response_ready = 0;
static uint8_t dns_result_ip[4];
static uint16_t dns_query_id = 0;
static uint8_t dns_server[4] = {8, 8, 8, 8};
static uint16_t dns_port = 0;

uint8_t *dns_tx_buffer;

void dns_init(uint8_t *server) {
  dns_tx_buffer = malloc(UDP_PACKET_LEN);

  memcpy(dns_server, server, 4);

  // Use ephemeral port in range 1024-2047
  dns_port = 1024 + (rand() & 0x3FF);
  udp_bind(dns_port, dns_rx);
}

static void dns_reset() {
  dns_response_ready = 0;
  dns_query_id = (dns_query_id + 1) & 0xFFFF;

  if (dns_query_id == 0) {
    dns_query_id = 1;
  }
}

uint8_t dns_encode_name(uint8_t *buffer, const char *hostname) {
  uint8_t *len_ptr;
  uint8_t len = 0;
  uint8_t total = 0;
  const char *p = hostname;

  len_ptr = buffer++;
  total++;

  while (*p) {
    if (*p == '.') {
      *len_ptr = len;
      len = 0;
      len_ptr = buffer++;
      total++;
      p++;
    } else {
      *buffer++ = *p++;
      len++;
      total++;
    }
  }

  *len_ptr = len;
  *buffer = 0;
  total++;

  return total;
}

static uint16_t dns_name_len(uint8_t *name_start, uint8_t *end) {
  uint8_t *p = name_start;
  uint8_t len;

  while (p < end && *p != 0) {
    if ((*p & 0xC0) == 0xC0) {
      return (p - name_start) + 2;
    }

    len = *p;
    if (len > 63) {
      return 0;
    }

    p += 1 + len;
  }

  if (p >= end) {
    return 0;
  }

  return (p - name_start) + 1;
}

static void dns_process_answer(uint8_t *dns_data, uint8_t *end, struct dns_parse_result *result) {
  struct dns_answer *ans;
  uint16_t rdlength;
  uint16_t name_len;
  uint16_t answer_type;

  result->success = 0;
  result->consumed = 0;

  name_len = dns_name_len(dns_data, end);

  if (name_len == 0) {
    if (dns_data + sizeof(struct dns_answer) <= end) {
      ans = (struct dns_answer *)dns_data;
      rdlength = ntohs(ans->rdlength);
      result->consumed = sizeof(struct dns_answer) + rdlength;
    }
    return;
  }

  if (dns_data + name_len + sizeof(struct dns_answer) > end) {
    return;
  }

  result->consumed = name_len;

  ans = (struct dns_answer *)(dns_data + name_len);
  answer_type = ntohs(ans->type);
  rdlength = ntohs(ans->rdlength);

  result->consumed += sizeof(struct dns_answer) + rdlength;

  if (answer_type == DNS_TYPE_A && rdlength == 4) {
    uint8_t *rdata = (uint8_t *)(ans + 1);

    if (rdata + 4 <= end) {
      memcpy(dns_result_ip, rdata, 4);
      result->success = 1;
    }
  }
}

void dns_rx(struct ip_hdr *iph) {
  struct udp_hdr *udph = (struct udp_hdr *)ip_data(iph);
  uint8_t *udpd = udp_data(udph);
  struct dns_hdr *dnsh = (struct dns_hdr *)udpd;
  uint8_t *dns_data = (uint8_t *)(dnsh + 1);
  uint8_t *end = udpd + udph->len;
  uint16_t id, flags, ancount;
  uint16_t name_len;
  uint8_t i;

  id = ntohs(dnsh->id);
  flags = ntohs(dnsh->flags);
  ancount = ntohs(dnsh->ancount);

  if (id != dns_query_id) {
    return;
  }

  if (!(flags & DNS_FLAG_QR)) {
    return;
  }

  dns_response_ready = 1;

  if ((flags & DNS_FLAG_RCODE) != DNS_RCODE_OK) {
    return;
  }

  name_len = dns_name_len(dns_data, end);
  if (name_len == 0) {
    return;
  }
  dns_data += name_len + 4;

  struct dns_parse_result result;

  for (i = 0; i < ancount && dns_data < end; i++) {
    dns_process_answer(dns_data, end, &result);

    dns_data += result.consumed;

    if (result.success) {
      return;
    }
  }
}

static void dns_tx(const char *hostname, uint16_t qtype) {
  struct dns_hdr *dnsh = (struct dns_hdr *)dns_tx_buffer;
  struct dns_question *question;
  uint8_t *qname;
  uint8_t name_len;
  uint16_t len;

  dns_reset();

  dnsh->id = htons(dns_query_id);
  dnsh->flags = htons(DNS_FLAG_RD);
  dnsh->qdcount = htons(1);
  dnsh->ancount = 0;
  dnsh->nscount = 0;
  dnsh->arcount = 0;

  qname = (uint8_t *)(dnsh + 1);
  name_len = dns_encode_name(qname, hostname);

  question = (struct dns_question *)(qname + name_len);
  question->qtype = htons(qtype);
  question->qclass = htons(DNS_CLASS_IN);

  len = 16 + name_len;

  udp_tx(dns_server, dns_port, DNS_PORT, dns_tx_buffer, len);
}

uint8_t dns_resolve(const char *hostname, uint8_t *ip) {
  uint16_t timeout = DNS_QUERY_TIMEOUT;

  dns_tx(hostname, DNS_TYPE_A);

  while (timeout-- && !dns_response_ready) {
    if (slip_rx_ready()) {
      slip_rx();
    }

    msleep(1);
  }

  if (dns_response_ready) {
    memcpy(ip, dns_result_ip, 4);
    return 1;
  }

  return 0;
}
