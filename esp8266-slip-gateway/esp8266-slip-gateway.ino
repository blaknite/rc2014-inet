/*
 * ESP8266 SLIP NAT Gateway for RC2014
 *
 * Network Architecture:
 *  - RC2014 (192.168.1.51) <--SLIP--> ESP8266 SLIP Interface (192.168.1.1)
 *  - ESP8266 WiFi STA <--WiFi--> Internet Router
 *
 * NAT Configuration:
 *  - NAPT enabled on SLIP interface (private/internal side)
 *  - WiFi STA is default route (public/external side)
 *  - Outbound: RC2014 packets are NATed from 192.168.1.51 to WiFi IP
 *  - Inbound: Port forwarding from WiFi IP to RC2014 for specific services
 */

#include <ESP8266WiFi.h>

extern "C" {
  #include "lwip/netif.h"
  #include "lwip/ip.h"
  #include "lwip/ip_addr.h"
  #include "lwip/pbuf.h"
  #include "lwip/napt.h"
  #include "lwip/tcp.h"
  #include "lwip/udp.h"
  #include "netif/ethernet.h"
  #include "lwip/inet_chksum.h"
  #include "lwip/ip4_frag.h"
  #include "lwip/ip4.h"
}

const char* WIFI_SSID = "The LANBox - www.thelanbox.com";
const char* WIFI_PASSWORD = "kobol.invium.net";

const IPAddress RC2014_IP(192, 168, 1, 51);
const IPAddress SLIP_GATEWAY_IP(192, 168, 1, 1);
const IPAddress SLIP_NETMASK(255, 255, 255, 0);
const uint32_t SERIAL_BAUD = 115200;

const int LED_WIFI = 5;
const int LED_ACTIVITY = 4;

#define SLIP_END     0xC0
#define SLIP_ESC     0xDB
#define SLIP_ESC_END 0xDC
#define SLIP_ESC_ESC 0xDD

const size_t SLIP_MTU = 576;
const size_t SLIP_MAX_PACKET = 1154;

struct SlipDecoder {
  uint8_t buffer[SLIP_MAX_PACKET];
  size_t length;
  bool escaped;

  void reset() {
    length = 0;
    escaped = false;
  }

  bool processByte(uint8_t b) {
    if (b == SLIP_END) {
      if (length > 0) return true;

      reset();

      return false;
    }

    if (b == SLIP_ESC) {
      escaped = true;
      return false;
    }

    if (escaped) {
      if (b == SLIP_ESC_END) b = SLIP_END;
      if (b == SLIP_ESC_ESC) b = SLIP_ESC;

      escaped = false;
    }

    buffer[length++] = b;

    // Buffer overflow - discard packet
    if (length > SLIP_MAX_PACKET) {
      reset();
    }

    return false;
  }
};

struct netif slipNetif;
SlipDecoder slipDecoder;
bool slipInitialized = false;

uint32_t lastActivityTime = 0;
const uint32_t ACTIVITY_LED_DURATION = 100;

err_t slipInput(struct pbuf *p, struct netif *inp) {
  return ip_input(p, inp);
}

err_t slipOutput(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr) {
  if (p->tot_len > SLIP_MTU) {
    return ERR_MEM;
  }

  digitalWrite(LED_ACTIVITY, HIGH);
  lastActivityTime = millis();

  uint8_t buffer[SLIP_MTU];
  pbuf_copy_partial(p, buffer, p->tot_len, 0);

  // Send SLIP_END to start frame
  Serial.write(SLIP_END);

  // Encode and send each byte with inter-byte delay
  // This prevents overwhelming the RC2014's slow character-by-character reads
  for (size_t i = 0; i < p->tot_len; i++) {
    uint8_t b = buffer[i];
    if (b == SLIP_END) {
      Serial.write(SLIP_ESC);
      Serial.write(SLIP_ESC_END);
    } else if (b == SLIP_ESC) {
      Serial.write(SLIP_ESC);
      Serial.write(SLIP_ESC_ESC);
    } else {
      Serial.write(b);
    }

    delayMicroseconds(500);
  }

  // Add SLIP_END to end frame
  Serial.write(SLIP_END);
  Serial.flush();

  return ERR_OK;
}

void processSlipData() {
  if (!slipInitialized) return;

  static uint8_t processBuffer[SLIP_MAX_PACKET];

  while (Serial.available()) {
    digitalWrite(LED_ACTIVITY, HIGH);
    lastActivityTime = millis();

    uint8_t b = Serial.read();
    bool packetComplete = slipDecoder.processByte(b);

    if (!packetComplete) continue;

    size_t packetLen = slipDecoder.length;
    slipDecoder.reset();

    // Validate packet length is reasonable
    if (packetLen < 20 || packetLen > SLIP_MTU) continue;

    memcpy(processBuffer, slipDecoder.buffer, packetLen);

    // Basic IP header validation
    uint8_t version = (processBuffer[0] >> 4) & 0x0F;
    uint8_t headerLen = (processBuffer[0] & 0x0F) * 4;

    if (version != 4 || headerLen < 20 || headerLen > packetLen) continue;

    // Process the packet
    struct pbuf* p = pbuf_alloc(PBUF_IP, packetLen, PBUF_RAM);
    if (!p) continue;

    memcpy(p->payload, processBuffer, packetLen);

    if (slipNetif.input(p, &slipNetif) != ERR_OK) {
      pbuf_free(p);
    }
  }
}

err_t slipNetifInit(struct netif *netif) {
  netif->name[0] = 's';
  netif->name[1] = 'l';
  netif->num = 2;

  netif->output = slipOutput;

  netif->mtu = SLIP_MTU;
  netif->flags = NETIF_FLAG_LINK_UP | NETIF_FLAG_UP;

  return ERR_OK;
}

void setupSlipInterface() {
  ip_addr_t ipaddr, netmask, gw;

  IP_ADDR4(&ipaddr, SLIP_GATEWAY_IP[0], SLIP_GATEWAY_IP[1], SLIP_GATEWAY_IP[2], SLIP_GATEWAY_IP[3]);
  IP_ADDR4(&netmask, SLIP_NETMASK[0], SLIP_NETMASK[1], SLIP_NETMASK[2], SLIP_NETMASK[3]);
  IP_ADDR4(&gw, SLIP_GATEWAY_IP[0], SLIP_GATEWAY_IP[1], SLIP_GATEWAY_IP[2], SLIP_GATEWAY_IP[3]);

  // Register SLIP network interface with lwIP stack
  // slipInput passes packets to ip_input for layer 3 processing (NAPT/forwarding handled there)
  netif_add(&slipNetif, &ipaddr, &netmask, &gw, NULL, slipNetifInit, slipInput);
  netif_set_up(&slipNetif);
  netif_set_link_up(&slipNetif);

  slipInitialized = true;
}

void setupNAT() {
  if (!slipInitialized) {
    return;
  }

  // Get WiFi interface - look for "st" (station) interface, skip SLIP
  struct netif* wifiNetif = netif_list;
  while (wifiNetif != NULL) {
    // Check if this is the WiFi station interface (not SLIP)
    if (wifiNetif != &slipNetif &&
        wifiNetif->name[0] == 's' &&
        wifiNetif->name[1] == 't') {
      break; // Found station (WiFi) interface
    }
    wifiNetif = wifiNetif->next;
  }

  if (!wifiNetif) {
    return;
  }

  // Initialize NAPT with table sizes (max entries, max port mappings)
  err_t ret = ip_napt_init(512, 32);

  if (ret == ERR_OK) {
    // Enable NAPT on SLIP interface (the internal/private side)
    // This enables NAT for packets originating from the SLIP network (192.168.1.x)
    u32_t slipAddr = ip4_addr_get_u32(&slipNetif.ip_addr);

    ip_napt_enable(slipAddr, 1);

    // Now add port forwarding rules for inbound connections
    // This allows connections to the WiFi IP to be forwarded to the RC2014
    IPAddress wifiIP = WiFi.localIP();
    u32_t wifiAddr = wifiIP;
    u32_t rc2014Addr = RC2014_IP;

    u16_t ports[] = {80, 23, 22, 21};
    for (int i = 0; i < sizeof(ports) / sizeof(ports[0]); i++) {
      ip_portmap_add(IP_PROTO_TCP, wifiAddr, ports[i], rc2014Addr, ports[i]);
      ip_portmap_add(IP_PROTO_UDP, wifiAddr, ports[i], rc2014Addr, ports[i]);
    }
  }
}

void setup() {
  pinMode(LED_WIFI, OUTPUT);
  pinMode(LED_ACTIVITY, OUTPUT);
  digitalWrite(LED_WIFI, LOW);
  digitalWrite(LED_ACTIVITY, HIGH);

  Serial.begin(SERIAL_BAUD);
  Serial.setRxBufferSize(1024);

  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  WiFi.setAutoReconnect(true);

  uint32_t startTime = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - startTime < 30000) {
    digitalWrite(LED_WIFI, !digitalRead(LED_WIFI));
    delay(250);
  }

  digitalWrite(LED_WIFI, WiFi.status() == WL_CONNECTED ? HIGH : LOW);
  digitalWrite(LED_ACTIVITY, LOW);

  if (WiFi.status() == WL_CONNECTED) {
    setupSlipInterface();
    setupNAT();
  }

  slipDecoder.reset();
}

void loop() {
  static bool lastWifiStatus = false;
  bool currentWifiStatus = (WiFi.status() == WL_CONNECTED);

  if (currentWifiStatus != lastWifiStatus) {
    digitalWrite(LED_WIFI, currentWifiStatus ? HIGH : LOW);
    lastWifiStatus = currentWifiStatus;

    if (currentWifiStatus && !slipInitialized) {
      setupSlipInterface();
      setupNAT();
    }
  }

  if (!currentWifiStatus) {
    delay(1000);
    return;
  }

  processSlipData();

  if (millis() - lastActivityTime > ACTIVITY_LED_DURATION) {
    digitalWrite(LED_ACTIVITY, LOW);
  }
}
