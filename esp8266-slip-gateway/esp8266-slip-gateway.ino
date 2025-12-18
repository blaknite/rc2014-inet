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
  uint32_t lastRxTime;

  void reset() {
    length = 0;
    escaped = false;
    lastRxTime = 0;
  }

  bool processByte(uint8_t b) {
    lastRxTime = millis();

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

  void checkTimeout() {
    // Reset if we have a partial frame that hasn't received data in 2 seconds
    if (length > 0 && millis() - lastRxTime > 2000) {
      reset();
    }
  }
};

struct netif slipNetif;
SlipDecoder slipDecoder;
bool slipInitialized = false;
uint32_t lastTxTime = 0;
uint32_t lastRxTime = 0;
uint32_t txPacingDelay = 250;  // Start at 250ms, adjust dynamically

// Flow control - packet queue
const uint8_t TX_QUEUE_SIZE = 16;
struct pbuf* txQueue[TX_QUEUE_SIZE];
uint8_t txQueueHead = 0;
uint8_t txQueueTail = 0;

err_t slipInput(struct pbuf *p, struct netif *inp) {
  return ip_input(p, inp);
}

void slipTxFrame(struct pbuf *p) {
  digitalWrite(LED_ACTIVITY, HIGH);

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

    delayMicroseconds(750);
  }

  // Add SLIP_END to end frame
  Serial.write(SLIP_END);
  Serial.flush();

  lastTxTime = millis();
  digitalWrite(LED_ACTIVITY, LOW);
}

bool txQueueEnqueue(struct pbuf *p) {
  uint8_t nextHead = (txQueueHead + 1) % TX_QUEUE_SIZE;

  // Check if queue is full
  if (nextHead == txQueueTail) {
    return false;
  }

  txQueue[txQueueHead] = p;
  pbuf_ref(p); // Increment reference count so lwIP doesn't free it
  txQueueHead = nextHead;

  return true;
}

struct pbuf* txQueuePeek() {
  // Check if queue is empty
  if (txQueueHead == txQueueTail) {
    return NULL;
  }

  return txQueue[txQueueTail];
}

struct pbuf* txQueueDequeue() {
  // Check if queue is empty
  if (txQueueHead == txQueueTail) {
    return NULL;
  }

  struct pbuf *p = txQueue[txQueueTail];
  txQueueTail = (txQueueTail + 1) % TX_QUEUE_SIZE;

  return p;
}

bool isTcpControlPacket(struct pbuf *p) {
  // Check if this is an IP packet with TCP protocol
  if (p->tot_len < 20) return false;  // Too small for IP header
  
  uint8_t *data = (uint8_t*)p->payload;
  uint8_t version = (data[0] >> 4) & 0x0F;
  uint8_t headerLen = (data[0] & 0x0F) * 4;
  uint8_t protocol = data[9];
  
  if (version != 4 || headerLen < 20 || protocol != 6) {
    return false;  // Not IPv4 or not TCP
  }
  
  // Check if packet is large enough for TCP header
  if (p->tot_len < headerLen + 14) return false;  // Need at least partial TCP header
  
  // Get TCP flags (13th byte of TCP header)
  uint8_t tcpFlags = data[headerLen + 13];
  
  // Check for SYN, FIN, or pure ACK (ACK without data)
  bool isSyn = tcpFlags & 0x02;  // SYN flag
  bool isFin = tcpFlags & 0x01;  // FIN flag
  bool isAck = tcpFlags & 0x10;  // ACK flag
  
  // Calculate TCP header length
  uint8_t tcpHeaderLen = (data[headerLen + 12] >> 4) * 4;
  uint16_t totalHeaderLen = headerLen + tcpHeaderLen;
  
  // Pure ACK: has ACK flag set and no data payload
  bool isPureAck = isAck && (p->tot_len <= totalHeaderLen);
  
  return isSyn || isFin || isPureAck;
}

void slipTx() {
  // Peek at the next packet without dequeuing
  struct pbuf *p = txQueuePeek();
  if (p == NULL) return;
  
  // Apply flow control only for data packets, not control packets (SYN, FIN, pure ACK)
  if (!isTcpControlPacket(p) && lastTxTime > 0 && millis() - lastTxTime < txPacingDelay) {
    return;
  }

  // Now dequeue and transmit
  txQueueDequeue();
  slipTxFrame(p);
  pbuf_free(p); // Decrement reference count
}

err_t slipOutput(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr) {
  if (p->tot_len > SLIP_MTU) {
    return ERR_MEM;
  }

  if (txQueueEnqueue(p)) {
    return ERR_OK;
  } else {
    // Queue full - connection will fail anyway due to RC2014's strict sequence checking
    // Tell lwIP to abort the connection immediately rather than retry
    return ERR_ABRT;
  }
}

void slipRx() {
  if (!slipInitialized) return;

  // Check for stalled partial frames and reset if needed
  slipDecoder.checkTimeout();

  static uint8_t processBuffer[SLIP_MAX_PACKET];

  if (Serial.available()) {
    digitalWrite(LED_ACTIVITY, HIGH);

    // Mark when we start receiving a frame
    if (lastRxTime == 0) {
      lastRxTime = millis();
    }
  }

  while (Serial.available()) {
    uint8_t b = Serial.read();
    bool packetComplete = slipDecoder.processByte(b);

    if (!packetComplete) continue;

    size_t packetLen = slipDecoder.length;
    slipDecoder.reset();

    // Validate packet length is reasonable
    if (packetLen < 20 || packetLen > SLIP_MTU) break;

    memcpy(processBuffer, slipDecoder.buffer, packetLen);

    // Basic IP header validation
    uint8_t version = (processBuffer[0] >> 4) & 0x0F;
    uint8_t headerLen = (processBuffer[0] & 0x0F) * 4;

    if (version != 4 || headerLen < 20 || headerLen > packetLen) break;

    // Process the packet
    struct pbuf* p = pbuf_alloc(PBUF_IP, packetLen, PBUF_RAM);
    if (!p) break;

    memcpy(p->payload, processBuffer, packetLen);

    if (slipNetif.input(p, &slipNetif) != ERR_OK) {
      pbuf_free(p);
    }

    // Adaptive flow control: measure how long it takes to receive a frame
    // Only measure for non-control packets to get accurate data transmission rates
    uint32_t now = millis();
    if (lastRxTime > 0 && !isTcpControlPacket(p)) {
      // Calculate the duration of receiving this frame
      // This tells us how long the RC2014 takes to transmit a packet
      uint32_t frameDuration = now - lastRxTime;

      // Smooth the pacing delay using exponential moving average
      // Weight: 75% old value, 25% new measurement
      txPacingDelay = (txPacingDelay * 3 + frameDuration) / 4;

      // Clamp between 50ms (max throughput) and 500ms (conservative)
      if (txPacingDelay < 50) txPacingDelay = 50;
      if (txPacingDelay > 500) txPacingDelay = 500;
    }

    lastRxTime = 0;  // Reset for next frame

    break;
  }

  digitalWrite(LED_ACTIVITY, LOW);
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

  slipTx();
  slipRx();
}
