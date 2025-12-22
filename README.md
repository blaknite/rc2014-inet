# rc2014-inet

Internet tools for the RC2014 Pro running CP/M - https://rc2014.co.uk

See it in action at http://kobol.thelanbox.com.au:8080/

## Tools

### HTTPD

A HTTP server which serves files from the current drive. Listens on the default port 80. It has a 1KB limit on request header size and only responds to GET and HEAD requests.

### PING

Rudimentary ping command. Current outputs a tcpdump-like debug log for all ICMP packets. No timing due to lack of RTC.

## SLIP Gateway

A NAT gateway that runs on the RC2014 WiFi module and provides internet connectivity to the RC2014 by bridgin WiFi to SLIP over SIO/2 port B.

## Run

Flash the gateway to your WiFi module and send `HTTPD.COM` to your RC2014. I have the programs on drive `C:` and the contents of www on drive `D:`. I then switch to drive `D:` and run `C:HTTPD` to serve files from there.

A tcpdump-like debug log can be output by calling `HTTPD -D`

## Build

Get z88dk from https://www.z88dk.org and then run the following command to build from source

```sh
./bin/httpd.sh
```

## Many thanks

I learned a lot from the following repos:
- https://github.com/jes/cpmhttpd
- https://github.com/saminiir/level-ip
