# rc2014-inet

Internet tools for the RC2014 Pro running CP/M - https://rc2014.co.uk

## Tools

### HTTPD

A HTTP server which serves files from the current drive. Listens on the default port 80. It has a 1KB limit on request header size and only responds to GET and HEAD requests.

## Run

These tools expect SIO port 2 to be connected to device that supports SLIP. It currently runs on the fixed IP 192.168.1.51. I've been connecting via a Raspberry Pi via the `slattach` command. 

## Build

Get z88dk from https://www.z88dk.org and then run the following command to build from source

```sh
zcc +cpm -O3 -DAMALLOC httpd.c slip.c ip.c icmp.c tcp.c http.c -o httpd.com -create-app
```

## Many thanks

I learned a lot from the following repos:
- https://github.com/jes/cpmhttpd
- https://github.com/saminiir/level-ip
