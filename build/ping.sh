#!/bin/bash

zcc +cpm -O3 -DAMALLOC -DENABLE_ICMP -DENABLE_UDP ping.c slip.c ip.c icmp.c udp.c dns.c -o ./bin/ping.com -create-app &&
ruby ~/Workspace/rc2014-package/rc2014-package.rb ./bin/PING.COM
