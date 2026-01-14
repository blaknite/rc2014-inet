#!/bin/bash

zcc +cpm -O3 -DAMALLOC -DENABLE_UDP nslookup.c slip.c ip.c udp.c dns.c -o ./bin/nslookup.com -create-app &&
ruby ~/Workspace/rc2014-package/rc2014-package.rb ./bin/NSLOOKUP.COM
