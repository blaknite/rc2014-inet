#!/bin/bash

zcc +cpm -O3 -DAMALLOC ping.c slip.c ip.c icmp.c tcp.c -o ./bin/ping.com -create-app &&
ruby ~/Workspace/rc2014-package/rc2014-package.rb ./bin/PING.COM
