#!/bin/bash

zcc +cpm -O3 -DAMALLOC httpd.c slip.c ip.c icmp.c tcp.c http.c -o ./bin/httpd.com -create-app &&
ruby ~/Workspace/rc2014-package/rc2014-package.rb ./bin/HTTPD.COM
