#!/bin/bash

zcc +cpm -O3 -DAMALLOC -DENABLE_TCP httpd.c slip.c ip.c tcp.c http.c -o ./bin/httpd.com -create-app &&
ruby ~/Workspace/rc2014-package/rc2014-package.rb ./bin/HTTPD.COM
