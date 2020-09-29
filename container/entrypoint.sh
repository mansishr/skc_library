#!/bin/bash

./configure_skc.sh
echo "daemon off;" >> /etc/nginx/nginx.conf
nginx
