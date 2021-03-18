#!/bin/bash

./credential_agent.sh
grep -qi "daemon off" /etc/nginx/nginx.conf || echo 'daemon off;' >> /etc/nginx/nginx.conf
nginx
