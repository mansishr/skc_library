#!/bin/bash

./credential_agent.sh
grep -qi "daemon off" /etc/nginx/nginx.conf || echo 'daemon off;' >> /etc/nginx/nginx.conf
OPENSSL_CONF=/etc/pki/tls/openssl.cnf /usr/sbin/nginx
