#!/bin/bash

current_dir=$(dirname "$(readlink -f "$0")")
set -x
. ${current_dir}/../config
pkill nginx
OPENSSL_CONF=${DATADIR}/engines.cnf G_MESSAGES_DEBUG=all /usr/sbin/nginx

wget -k -v https://localhost:2443/ --no-check-certificate
