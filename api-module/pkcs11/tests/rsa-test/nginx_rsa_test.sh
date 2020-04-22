#!/bin/bash

current_dir=$(dirname "$(readlink -f "$0")")
set -x
. ${current_dir}/../config
pkill -9 nginx
OPENSSL_CONF=${DATADIR}/engines.cnf G_MESSAGES_DEBUG=all /usr/sbin/nginx

wget https://localhost:443/ --no-check-certificate
