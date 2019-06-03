
#!/bin/bash

export https_proxy=
export http_proxy=

current_dir=$(dirname "$(readlink -f "$0")")
set -x
. ${current_dir}/../config
kill -9 nginx
OPENSSL_CONF=${DATADIR}/engines.cnf G_MESSAGES_DEBUG=all /usr/sbin/nginx
