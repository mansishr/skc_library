#!/bin/bash

if [ -d "$1" ] && [ "$2" = "sgx" ]; then
	bash  "${1}"/build_sgx.sh
fi
