# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
FROM ubuntu:focal

LABEL org.label-schema.name="SKC Library" \
      org.label-schema.vendor="Intel Corporation" \
      org.label-schema.license="BSD-3-Clause" \
      org.label-schema.url="https://github.com/intel-secl/intel-secl"

# Set env variables
ENV SGX_INSTALL_DIR /opt/intel
ENV SKC_LIBRARY_BIN_NAME skc_library_*.bin
 
# Copy binaries and SGX local repo
COPY dist/image/bin/libp11.so* /usr/lib/x86_64-linux-gnu/
COPY dist/image/bin/pkcs11.so /usr/lib/x86_64-linux-gnu/engines-1.1/

COPY dist/image/bin/${SKC_LIBRARY_BIN_NAME} $PWD
COPY dist/image/entrypoint.sh $PWD
RUN chmod 700 /entrypoint.sh
COPY dist/image/credential_agent.sh $PWD
RUN chmod 700 /credential_agent.sh
COPY dist/image/sgxssl ${SGX_INSTALL_DIR}/sgxssl
COPY dist/image/cryptoapitoolkit ${SGX_INSTALL_DIR}/cryptoapitoolkit

#Install dependencies and SGX components
RUN apt-get -yqq update 
RUN apt-get -yqq install wget gnupg1 gnupg2 apt-utils curl p11-kit
RUN echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu/ focal main' | tee /etc/apt/sources.list.d/intel-sgx.list
RUN wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add - 
RUN DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC  apt-get -yqq install opensc makeself libgda-5.0-bin libgda-5.0-dev libcurl4-openssl-dev libssl-dev \ 
    libjsoncpp1 libjsoncpp-dev libcppunit-dev libcrypto++6 libglib2.0-dev jq cron nginx

RUN apt-get -yqq update
RUN DEBIAN_FRONTEND=noninteractive apt-get -yqq install libsgx-launch libsgx-uae-service libsgx-urts libsgx-ae-qve libsgx-dcap-ql libsgx-dcap-ql-dev \
    libsgx-dcap-default-qpl-dev libsgx-dcap-default-qpl 

RUN groupadd intel && \
    usermod -G intel www-data && \
    ln -sf /usr/lib/x86_64-linux-gnu/libp11.so.3.4.3 /usr/lib/x86_64-linux-gnu/libp11.so 

RUN apt-get clean && apt-get autoclean

# Install SKC-Library and copy entrypoint script
RUN ./${SKC_LIBRARY_BIN_NAME}
ENTRYPOINT ["./entrypoint.sh"]
