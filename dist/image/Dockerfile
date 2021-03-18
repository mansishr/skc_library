# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

FROM centos:8

# Set env variables
ENV SGX_INSTALL_DIR /opt/intel
ENV SKC_LIBRARY_BIN_NAME skc_library_v3.4.bin
 
# Copy binaries and SGX local repo
COPY dist/image/bin/pkcs11.so /usr/lib64/engines-1.1/
COPY dist/image/bin/libp11.so.3.4.3 /usr/lib64/
COPY dist/image/bin/sgx_rpm_local_repo ${PWD}/sgx_rpm_local_repo
COPY dist/image/bin/${SKC_LIBRARY_BIN_NAME} $PWD
COPY dist/image/entrypoint.sh $PWD
RUN chmod 700 /entrypoint.sh
COPY dist/image/credential_agent.sh $PWD
RUN chmod 700 /credential_agent.sh
COPY dist/image/sgxssl ${SGX_INSTALL_DIR}/sgxssl
COPY dist/image/cryptoapitoolkit ${SGX_INSTALL_DIR}/cryptoapitoolkit

#Install dependencies and SGX components
RUN dnf install -y https://dl.fedoraproject.org/pub/fedora/linux/releases/32/Everything/x86_64/os/Packages/s/softhsm-2.5.0-4.fc32.3.x86_64.rpm \
    https://dl.fedoraproject.org/pub/fedora/linux/releases/32/Everything/x86_64/os/Packages/l/libgda-5.2.9-4.fc32.x86_64.rpm \
    https://dl.fedoraproject.org/pub/fedora/linux/releases/32/Everything/x86_64/os/Packages/l/libgda-sqlite-5.2.9-4.fc32.x86_64.rpm \
    https://download-ib01.fedoraproject.org/pub/epel/8/Everything/x86_64/Packages/j/jsoncpp-1.8.4-6.el8.x86_64.rpm \
    https://download-ib01.fedoraproject.org/pub/epel/8/Everything/x86_64/Packages/j/jsoncpp-devel-1.8.4-6.el8.x86_64.rpm
RUN dnf install -y yum-utils jq protobuf opensc nginx cronie sudo
RUN groupadd intel && \
    usermod -G intel nginx && \
    ln -sf /usr/lib64/libp11.so.3.4.3 /usr/lib64/libp11.so && \
    ln -sf /usr/lib64/engines-1.1/pkcs11.so /usr/lib64/engines-1.1/libpkcs11.so && \
    ln -sf /usr/lib64/libjsoncpp.so /usr/lib64/libjsoncpp.so.0
RUN yum-config-manager --add-repo file://${PWD}/sgx_rpm_local_repo && \
    dnf install -y --nogpgcheck libsgx-launch libsgx-uae-service libsgx-urts libsgx-ae-qve libsgx-dcap-ql libsgx-dcap-ql-devel \
    libsgx-dcap-default-qpl-devel libsgx-dcap-default-qpl && \
    rm -rf sgx_rpm_local_repo /etc/yum.repos.d/*sgx_rpm_local_repo.repo

# Install SKC-Library and copy entrypoint script
RUN ./${SKC_LIBRARY_BIN_NAME}
ENTRYPOINT ["./entrypoint.sh"]
