FROM centos:8

# Set env variables
ARG SGX_INSTALL_DIR /opt/intel
ARG SKC_LIBRARY_BIN_NAME skc_library_v1.0.bin
 
# Copy binaries and SGX local repo
COPY bin/pkcs11.so /usr/lib64/engines-1.1/
COPY bin/sgx_rpm_local_repo ${PWD}/sgx_rpm_local_repo
COPY bin/${SKC_LIBRARY_BIN_NAME} $PWD
COPY configure_skc.sh $PWD
COPY sgxssl ${SGX_INSTALL_DIR}/sgxssl
COPY cryptoapitoolkit ${SGX_INSTALL_DIR}/cryptoapitoolkit

#Install dependencies and SGX components
RUN dnf localinstall -y https://dl.fedoraproject.org/pub/fedora/linux/releases/32/Everything/x86_64/os/Packages/s/softhsm-2.5.0-4.fc32.1.x86_64.rpm \
    https://dl.fedoraproject.org/pub/fedora/linux/releases/32/Everything/x86_64/os/Packages/l/libgda-5.2.9-4.fc32.x86_64.rpm \
    https://dl.fedoraproject.org/pub/fedora/linux/releases/32/Everything/x86_64/os/Packages/l/libgda-sqlite-5.2.9-4.fc32.x86_64.rpm \
    https://download-ib01.fedoraproject.org/pub/epel/8/Everything/x86_64/Packages/j/jsoncpp-1.8.4-6.el8.x86_64.rpm \
    https://download-ib01.fedoraproject.org/pub/epel/8/Everything/x86_64/Packages/j/jsoncpp-devel-1.8.4-6.el8.x86_64.rpm
RUN dnf install -y yum-utils jq protobuf opensc nginx cronie sudo && \
    ln -sf /usr/lib64/engines-1.1/pkcs11.so /usr/lib64/engines-1.1/libpkcs11.so && \
    ln -sf /usr/lib64/libjsoncpp.so /usr/lib64/libjsoncpp.so.0
RUN yum-config-manager --add-repo file://${PWD}/sgx_rpm_local_repo && \
    dnf install -y --nogpgcheck libsgx-launch libsgx-uae-service libsgx-urts libsgx-ae-qve libsgx-dcap-ql libsgx-dcap-ql-devel \
    libsgx-dcap-default-qpl-devel libsgx-dcap-default-qpl && \
    rm -rf sgx_rpm_local_repo /etc/yum.repos.d/*sgx_rpm_local_repo.repo

# Install SKC-Library and copy entrypoint script
RUN ./${SKC_LIBRARY_BIN_NAME}
COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["./entrypoint.sh"]
