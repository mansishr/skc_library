# SKC Library

The `SKC Library` enables secure transfer of application keys from KBS after performing SGX attestation.

## Key features

- Using SKC library, applications can retrieve keys from the ISecL-DC KBS and load them to an SGX enclave
- SKC library stores the keys in the SGX enclave ensuring the keys are never exposed in use, at rest and in transit outside of enclave

## System Requirements

- ubuntu 20.04
- Proxy settings if applicable

## Software requirements

- wget
- git
- make
- gcc-c++
- makeself

# Step By Step Build Instructions

## Install required shell commands

### Install tools from `dnf`

```{.shell}
sudo dnf install -y git wget make gcc-c++ makeself
```

## Build SKC Library

- Git clone the SKC Library
- Run scripts to build the SKC Library

```shell
repo init -u  https://github.com/intel-secl/build-manifest.git -b refs/tags/v5.0.0 -m manifest/skc.xml
repo sync
make skc_library_k8s 
- Skc Library container image will be generated. Use: `docker images` to list 
```

## Third Party Dependencies

- Certificate Management Service
- Authentication and Authorization Service
- Key Broker Service

## Direct dependencies

Name          | Repo URL                                                                          | Minimum Version Required
------------- | --------------------------------------------------------------------------------- | ------------------------
libcurl       | github.com/curl/curl                                                              | v7.68.0
glib          |                                                                                   | v2.0.0
libgda        |                                                                                   | v5.0
libgda-sqlite |                                                                                   | v5.0
libjsoncpp    |                                                                                   | v1.7.4     

## Links

<https://01.org/intel-secl/>
