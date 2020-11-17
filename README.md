# SKC Library

The `SKC Library` enables secure transfer of application keys from KBS after performing SGX attestation.

## Key features

- Using SKC library, applications can retrieve keys from the ISecL-DC KBS and load them to an SGX enclave
- SKC library stores the keys in the SGX enclave ensuring the keys are never exposed in use, at rest and in transit outside of enclave

## System Requirements

- RHEL 8.2
- Epel 8 Repo
- Proxy settings if applicable

## Software requirements

- git
- makeself

# Step By Step Build Instructions

## Install required shell commands

### Install tools from `dnf`

```{.shell}
sudo dnf install -y git wget makeself
```

## Build SKC Library

- Git clone the SKC Library
- Run scripts to build the SKC Library

```shell
git clone https://github.com/intel-secl/skc-tools.git
cd skc-tools/skc_library/build_scripts
- To build SKC Library,
# ./skc_library_build.sh
- This script will generate a tarball(skc_library.tar) and checksum file(skc_library.sha2)
- Copy skc_library.tar, skc_library.sha2 and untar.sh(from skc_library directory) to a directory in the deployment machine
```

## Third Party Dependencies

- Certificate Management Service
- Authentication and Authorization Service
- Key Broker Service

## Direct dependencies

Name          | Repo URL                                                                          | Minimum Version Required
------------- | --------------------------------------------------------------------------------- | ------------------------
libcurl       | github.com/curl/curl                                                              | v7.72.0
libgda        | dl.fedoraproject.org/pub/fedora/linux/releases/32/Everything/x86_64/os/Packages/l | v5.2.9
glib          | gitlab.gnome.org/GNOME/glib                                                       | v2.0.0
libgda-sqlite | dl.fedoraproject.org/pub/fedora/linux/releases/32/Everything/x86_64/os/Packages/l | v5.2.9
libjsoncpp    | github.com/open-source-parsers/jsoncpp                                            | v1.9.3

_Note: All dependencies are listed in go.mod_

## Links

<https://01.org/intel-secl/>
