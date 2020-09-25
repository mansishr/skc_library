SKC Library
===========

The `SKC Library` enables secure transfer of application keys from KBS
after performing SGX attestation.

Key features
------------

-   SKC library stores the keys in the SGX enclave and performs crypto
    operations ensuring the keys are never exposed in use, at rest and
    in transit outside of enclave
-   Using SKC library, applications can retrieve keys from the ISecL-DC
    KBS and load them to an SGX enclave

System Requirements
-------------------

-   RHEL 8.2
-   Epel 8 Repo
-   Proxy settings if applicable

Software requirements
---------------------

-   git
-   makeself
-   Go 1.14.1 or newer

Step By Step Build Instructions
===============================

Install required shell commands
-------------------------------

### Install tools from `dnf`

``` {.shell}
sudo dnf install -y git wget makeself
```

### Install `go 1.14.1` or newer

The `Certificate Management Service` requires Go version 1.14 that has
support for `go modules`. The build was validated with version 1.14.1
version of `go`. It is recommended that you use a newer version of `go`
- but please keep in mind that the product has been validated with
1.14.1 and newer versions of `go` may introduce compatibility issues.
You can use the following to install `go`.

``` {.shell}
wget https://dl.google.com/go/go1.14.2.linux-amd64.tar.gz
tar -xzf go1.14.2.linux-amd64.tar.gz
sudo mv go /usr/local
export GOROOT=/usr/local/go
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
```

Build SKC Library
-----------------

-   Git clone the SKC Library
-   Run scripts to build the SKC Library

``` {.shell}
git clone https://github.com/intel-secl/skc-tools.git
cd skc-tools/skc_library/build_scripts
- To build SKC Library,
# ./skc_library_build.sh
- This script will generate a tarball(skc_library.tar) and checksum file(skc_library.sha2)
- Copy skc_library.tar, skc_library.sha2 and untar.sh(from skc_library directory) to a directory in the deployment machine
```

Third Party Dependencies
========================

Certificate Management Service
------------------------------

Authentication and Authorization Service
----------------------------------------

### Direct dependencies

  Name                Repo URL                             Minimum Version Required
  ------------------- ------------------------------ ------------------------------------
  uuid                github.com/google/uuid                        v1.1.1
  logrus              github.com/sirupsen/logrus                    v1.4.0
  testify             github.com/stretchr/testify                   v1.3.0
  golang crypto       golang.org/x/crypto             v0.0.0-20190325154230-a5d413f7728c
  gorilla handlers    github.com/dgrijalva/jwt-go                   v1.4.0
  gorilla mux         github.com/gorilla/mux                        v1.7.3
  gorilla context     github.com/gorilla/context                    v1.1.1
  gorm                github.com/jinzhu/gorm                       v1.9.10
  jinzhu inflection   github.com/jinzhu/inflection    v0.0.0-20180308033659-04140366298a
  yaml for Go         gopkg.in/yaml.v2                              v2.2.2

### Indirect Dependencies

  Repo URL                     Minimum version required
  --------------------------- --------------------------
  https://github.com/lib/pq             1.0.0

*Note: All dependencies are listed in go.mod*

Links
=====

<https://01.org/intel-secl/>
