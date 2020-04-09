# ISecL mtwilson-client
ISecL mtwilson client provides rest interface for verification service for making calls such as certify host binding key and certify host signing key.

## System Requirements
- RHEL 7.5/7.6
- Epel 7 Repo
- Proxy settings if applicable

## Software requirements
- git
- `go` version >= `go1.12.1` & <= `go1.14.1`

# Step By Step Build Instructions

## Install required shell commands

### Install `go` version >= `go1.12.1` & <= `go1.14.1`
The `mtwilson-client` requires Go version 1.12.1 that has support for `go modules`. The build was validated with the latest version 1.14.1 of `go`. It is recommended that you use 1.14.1 version of `go`. More recent versions may introduce compatibility issues. You can use the following to install `go`.
```shell
wget https://dl.google.com/go/go1.14.1.linux-amd64.tar.gz
tar -xzf go1.14.1.linux-amd64.tar.gz
sudo mv go /usr/local
export GOROOT=/usr/local/go
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
```

## Build  mtwilson-client

- Git clone the mtwilson-client
- Run scripts to build the mtwilson-client

```shell
git clone https://github.com/intel-secl/mtwilson-client.git
cd mtwilson-client
go build ./...
```

# Links
https://01.org/intel-secl/
