# ISecL mtwilson-client
ISecL mtwilson client provides rest interface for verification service for making calls such as certify host binding key and certify host signing key.

## System Requirements
- RHEL 7.5/7.6
- Epel 7 Repo
- Proxy settings if applicable

## Software requirements
- git
- Go 11.4 or newer

# Step By Step Build Instructions

## Install required shell commands

### Install `go 1.11.4` or newer
The `mtwilson-client` requires Go version 11.4 that has support for `go modules`. The build was validated with version 11.4 version of `go`. It is recommended that you use a newer version of `go` - but please keep in mind that the product has been validated with 1.11.4 and newer versions of `go` may introduce compatibility issues. You can use the following to install `go`.
```shell
wget https://dl.google.com/go/go1.11.4.linux-amd64.tar.gz
tar -xzf go1.11.4.linux-amd64.tar.gz
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
