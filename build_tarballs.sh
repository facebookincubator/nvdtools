#!/bin/bash

CPE2CVE=cpe2cve
CSV2CPE=csv2cpe
NVDSYNC=nvdsync
RPM2CPE=rpm2cpe
NAME=nvdtools

function build_binaries_and_tars(){
    GOOS=$1; shift
    ARCHS=("$@")
    for GOARCH in ${ARCHS[@]}; do
        for BINARY in $CPE2CVE $CSV2CPE $NVDSYNC $RPM2CPE; do
            env GOOS=$GOOS GOARCH=$GOARCH go build -o $BINARY ./cmd/$BINARY
        done
	tar -zcvf release/$NAME-$VERSION-$GOOS-$GOARCH.tar.gz \
            {$CPE2CVE,$CSV2CPE,$NVDSYNC,$RPM2CPE}
	make clean
    done
}

mkdir -p {binaries,release}

# create tarballs for different architectures
archs=(arm64 amd64)
build_binaries_and_tars linux ${archs[@]}

archs=(amd64 arm)
build_binaries_and_tars freebsd ${archs[@]}

archs=(amd64 386)
build_binaries_and_tars windows ${archs[@]}

archs=(amd64)
build_binaries_and_tars darwin ${archs[@]}

# cleanup
rm -rf binaries
