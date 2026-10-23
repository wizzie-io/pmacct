#!/bin/sh
#
# Runs inside the container started by run.sh: builds a copy of /src and runs
# the harness against the resulting nfacctd.

set -e

cp -a /src /build
cd /build
[ -f Makefile ] && make distclean >/dev/null 2>&1 || true

echo "Building nfacctd (--enable-debug --enable-jansson --enable-http --enable-geoipv2) ..."
./autogen.sh >/tmp/build.log 2>&1
./configure --enable-debug --enable-jansson --enable-http --enable-geoipv2 >>/tmp/build.log 2>&1
if ! make -j"$(nproc)" >>/tmp/build.log 2>&1; then
  grep -E "error|warning" /tmp/build.log | head -40
  echo "BUILD FAILED"
  exit 1
fi

python3 -I /src/ci/http-plugin/harness.py /build/src/nfacctd "$@"
