#!/bin/sh
#
# Runs inside the container started by run.sh: builds a copy of /src and runs
# the harness against the resulting nfacctd.

set -e

cp -a /src /build
cd /build
# On a Linux host the tree belongs to the user, not to root: without this git
# refuses the repository, configure sees no git checkout and, libcdada being
# an uninitialised submodule, fails with "Could not find libcdada"
git config --global --add safe.directory '*'
[ -f Makefile ] && make distclean >/dev/null 2>&1 || true

echo "Building nfacctd (--enable-debug --enable-jansson --enable-http --enable-geoipv2 --enable-h3) ..."
if ! { ./autogen.sh && ./configure --enable-debug --enable-jansson --enable-http --enable-geoipv2 --enable-h3; } >/tmp/build.log 2>&1; then
  tail -20 /tmp/build.log
  echo "CONFIGURE FAILED"
  exit 1
fi
if ! make -j"$(nproc)" >>/tmp/build.log 2>&1; then
  grep -E "error|warning" /tmp/build.log | head -40
  echo "BUILD FAILED"
  exit 1
fi

python3 -I /src/ci/http-plugin/harness.py /build/src/nfacctd "$@"
