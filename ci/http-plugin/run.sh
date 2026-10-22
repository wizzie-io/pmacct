#!/bin/sh
#
# Functional test of the http plugin: builds nfacctd from this source tree with
# --enable-debug --enable-jansson --enable-http inside a container, then runs
# harness.py, which feeds it NetFlow v5 and checks what a mock HTTP endpoint
# receives. Needs Docker and network access (the build clones libcdada).
#
#   ci/http-plugin/run.sh                 # all cases
#   ci/http-plugin/run.sh retry_5xx       # only the named cases
#
# The source tree is mounted read-only and copied inside the container, so the
# working copy is left untouched.

set -e

HERE=$(cd "$(dirname "$0")" && pwd)
TOP=$(cd "$HERE/../.." && pwd)
IMAGE=pmacct-http-plugin-test

docker build -q -t "$IMAGE" "$HERE" >/dev/null
docker run --rm -v "$TOP":/src:ro "$IMAGE" sh /src/ci/http-plugin/build-and-test.sh "$@"
