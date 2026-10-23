# Build environment for the http plugin functional test (ci/http-plugin/run.sh):
# just what nfacctd needs with --enable-jansson --enable-http --enable-geoipv2, plus python3 for
# the harness. The source tree is mounted at run time, not copied in.
FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential autoconf automake libtool pkg-config git ca-certificates \
      libpcap-dev libjansson-dev libcurl4-openssl-dev libmaxminddb-dev python3 && \
    rm -rf /var/lib/apt/lists/*
