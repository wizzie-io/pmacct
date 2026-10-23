# Build environment for the http plugin functional test (ci/http-plugin/run.sh):
# just what nfacctd needs with --enable-jansson --enable-http --enable-geoipv2 --enable-h3, plus
# python3 for the harness. The source tree is mounted at run time, not copied in.
FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential autoconf automake libtool pkg-config git ca-certificates cmake \
      libpcap-dev libjansson-dev libcurl4-openssl-dev libmaxminddb-dev python3 && \
    rm -rf /var/lib/apt/lists/*

# H3: same version as pyflow/Dockerfile
WORKDIR /tmp
RUN git clone --depth 1 -b v4.5.0 https://github.com/uber/h3 && \
  cmake -S h3 -B h3/build -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DBUILD_TESTING=OFF -DBUILD_BENCHMARKS=OFF -DBUILD_FUZZERS=OFF -DBUILD_FILTERS=OFF -DBUILD_GENERATORS=OFF \
        -DENABLE_DOCS=OFF -DENABLE_FORMAT=OFF -DENABLE_LINTING=OFF && \
  cmake --build h3/build && cmake --install h3/build && ldconfig
