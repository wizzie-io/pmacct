# Wizzie image of pmacctd: captures traffic with libpcap, classifies it with
# nDPI and publishes it over HTTP (http plugin) to Kong + http2k. pyflow, the
# main process, writes the pmacctd configuration out of environment variables
# and runs pmacctd, see README.md. Built from the root of the repository:
#
#   docker buildx build -f pyflow/Dockerfile .
#
# Lighter than docker/base/Dockerfile (upstream, left untouched): only the
# traffic daemons and the backends this image uses.

FROM debian:trixie-slim AS build-stage
COPY ci/dpkg.cfg.d/excludes /etc/dpkg/dpkg.cfg.d/excludes
RUN apt-get update && \
  apt-get install -y --no-install-recommends \
    autoconf \
    automake \
    build-essential \
    ca-certificates \
    git \
    libcurl4-openssl-dev \
    libjansson-dev \
    libmaxminddb-dev \
    libpcap-dev \
    libtool \
    pkg-config && \
  rm -rf /var/lib/apt/lists/*

ARG NUM_WORKERS=4
ENV MAKEFLAGS="-j${NUM_WORKERS}"

# nDPI: same version as ci/deps.sh
WORKDIR /tmp
RUN git clone --depth 1 -b 4.14-stable https://github.com/ntop/nDPI && \
  cd nDPI && ./autogen.sh && ./configure --prefix=/usr/local/ && make && make install && ldconfig

WORKDIR /tmp/pmacct/
COPY . .
RUN ./autogen.sh && \
  ./configure --enable-jansson --enable-http --enable-ndpi --enable-geoipv2 \
              --disable-bgp-bins --disable-bmp-bins --disable-st-bins && \
  make && make install

FROM debian:trixie-slim
COPY ci/dpkg.cfg.d/excludes /etc/dpkg/dpkg.cfg.d/excludes
RUN apt-get update && \
  apt-get install -y --no-install-recommends \
    ca-certificates \
    libcurl4 \
    libjansson4 \
    libmaxminddb0 \
    libpcap0.8 \
    python3 \
    tini && \
  rm -rf /var/lib/apt/lists/*
COPY --from=build-stage /usr/local/ /usr/local/
RUN ldconfig

WORKDIR /app
COPY pyflow/launch.sh pyflow/pyflow.py /app/
COPY pyflow/wizzie/ /app/wizzie/

# Version of the image: passed with --build-arg and read by pyflow at start. Last, so that
# changing it does not invalidate the cache of the layers above
ARG VERSION=unknown
ENV PYFLOW_VERSION=${VERSION}
LABEL org.opencontainers.image.version=${VERSION}

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/app/launch.sh"]
