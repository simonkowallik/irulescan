FROM cgr.dev/chainguard/wolfi-base AS build-image

ENV PATH="/:/root/.cargo/bin:$PATH"

WORKDIR /build

RUN echo "* install packages" \
&&  apk update \
&&  apk add \
          curl \
          make \
          patch \
&&  apk add \
          gcc-13 \
          clang-15 \
          glibc-dev \
&& ln -sf /usr/bin/gcc-13 /usr/bin/gcc \
;

#ENV TCL_SOURCE_LOCATION=https://sourceforge.net/projects/tcl/files/Tcl/8.4.20/tcl8.4.20-src.tar.gz/download
ENV TCL_SOURCE_LOCATION=http://archive.ubuntu.com/ubuntu/pool/universe/t/tcl8.4/tcl8.4_8.4.20.orig.tar.gz
ENV TCL_ARCHIVE_SHASUM=fcb317b65c69f1d6962057c5622a80980bc22ffadf25c1cc50b6d02ff6c2cf40
ENV TCL_ARCHIVE=tcl8.4.20.tar.gz

RUN echo "* download and verify tcl" \
&&  curl -sSf -Lo "$TCL_ARCHIVE" "$TCL_SOURCE_LOCATION" \
&&  echo "$TCL_ARCHIVE_SHASUM  $TCL_ARCHIVE" > "$TCL_ARCHIVE".sha256 \
&&  sha256sum -c "$TCL_ARCHIVE".sha256 \
;

ADD files/irule_expressions_tcl8.4.20.patch /build

RUN echo "* configure, patch, compile and install tcl" \
&&  tar xzf "$TCL_ARCHIVE" \
&&  patch -p0 < irule_expressions_tcl8.4.20.patch \
&&  cd tcl8.4.20/unix \
&&  ./configure --enable-64bit --prefix=/usr \
&&  make && make install \
;

RUN echo "* install rust nightly" \
&&  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --default-toolchain none -y \
&&  rustup toolchain install nightly-2024-12-01 --profile minimal \
;

COPY ./irulescan/Cargo.toml /build/irulescan/Cargo.toml
COPY ./irulescan/Cargo.lock /build/irulescan/Cargo.lock
COPY ./irulescan/src /build/irulescan/src

RUN echo "* compile irulescan" \
&&  cd /build/irulescan \
&&  cargo update \
&&  cargo build --release \
;

RUN echo "* prepare artifacts" \
&&  mkdir -p /build/artifacts/usr/bin /build/artifacts/usr/lib \
&&  cp /usr/lib/libtcl8.4.so /build/artifacts/usr/lib \
&&  cp /build/irulescan/target/release/irulescan /build/artifacts/usr/bin \
;

COPY README.md /build/artifacts/
COPY LICENSE /build/artifacts/

FROM cgr.dev/chainguard/glibc-dynamic:latest AS containerimage

LABEL org.label-schema.name="irulescan" \
      org.label-schema.description="irulescan: security analyzer for iRules" \
      org.label-schema.vcs-url="https://github.com/simonkowallik/irulescan" \
      org.label-schema.vendor="Simon Kowallik"

VOLUME /scandir

WORKDIR /scandir

COPY --from=build-image /build/artifacts /

ENTRYPOINT ["irulescan"]

CMD ["check", "."]
