FROM debian:stable-slim AS build-image

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/:/root/.cargo/bin:$PATH"

WORKDIR /build

RUN echo "* install packages" \
&&  apt-get update -y \
&&  apt-get install -y \
          curl \
          make \
          clang \
          patch \
&& echo "* remove default rust, cargo and tcl installation" \
&&  apt-get remove -y \
          cargo \
          rustc \
          tcl8.6 \
&& apt-get autoremove -y

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
&&  curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain nightly-2022-12-06 \
&&  rustup component add rustfmt \
;

ADD ./irulescan /build/irulescan

RUN echo "* compile irulescan" \
&&  cd /build/irulescan \
&&  cargo build --release \
;

ADD files/scandir.sh /build/artifacts/scandir.sh
ADD README.md /build/artifacts/
ADD LICENSE /build/artifacts/

RUN echo "* prepare artifacts" \
&&  mkdir -p /build/artifacts/usr/bin /build/artifacts/usr/lib \
&&  cp /usr/lib/libtcl8.4.so /build/artifacts/usr/lib \
&&  cp /build/irulescan/target/release/irulescan /build/artifacts/usr/bin \
;

FROM debian:stable-slim AS containerimage

LABEL org.label-schema.name="irulescan" \
      org.label-schema.description="irulescan: static security analyzer for iRules" \
      org.label-schema.vcs-url="https://github.com/simonkowallik/irulescan" \
      org.label-schema.vendor="Simon Kowallik"

VOLUME /scandir

WORKDIR /scandir

COPY --from=build-image /build/artifacts /

CMD ["/scandir.sh", "/scandir"]
