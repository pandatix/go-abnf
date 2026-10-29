FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:6381f9b0ecc8a6bb36ab16fc7a2a01d0c48df1fd4f510ca2babb98defe6213d8
RUN git clone --depth 1 https://github.com/pandatix/go-abnf.git
COPY .clusterfuzzlite/build.sh $SRC/
WORKDIR $SRC/go-abnf
