FROM gcr.io/oss-fuzz-base/base-builder-go:v1
RUN git clone --depth 1 https://github.com/pandatix/go-abnf.git
COPY .clusterfuzzlite/build.sh $SRC/
WORKDIR $SRC/go-abnf
