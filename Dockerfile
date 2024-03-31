FROM golang:1.21-alpine

ARG VERSION=Unknown

RUN apk add git build-base openssl bash coreutils

WORKDIR /build

COPY . /build

RUN if [ "${VERSION}" = "Unknown" ]; then \
        VERSION=$(git describe --dirty --always --tags | sed 's/-/./g'); \
    fi; \
    CGO_ENABLED=0 go build -mod vendor -buildmode=pie \
        -ldflags "-s -w -X cert-tool/version.BuildVersion=${VERSION} -linkmode 'external' -extldflags '-static'" \
        -o /opt/output/cert-tool cmd/main.go
RUN CERT_TOOL=/opt/output/cert-tool bash tests/test.sh

FROM scratch
COPY --from=0 /opt/output/cert-tool /
