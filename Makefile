
VERSION ?= $(shell git describe --dirty --always --tags | sed 's/-/./g')
GO_LDFLAGS := -ldflags '-X cert-tool/version.BuildVersion=$(VERSION)'

ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# Setting SHELL to bash allows bash commands to be executed by recipes.
# This is a requirement for 'setup-envtest.sh' in the test target.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: build

.PHONY: fmt
fmt:
	go fmt ./...
.PHONY: vet
vet:
	go vet ./...

.PHONY: test
test: fmt vet envtest
	go test ./... -coverprofile cover.out

LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

.PHONY: build
build: fmt vet $(LOCALBIN)
	CGO_ENABLED=0 go build -mod vendor -buildmode=pie $(GO_LDFLAGS) -a -o bin/cert-tool cmd/main.go
