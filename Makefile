ifneq ($(strip $(DEBUG)),)
GO_BUILD_FLAGS := -gcflags=all=-N -l
BASE_LDFLAGS := $(LDFLAGS_VARS)
else
GO_BUILD_FLAGS := -trimpath
BASE_LDFLAGS := -s -w
endif

GOOS ?= linux
BIN_DIR ?= bin
BINARY_NAME ?= http-redirector

.PHONY: build build-amd64 build-arm64 test clean

build: build-amd64 build-arm64

build-amd64:
	@out_dir="$(BIN_DIR)/$(GOOS)-amd64"; \
	mkdir -p "$$out_dir"; \
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=amd64 go build $(GO_BUILD_FLAGS) -ldflags "$(BASE_LDFLAGS)" -o "$$out_dir/$(BINARY_NAME)" .

build-arm64:
	@out_dir="$(BIN_DIR)/$(GOOS)-arm64"; \
	mkdir -p "$$out_dir"; \
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=arm64 go build $(GO_BUILD_FLAGS) -ldflags "$(BASE_LDFLAGS)" -o "$$out_dir/$(BINARY_NAME)" .

build-android-arm64:
	@out_dir="$(BIN_DIR)/android-arm64"; \
	mkdir -p "$$out_dir"; \
	CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build $(GO_BUILD_FLAGS) -ldflags "$(BASE_LDFLAGS)" -o "$$out_dir/$(BINARY_NAME)" .

test:
	go test ./...

clean:
	rm -rf "$(BIN_DIR)"