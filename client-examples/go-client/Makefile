# Variables
RUST_LIB_NAME := ffi_tss
RUST_LIB_PATH := ../..
GO_EXAMPLE := examples/dkls23_example.go
RUST_TARGET := $(RUST_LIB_PATH)/target/release
RUST_LIB := $(RUST_TARGET)/lib$(RUST_LIB_NAME).so

# Default target
.PHONY: all
all: build-rust build-go

# Build the Rust library
.PHONY: build-rust
build-rust:
	@echo "Building Rust library..."
	cd $(RUST_LIB_PATH) && cargo build --release

# Run the Go example
.PHONY: run-example
run-example: build-rust
	@echo "Running Go example..."
	CGO_LDFLAGS="-L$(RUST_TARGET) -lffi_tss" LD_LIBRARY_PATH=$(RUST_TARGET) \
	    go run $(GO_EXAMPLE)

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	cd $(RUST_LIB_PATH) && cargo clean
	rm -rf bin

# Help message
.PHONY: help
help:
	@echo "Usage:"
	@echo "  make all          - Build both Rust library and Go application"
	@echo "  make build-rust   - Build only the Rust library"
	@echo "  make build-go     - Build only the Go application"
	@echo "  make run-example  - Run the Go example"
	@echo "  make clean        - Clean build artifacts"
	@echo "  make help         - Show this help message"
