# Compiler
CC = gcc

# Compiler flags
CFLAGS = -Wall -Wextra -O2

# Source files
SRCS = src/main.c src/dkls23.c src/utils/files.c

# Object files
OBJS = $(SRCS:.c=.o)

# Executable name
EXEC = ffi_tss_client

# Output directory for the cdylib
OUT_DIR = ../../target/debug

# Default target
all: $(OUT_DIR)/libffi_tss.so $(EXEC)

# Build the Rust library
$(OUT_DIR)/libffi_tss.so:
	cd ../.. && cargo build --features deterministic

# Link object files to create the executable
$(EXEC): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ -lffi_tss -L$(OUT_DIR)

# Compile source files into object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up build files
clean:
	rm -f $(OBJS) $(EXEC)

# Run the program
run: $(EXEC)
	LD_LIBRARY_PATH=$(OUT_DIR) ./$(EXEC)

# Phony targets
.PHONY: all clean run
