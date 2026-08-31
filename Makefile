# Makefile for ko-loader

TARGET ?= aarch64-linux-musl
CC := zig cc
CFLAGS := -target $(TARGET) -Oz -static -Wl,--gc-sections,-z,norelro -fno-unwind-tables -fno-ident -flto -fmerge-all-constants -fomit-frame-pointer

all: ko-loader

ko-loader:
	@echo "Compiling ko-loader for $(TARGET)..."
	$(CC) $(CFLAGS) src/ko-loader.c -o ko-loader

clean:
	rm -rf  ko-loader

.PHONY: all clean
