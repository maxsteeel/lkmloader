# Makefile for lkmloader

TARGET ?= aarch64-linux-musl
CC := zig cc
CFLAGS := -target $(TARGET) -Oz -static -Wl,--gc-sections,-z,norelro -fno-unwind-tables -fno-ident -flto -fmerge-all-constants -fomit-frame-pointer

all: lkmloader

lkmloader:
	@echo "Compiling ko-loader for $(TARGET)..."
	$(CC) $(CFLAGS) src/lkmloader.c -o lkmloader

clean:
	rm -rf lkmloader

.PHONY: all clean
