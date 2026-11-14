# Makefile for lkmloader

TARGET ?= aarch64
CC := zig cc
CFLAGS := -target $(TARGET)-linux -Oz -Xclang -Oz -static -ffreestanding -flto -fmerge-all-constants -fomit-frame-pointer -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-ident -Wl,--gc-sections,-z,norelro -Wno-invalid-noreturn -mllvm -enable-machine-outliner=always

all: lkmloader-$(TARGET)

lkmloader-$(TARGET):
	@echo "Compiling lkmloader for $(TARGET)..."
	$(CC) $(CFLAGS) src/lkmloader.c -o lkmloader-$(TARGET)

clean:
	rm -rf lkmloader*

.PHONY: all clean
