# Makefile for ko-loader

ASSETS_DIR := assets
INCLUDE_DIR := src/include
ASSETS := $(wildcard $(ASSETS_DIR)/*.ko)
HEADERS := $(patsubst $(ASSETS_DIR)/%.ko,$(INCLUDE_DIR)/%.h,$(ASSETS))

TARGET ?= aarch64-linux-musl
CC := zig cc
CFLAGS := -target $(TARGET) -s -Oz -static -ffreestanding -Wl,--gc-sections,-z,norelro -fno-unwind-tables -fno-ident -flto -fmerge-all-constants -fomit-frame-pointer

all: ko-loader

$(INCLUDE_DIR)/%.h: $(ASSETS_DIR)/%.ko
	@mkdir -p $(INCLUDE_DIR)
	@echo "Generating header for $<..."
	@cd $(ASSETS_DIR) && xxd -i $(notdir $<) > ../$@

ko-loader: $(HEADERS) src/ko-loader.c
	@echo "Compiling ko-loader for $(TARGET)..."
	$(CC) $(CFLAGS) src/ko-loader.c -o ko-loader

clean:
	rm -rf $(INCLUDE_DIR) ko-loader

.PHONY: all clean
