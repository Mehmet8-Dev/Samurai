# AF_XDP Sender & Pacing Engine Build Makefile for Samurai
# ============================================================
#
# Usage:
#   make xdp        - Build xdp_sender.so
#   make xdp-prog   - Compile XDP BPF program
#   make pacing     - Build pacing_engine.so
#   make all        - Build everything
#   make clean      - Clean build artifacts
#   make check      - Check dependencies
#
# Requirements:
#   - Python 3.8+
#   - gcc
#   - libbpf-dev
#   - libelf-dev
#   - clang (for BPF program)
#   - linux-headers

# Python configuration
PYTHON := python3
PYTHON_CONFIG := $(PYTHON)-config
PYTHON_INCLUDE := $(shell $(PYTHON_CONFIG) --includes)
PYTHON_LDFLAGS := $(shell $(PYTHON_CONFIG) --ldflags --embed 2>/dev/null || $(PYTHON_CONFIG) --ldflags)

# Compiler settings
CC := gcc
CLANG := clang
CFLAGS := -O2 -Wall -Wextra -fPIC -shared -I. -Ixdp
XDP_CFLAGS := -O2 -target bpf -D__BPF_TRACING__
MULTIARCH_INC := /usr/include/$(shell uname -m)-linux-gnu
ifneq ($(wildcard $(MULTIARCH_INC)),)
    XDP_CFLAGS += -I$(MULTIARCH_INC)
endif

# Source files
# XDP sources live in the dedicated xdp/ subtree.
XDP_DIR := xdp
XDP_SENDER_SRC := $(XDP_DIR)/xdp_sender.c
XDP_SENDER_OUT := $(XDP_DIR)/xdp_sender.so
XDP_PROG_SRC := $(XDP_DIR)/xdp_prog.c
XDP_PROG_OUT := $(XDP_DIR)/xdp_prog.o
PACING_SRC := pacing_engine.c $(XDP_DIR)/xdp_core.c

# Libraries
LIBS := -lpthread
PACING_LIBS := -lpthread -lm

# Detect architecture for Python extension suffix
ARCH := $(shell uname -m)
PYTHON_EXT := $(shell $(PYTHON) -c "import sysconfig; print(sysconfig.get_config_var('EXT_SUFFIX') or '.so')")
XDP_SENDER_MODULE := xdp_sender$(PYTHON_EXT)
PACING_MODULE := pacing_engine$(PYTHON_EXT)

# Colors for output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[0;33m
BLUE := \033[0;34m
NC := \033[0m # No Color

.PHONY: all xdp xdp-prog pacing clean check help install

all: xdp xdp-prog pacing
	@echo "$(GREEN)✅ All targets built successfully!$(NC)"

# Build AF_XDP Python extension
xdp: $(XDP_SENDER_MODULE)
	@echo "$(GREEN)✅ XDP sender module built: $(XDP_SENDER_MODULE)$(NC)"

$(XDP_SENDER_MODULE): $(XDP_SENDER_SRC)
	@echo "$(BLUE)Building AF_XDP sender module...$(NC)"
	$(CC) $(CFLAGS) $(PYTHON_INCLUDE) -o $@ $< $(PYTHON_LDFLAGS) $(LIBS)
	@if [ -f "$@" ]; then \
		cp -f "$@" $(XDP_SENDER_OUT); \
		cp -f "$@" xdp_sender.so; \
		echo "$(GREEN)✅ Built: $@ (and synced to $(XDP_SENDER_OUT))$(NC)"; \
	else \
		echo "$(RED)❌ Failed to build: $@$(NC)"; \
		exit 1; \
	fi

# Compile XDP BPF program
xdp-prog: $(XDP_PROG_OUT)
	@echo "$(GREEN)✅ XDP BPF program compiled: $(XDP_PROG_OUT)$(NC)"

$(XDP_PROG_OUT): $(XDP_PROG_SRC)
	@echo "$(BLUE)Compiling XDP BPF program...$(NC)"
	@if command -v $(CLANG) >/dev/null 2>&1; then \
		$(CLANG) $(XDP_CFLAGS) -c $< -o $@ || exit 1; \
		echo "$(GREEN)✅ Compiled: $@$(NC)"; \
	else \
		echo "$(YELLOW)⚠️  clang not found, skipping BPF program$(NC)"; \
	fi

# Build Pacing Engine Python extension
pacing: $(PACING_MODULE)
	@echo "$(GREEN)✅ Pacing engine module built: $(PACING_MODULE)$(NC)"

$(PACING_MODULE): $(PACING_SRC)
	@echo "$(BLUE)Building Pacing Engine module...$(NC)"
	$(CC) $(CFLAGS) $(PYTHON_INCLUDE) -o $@ $< $(PYTHON_LDFLAGS) $(PACING_LIBS)
	@if [ -f "$@" ]; then \
		echo "$(GREEN)✅ Built: $@$(NC)"; \
	else \
		echo "$(RED)❌ Failed to build: $@$(NC)"; \
		exit 1; \
	fi

# Check dependencies
check:
	@echo "$(BLUE)Checking dependencies...$(NC)"
	@echo ""
	@echo "Python: $(shell $(PYTHON) --version 2>&1)"
	@echo "GCC: $(shell $(CC) --version | head -1)"
	@echo ""
	@echo "Checking Python development headers..."
	@if $(PYTHON_CONFIG) --includes >/dev/null 2>&1; then \
		echo "$(GREEN)  ✅ Python headers: OK$(NC)"; \
	else \
		echo "$(RED)  ❌ Python headers: NOT FOUND$(NC)"; \
		echo "     Install: sudo apt install python3-dev"; \
	fi
	@echo ""
	@echo "Checking for libbpf..."
	@if [ -f /usr/include/bpf/bpf.h ] || [ -f /usr/include/linux/bpf.h ]; then \
		echo "$(GREEN)  ✅ libbpf: OK$(NC)"; \
	else \
		echo "$(YELLOW)  ⚠️  libbpf headers not found (optional for Copy Mode)$(NC)"; \
		echo "     Install: sudo apt install libbpf-dev"; \
	fi
	@echo ""
	@echo "Checking for AF_XDP headers..."
	@if [ -f /usr/include/linux/if_xdp.h ]; then \
		echo "$(GREEN)  ✅ AF_XDP headers: OK$(NC)"; \
	else \
		echo "$(RED)  ❌ AF_XDP headers: NOT FOUND$(NC)"; \
		echo "     Install: sudo apt install linux-headers-$$(uname -r)"; \
	fi
	@echo ""
	@echo "Checking for clang (BPF compiler)..."
	@if command -v $(CLANG) >/dev/null 2>&1; then \
		echo "$(GREEN)  ✅ clang: OK$(NC)"; \
	else \
		echo "$(YELLOW)  ⚠️  clang not found (optional, needed for XDP programs)$(NC)"; \
		echo "     Install: sudo apt install clang"; \
	fi
	@echo ""
	@echo "Checking kernel version..."
	@KERNEL_VER=$$(uname -r); \
	MAJOR=$$(echo $$KERNEL_VER | cut -d. -f1); \
	MINOR=$$(echo $$KERNEL_VER | cut -d. -f2); \
	if [ $$MAJOR -gt 4 ] || ([ $$MAJOR -eq 4 ] && [ $$MINOR -ge 18 ]); then \
		echo "$(GREEN)  ✅ Kernel $$KERNEL_VER: OK (>= 4.18)$(NC)"; \
	else \
		echo "$(RED)  ❌ Kernel $$KERNEL_VER: TOO OLD (need >= 4.18)$(NC)"; \
	fi
	@echo ""

# Install the module
install: xdp
	@echo "$(BLUE)Installing xdp_sender module...$(NC)"
	@cp $(XDP_SENDER_MODULE) ../
	@echo "$(GREEN)✅ Installed$(NC)"

# Clean build artifacts
clean:
	@echo "$(BLUE)Cleaning build artifacts...$(NC)"
	rm -f $(XDP_SENDER_MODULE) $(PACING_MODULE) $(XDP_PROG_OUT) *.o *.so
	rm -f xdp_sender.cpython-*.so pacing_engine.cpython-*.so
	@echo "$(GREEN)✅ Cleaned$(NC)"

# Help
help:
	@echo ""
	@echo "$(BLUE)AF_XDP Build System for Samurai$(NC)"
	@echo "====================================="
	@echo ""
	@echo "Targets:"
	@echo "  make xdp        Build xdp_sender Python extension"
	@echo "  make xdp-prog   Compile XDP BPF program"
	@echo "  make pacing     Build pacing_engine Python extension"
	@echo "  make all        Build everything"
	@echo "  make check      Check system dependencies"
	@echo "  make clean      Remove build artifacts"
	@echo "  make install    Install module to parent directory"
	@echo "  make help       Show this help"
	@echo ""
	@echo "Requirements:"
	@echo "  - Linux kernel >= 4.18 (recommended: 5.10+)"
	@echo "  - Python 3.8+ with development headers"
	@echo "  - GCC compiler"
	@echo "  - libbpf-dev (optional for Native mode)"
	@echo "  - clang (optional, for BPF programs)"
	@echo ""
	@echo "Install dependencies on Ubuntu/Debian:"
	@echo "  sudo apt install python3-dev libbpf-dev libelf-dev clang linux-headers-\$$(uname -r)"
	@echo ""
