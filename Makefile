# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
CLANG     ?= clang
LLVM_STRIP ?= llvm-strip
CC        ?= cc
V         ?= 0

ROOT_DIR    := $(abspath .)
OUTPUT      := $(ROOT_DIR)/.output
LIBBPF_SRC  := $(ROOT_DIR)/libbpf/src
BPFTOOL_SRC := $(ROOT_DIR)/bpftool/src

ARCH := $(shell uname -m | sed 's/x86_64/x86/' \
                         | sed 's/aarch64/arm64/' \
                         | sed 's/ppc64le/powerpc/' \
                         | sed 's/mips.*/mips/' \
                         | sed 's/arm.*/arm/' \
                         | sed 's/riscv64/riscv/')

LIBBPF_OBJ  := $(OUTPUT)/libbpf.a
BPFTOOL     := $(OUTPUT)/bpftool/bootstrap/bpftool
VMLINUX_BTF := /sys/kernel/btf/vmlinux
VMLINUX_H   := $(ROOT_DIR)/vmlinux/$(ARCH)/vmlinux.h

ifeq ($(V),1)
    Q =
    msg = @true
else
    Q = @
    msg = @printf '  %-8s %s\n' "$(1)" "$(2)";
endif

.DEFAULT_GOAL := help

.PHONY: all
all: prebuild
	$(Q)$(MAKE) -C src all

.PHONY: prebuild
prebuild: libbpf bpftool	
	@echo "  OK "

.PHONY: vmlinux
vmlinux: bpftool
	$(call msg,VMLINUX,$(VMLINUX_H))
	@if [ ! -f $(VMLINUX_BTF) ]; then \
		echo "$(VMLINUX_BTF) BTF"; \
		exit 1; \
	fi
	$(Q)mkdir -p $(dir $(VMLINUX_H))
	$(Q)$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $(VMLINUX_H)
	@echo "  OK       vmlinux.h "

.PHONY: submodules
submodules:	
	@if [ ! -f "$(LIBBPF_SRC)/Makefile" ] || [ ! -f "$(BPFTOOL_SRC)/../libbpf/src/Makefile" ]; then \
		echo "  INIT     Git "; \
		git submodule update --init --recursive; \
	fi

.PHONY: libbpf
libbpf: submodules $(LIBBPF_OBJ)

.PHONY: bpftool
bpftool: submodules $(BPFTOOL)

$(OUTPUT)/libbpf:
	$(Q)mkdir -p $@

$(OUTPUT)/bpftool:
	$(Q)mkdir -p $@

$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,libbpf.a)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1 \
		OBJDIR=$(OUTPUT)/libbpf DESTDIR=$(OUTPUT) \
		INCLUDEDIR= LIBDIR= UAPIDIR= install

$(BPFTOOL): | $(OUTPUT)/bpftool
	$(call msg,BPFTOOL,bpftool)
	$(Q)$(MAKE) ARCH= CROSS_COMPILE= OUTPUT=$(OUTPUT)/bpftool/ -C $(BPFTOOL_SRC) bootstrap

.PHONY: clean
clean:
	$(Q)$(MAKE) -C src clean

.PHONY: clean-all
clean-all: clean
	$(call msg,CLEAN,.output)
	$(Q)rm -rf $(OUTPUT)

.PHONY: install-deps
install-deps:	
	sudo apt update
	sudo apt-get install -y --no-install-recommends \
		libelf1 libelf-dev zlib1g-dev \
		make clang llvm libbpf-dev \
		linux-headers-$(shell uname -r)

.PHONY: help
help:	
	@echo "  make prebuild"
	@echo "  make all"

