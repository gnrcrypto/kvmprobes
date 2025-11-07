# KVM Escape Toolkit Makefile
# Builds kernel module and userland prober tool

# Kernel module name and source
MODULE_NAME := kvm_probe_drv
MODULE_SRC := kvm_probe_drv.c
PROBER_SRC := kvm_prober.c
PROBER_EXE := kvm_prober

# Kernel build configuration
KERNEL_DIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

# Compiler flags
CFLAGS_user := -O2 -Wall -Wextra -I.

all: module prober

module:
	@echo "Building kernel module from $(MODULE_SRC)..."
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules

prober: $(PROBER_EXE)

$(PROBER_EXE): $(PROBER_SRC)
	@echo "Building userland prober from $(PROBER_SRC)..."
	$(CC) $(CFLAGS_user) -o $@ $^

clean:
	@echo "Cleaning build artifacts..."
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) clean
	rm -f $(PROBER_EXE) *.o .*.cmd *.mod.c *.mod *.ko modules.order Module.symvers

install-module: module
	sudo insmod $(MODULE_NAME).ko
	sudo chmod 666 /dev/kvm_probe_dev

uninstall-module:
	-sudo rmmod $(MODULE_NAME) 2>/dev/null || true
	-sudo rm -f /dev/kvm_probe_dev 2>/dev/null || true

load: install-module

unload: uninstall-module

install: all install-module
	@echo "Toolkit installed and loaded"

.PHONY: all module prober clean install-module uninstall-module load unload install

# Kernel module objects
obj-m := $(MODULE_NAME).o