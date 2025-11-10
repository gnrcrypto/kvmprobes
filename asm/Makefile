obj-m += kvm_probe_drv.o

KDIR := /lib/modules/$(shell uname -r)+/build

all:
        $(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
        $(MAKE) -C $(KDIR) M=$(PWD) clean

install:
        sudo insmod kvm_probe_drv.ko

uninstall:
        sudo rmmod kvm_probe_drv
