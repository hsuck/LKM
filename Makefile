obj-m += sandbox-unwind.o
obj-m += sandbox.o
PWD = $(shell pwd)
KDIR = /lib/modules/6.3.0-asahi-11-1-ARCH/build/base
EXTRA_CFLAGS = -Wall -g

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

ins:
	sudo insmod sandbox-unwind.ko
	sudo insmod sandbox.ko
	dmesg

rm:
	sudo dmesg -C
	sudo rmmod sandbox sandbox-unwind
	dmesg
	sudo dmesg -C

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
