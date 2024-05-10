obj-m = sandbox.o
sandbox-objs := sandbox-main.o sandbox-unwind.o
PWD = $(shell pwd)
KDIR = /lib/modules/6.3.0-asahi-11-1-ARCH/build/base
EXTRA_CFLAGS = -Wall -g

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

ins:
	sudo insmod sandbox.ko
	dmesg

rm:
	sudo dmesg -C
	sudo rmmod sandbox
	dmesg
	sudo dmesg -C

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
