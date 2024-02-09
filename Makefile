obj-m += sandbox-unwind.o
obj-m += sandbox.o
PWD = $(shell pwd)
KDIR = /lib/modules/6.3.0-asahi-13-1-edge-ARCH/build/edge/
EXTRA_CFLAGS = -Wall -g

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

ins:
	sudo insmod sandbox-unwind.ko
	sudo insmod sandbox.ko
	dmesg

rm:
	sudo rmmod sandbox sandbox-unwind
	sudo dmesg -C

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
