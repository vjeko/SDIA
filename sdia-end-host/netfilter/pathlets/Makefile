obj-m = pathlet.o
KVERSION = $(shell uname -r)
ccflags-y := -std=gnu99 -Wno-declaration-after-statement
EXTRA_CFLAGS += -I/usr/include
all:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean
