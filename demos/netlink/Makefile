bin=netlink_test
obj-m = netlink_module.o
KVERSION = $(shell uname -r)
all:$(bin)
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules
bin:
	gcc netlink_test.c -o netlink_test
clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean
	rm -rf netlink_test.o netlink_test