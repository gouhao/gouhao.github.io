KERNEL_VER=$(shell uname -r)
obj-m += kprobe_example.o

all:kernel_modules

kernel_modules:
	make -C /lib/modules/$(KERNEL_VER)/build M=$(CURDIR) modules

clean:
	make -C /lib/modules/$(KERNEL_VER)/build M=$(CURDIR) clean
