MODULENAME=spindrv

obj-m += $(MODULENAME).o

module:
	make -C /lib/modules/$(shell uname -r)/build M=$$PWD modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$$PWD clean

install:
	mkdir -p /usr/include/spin
	cp include/*.h /usr/include/spin
	cp Module.symvers ../spinnvme
	sudo chmod -R 755 /usr/include/spin
	sudo insmod $(MODULENAME).ko
	sudo chmod 666 /dev/$(MODULENAME)

uninstall:
	sudo rmmod $(MODULENAME)

