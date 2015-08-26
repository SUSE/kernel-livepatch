KDIR ?= /lib/modules/`uname -r`/build

obj-m := kgraft-patch-@@RPMRELEASE@@.o

kgraft-patch-@@RPMRELEASE@@-y := kgr_patch_main.o uname_patch/kgr_patch_uname.o

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
