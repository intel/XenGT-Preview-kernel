VGT_SOURCE := vgt.o render.o mmio.o handlers.o interrupt.o  \
	sysfs.o display.o debugfs.o edid.o gtt.o aperture_gm.o utility.o \
	klog.o dev.o cmd_parser.o sched.o instance.o cfg_space.o hypercall.o \
	fb_decoder.o vbios.o

ccflags-y				+= -I$(src)
xen_vgt-y				:= $(VGT_SOURCE)
ccflags-$(CONFIG_XEN_VGT_I915)		+= -Wall -Werror
obj-$(CONFIG_XEN_VGT_I915)		+= xen_vgt.o
