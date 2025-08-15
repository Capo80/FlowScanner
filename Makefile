KERNEL_MODULE_NAME := hook

KERNEL_MODULE_OBJECT_FILE_LIST := \
    mod.o \
    driver.o \
    libs/fprobes/fprobe_change_prot.o \
    libs/fprobes/fprober_handle_mm.o \
    libs/fprobes/fprober_invalid_op.o \
    libs/fprobes/fprober_mmap.o \
    libs/fprobes/fprober_proc_mngmt.o \
    libs/fprobes/fprober_sig_handler.o \
    libs/fprobes/fprober_new.o \
    libs/fprobes/fprober_mmap.o \
    libs/fprobes/fprobes_helper.o \
    libs/kernel_checks.o \
    libs/page_table_libs/page_table_utils.o \
    libs/utils.o \
    libs/zone.o \
    libs/my_rcu.o \
    libs/check_functions/check_functions.o

#NUM_OF_SYNC_CHECKS = $(shell cat /sys/module/hook/parameters/num_of_sync_checks)

# DOS_PROTECTION
# from command line use: make EXTRA_CFLAGS=-DKERNEL_SYNC_CHECK=42
#  make EXTRA_CFLAGS='-DHOOKED_PROCESS_NAME=\"file\"'
# make EXTRA_CFLAGS='-DHOOKED_PROCESS_NAME=\"file\" -DZONE_KERNEL_SYNC_CHECK'^C
# EXTRA_CFLAGS:='-DHOOKED_PROCESS_NAME="$(HOOK)"'
ifneq ($(PAGE), y)
	EXTRA_CFLAGS+='-DZONE_KERNEL_SYNC_CHECK'
endif




obj-m := $(KERNEL_MODULE_NAME).o
$(KERNEL_MODULE_NAME)-y += $(KERNEL_MODULE_OBJECT_FILE_LIST)

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$$PWD 

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$$PWD clean

install:
	insmod hook.ko 
	
remove:
	rmmod hook 
