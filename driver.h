#ifndef H_DRIVER
#define H_DRIVER

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/slab.h>    //kmalloc()
#include <linux/uaccess.h> //copy_to/from_user()
#include <linux/ioctl.h>
#include <linux/err.h>
#include <linux/uidgid.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>

#include "libs/fprobes/fprobes_helper.h"
#include "libs/zone.h"
#include "mod.h"

#ifdef ZONE_KERNEL_SYNC_CHECK
struct user_zone
{
    char data[PAGE_SIZE * MAX_PAGES];
    pid_t pid; // Process ID
    pid_t ptid; // Parent Thread ID
    pid_t tid; // Thread ID
    unsigned long start;
    unsigned long end;
    struct timespec64 ts;
    struct stats stats;
};
#else
struct user_page_info
{
    char data[PAGE_SIZE];
    unsigned long address;
    pid_t pid;
    kuid_t uid;
};
#endif

struct mem_info
{
    unsigned long tot_memory_bytes;
    struct timespec64 ts;
};

// _IOR means that we're creating an ioctl command number for passing information from a user process to the kernel module.

#ifdef ZONE_KERNEL_SYNC_CHECK
#define RD_VALUE _IOR(0xf0, 0x1, struct user_zone)
#define GET_CFG_BY_PID _IOR(0xf0, 0x2, struct user_zone)
#else
#define RD_VALUE _IOR(0xf0, 0x1, struct user_page_info)
#endif

#define RD_MEM _IOR(0xf0, 0x3, struct mem_info)

extern dev_t dev;

extern struct class *dev_class;
extern struct cdev insp_cdev;

extern struct file_operations fops;

#endif