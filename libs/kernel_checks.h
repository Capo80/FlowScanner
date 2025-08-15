#ifndef H_KERNEL_CHECK
#define H_KERNEL_CHECK

#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/kprobes.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/dcache.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/seqlock.h>
#include <linux/time64.h>
#include <linux/timex.h>
#include <linux/string.h>
#include <linux/limits.h>
#include <linux/uaccess.h>
#include <linux/mm_types.h>
#include <linux/mm.h>
#include <asm/tlbflush.h>
#include <linux/hashtable.h>


typedef int (*check_function_t)(void* , unsigned long, unsigned long);

int add_check_function(check_function_t check, struct module *module);
int remove_check_function(check_function_t check, struct module *module);
int run_kernel_check(char *data, unsigned long start, unsigned long end);

#endif
