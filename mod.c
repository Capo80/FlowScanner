#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/mm_types.h>
#include <linux/string.h>
#include <linux/jiffies.h>
#include <linux/delay.h>
#include <linux/pid.h>
#include <linux/notifier.h>
#include <linux/kdebug.h>
#include <linux/kallsyms.h>


#include "libs/fprobes/fprobes_helper.h"
#include "libs/page_table_libs/page_table_utils.h"
#include "libs/zone.h"
#include "driver.h"
#include "libs/utils.h"
#include "libs/my_rcu.h"
#include "mod.h"
#include "libs/check_functions/check_function.h"
#include "libs/kernel_checks.h"
#include "linux/init.h"

#ifdef EXCLUDE_SCRIPT_INTERPRETERS
char* interpreters[TOTAL_INTERPRETERS] = {
	"php",
	"python",
	"luajit",
	"ruby",
};
#endif

#ifndef HOOKED_PROCESS_NAME
char *hooked_list[TOTAL_HOOKED] = {
	"objdump",
	"cat",
	"perlbench_s", 
	"gcc_s", 
	"mcf_s", 
	"omnetpp_s", 
	"xalancbmk_s", 
	"x264_s", 
	"deepsjeng_s", 
	"leela_s", 
	"exchange2_s", 
	"xz_s",
	"a.out",
	"objdump",
	"php",
	"/tmp/python3",
	"luajit",
	/* "ruby", */
};
DEFINE_HASHTABLE(hooked_pids, 8);
#endif

int num_of_sync_checks = NUM_SYNC_CHECKS;
module_param(num_of_sync_checks, int, 0660);

int num_of_contiguous_block = NUM_CONT_BLOCK; // Number of Contiguos Basic Block to open at a time
module_param(num_of_contiguous_block, int, 0660);

int page_checked = 0;
int zone_checked = 0;

unsigned long num_of_cow_pages = 0;
unsigned long tot_num_of_pages = 0;
unsigned long total_zones_size = 0;
unsigned long tot_num_of_zones = 0;

unsigned long ret_addr = 0;

bool started = false;
bool finished = false;

// TODO:: hardcoded and ugly
check_function_t check_1 = check_function_1;
check_function_t check_2 = check_function_2;

void cleaner_handler(struct work_struct *work);
DECLARE_DELAYED_WORK(user_hash_cleaner, cleaner_handler);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
#define KPROBE_KALLSYMS_LOOKUP 1
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
kallsyms_lookup_name_t kallsyms_lookup_name_func;
#define kallsyms_lookup_name kallsyms_lookup_name_func

static struct kprobe kp = {
	.symbol_name = "kallsyms_lookup_name"};
#endif

void (*flush_tlb_mm_range_func)(struct mm_struct *, unsigned long, unsigned long, unsigned int, bool);

static void spinlocks_init(void)
{
	int i;
#ifdef ZONE_KERNEL_SYNC_CHECK
	int j;
#endif

	for (i = 0; i < (1 << USER_BUCKET_BITS); i++)
	{
		spin_lock_init(&user_hash_spinlocks[i]);
	}

	for (i = 0; i < (1 << PAGE_BUCKET_BITS); i++)
	{
#ifndef ZONE_KERNEL_SYNC_CHECK
		spin_lock_init(&page_hash_table_spinlocks[i]);
#else
		// spin_lock_init(&cross_pages_integrity_hash_table_spinlocks[i]);
		// spin_lock_init(&page_hash_table_spinlocks[i]);
#endif
	}

#ifdef ZONE_KERNEL_SYNC_CHECK

	for (i = 0; i < (1 << NUM_PID_BITS) + 1; i++)
	{
		for (j = 0; j < (1 << NUM_PAGE_BITS); j++)
		{
			mutex_init(&mutexes[i][j]);
		}
	}

	// for (i = 0; i < (1 << ZONE_BUCKET_BITS); i++)
	// {
	// 	spin_lock_init(&zone_spinlocks[i]);
	// }
#endif
}

void cleaner_handler(struct work_struct *work)
{

	unsigned long bkt;
	struct user_hash_node *cur = NULL;
	struct hlist_node *tmp = NULL;
	hash_for_each_safe(user_hash, bkt, tmp, cur, node)
	{
		if (cur == NULL)
			continue;

		if (__sync_bool_compare_and_swap(&cur->is_being_updated, 1, 0) == false)
		{
			// no update in a while delete this
			AUDIT printk("%s: cleaning..\n", MODULE_NAME);
			hash_del(&cur->node);
		}
	}

	schedule_delayed_work(&user_hash_cleaner, msecs_to_jiffies(10000));
}

static __init int test_init(void)
{

	int ret = 0;

	/*Allocating Major number*/
	if ((alloc_chrdev_region(&dev, 0, 1, "page_inspector")) < 0)
	{
		pr_err("%s: Cannot allocate major number\n", MODULE_NAME);
		return -1;
	}

	/*Creating cdev structure*/
	cdev_init(&insp_cdev, &fops);

	/*Adding character device to the system*/
	if ((cdev_add(&insp_cdev, dev, 1)) < 0)
	{
		pr_err("%s: Cannot add the device to the system\n", MODULE_NAME);
		goto r_cdev;
	}

#if ( LINUX_VERSION_CODE >= KERNEL_VERSION( 6, 4, 0 ) )
	/*Creating struct class*/
	if (IS_ERR(dev_class = class_create("insp_class")))
	{
		pr_err("%s: Cannot create the struct class\n", MODULE_NAME);
		goto r_class;
	}
#else
	/*Creating struct class*/
	if (IS_ERR(dev_class = class_create(THIS_MODULE, "insp_class")))
	{
		pr_err("%s: Cannot create the struct class\n", MODULE_NAME);
		goto r_class;
	}
#endif

	

	/*Creating device*/
	if (IS_ERR(device_create(dev_class, NULL, dev, NULL, "insp_device")))
	{
		pr_err("%s: Cannot create the Device 1\n", MODULE_NAME);
		goto r_device;
	}

	printk(KERN_INFO "%s: Command RD_VALUE code is 0x%lx\n", MODULE_NAME, RD_VALUE);
	printk(KERN_INFO "%s: Command RD_MEM code is 0x%lx\n", MODULE_NAME, RD_MEM);
#ifdef ZONE_KERNEL_SYNC_CHECK
	printk(KERN_INFO "%s: Command GET_CFG_BY_PID code is 0x%lx\n", MODULE_NAME, GET_CFG_BY_PID);
#endif

	if (check_mode() != LONG_MODE)
	{
		printk(KERN_INFO "%s: Not in long mode\n", MODULE_NAME);
		goto r_check_mode;
	}

	printk(KERN_INFO "%s: Initializing spinlocks\n", MODULE_NAME);
	spinlocks_init();

#ifdef DOS_PROTECTION
	// star cleaner
	schedule_delayed_work(&user_hash_cleaner, msecs_to_jiffies(10000));
#endif

	// create hash table
	pr_info("%s: Creating hash table for the mapping (instruction op-code, size)\n", MODULE_NAME);
	// create_instruction_hash_table();


#ifdef SYNC_CHECK
	// add check functions - should never fail here, we just inserted the module
	add_check_function(check_1, THIS_MODULE); 
	/* add_check_function(check_2, THIS_MODULE);  */
#endif
	ret_addr = find_ret(&return_function);
	printk(KERN_INFO "%s: Return address is 0x%lx\n", MODULE_NAME, ret_addr);

	ret = register_kprobe(&kp);
	if (ret < 0)
	{
		printk(KERN_ERR "%s: Cannot register kprobe\n", MODULE_NAME);
		goto r_check_mode;
	}

	kallsyms_lookup_name = (kallsyms_lookup_name_t)kp.addr;

	printk(KERN_INFO "%s: kallsyms_lookup_name is at 0x%lx\n", MODULE_NAME, (unsigned long)kallsyms_lookup_name);

	unregister_kprobe(&kp);

	flush_tlb_mm_range_func = (void *)kallsyms_lookup_name("flush_tlb_mm_range");
	if (flush_tlb_mm_range_func == NULL)
	{
		printk(KERN_ERR "%s: Cannot find flush_tlb_mm_range\n", MODULE_NAME);
		goto r_check_mode;
	}

	printk(KERN_INFO "%s: flush_tlb_mm_range is at 0x%lx\n", MODULE_NAME, (unsigned long)flush_tlb_mm_range_func);

	// printk(KERN_INFO "%s: Initializing kprobes\n", MODULE_NAME);
	// ret = init_kprobes();
	// if (ret < 0)
	// {
	// 	printk(KERN_ERR "%s: Cannot initialize kprobes\n", MODULE_NAME);
	// 	goto r_check_mode;
	// }

	// ADD: init fprobe
	printk(KERN_INFO "%s: Initializing fprobes\n", MODULE_NAME);
	ret = init_fprobes();
	if (ret < 0)
	{
		printk(KERN_ERR "%s: Cannot initialize fprobes\n", MODULE_NAME);
		goto r_check_mode;
	}

	pr_info("%s: module init with ret %d\n", MODULE_NAME, ret);

#ifdef ZONE_KERNEL_SYNC_CHECK
	pr_info("Current mode: ZONE\n");
#else
	pr_info("Current mode: PAGE\n");
#endif
	pr_info("RD_MEM: %lx\n", RD_MEM);;
	return ret;

r_check_mode:
	device_destroy(dev_class, dev);
r_device:
	class_destroy(dev_class);
r_class:
	cdev_del(&insp_cdev);
r_cdev:
	unregister_chrdev_region(dev, 1);
	return -1;
}

void __exit test_exit(void)
{

#ifdef SYNC_CHECK
	remove_check_function(check_1, THIS_MODULE);
	/* remove_check_function(check_2, THIS_MODULE); */
#endif

	printk(KERN_INFO "%s: Removing device\n", MODULE_NAME);
	device_destroy(dev_class, dev);
	class_destroy(dev_class);
	cdev_del(&insp_cdev);
	unregister_chrdev_region(dev, 1);
	// printk(KERN_INFO "%s: Removing kprobes\n", MODULE_NAME);
	// remove_probes();
	printk(KERN_INFO "%s: Removing fprobes\n", MODULE_NAME);
	remove_fprobes();

#ifdef DOS_PROTECTION
	cancel_delayed_work_sync(&user_hash_cleaner);
#endif

#ifdef ZONE_KERNEL_SYNC_CHECK
#endif

	printk(KERN_INFO "%s: Destroying hash table for the mapping (instruction op-code, size)\n", MODULE_NAME);
	// destroy_instruction_hash_table();

	pr_info("%s: module exit\n", MODULE_NAME);
}

module_init(test_init);
module_exit(test_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Anonimized");
