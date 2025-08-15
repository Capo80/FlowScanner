#ifndef FPROBES_H
#define FPROBES_H


#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/slab.h>
#include <linux/dcache.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/time64.h>
#include <linux/timex.h>
#include <linux/limits.h>
#include <linux/uaccess.h>
#include <linux/mm_types.h>
#include <linux/mm.h>
#include <linux/hashtable.h>
#include <linux/list.h>
#include <linux/sched/task.h>
#include <linux/smp.h>
#include <linux/ktime.h>
#include <asm/trapnr.h>
#include <asm/trap_pf.h>
#include <linux/mman.h>
#include <linux/kthread.h>
#include <linux/signal.h>
#include <asm/pgtable.h>
#include <linux/wait.h>
#include <linux/types.h>



#include <linux/fprobe.h>

#include "../../mod.h"
#include "../page_table_libs/page_table_utils.h"
#include "../zone.h"

#define bool	_Bool

#define PATH_MAX 4096
#define PAGE_BUCKET_BITS 10
#define USER_BUCKET_BITS 4
#define SHARED_BUCKET_BITS 10
#define PAGE_MAX_LIMIT 200000
#define MAX_PAGES 2

#define PTE_RETRY 200 //sometimes we fail to get the pte, this is how many times we retryì

#define INVALID_OP_HANDLED_FLAG 0x00000008

#define PARTIALLY_OPENED_START 0x1 // The page contains a cross-page instruction that starts from the previous page
#define PARTIALLY_OPENED_END 0x2   // The page contains a cross-page instruction that ends in the next page

#define FPROBES_kret_COUNT 3 // do_mmap, handle_mm_fault, kernel_clone


#ifdef ZONE_KERNEL_SYNC_CHECK
	#ifdef DEBUG_PROBES

		#define KPROBES_COUNT 8	   // force_sig_fault, force_sig, mprotect_fixup, change_protection, do_task_dead, bprm_execve, do_error_trap

	#else // DEBUG_PROBES

		#define KPROBES_COUNT 6	   // force_sig_fault, do_task_dead, bprm_execve, do_error_trap, mprotect_fixup, change_protection

	#endif // DEBUG_PROBES
#else

	#ifdef DEBUG_PROBES

		#define KPROBES_COUNT 6	   // force_sig_fault, force_sig, do_task_dead, bprm_execve, mprotect_fixup, change_protection

	#else

		#define KPROBES_COUNT 5	   // force_sig_fault, do_task_dead, bprm_execve, mprotect_fixup, change_protection

	#endif
#endif

#define FPROBES_COUNT FPROBES_kret_COUNT + KPROBES_COUNT

#define PROT_WRITE 0x2
#define PROT_EXEC 0x4




struct page_info
{
	char data[PAGE_SIZE];  // The data of the page.
	atomic_t ref_count;	   // The reference count of the page.
	short opened;		   // number of bytes opened on the page
	bool is_shared;		   // Whether the page is shared or not.
	//char * comm;		   // The name of the process that owns the page. To distinguish shared pages of different programs.
#ifndef ZONE_KERNEL_SYNC_CHECK
	kuid_t uid; // The UID of the process that owns the page.
#endif
};

struct page_hash_node
{
	pid_t pid;				// The PID of the process that owns the page.
	unsigned long address; // The address of the page.
	struct page_info *info; // The page info.
	struct hlist_node node; // The node for the hash table.
};

struct page_cross_pages_integrity_hash_node
{
	pid_t pid;				// The PID of the process that owns the page.
	unsigned long address;	// The address of the page.
	uint8_t flags;			// The flags of the page.
	struct hlist_node node; // The node for the hash table.
};

struct user_hash_node
{
	kuid_t uid; // The UID of the user.

#ifdef ZONE_KERNEL_SYNC_CHECK
	unsigned long bytes_allocated; // The number of bytes allocated to the user.

#else
	unsigned long page_allocated; // The number of pages allocated to the user.
#endif

	char is_blocked;		// Whether the user is blocked or not.
	char is_being_updated;	// Whether the user is being updated or not.
	struct hlist_node node; // The node for the hash table.
};

struct page_table_node
{
	pgd_t* pgd;
	struct list_head node;
};

struct shared_map_hash_node
{
	struct list_head page_tables;

	struct hlist_node node;
};


extern DECLARE_HASHTABLE(shared_map_hash, SHARED_BUCKET_BITS); // hashmap to find shared pages
extern spinlock_t shared_map_hash_spinlocks_f[1 << SHARED_BUCKET_BITS];

#define get_bucket(key, hashtable) hash_min(key, HASH_BITS(hashtable))

#define VM_WAS_EXECUTABLE 0x00000800

extern struct list_head page_list;

extern DECLARE_HASHTABLE(user_hash, USER_BUCKET_BITS); // For DoS protection
extern spinlock_t user_hash_spinlocks[1 << USER_BUCKET_BITS];

#define get_shared_page_bucket(bits) (1 << bits)

#ifdef ZONE_KERNEL_SYNC_CHECK

extern struct hlist_head page_hash_table[(1 << PAGE_BUCKET_BITS) + 1]; // Pages that contains the master copy of each page

#else
extern DECLARE_HASHTABLE(page_hash_table, PAGE_BUCKET_BITS); // Pages that contains the master copy of each page
extern spinlock_t page_hash_table_spinlocks[1 << PAGE_BUCKET_BITS];
#endif

#ifdef ZONE_KERNEL_SYNC_CHECK
extern DECLARE_HASHTABLE(cross_pages_integrity_hash_table, PAGE_BUCKET_BITS); // Pages that contains cross-page instructions
// extern spinlock_t cross_pages_integrity_hash_table_spinlocks[1 << PAGE_BUCKET_BITS]
#endif

#define NUM_PID_BITS 6
#define NUM_PAGE_BITS 10

#define get_pid_bucket(key, bits) hash_min(key, NUM_PID_BITS)
#define get_page_bucket(page_addr, bits) hash_min(page_addr, NUM_PAGE_BITS)

extern struct mutex mutexes[(1 << NUM_PID_BITS) + 1][1 << NUM_PAGE_BITS]; // Mutexes for each page + 1 for the shared pages

extern struct page_info *register_page(char *page_data, unsigned long start);
extern struct page_info *register_private_page(char *page_data, unsigned long start);
extern struct page_info *register_shared_page(char *page_data, unsigned long start);
extern struct page_info *page_shared_not_registered_yet(unsigned long address);

#ifdef ZONE_KERNEL_SYNC_CHECK
extern int register_page_cross_pages_integrity(unsigned long start, uint8_t);
extern int unregister_page_cross_pages_integrity(unsigned long start);
#endif

#ifdef ZONE_KERNEL_SYNC_CHECK
extern int check_bytes_limit(kuid_t uid, unsigned long size);
#else
int check_page_limit(kuid_t uid);
#endif

#define on_each_cpu(x, y, z) on_each_cpu_cond_mask(NULL, x, y, z, &__cpu_online_mask)


extern int init_fprobes(void);
extern void remove_fprobes(void);

#endif