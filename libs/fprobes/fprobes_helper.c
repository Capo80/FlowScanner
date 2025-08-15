/**
 * @file fprobes_helper.c
 * @author 
 * @brief Main logic for fprobes
 * @version 0.1
 * @date 2025-03-20
 * 
 * @copyright Copyright (c) 2025
 * 
 */
#include "../kernel_checks.h"
#include "../page_table_libs/page_table_utils.h"
#include "../utils.h"
#include "../zone.h"
#include "asm/segment.h"
#include "../instruction.h"
#include "../hlist_lock_free.h"
#include "../my_mutexes.h"

#include "fprobes_helper.h"
#include "fprobers.h"




DEFINE_HASHTABLE(shared_map_hash, SHARED_BUCKET_BITS); // hashmap to find shared pages
spinlock_t shared_map_hash_spinlocks[1 << SHARED_BUCKET_BITS];

DEFINE_HASHTABLE(user_hash, USER_BUCKET_BITS);
spinlock_t user_hash_spinlocks[1 << USER_BUCKET_BITS];

#ifdef ZONE_KERNEL_SYNC_CHECK
struct hlist_head page_hash_table[(1 << (PAGE_BUCKET_BITS)) + 1] = {[0 ...((1 << (PAGE_BUCKET_BITS)))] = HLIST_HEAD_INIT};

#else
DEFINE_HASHTABLE(page_hash_table, PAGE_BUCKET_BITS);
spinlock_t page_hash_table_spinlocks[1 << PAGE_BUCKET_BITS];
#endif

#ifdef ZONE_KERNEL_SYNC_CHECK
DEFINE_HASHTABLE(cross_pages_integrity_hash_table, PAGE_BUCKET_BITS); // It is used to store the pages that could have some instruction integrity problems, like cross-page instructions cut in half
// spinlock_t cross_pages_integrity_hash_table_spinlocks[1 << PAGE_BUCKET_BITS];
#endif

/** 
 * @brief IMPORTANT!! DO NOT TAKE THIS LOCK IF THE CURRENT THREAD HOLDS THE PTE LOCK FOR THE PAGE
 * 		  (ALSO PTE LOCK == PMD LOCK SO MULTIPLE PAGES WILL HAVE THE SAME LOCK)
 *        A lot of probes take the pte lock while inside this
 */
struct mutex mutexes[(1 << NUM_PID_BITS) + 1][1 << NUM_PAGE_BITS];


void print_address_space(pid_t pid)
{

	struct task_struct *p;
	struct vm_area_struct *vma;
	const char *name;

	for_each_process(p)
	{

		if (p->pid == pid)
		{
			printk("Task %s (pid = %d)\n", p->comm, task_pid_nr(p));

			if (p->mm != NULL)
			{	
				VMA_ITERATOR(iter, p->mm, 0);
				
				//mmap_read_lock(mm);
				for_each_vma(iter, vma)
				{
					name = NULL;

					name = vma->vm_file == NULL ? NULL : vma->vm_file->f_path.dentry->d_name.name;

					printk("[%d] %s: %lx - %lx\n", pid, name, (unsigned long)vma->vm_start, (unsigned long)vma->vm_end);

					
				}
			}
			//mmap_read_unlock(mm);
		}
	}
}

#ifndef ZONE_KERNEL_SYNC_CHECK
// ret 1 = overloaded, stop process
// ret 0 = all good, continue
int check_page_limit(kuid_t uid)
{

	struct user_hash_node *cur = NULL;
	unsigned long flags;
	// recover the user information
	hash_for_each_possible(user_hash, cur, node, uid.val)
	{
		if (uid_eq(cur->uid, uid))
			break;
	}
	if (cur == NULL || !uid_eq(cur->uid, uid))
	{
		// first page from this user add to the hash
		struct user_hash_node *new_node = kmalloc(sizeof(struct user_hash_node), GFP_ATOMIC);
		if (new_node == NULL)
		{
			// cannot allocate memory - hope somebody else can
			return 0;
		}
		new_node->is_being_updated = 1;
		new_node->is_blocked = 0;
		new_node->uid = uid;
		new_node->page_allocated = 1;

		spin_lock_irqsave(user_hash_spinlocks + get_bucket(uid.val, user_hash), flags);
		hash_add(user_hash, &new_node->node, uid.val);
		spin_unlock_irqrestore(user_hash_spinlocks + get_bucket(uid.val, user_hash), flags);

		return 0;
	}
	// user exists, set update bool
	__sync_fetch_and_or(&cur->is_being_updated, 1);

	// check if its blocked
	if (cur->is_blocked)
	{
		printk("%s: pages allocated: %lu\n", MODULE_NAME, cur->page_allocated);
		return 1;
	}
	// not blocked check limit
	__sync_fetch_and_add(&cur->page_allocated, 1);
	if (cur->page_allocated > PAGE_MAX_LIMIT)
	{
		// limit surpassed block
		__sync_fetch_and_or(&cur->is_blocked, 1);
		return 1;
	}
	// not over limit
	return 0;
}
#endif

#ifdef ZONE_KERNEL_SYNC_CHECK
// ret 1 = overloaded, stop process
// ret 0 = all good, continue
	int check_bytes_limit(kuid_t uid, unsigned long size)
	{

		struct user_hash_node *cur = NULL;
		unsigned long flags;

		// recover the user information
		hash_for_each_possible(user_hash, cur, node, uid.val)
		{
			if (uid_eq(cur->uid, uid))
				break;
		}
		if (cur == NULL || !uid_eq(cur->uid, uid))
		{
			// first page from this user add to the hash
			struct user_hash_node *new_node = kmalloc(sizeof(struct user_hash_node), GFP_ATOMIC);
			if (new_node == NULL)
			{
				// cannot allocate memory - hope somebody else can
				return 0;
			}
			new_node->is_being_updated = 1;
			new_node->is_blocked = 0;
			new_node->uid = uid;
			new_node->bytes_allocated = size;

			spin_lock_irqsave(user_hash_spinlocks + get_bucket(uid.val, user_hash), flags);
			hash_add(user_hash, &new_node->node, uid.val);
			spin_unlock_irqrestore(user_hash_spinlocks + get_bucket(uid.val, user_hash), flags);

			return 0;
		}
		// user exists, set update bool
		__sync_fetch_and_or(&cur->is_being_updated, 1);

		// check if its blocked
		if (cur->is_blocked)
		{
			printk("%s: bytes allocated: %lu\n", MODULE_NAME, cur->bytes_allocated);
			return 1;
		}
		// not blocked check limit
		__sync_fetch_and_add(&cur->bytes_allocated, size);
		if (cur->bytes_allocated > (PAGE_MAX_LIMIT * PAGE_SIZE))
		{
			// limit surpassed block
			__sync_fetch_and_or(&cur->is_blocked, 1);
			return 1;
		}
		// not over limit
		return 0;
	}
#endif

/**
 * Adding a page to the page hash table
 *
 * @brief - Adding a page to the page hash table
 * @param start - The start address within the page
 * @param page_data - The page data
 *
 * @return struct page_info* - pointer to the page info struct
 */
struct page_info *register_page(char *page_data, unsigned long start)
{
	struct page_info *page_info = NULL;
	struct page_hash_node *new_hash = NULL;
	pid_t pid = current->tgid;
	unsigned long page_addr = start & PAGE_MASK;
	unsigned char compare_value[QWORD_SIZE + 1] = {[0 ... QWORD_SIZE] = INVALID_ONE_BYTE_OPCODE}; // Max operand size is 8 bytes

#ifdef ZONE_KERNEL_SYNC_CHECK
	// struct page_hash_node *cur = NULL;
#endif

	AUDIT printk("%s: register_page: %lx\n", MODULE_NAME, page_addr);

	if (page_data == NULL)
	{
		printk(KERN_ERR "%s: (register_page) page_data is NULL\n", MODULE_NAME);
		return NULL;
	}

	if (memcmp(page_data, compare_value, QWORD_SIZE + 1) == 0) // dummy consistency check: if the page contains max operand size + 1 0x0E the page has been altered by the software
	{

		printk(KERN_ERR "%s: (register_page) Trying to register page %lx with some 0x0E, It might have been alterated\n", MODULE_NAME, page_addr);
		return NULL;
	}

	if (memcmp(page_data + PAGE_SIZE - QWORD_SIZE - 1, compare_value, QWORD_SIZE + 1) == 0) // dummy consistency check: if the page contains max operand size + 1 0x0E the page has been altered by the software
	{

		printk(KERN_ERR "%s: (register_page) Trying to register page %lx with some 0x0E, It might have been alterated\n", MODULE_NAME, page_addr);
		return NULL;
	}

	page_info = kmalloc(sizeof(struct page_info), GFP_ATOMIC);

	if (page_info == NULL)
	{
		printk(KERN_ERR "%s: (register_page) Error allocating page info\n", MODULE_NAME);
		return NULL;
	}

	memcpy(page_info->data, page_data, PAGE_SIZE);

	atomic_set(&page_info->ref_count, 1);
	page_info->is_shared = false;
	page_info->opened = 0;

#ifndef ZONE_KERNEL_SYNC_CHECK
	page_info->uid = current->cred->uid;
#endif

	new_hash = kmalloc(sizeof(struct page_hash_node), GFP_ATOMIC);

	if (new_hash == NULL)
	{
		printk(KERN_ERR "%s: (register_page) Error allocating page hash node\n", MODULE_NAME);
		kfree(page_info);
		return NULL;
	}

	new_hash->info = page_info;
	new_hash->pid = pid;
	new_hash->address = start;

	AUDIT printk("%s: Adding page %lx to the page hash table\n", MODULE_NAME, page_addr);

#ifdef ZONE_KERNEL_SYNC_CHECK
	/**
	 * There should be no old page with the same address and pid, because the page is added only once and when a write occurr the page is deleted in the restore_page function.
	 * The instruction fetch fault on the same page occurrs only once, so the page is added only once. If it occurs more than once, it means that the page has been writed
	 * and the old page is deleted in the restore_page function.
	 *
	 * Moreover, if, for some reason, the page is added more than once, the page is added on the top of the list, in the same bucket. So, during the restore_zone phase
	 * the up to date page is the first one in the list.
	 *
	 */

	// hash_for_each_possible(page_hash_table, cur, node, pid)
	// {
	// 	if (cur->info != NULL && cur->pid == pid && cur->info->address == page_addr)
	// 	{
	// 		// page already exists
	// 		AUDIT printk("%s: found an older version of the same page\n", MODULE_NAME);
	// 		break;
	// 	}
	//}
	;
	// if (cur != NULL) // page already exists
	// {
	// 	hash_del_atomic(&cur->node);
	// 	if (cur->info != NULL)
	// 		kfree(cur->info);
	// 	kfree(cur);

	// 	tot_num_of_pages--;
	// }
#endif
	hash_add_atomic(page_hash_table, &new_hash->node, pid);

	tot_num_of_pages++;

	return page_info;
}

/**
 * Unregistering a page from the page hash table
 *
 * @param addr The address of the page to restore.
 */

#ifdef ZONE_KERNEL_SYNC_CHECK

/**
 * Adding a shared page to the page hash table
 *
 * @brief - Adding a page to the page hash table
 * @param start - The start address within the page
 * @param page_data - The page data
 *
 * @return struct page_info* - pointer to the page info struct
 */
struct page_info *register_shared_page(char *page_data, unsigned long start)
{
	struct page_info *page_info = NULL;
	struct page_hash_node *new_shared_page_hash = NULL;
	struct page_hash_node *new_hash = NULL;
	pid_t pid = current->tgid;
	unsigned long page_addr = start & PAGE_MASK;
	unsigned char compare_value[QWORD_SIZE + 1] = {[0 ... QWORD_SIZE] = INVALID_ONE_BYTE_OPCODE}; // Max operand size is 8 bytes

	AUDIT printk("%s: register_shared_page: %lx\n", MODULE_NAME, page_addr);

	if (page_data == NULL)
	{
		printk(KERN_ERR "%s: (register_shared_page) page_data is NULL\n", MODULE_NAME);
		return NULL;
	}

	if (memcmp(page_data, compare_value, QWORD_SIZE + 1) == 0) // dummy consistency check: if the page contains max operand size + 1 0x0E the page has been altered by the software
	{

		printk(KERN_ERR "%s: (register_shared_page) Trying to register page %lx with some 0x0E, It might have been alterated\n", MODULE_NAME, page_addr);
		return NULL;
	}

	if (memcmp(page_data + PAGE_SIZE - QWORD_SIZE - 1, compare_value, QWORD_SIZE + 1) == 0) // dummy consistency check: if the page contains max operand size + 1 0x0E the page has been altered by the software
	{

		printk(KERN_ERR "%s: (register_shared_page) Trying to register page %lx with some 0x0E, It might have been alterated\n", MODULE_NAME, page_addr);
		return NULL;
	}

	page_info = kmalloc(sizeof(struct page_info), GFP_ATOMIC);

	if (page_info == NULL)
	{
		printk(KERN_ERR "%s: (register_shared_page) Error allocating page info\n", MODULE_NAME);
		return NULL;
	}

	memcpy(page_info->data, page_data, PAGE_SIZE);

	atomic_set(&page_info->ref_count, 1); // If a page is shared, it has to be referenced by at least two processes
	page_info->is_shared = true;
	page_info->opened = 0;
	page_info->opened = 0;

	new_hash = kmalloc(sizeof(struct page_hash_node), GFP_ATOMIC);

	if (new_hash == NULL)
	{
		printk(KERN_ERR "%s: (register_shared_page) Error allocating page hash node\n", MODULE_NAME);
		kfree(page_info);
		return NULL;
	}

	new_shared_page_hash = kmalloc(sizeof(struct page_hash_node), GFP_ATOMIC);

	if (new_shared_page_hash == NULL)
	{
		printk(KERN_ERR "%s: (register_shared_page) Error allocating page hash node\n", MODULE_NAME);
		kfree(page_info);
		kfree(new_hash);
		return NULL;
	}

	new_hash->info = page_info;
	new_hash->pid = pid;

	new_shared_page_hash->info = page_info;
	new_shared_page_hash->pid = pid;
	new_shared_page_hash->address = page_addr;

	AUDIT printk("%s: Adding page %lx to the page hash table\n", MODULE_NAME, page_addr);

	hash_add_atomic_last(page_hash_table, &new_shared_page_hash->node, NUM_PAGE_BITS); // The shared pages are inserted in the last bucket
	hash_add_atomic(page_hash_table, &new_hash->node, pid);

	tot_num_of_pages++;

	return page_info;
}

/**
 * Adding a the master copy of a private page to the page hash table
 *
 * @brief - Adding a page to the page hash table
 * @param start - The start address within the page
 * @param page_data - The page data
 *
 * @return struct page_info* - pointer to the page info struct
 */
struct page_info *register_private_page(char *page_data, unsigned long start)
{
	struct page_info *page_info = NULL;
	struct page_hash_node *new_hash = NULL;
	pid_t pid = current->tgid;
	unsigned long page_addr = start & PAGE_MASK;
	unsigned char compare_value[QWORD_SIZE + 1] = {[0 ... QWORD_SIZE] = INVALID_ONE_BYTE_OPCODE}; // Max operand size is 8 bytes

	AUDIT printk("%s: register_private_page: %lx\n", MODULE_NAME, page_addr);

	if (page_data == NULL)
	{
		printk(KERN_ERR "%s: (register_private_page) page_data is NULL\n", MODULE_NAME);
		return NULL;
	}

	if (memcmp(page_data, compare_value, QWORD_SIZE + 1) == 0) // dummy consistency check: if the page contains max operand size + 1 0x0E the page has been altered by the software
	{

		printk(KERN_ERR "%s: (register_private_page) Registering page %lx with some 0x0E, It might have been alterated\n", MODULE_NAME, page_addr);
		return NULL;
	}

	if (memcmp(page_data + PAGE_SIZE - QWORD_SIZE - 1, compare_value, QWORD_SIZE + 1) == 0) // dummy consistency check: if the page contains max operand size + 1 0x0E the page has been altered by the software
	{

		printk(KERN_ERR "%s: (register_private_page) Registering page %lx with some 0x0E, It might have been alterated\n", MODULE_NAME, page_addr);
		return NULL;
	}

	page_info = kmalloc(sizeof(struct page_info), GFP_ATOMIC);

	if (page_info == NULL)
	{
		printk(KERN_ERR "%s: (register_private_page) Error allocating page info\n", MODULE_NAME);
		return NULL;
	}

	memcpy(page_info->data, page_data, PAGE_SIZE);

	atomic_set(&page_info->ref_count, 1);
	page_info->is_shared = false;
	page_info->opened = 0;

	new_hash = kmalloc(sizeof(struct page_hash_node), GFP_ATOMIC);

	if (new_hash == NULL)
	{
		printk(KERN_ERR "%s: (register_private_page) Error allocating page hash node\n", MODULE_NAME);
		kfree(page_info);
		return NULL;
	}

	new_hash->info = page_info;
	new_hash->pid = pid;
	new_hash->address = page_addr;

	AUDIT printk("%s: Adding master page %lx to the page hash table\n", MODULE_NAME, page_addr);

	hash_add_atomic(page_hash_table, &new_hash->node, pid);
	tot_num_of_pages++;

	return page_info;
}

/**
 * Adding a page to cross pages integrity hash table
 *
 * @brief - Adding a page to the cross pages integrity hash table
 * @param start - The start address within the page
 * @param flags - The flags of the page
 *
 * @return 0 on success, -1 on failure
 */
int register_page_cross_pages_integrity(unsigned long start, uint8_t flags)
{
	struct page_cross_pages_integrity_hash_node *curr = NULL;
	pid_t pid = current->tgid;
	unsigned long page_addr = start & PAGE_MASK;

	// AUDIT printk("%s: register_page_cross_pages_integrity: %lx\n", MODULE_NAME, page_addr)

	hash_for_each_possible(cross_pages_integrity_hash_table, curr, node, pid)
	{
		if (curr->address == page_addr && curr->pid == pid)
		{
			curr->flags |= flags;
			AUDIT printk(KERN_INFO "%s: (register_page_cross_pages_integrity) Page %lx already exists in the cross-pages integrity hash table %08x\n", MODULE_NAME, page_addr, curr->flags);
			return 0;
		}
	}

	curr = kmalloc(sizeof(struct page_cross_pages_integrity_hash_node), GFP_ATOMIC);

	if (curr == NULL)
	{
		printk(KERN_ERR "%s: (register_page_cross_pages_integrity) Error allocating page hash node\n", MODULE_NAME);
		return -1;
	}

	curr->address = page_addr;
	curr->pid = pid;
	curr->flags = flags;

	AUDIT printk(KERN_INFO "%s: (register_page_cross_pages_integrity) Adding page %lx to the page hash table (not opened)\n", MODULE_NAME, page_addr);

	hash_add_atomic(cross_pages_integrity_hash_table, &curr->node, pid);

	return 0;
}

/**
 * Removing a page from the page not openend to the hash table
 *
 * @brief - Removing a page from the page hash table (not opened)
 * @param start - The start address within the page
 *
 * @return 0 on success, -1 on failure
 */
int unregister_page_cross_pages_integrity(unsigned long start)
{
	struct page_cross_pages_integrity_hash_node *curr = NULL;
	struct hlist_node *tmp;
	pid_t pid = current->tgid;
	unsigned long page_addr = start & PAGE_MASK;

	hash_for_each_possible_safe(cross_pages_integrity_hash_table, curr, tmp, node, pid)
	{
		if (curr->address == page_addr && curr->pid == pid)
		{
			AUDIT printk(KERN_INFO "%s: (unregister_page_cross_pages_integrity) Removing page %lx from the page hash table (not opened)\n", MODULE_NAME, page_addr);
			hash_del_atomic(&curr->node);
			kfree(curr);
			return 0;
		}
	}

	return -1;
}

/**
 * Updating page_info struct for a shared page
 *
 * @brief - Adding a page to the page hash table
 *
 * @param page_info - The page info struct
 * @param start - The start address within the page
 *
 * @return struct page_info* - pointer to the page info struct
 */
static struct page_info *creating_shared_page_node(struct page_info *page_info, unsigned long start)
{
	struct page_hash_node *new_hash = NULL;
	pid_t pid = current->tgid;
	unsigned long page_addr = start & PAGE_MASK;

	// AUDIT printk("%s: updating_shared_page: %lx\n", MODULE_NAME, page_addr);

	if (page_info == NULL)
	{
		printk(KERN_ERR "%s: (creating_shared_page_node) page_info is NULL\n", MODULE_NAME);
		return NULL;
	}

	new_hash = kmalloc(sizeof(struct page_hash_node), GFP_ATOMIC);

	if (new_hash == NULL)
	{
		printk(KERN_ERR "%s: (creating_shared_page_node) Error allocating page hash node\n", MODULE_NAME);
		kfree(page_info);
		return NULL;
	}

	atomic_inc(&page_info->ref_count);

	new_hash->info = page_info;
	new_hash->pid = pid;
	new_hash->address = page_addr;

	AUDIT printk("%s: (creating_shared_page_node) Adding page %lx to the page hash table\n", MODULE_NAME, page_addr);

	hash_add_atomic(page_hash_table, &new_hash->node, pid);

	return page_info;
}

/**
 * Registering a shared page that has not been registered yet.
 *
 * @param address The address of the page.
 *
 * @return struct page_info* - pointer to the page info struct
 *
 */
struct page_info *page_shared_not_registered_yet(unsigned long address)
{
	unsigned long page_addr = address & PAGE_MASK;
	struct page_hash_node *curr = NULL;
	int bkt = get_shared_page_bucket(PAGE_BUCKET_BITS); // The last bucket is for shared pages. It's necessary to avoid collisions with the other pages

	/**
	 * SHARED PAGE --> A child process has been created and the page searched is SHARED.
	 *
	 * A process that is sharing the page has generated the first instruction fetch fault. The page should be already opened and checked in force_sig_fault kprober.
	 * 1) In concurrency another process that is sharing the page has generated an instruction fetch fault on the same page.
	 * 2) Another process that is sharing the page has generated an invalid opcode fault because the page contains invalid bytes. So a normal instruction fetch (faulting) has become an invalid opcode fetch.
	 **/

	AUDIT printk(KERN_INFO "%s: (page_shared_not_registered_yet) Register the shared master copy for page %lx for the process [%s] %d\n", MODULE_NAME, address & PAGE_MASK, current->comm, current->tgid);

	hlist_for_each_entry(curr, &page_hash_table[bkt], node)
	{
		if (curr->info != NULL && curr->address == page_addr) // Shared pages have the same logical address in both address spaces
		{
			printk(KERN_INFO "%s: (page_shared_not_registered_yet) found shared page %lx in the hash table for pid %d\n", MODULE_NAME, page_addr, curr->pid);

			return creating_shared_page_node(curr->info, page_addr);
		}
	}

	/**
	 * If the master copy is not found in the hash table it means that the page has not been fetched yet (see page_not_fetched_yet).
	 */
	printk(KERN_INFO "%s: (page_shared_not_registered_yet) [%s] Error finding page_info for page %lx\n", MODULE_NAME, current->comm, address & PAGE_MASK);
	return NULL;
}

#endif

// --- FPROBE insertion logic


const char *syms_ret[] = {"kernel_clone", "do_mmap", "handle_mm_fault",
							//"should_fault_around",
							
							// old kprobes
							"bprm_execve",
							"mprotect_fixup",
							"change_protection",
							"force_sig_fault",

					#ifdef DEBUG_PROBES							
							"force_sig",
					#endif

					#ifdef ZONE_KERNEL_SYNC_CHECK							
							"do_error_trap",
					#endif
							"do_task_dead",
							"filemap_map_pages"
						
						};

struct fprobe fprobe [] = {

	// OLD kretprobes
    {
        .entry_handler  = kernel_clone_handler_f,
        .exit_handler   = kernel_clone_ret_handler_f,
        .entry_data_size = sizeof(u64), 
        .nr_maxactive = 20
    },

    {
        .entry_handler  = do_mmap_handler_f,
        .exit_handler   = do_mmap_ret_handler_f,
        .entry_data_size = sizeof(struct mmap_info_f), 
        .nr_maxactive = 20
    },
    
    {
        .entry_handler  = do_fault_handler_f,
        .exit_handler   = do_fault_ret_handler_f,
        .entry_data_size = sizeof(struct addr_info_f), 
        .nr_maxactive = 20
    },
    
    // {
    //     // .entry_handler  = NULL,
    //     .exit_handler   = should_fault_around_handler_f,
    //     .nr_maxactive = 20
    // },

	// ---- OLD kprobes
	{
        .entry_handler  = exec_handler,
        // .exit_handler   = NULL,
    },

	{
        .entry_handler  = mprotect_handler,
        // .exit_handler   = NULL,
    },

	{
        .entry_handler  = change_protection_handler,
        // .exit_handler   = NULL,
    },

	{
        .entry_handler  = sig_handler,
        // .exit_handler   = NULL,
    },


#ifdef DEBUG_PROBES
	{
		.entry_handler  = sig_handler_2,
		// .exit_handler   = NULL,
	},
#endif	

#ifdef ZONE_KERNEL_SYNC_CHECK
	{
		.entry_handler  = invalid_op_handler,
		// .exit_handler   = NULL,
	},
#endif	

	{
		.entry_handler  = handle_exit,
		// .exit_handler   = NULL,
	},
	{
		.entry_handler  = filemap_handler,
		// .exit_handler   = NULL,
	}

};


int fprobe_flags[FPROBES_COUNT] = {[0 ... FPROBES_COUNT - 1] = 0};


int init_fprobes(void)
{
    int i, ret;



    for (i = 0; i < FPROBES_COUNT; i++)
	{
		ret = register_fprobe_syms(&fprobe[i],&syms_ret[i],1);
		if (ret < 0)
		{
			printk(KERN_ERR "register_fprobe %d failed, returned %d\n", i, ret);
			
			// unregister the previous fprobe
			while (--i >= 0)
				unregister_fprobe(&fprobe[i]);

			return ret;
		}
		fprobe_flags[i] = 1;
	}

	return ret;

}

void remove_fprobes(void)
{
    int i;

	for (i = 0; i < FPROBES_COUNT; i++)
	{
		if (fprobe_flags[i] == 0)
			continue;
		unregister_fprobe(&fprobe[i]);
	}
}
