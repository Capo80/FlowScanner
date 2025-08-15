/**
 * @file fprober_proc_mngmt.c
 * @author 
 * @brief kernel clone callbacks logic
 * @version 0.1
 * @date 2025-03-20
 * 
 * @copyright Copyright (c) 2025
 * 
*/

#include "fprobes_helper.h"
#include "fprobers.h"
#include "../hlist_lock_free.h"

#include <linux/binfmts.h>


static void add_shared_to_hash(struct mm_struct* mm) {

	/* int bkt = 0; */
    /* struct hlist_node *tmp = NULL; */
    struct shared_map_hash_node *curr = NULL;
	struct vm_area_struct* vma;
	struct vm_area_struct* shared_vma = NULL;
    struct inode *inode = NULL;
	struct address_space *mapping = NULL;
	struct page_table_node* pt_node = NULL; 
    struct rb_node *node = NULL;
	VMA_ITERATOR(iter, mm, 0);


	//mmap_read_lock(mm);
	for_each_vma(iter, vma) {

		if (vma->vm_flags & VM_SHARED) {

			SHARED_DEBUG printk("(kernel_clone_ret_handler/add_shared_to_hash) process (%d) found shared mapping, vma = %lx, start = %lx, pgd=%lx\n", current->pid, (unsigned long) vma, (unsigned long) vma->vm_start, (unsigned long) mm->pgd);
			SHARED_DEBUG printk("(clone/add_shared) vm_file = %lx\n", (unsigned long) vma->vm_file);


            hash_for_each_possible(shared_map_hash, curr, node, (unsigned long)vma)
            {
				SHARED_DEBUG printk(KERN_ERR "(clone/add_shared) mapping already saved"); // should never happen
				continue;
			}

			// create its own node
			curr = kmalloc(sizeof(struct shared_map_hash_node), GFP_ATOMIC);
			INIT_LIST_HEAD(&curr->page_tables);
			pt_node = kmalloc(sizeof(struct page_table_node), GFP_ATOMIC);
			pt_node->pgd = vma->vm_mm->pgd;
			list_add_tail(&pt_node->node, &curr->page_tables);
			hash_add_atomic(shared_map_hash, &curr->node, (unsigned long) vma);
			SHARED_DEBUG printk("(clone/add_shared) new shared saved");


			if (!vma->vm_file) { // should not happed - shared areas are always mapped
				SHARED_DEBUG printk(KERN_ERR "VMA does not have an associated file\n");
				continue;
			}


			// add all other shared vma to the pt list
    		inode = vma->vm_file->f_inode;	
			mapping = inode->i_mapping;		
			for (node = rb_first(&mapping->i_mmap.rb_root); node; node = rb_next(node)) {
				shared_vma = rb_entry(node, struct vm_area_struct, shared.rb);
				if (shared_vma->vm_flags & VM_SHARED) {
					if (shared_vma != vma) {
						// SHARED_DEBUG printk("(clone/add_shared) Addded shared VMA to pt: vma = %lx, start = 0x%lx, end = 0x%lx, pid = %d\n", (unsigned long) shared_vma,
						// 	shared_vma->vm_start, shared_vma->vm_end, shared_vma->vm_mm->owner->pid);
						SHARED_DEBUG printk("(clone/add_shared) Added PT %lx\n", (unsigned long) shared_vma->vm_mm->pgd);
						SHARED_DEBUG printk("(clone/add_shared) Own %lx\n", (unsigned long) vma->vm_mm->pgd);
						pt_node = kmalloc(sizeof(struct page_table_node), GFP_ATOMIC);
						pt_node->pgd = shared_vma->vm_mm->pgd;
						list_add_tail(&pt_node->node, &curr->page_tables);
	
					}
				}
    		}

		}
	}
	//mmap_read_unlock(mm);
}

/**
 * @brief 
 * 
 * @param fp address of fprobe data structure
 * @param entry_ip ftrace address of the traced function
 * @param ret_ip return address that the traced function will return to
 * @param fregs registers
 * @param data local storage to share the data between entry and exit handlers
 * @return int - 0 on success, 1 on failure 
 */
int kernel_clone_handler_f(struct fprobe *fp, unsigned long entry_ip,unsigned long ret_ip, struct pt_regs *regs,void *data)
{
    /**
	 * pid_t kernel_clone(struct kernel_clone_args *args)
	 */
	// struct pt_regs*	regs = &fregs->regs;

	struct kernel_clone_args *args = (struct kernel_clone_args *)regs_get_kernel_argument(regs, 0);
    *((u64 *)(data)) = args->flags;
#ifdef HOOKED_PROCESS_NAME
	if (strstr(current->comm, HOOKED_PROCESS_NAME) == NULL)
	{
		// AUDIT printk("%s: (kernel_clone_handler) process [%s] %d is excluded from the analysis\n", MODULE_NAME, current->comm, current->tgid);
		return 0;
	}
#else
	// TODO handle hooked_list for shared memory
	return 0;
#endif

    if (likely(args->flags & CLONE_THREAD)) // Same thread group
	{
		AUDIT printk("%s: kernel_clone_handler: The process %s invoked kernel_clone (__clone()) with pid %d and flags %08llx\n", MODULE_NAME, current->comm, current->tgid, args->flags);
	}
	else
	{
		AUDIT printk("%s: kernel_clone_handler: The process %s invoked kernel_clone (fork ()) with pid %d and flags %08llx\n", MODULE_NAME, current->comm, current->tgid, args->flags);

	}
	
	return 0;


}


/**
 * @brief 
 * 
 * @param fp address of fprobe data structure
 * @param entry_ip ftrace address of the traced function
 * @param ret_ip return address that the traced function will return to
 * @param fregs registers
 * @param data local storage to share the data between entry and exit handlers
 */
void kernel_clone_ret_handler_f (struct fprobe *fp, unsigned long ip,
    unsigned long ret_ip, struct pt_regs *regs,
    void *data)

{
    /**
	 * pid_t kernel_clone(struct kernel_clone_args *args)
	*/

    // struct pt_regs*	regs = &fregs->regs;

	u64 flags = *((u64 *)(data));
	pid_t child_pid = regs_return_value(regs);
	pid_t parent_pid = current->tgid;
	struct pid *pid_struct = find_get_pid(child_pid);
	struct task_struct *child_task = pid_task(pid_struct, PIDTYPE_PID);
#ifndef HOOKED_PROCESS_NAME
	unsigned char found = 0;
	struct hooked_pid_node* cur;
#endif
	if (child_pid < 0)
	{
		
		return ;
	}

#ifdef HOOKED_PROCESS_NAME
	if (strstr(current->comm, HOOKED_PROCESS_NAME) == NULL)
	{
		// AUDIT printk("%s: (kernel_clone_ret_handler) process [%s] %d is excluded from the analysis\n", MODULE_NAME, current->comm, current->tgid);
		return ;
	}
#else
	hash_for_each_possible(hooked_pids, cur, node, current->pid) {
		if (cur->pid == current->pid) {
			found = 1;
			break;
		}
	}
	if (!found)
		return ;
#endif

#ifdef SHARED_DEFENCE

	//SHARED_DEBUG printk("%s: (kernel_clone_ret_handler) process [%s] completed clone (%d -> %d) \n", MODULE_NAME, current->comm, current->tgid, current->pid, child_pid);
	
	// look for shared pages
	add_shared_to_hash(current->mm);
	add_shared_to_hash(child_task->mm);
#endif

	if (!(flags & CLONE_THREAD))
	{
		/**
		 * The pages inherited from the parent process in the child one are set as non-executable (if they are private) and non-writable (if they are shared).
		*/
		set_all_sh_pages_non_writable(child_task);
	}

	SHARED_DEBUG printk("%s: kernel_clone_ret_handler: kernel_clone ended successfully. [%s] ppid is %d, [%s] child tgid %d - pid %d and original flags are %08llx\n", MODULE_NAME, current->comm, parent_pid, child_task->comm, child_task->tgid, child_pid, flags);

	return ;

}

int exec_handler(struct fprobe *fp, unsigned long entry_ip,unsigned long ret_ip, struct pt_regs *regs,void *data)
{
	/**
	 *int bprm_execve(struct linux_binprm *bprm)
	 */

	struct linux_binprm *bprm = (struct linux_binprm *)regs_get_kernel_argument(regs, 0);
	const char *executable_name = NULL;
#ifndef HOOKED_PROCESS_NAME
	unsigned char found;
	int i;
	struct hooked_pid_node* new_hash;
#endif

	if (bprm->filename == NULL)
	{
		/* printk(KERN_ERR "%s: (exec_handler) filename is NULL\n", MODULE_NAME); */
		return 0;
	}

	/* executable_name = get_basename(filename->name); */
	executable_name = bprm->filename;
	DELETE_ME printk("bprm: %s\n", executable_name);
#ifdef HOOKED_PROCESS_NAME
	if (strstr(executable_name, HOOKED_PROCESS_NAME) == NULL)
	{
		AUDIT printk("%s: (exec_handler) process [%s] %d is excluded from the analysis\n", MODULE_NAME, current->comm, current->tgid);
		return 0;
	}
#else
	found = 0;
	for (i = 0; i < TOTAL_HOOKED; i++) {
		if (strstr(executable_name, hooked_list[i]) != NULL) {
			found = 1;
			new_hash = kmalloc(sizeof(struct hooked_pid_node), GFP_KERNEL);
			new_hash->pid = current->pid;
			new_hash->open_start = 0;
			new_hash->open_end = 0;
			hash_add(hooked_pids, &new_hash->node, current->pid);
		}
	}
	if (!found) {
		
		/* DELETE_ME printk("%s: (exec_handler) process [%s] %d is excluded from the analysis\n", MODULE_NAME, current->comm, current->tgid); */

		return 0;
	}
#endif

	finished = false;
	started = true;

	AUDIT printk("%s: exec_handler: [%s] pid %d is executing %s\n", MODULE_NAME, current->comm, current->tgid, executable_name);

	return 0;
}

void shared_pages_cleaner(struct work_struct *work);
DECLARE_DELAYED_WORK(shared_cleaner, shared_pages_cleaner);

void shared_pages_cleaner(struct work_struct *work)
{
	struct page_hash_node *curr = NULL;
	int bkt = get_shared_page_bucket(PAGE_BUCKET_BITS);
	struct hlist_node *tmp = NULL;

	/**
	 * If the process is the last one that uses a shared page, then the page_info is freed.
	 * We are implementing a TTL for the shared pages, if a page is not accessed for a while, then it is freed.
	 */

	hlist_for_each_entry_safe(curr, tmp, &page_hash_table[bkt], node)
	{
		if (curr->info != NULL && atomic_read(&curr->info->ref_count) == 0)
		{
			AUDIT printk(KERN_INFO "%s: Freeing page_info for shared page %lx\n", MODULE_NAME, curr->address);
			hash_del(&curr->node);
			kfree(curr->info);
			kfree(curr);
		}
	}
}
/**
 * The function frees the memory allocated for the page hash table.
 * @return void
 */

int cleanup_process(void *data)
{
	pid_t pid = *(pid_t *)data;
	struct page_hash_node *curr = NULL;
	bool at_least_one_shared_page = false;

#ifdef ZONE_KERNEL_SYNC_CHECK

	struct page_cross_pages_integrity_hash_node *cross_pages_curr = NULL;
#endif
	struct hlist_node *tmp;

	AUDIT printk(KERN_INFO "%s: Cleaning up process %d\n", MODULE_NAME, pid);

	if (page_hash_table != NULL)
	{
		hash_for_each_possible_safe(page_hash_table, curr, tmp, node, pid)
		{
			if (curr->pid == pid)
			{
				hash_del(&curr->node);

				if (curr->info != NULL)
				{

					if (!curr->info->is_shared) // Should be equal to curr->info->ref_count == 1
					{
						AUDIT printk("%s: Freeing page_info %lx\n", MODULE_NAME, curr->address);
						kfree(curr->info);
					}
					else
					{
						AUDIT printk("%s: Decreasing ref_count of shared page %lx, current value is %d\n", MODULE_NAME, curr->address, atomic_read(&curr->info->ref_count));
						at_least_one_shared_page = true;
						atomic_dec(&curr->info->ref_count); // There are other processes that share the page
					}
				}

				kfree(curr);
				tot_num_of_pages--;
			}
		}

		// The process has decremented the ref_count of a shared page, so we need to check if we can free the page_info
		if (at_least_one_shared_page)
			schedule_delayed_work(&shared_cleaner, msecs_to_jiffies(1000));
	}

#ifdef ZONE_KERNEL_SYNC_CHECK
	if (cross_pages_integrity_hash_table != NULL)
	{
		hash_for_each_possible_safe(cross_pages_integrity_hash_table, cross_pages_curr, tmp, node, pid)
		{
			if (cross_pages_curr->pid == pid)
			{
				// printk("%s: %lx\n", MODULE_NAME, cross_pages_curr->address);
				hash_del(&cross_pages_curr->node);
				kfree(cross_pages_curr);
			}
		}
	}
#endif

	return 0;
}


int handle_exit(struct fprobe *fp, unsigned long entry_ip,unsigned long ret_ip, struct pt_regs *regs,void *data)
{
	struct task_struct *task = current;
	pid_t pid = current->pid;
#ifdef ZONE_KERNEL_SYNC_CHECK
	struct task_struct *cleanup_task = NULL;
#endif
#ifndef HOOKED_PROCESS_NAME
	unsigned char found = 0;
	struct hooked_pid_node* cur;
#endif

#ifdef HOOKED_PROCESS_NAME
	if (strstr(current->comm, HOOKED_PROCESS_NAME) == NULL)
	{
		// AUDIT printk("%s: (do_fault_handler) process [%s] %d is excluded from the analysis\n", MODULE_NAME, current->comm, current->tgid);
		return 0;
	}
#else
	hash_for_each_possible(hooked_pids, cur, node, current->pid) {
		if (cur->pid == current->pid) {
			found = 1;
			break;
		}
	}
	if (!found)
		return 0;

	hash_del(&cur->node);
	kfree(cur);
#endif

	if (!task || (READ_ONCE(task->exit_state) && thread_group_empty(task)))
	{
		if (!(task->flags & PF_KTHREAD))
		{ // It's an user process
			AUDIT printk("%s: LWP %d with PID %d is terminating with exit code %d \n", MODULE_NAME, pid, current->tgid, task->exit_code);

#ifdef ZONE_KERNEL_SYNC_CHECK
			/* cleanup_task = kthread_run(cleanup_process, &current->tgid, "cleanup_process"); */
			/* if (IS_ERR(cleanup_task)) */
			/* { */
			/* 	printk(KERN_ERR "%s: Cannot create cleanup_process thread\n", MODULE_NAME); */
			/* } */
#endif
			AUDIT printk("%s: handle_exit: [%s] LWP %d with PID %d, page checked are %d, zone checked are %d, num_of_cow_pages is %ld\n", MODULE_NAME, current->comm, pid, current->tgid, page_checked, zone_checked, num_of_cow_pages);

			finished = true;
		}
	}

	return 0;
}
