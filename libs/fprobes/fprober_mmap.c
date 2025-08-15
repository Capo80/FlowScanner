/**
 * @file fprobe_mmap.c
 * @author 
 * @brief mmap callback logic
 * @version 0.1
 * @date 2025-03-20
 * 
 * @copyright Copyright (c) 2025
 * 
*/

#include "fprobes_helper.h"
#include "fprobers.h"





/**
 * @brief fprob entry handler for do_mmap
 * 
 * @param fp address of fprobe data structure
 * @param entry_ip ftrace address of the traced function
 * @param ret_ip return address that the traced function will return to
 * @param fregs registers
 * @param entry_data local storage to share the data between entry and exit handlers
 * 
 * @return int - 0 on success, 1 on failure
 */
int do_mmap_handler_f(struct fprobe *fp, unsigned long entry_ip,unsigned long ret_ip, struct pt_regs *regs,void *entry_data){

	/**
	 * The caller must write-lock current->mm->mmap_lock.
	 *
	 * unsigned long do_mmap(struct file *file, unsigned long addr,
			unsigned long len, unsigned long prot,
			unsigned long flags, vm_flags_t vm_flags,
			unsigned long pgoff, unsigned long *populate,
			struct list_head *uf)
	*/
	// struct pt_regs*	regs = &fregs->regs;
	
	struct file *file = (struct file *)regs_get_kernel_argument(regs, 0);
	unsigned long addr = (unsigned long)regs_get_kernel_argument(regs, 1);
	unsigned long len = (unsigned long)regs_get_kernel_argument(regs, 2);
	unsigned long prot = (unsigned long)regs_get_kernel_argument(regs, 3);
	unsigned long flags = (unsigned long)regs_get_kernel_argument(regs, 4);
	struct mmap_info_f *mmap_info = (struct mmap_info_f *)entry_data;

#ifndef HOOKED_PROCESS_NAME
	unsigned char found = 0;
	struct hooked_pid_node* cur;
#endif

mmap_info->name = NULL;

#ifdef HOOKED_PROCESS_NAME
	if (strstr(current->comm, HOOKED_PROCESS_NAME) == NULL)
	{
		// AUDIT printk("%s: (do_mmap_handler) process [%s] %d is excluded from the analysis\n", MODULE_NAME, current->comm, current->tgid);
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
#endif

	AUDIT printk(KERN_INFO "%s: do_mmap_handler: [%s] The process %d is mapping pages [%lx, %lx] with prot %08lx\n",
		MODULE_NAME, current->comm, current->tgid, addr, addr + len, prot);

	mmap_info->addr = addr;
	mmap_info->len = len;
	mmap_info->prot = prot;
	mmap_info->flags = flags;

	if (file == NULL) // mmapping pages that are not from a file.
	{
	// AUDIT printk(KERN_INFO "%s: (do_mmap_handler) file is NULL\n", MODULE_NAME);
	return 0;
	}

	mmap_info->name = file->f_path.dentry->d_name.name;

	return 0;

}


/**
 * @brief fprob exit handler for do_mmap
 * 
 * @param fp address of fprobe data structure
 * @param entry_ip ftrace address of the traced function
 * @param ret_ip return address that the traced function will return to
 * @param fregs registers
 * @param entry_data local storage to share the data between entry and exit handlers
 * 
 */
void do_mmap_ret_handler_f (struct fprobe *fp, unsigned long ip,
									unsigned long ret_ip, struct pt_regs *regs,
									void *data)
{
		/**
	 * The caller must write-lock current->mm->mmap_lock.
	 * unsigned long do_mmap(struct file *file, unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long pgoff, unsigned long *populate, struct list_head *uf)
	 */
	// struct pt_regs*	regs = &fregs->regs;

	unsigned long addr = (unsigned long)regs_return_value(regs);
	struct mmap_info_f *mmap_info = (struct mmap_info_f *)data;
	unsigned long page_addr = 0;
	uint8_t byte = 0;
#ifndef HOOKED_PROCESS_NAME
	unsigned char found = 0;
	struct hooked_pid_node* cur;
#endif
	int ret = 0;

	if (addr < 0)
	{
		return ;
	}

	#ifdef HOOKED_PROCESS_NAME
	if (strstr(current->comm, HOOKED_PROCESS_NAME) == NULL)
	{
		// AUDIT printk("%s: (do_mmap_ret_handler) process [%s] %d is excluded from the analysis\n", MODULE_NAME, current->comm, current->tgid);
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

	/* Careful about overflows.. */
	mmap_info->len = PAGE_ALIGN(mmap_info->len);

	if (mmap_info->name != NULL)
	{
		// printk(KERN_INFO "%s: do_mmap_ret_handler: [%s] The process %d is mapping pages [%lx, %lx] from file %s with prot %08lx\n",
		// 	   MODULE_NAME, current->comm, current->tgid, addr, addr + mmap_info->len, mmap_info->name, mmap_info->prot);
	}

	else if (mmap_info->name == NULL && mmap_info->flags & MAP_ANONYMOUS)
	{
		// printk(KERN_INFO "%s: do_mmap_ret_handler: [%s] The process %d is mapping anonymous pages [%lx, %lx] with prot %08lx\n",
		// 	   MODULE_NAME, current->comm, current->tgid, addr, addr + mmap_info->len, mmap_info->prot);

		goto handle_anonymous;
	}

#ifdef EXCLUDE_SHARED_LIBRARIES
	if (strstr(mmap_info->name, ".so") != NULL)
	{
		AUDIT printk(KERN_INFO "%s: (do_mmap_ret_handler) The file %s is skipped by the checks\n", MODULE_NAME, mmap_info->name);
		return ;
	}
#endif

#ifdef EXCLUDE_SCRIPT_INTERPRETERS
	int i = 0;
	for (i = 0; i < TOTAL_INTERPRETERS; i++) {
	      if (strstr(mmap_info->name, interpreters[i]) != NULL)
	      {
		      AUDIT printk(KERN_INFO "%s: (do_mmap_ret_handler) The file %s is skipped by the checks\n", MODULE_NAME, mmap_info->name);
		      return ;
	      }
	}
#endif

handle_anonymous:

// TODO: the sleeping kprobe see if preemption is needed

	if ((mmap_info->prot & PROT_EXEC))
	{
		DELETE_ME pr_info("preempt: %d\n", preempt_count() );
		preempt_enable_notrace();
		preempt_enable_notrace();
		DELETE_ME pr_info("preempt: %d\n", preempt_count() );
		/* mmap_write_unlock(current->mm); // Let's unlock the mmap_lock to avoid a deadlock */
		for (page_addr = addr; page_addr < addr + mmap_info->len; page_addr += PAGE_SIZE)
		{
			
			ret = get_user_pages(page_addr, 1, FOLL_FORCE, NULL);
			/* ret = copy_from_user(&byte, (void *)page_addr, 1); // Forcing PTE lazy mapping */
			DELETE_ME printk(KERN_INFO "%s: do_mmap_ret_handler: [%s] pid %d is mapping %lx (%ld - %ld), ret %d\n", MODULE_NAME, current->comm, current->tgid, page_addr, (mmap_info->prot & PROT_EXEC), (mmap_info->prot & PROT_WRITE), ret);

			if (flip_bit(page_addr, EXE_DENY_BIT, 1) == NO_MAP)
				printk(KERN_ERR "%s: (do_mmap_ret_handler) Error flipping EXE_DENY_BIT for page %lx\n", MODULE_NAME, page_addr);
			else
			{
				AUDIT printk(KERN_INFO "%s: (do_mmap_ret_handler) EXE_DENY_BIT for page %lx is flipped\n", MODULE_NAME, page_addr);

				flip_bit(page_addr, ORIG_EXE_BIT, 1); // It's an X page
				flip_bit(page_addr, CHECK_DENY_BIT, 0); // The page is not checked here
			}

		}

		flush_tlb_mm_range_func(current->mm, addr, addr + mmap_info->len, PAGE_SHIFT, false);
		preempt_disable_notrace();
 		preempt_disable_notrace();
		/* mmap_write_lock(current->mm); // Let's relock the mmap_lock that will be unlocked by the caller */
	}


 // TODO: the sleeping kprobe see if preemption is needed

 
}
