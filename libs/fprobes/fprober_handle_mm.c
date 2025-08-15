/**
 * @file fprober_handle_mm.c
 * @author 
 * @brief 
 * @version 0.1
 * @date 2025-03-20
 * 
 * @copyright Copyright (c) 2025
 * 
 */

#include "fprobes_helper.h"
#include "fprobers.h"
#include "../utils.h"

// pass mmap information



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
int do_fault_handler_f(struct fprobe *fp, unsigned long entry_ip,unsigned long ret_ip, struct pt_regs *regs,void *data)
{
    /**
 * (handle_mm_fault) The mmap_lock may have been released depending on flags and our
 * return value.
 * vma->vm_mm->mmap_lock must be held on entry.
 * If we need to retry the mmap_lock has already been released,
 * and if there is a fatal signal pending there is no guarantee
 * that we made any progress. --> mmap_locked = 0
 *
 * vm_fault_t handle_mm_fault(struct vm_area_struct *vma, unsigned long address, unsigned int flags, struct pt_regs *regs);
 */
	// struct pt_regs*	regs = &fregs->regs;

    #if LINUX_VERSION_CODE < KERNEL_VERSION(4, 20, 0)
    struct vm_area_struct *vma = (struct vm_area_struct *)regs_get_register(regs, offsetof(struct pt_regs, di)); // first argument
    unsigned long address = (unsigned long)regs_get_register(regs, offsetof(struct pt_regs, si));				 // second argument
    unsigned int flags = (unsigned int)regs_get_register(regs, offsetof(struct pt_regs, dx));					 // third argument
    #else
    struct vm_area_struct *vma = (struct vm_area_struct *)regs_get_kernel_argument(regs, 0); // It's mapped
    unsigned long address = (unsigned long)regs_get_kernel_argument(regs, 1);
    unsigned int flags = (unsigned int)regs_get_kernel_argument(regs, 2);
    #endif

    struct addr_info_f *addr_info = (struct addr_info_f *)data;

#ifndef HOOKED_PROCESS_NAME
	unsigned char found = 0;
	struct hooked_pid_node* cur;
#endif
	addr_info->addr = 0;

	if (vma == NULL)
	{
		printk(KERN_ERR "%s: (do_fault_handler) vma is NULL\n", MODULE_NAME);
		return 0;
	}

	if (current->tgid == 1)
	{
		AUDIT printk("%s: (do_fault_handler) process %d is excluded\n", MODULE_NAME, current->tgid);
		return 0;
	}

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
#endif
	// Check if the vm area is mapped to a file: Both code and shared libraries are mapped to a file
	if (vma->vm_file == NULL)
	{
		AUDIT printk(KERN_INFO "%s: (do_fault_handler) The vm area is not mapped to a file\n", MODULE_NAME);
		goto handle_no_file_mapping;
	}

#ifdef EXCLUDE_SHARED_LIBRARIES
	if (strstr(vma->vm_file->f_path.dentry->d_name.name, ".so") != NULL)
	{
		AUDIT printk(KERN_CRIT "%s: (do_fault_handler) The file %s is skipped by the checks\n", MODULE_NAME, vma->vm_file->f_path.dentry->d_name.name);
		return 0;
	}
#endif

#ifdef EXCLUDE_SCRIPT_INTERPRETERS
	int i = 0;
	for (i = 0; i < TOTAL_INTERPRETERS; i++) {
	      if (strstr(vma->vm_file->f_path.dentry->d_name.name, interpreters[i]) != NULL)
	      {
		      AUDIT printk(KERN_INFO "%s: (do_mmap_ret_handler) The file %s is skipped by the checks\n", MODULE_NAME, vma->vm_file->f_path.dentry->d_name.name);
		      return 0;
	      }
	}
#endif
handle_no_file_mapping:

	/**
	 * If the page accessed is mapped in the PTE, in the handler we set the info for the kretprobe handler.
	 * After the handle_mm_fault the PTE can be changed by the kernel, so we need to set the info before the handle_mm_fault.
	 */

	addr_info->pte = get_page_table_entry(address & PAGE_MASK);

	DEBUG_INFO printk(KERN_INFO "%s: (do_fault_handler) pid %d [%s] is accessing page %lx with flags %08lx, pteval is %08lx\n", MODULE_NAME, current->tgid, current->comm, address & PAGE_MASK, vma->vm_flags, addr_info->pte);

	if (vma->vm_flags & VM_EXEC || ((vma->vm_flags & VM_WRITE) && (flags & FAULT_FLAG_WRITE) && test_bit(ORIG_WRITE_BIT, &addr_info->pte)))
	{
		addr_info->vma = vma;
		addr_info->addr = address;
		addr_info->flags = flags;

		/**
		 * It's not an error, KERN_CRIT has been used to highlight the name of the file
		 */
		if (vma->vm_file != NULL)
		{
			DEBUG_INFO printk(KERN_CRIT "%s: (do_fault_handler) file name associated to the (EXE) VM area at address %lx is %s with vm_flags %08lx\n", MODULE_NAME, address, vma->vm_file->f_path.dentry->d_name.name, vma->vm_flags);
		}
		else
		{
			DEBUG_INFO printk(KERN_CRIT "%s: (do_fault_handler) file name associated to the (EXE) VM area at address %lx is not mapped to a file with vm_flags %08lx\n", MODULE_NAME, address, vma->vm_flags);
		}
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
void do_fault_ret_handler_f (struct fprobe *fp, unsigned long ip,
    unsigned long ret_ip, struct pt_regs *regs,
    void *data)

{
    /**
	 * (handle_mm_fault) The mmap_lock may have been released depending on flags and our
	 * return value.
	 * vma->vm_mm->mmap_lock must be held on entry.
	 * If we need to retry the mmap_lock has already been released,
	 * and if there is a fatal signal pending there is no guarantee
	 * that we made any progress. --> mmap_locked = 0
	 *
	 * vm_fault_t handle_mm_fault(struct vm_area_struct *vma, unsigned long address, unsigned int flags, struct pt_regs *regs);
	 */
	// struct pt_regs*	regs = &fregs->regs;
	struct addr_info_f *addr_info = (struct addr_info_f *)data;
	unsigned long pte = addr_info->pte;
	struct vm_area_struct *vma = addr_info->vma;
	unsigned long addr = addr_info->addr;
	unsigned int flags = addr_info->flags;
	vm_fault_t retval = (vm_fault_t)regs_return_value(regs);
	bool mmap_locked = 0;
	pid_t pid = current->tgid;
	bool orig_write_bit = 0;
	bool check_deny_bit = 0;
	spinlock_t* pte_lock;
	int ret = 0;


	if (addr == 0) // If addr is 0 the page is not executable
	{
		// AUDIT printk(KERN_INFO "%s: (do_fault_ret_handler) The page is not executable\n", MODULE_NAME);
		return ;
	}

	DELETE_ME printk("%s: do_fault_ret_handler: %lx\n", MODULE_NAME, addr);

	if (unlikely(retval & VM_FAULT_ERROR))
	{
		printk(KERN_INFO "%s: (do_fault_ret_handler) VM_FAULT_ERROR for page %lx and pid %d (%s)\n", MODULE_NAME, addr & PAGE_MASK, pid, current->comm);
		return ;
	}

	if (unlikely((retval & VM_FAULT_RETRY)))
	{
		/**
		 * If our return value has VM_FAULT_RETRY set, it's because the mmap_lock
		 * may be dropped before doing I/O or by lock_page_maybe_drop_mmap().*/

		printk(KERN_INFO "%s: (do_fault_ret_handler) VM_FAULT_RETRY for page %lx and pid %d (%s)\n", MODULE_NAME, addr & PAGE_MASK, pid, current->comm);

		if (unlikely(flags & FAULT_FLAG_ALLOW_RETRY)) // It will retry to manage the fault
		{
			DEBUG_INFO printk(KERN_INFO "%s: (do_fault_ret_handler) FAULT_FLAG_ALLOW_RETRY for page %lx and pid %d (%s)\n", MODULE_NAME, addr & PAGE_MASK, pid, current->comm);
		}

		mmap_locked = 0;
		return ;
	}
	/**
	 * If our return value does not have VM_FAULT_RETRY set, the mmap_lock
	 * has not been released.
	 */
	else
		mmap_locked = 1; //If we continue the execution, the mmap_lock has not been released

	AUDIT printk(KERN_CRIT "%s: (do_fault_ret_handler) pid %d (%d) [%s] is accessing page %lx with flags %08x and retval = %08x\n", MODULE_NAME, pid, current->pid, current->comm, addr & PAGE_MASK, flags, retval);

	if (!(flags & FAULT_FLAG_WRITE) && !(retval & VM_FAULT_NOPAGE)) // Only the materialization of the page or a write fault are handled
	{
		AUDIT printk(KERN_INFO "%s: (do_fault_ret_handler) The fault on %lx is neither a materialization nor a writing \n", MODULE_NAME, addr & PAGE_MASK);
		return ;
	}

	/**
	 * VM_FAULT_WRITE:		Special case for get_user_pages
	 */
	// if (retval & VM_FAULT_WRITE && !(flags & FAULT_FLAG_USER))
	// {
	// 	// AUDIT printk(KERN_INFO "%s: (do_fault_ret_handler) get_user_pages invoked for page %lx and pid %d (%d) (%s), pteval is %08lx\n", MODULE_NAME, addr & PAGE_MASK, pid, current->pid, current->comm, pte);
	// 	// return 0;
	// }

    // TODO: the sleeping kprobe see if preemption is needed
    // if (pte != 0) // If the page is already mapped
	// {
	// 	orig_write_bit = test_bit(ORIG_WRITE_BIT, &pte);
	// 	check_deny_bit = test_bit(CHECK_DENY_BIT, &pte);
	// }

	pte_lock = get_pte_lock(current->mm, addr);

	if ((vma->vm_flags & VM_EXEC) && (vma->vm_flags & VM_WRITE)) // WX PAGE
	{
		AUDIT printk(KERN_INFO "%s: (do_fault_ret_handler) WX page for %d (%s) at %lx and retval = %08x\n", MODULE_NAME, pid, current->comm, addr & PAGE_MASK, retval);

		spin_lock(pte_lock);	
		// read pt bits after page table lock
		if (pte != 0) // If the page is already mapped
		{
			orig_write_bit = test_bit(ORIG_WRITE_BIT, &pte);
			check_deny_bit = test_bit(CHECK_DENY_BIT, &pte);
		}

		if ((flags & FAULT_FLAG_WRITE) && orig_write_bit) // write fault (caused by our system) on a WX page
		{
			SHARED_DEBUG printk(KERN_INFO "%s: (do_fault_ret_handler) A write fault on the WX page %lx has happened\n", MODULE_NAME, addr & PAGE_MASK);
#ifdef ZONE_KERNEL_SYNC_CHECK
			/**
			 * The page has been checked so it's was modified with invalid op-code byte
			 * However, if the page is shared, the check_deny_bit could be 0 because the page has been checked by another process.
			 */
			if (check_deny_bit) // The page has been checked by the current process
			{
				// Restore the original page
				printk(KERN_INFO "%s: (do_fault_ret_handler) Restoring page %lx\n", MODULE_NAME, addr & PAGE_MASK);

				ret = restore_page(addr);

				if (ret == PAGE_NOT_FOUND)
					printk(KERN_ERR "%s: (do_fault_ret_handler) page %lx not found\n", MODULE_NAME, addr & PAGE_MASK);
				else if (ret == WRITE_ERROR)
					printk(KERN_ERR "%s: (do_fault_ret_handler) error restoring page %lx\n", MODULE_NAME, addr & PAGE_MASK);
				else if (ret == PAGE_FOUND)
					AUDIT printk(KERN_INFO "%s: (do_fault_ret_handler) page %lx just restored\n", MODULE_NAME, addr & PAGE_MASK);
			}
			else if ((vma->vm_flags & VM_SHARED)) // The shared page has been checked by another process
			{
				printk(KERN_INFO "%s: (do_fault_ret_handler) The page %lx is shared and has been checked by another process\n", MODULE_NAME, addr & PAGE_MASK);

				ret = restore_sh_page(addr);

				if (ret == PAGE_NOT_FOUND)
					printk(KERN_ERR "%s: (do_fault_ret_handler) shared page %lx not found\n", MODULE_NAME, addr & PAGE_MASK);
				else if (ret == WRITE_ERROR)
					printk(KERN_ERR "%s: (do_fault_ret_handler) error restoring shared page %lx\n", MODULE_NAME, addr & PAGE_MASK);
				else if (ret == PAGE_FOUND)
					AUDIT printk(KERN_INFO "%s: (do_fault_ret_handler) shared page %lx just restored\n", MODULE_NAME, addr & PAGE_MASK);
			}

#endif
			flip_bit((addr & PAGE_MASK), WRITE_BIT, 1); // Allow write
			shared_flip_bit(vma, (addr & PAGE_MASK), WRITE_BIT, 1);

		}

		flip_bit((addr & PAGE_MASK), ORIG_EXE_BIT, 1);
		flip_bit((addr & PAGE_MASK), EXE_DENY_BIT, 1); // Deny execution
		shared_flip_bit(vma, (addr & PAGE_MASK), EXE_DENY_BIT, 1);

		/**
		 * If the page will generate an IF fault, it should be checked again.
		 */
		flip_bit((addr & PAGE_MASK), CHECK_DENY_BIT, 0);

		spin_unlock(pte_lock);
	}

	else if ((vma->vm_flags & VM_EXEC) && !(vma->vm_flags & VM_WRITE)) // EXE page materialization
	{
		DEBUG_INFO printk(KERN_INFO "%s: (do_fault_ret_handler) Only EXE page (%lx) materialized for %d (%s) at %lx and retval = %08x\n", MODULE_NAME, (addr & PAGE_MASK), pid, current->comm, addr, retval);
		spin_lock(pte_lock);

		flip_bit((addr & PAGE_MASK), ORIG_EXE_BIT, 1);
		flip_bit((addr & PAGE_MASK), EXE_DENY_BIT, 1); // Deny execution
		flip_bit((addr & PAGE_MASK), CHECK_DENY_BIT, 0);
		shared_flip_bit(vma, (addr & PAGE_MASK), EXE_DENY_BIT, 1); // do it for the shared (if they exist)
		
		spin_unlock(pte_lock);
	}

	/** the page was only executable and then it became write-only */
	else if ((vma->vm_flags & VM_WRITE) && (flags & FAULT_FLAG_WRITE) && orig_write_bit)
	{
		spin_lock(pte_lock);	
		// read pt bits after page table lock
		if (pte != 0) // If the page is already mapped
		{
			orig_write_bit = test_bit(ORIG_WRITE_BIT, &pte);
			check_deny_bit = test_bit(CHECK_DENY_BIT, &pte);
		}


		if (orig_write_bit) {
			SHARED_DEBUG printk(KERN_INFO "%s: (do_fault_ret_handler) A write fault on the W page %lx that was X has happened\n", MODULE_NAME, addr & PAGE_MASK);

	#ifdef ZONE_KERNEL_SYNC_CHECK
			/**
			 * The page has been checked so it's was modified with invalid op-code byte
			 * However, if the page is shared, the check_deny_bit could be 0 because the page has been checked by another process.
			 */
			if (check_deny_bit) // The page has been checked by the current process
			{
				// Restore the original page
				printk(KERN_INFO "%s: (do_fault_ret_handler) Restoring page %lx\n", MODULE_NAME, addr & PAGE_MASK);

				ret = restore_page(addr);

				if (ret == PAGE_NOT_FOUND)
					printk(KERN_ERR "%s: (do_fault_ret_handler) page %lx not found\n", MODULE_NAME, addr & PAGE_MASK);
				else if (ret == WRITE_ERROR)
					printk(KERN_ERR "%s: (do_fault_ret_handler) error restoring page %lx\n", MODULE_NAME, addr & PAGE_MASK);
				else if (ret == PAGE_FOUND)
					AUDIT printk(KERN_INFO "%s: (do_fault_ret_handler) page %lx just restored\n", MODULE_NAME, addr & PAGE_MASK);
			}
			else if ((vma->vm_flags & VM_SHARED)) // The shared page has been checked by another process
			{
				printk(KERN_INFO "%s: (do_fault_ret_handler) The page %lx is shared and has been checked by another process\n", MODULE_NAME, addr & PAGE_MASK);

				ret = restore_sh_page(addr);

				if (ret == PAGE_NOT_FOUND)
					printk(KERN_ERR "%s: (do_fault_ret_handler) shared page %lx not found\n", MODULE_NAME, addr & PAGE_MASK);
				else if (ret == WRITE_ERROR)
					printk(KERN_ERR "%s: (do_fault_ret_handler) error restoring shared page %lx\n", MODULE_NAME, addr & PAGE_MASK);
				else if (ret == PAGE_FOUND)
					AUDIT printk(KERN_INFO "%s: (do_fault_ret_handler) shared page %lx just restored\n", MODULE_NAME, addr & PAGE_MASK);
			}
	#endif

			flip_bit((addr & PAGE_MASK), WRITE_BIT, 1); // Allow write
			shared_flip_bit(vma, (addr & PAGE_MASK), WRITE_BIT, 1);

			/** The page-fault handling set WE_CHECK_DENY_BIT to 0.*/
			flip_bit((addr & PAGE_MASK), CHECK_DENY_BIT, 0); // If the page will became executable again, it should be checked
		}

		spin_unlock(pte_lock);
	}

	if (!thread_group_empty(current))
		on_each_cpu((smp_call_func_t)__flush_tlb_one_user, (void *)(addr & PAGE_MASK), true);
	else
		on_each_cpu((smp_call_func_t)__flush_tlb_one_user, (void *)(addr & PAGE_MASK), false);

    // TODO: the sleeping kprobe see if preemption is needed

}

