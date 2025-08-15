/**
 * @file fprobe_change_prot.c
 * @author 
 * @brief 
 * @version 0.1
 * @date 2025-04-04
 * 
 * @copyright Copyright (c) 2025
 * 
 */

#include "asm/pgtable_types.h"
#include "fprobes_helper.h"
#include "fprobers.h"
#include <linux/hugetlb.h>



/**
 * @brief fprob entry handler
 * 
 * @param fp address of fprobe data structure
 * @param entry_ip ftrace address of the traced function
 * @param ret_ip return address that the traced function will return to
 * @param fregs registers
 * @param entry_data local storage to share the data between entry and exit handlers
 * 
 * @return int - 0 on success, 1 on failure
 */
int mprotect_handler(struct fprobe *fp, unsigned long entry_ip,unsigned long ret_ip, struct pt_regs *regs,void *entry_data)
{
	/**
	 * int mprotect_fixup(struct vma_iterator *vmi, struct mmu_gather *tlb,
			struct vm_area_struct *vma, struct vm_area_struct **pprev,
	  unsigned long start, unsigned long end, unsigned long newflags);
	 */

	struct vm_area_struct *vma = (struct vm_area_struct *)regs_get_kernel_argument(regs, 2);
	unsigned long start = (unsigned long)regs_get_kernel_argument(regs, 4);
	unsigned long end = (unsigned long)regs_get_kernel_argument(regs, 5);
	unsigned long newflags = (unsigned long)regs_get_kernel_argument(regs, 6);

	int was_executable = vma->vm_flags & VM_EXEC;
	int is_writable = newflags & VM_WRITE;
	int is_executable = newflags & VM_EXEC;
#ifndef HOOKED_PROCESS_NAME
	unsigned char found = 0;
	struct hooked_pid_node* cur;
#endif
	if (current->tgid == 1)
	{
		AUDIT printk("%s: [%d] It's init\n", MODULE_NAME, current->tgid);
		return 0;
	}

#ifdef HOOKED_PROCESS_NAME
	if (strstr(current->comm, HOOKED_PROCESS_NAME) == NULL)
	{
		// AUDIT printk("%s: (mprotect_handler) process [%s] %d is excluded from the analysis\n", MODULE_NAME, current->comm, current->tgid);
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
	if (vma->vm_file == NULL)
	{
		AUDIT printk(KERN_INFO "%s: (mprotect_handler) The vm area is not mapped to a file\n", MODULE_NAME);
		goto handle_no_file_mapping;
	}

#ifdef EXCLUDE_SHARED_LIBRARIES
	if (strstr(vma->vm_file->f_path.dentry->d_name.name, ".so") != NULL)
	{
		AUDIT printk(KERN_CRIT "%s: (mprotect_handler) The file %s is skipped by the checks\n", MODULE_NAME, vma->vm_file->f_path.dentry->d_name.name);
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

	DEBUG_INFO printk(KERN_INFO "%s: (mprotect_handler) [%s] pid %d is executing mprotect in [%lx, %lx] with %08lx\n", MODULE_NAME, current->comm, current->tgid, start, end, newflags);

	if (was_executable)
	{
		if (is_writable)
		{
			AUDIT printk(KERN_INFO "%s: (mprotect_handler) [%s] pid %d is making an X VMA in [%lx, %lx] W. A page restore is required if a write on that page is needed\n", MODULE_NAME, current->comm, current->tgid, start, end);
		}
		else if (is_executable)
		{
			AUDIT printk(KERN_INFO "%s: (mprotect_handler) [%s] pid %d is making an X VMA in [%lx, %lx] X. A check is necessary if the IF has not yet occurred in the previous state\n", MODULE_NAME, current->comm, current->tgid, start, end);
		}

		newflags |= VM_WAS_EXECUTABLE;
	}

	else // The page wasn't executable
	{
		DEBUG_INFO printk(KERN_INFO "%s: (mprotect_handler) [%s] pid %d; The VMA in [%lx, %lx] wasn't executable. \n", MODULE_NAME, current->comm, current->tgid, start, end);
		newflags &= ~VM_WAS_EXECUTABLE;
	}

	regs->r10 = newflags;
	return 0;
}




int change_protection_handler(struct fprobe *fp, unsigned long entry_ip,unsigned long ret_ip, struct pt_regs *regs,void *entry_data)
{
	/**
		long change_protection(struct mmu_gather *tlb,
		       struct vm_area_struct *vma, unsigned long start,
		       unsigned long end, unsigned long cp_flags)

		static long change_protection_range(struct mmu_gather *tlb,
		struct vm_area_struct *vma, unsigned long addr,
		unsigned long end, pgprot_t newprot, unsigned long cp_flags)
	 */

	struct vm_area_struct *vma = (struct vm_area_struct *)regs_get_kernel_argument(regs, 1);
	unsigned long start = (unsigned long)regs_get_kernel_argument(regs, 2);
	unsigned long end = (unsigned long)regs_get_kernel_argument(regs, 3);
	unsigned long prot = (unsigned long) vma->vm_page_prot.pgprot;
	
	int is_executable = vma->vm_flags & VM_EXEC;
	int is_writable = vma->vm_flags & VM_WRITE;
	int was_executable = vma->vm_flags & VM_WAS_EXECUTABLE;
#ifndef HOOKED_PROCESS_NAME
	unsigned char found = 0;
	struct hooked_pid_node* cur;
#endif

	if (current->tgid == 1)
	{

		AUDIT printk("%s: [%d] It's init\n", MODULE_NAME, current->tgid);
		return 0;
	}

#ifdef HOOKED_PROCESS_NAME
	if (strstr(current->comm, HOOKED_PROCESS_NAME) == NULL)
	{
		// AUDIT printk("%s: (change_protection_handler) process [%s] %d is excluded from the analysis\n", MODULE_NAME, current->comm, current->tgid);
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
	if (vma->vm_file == NULL)
	{
		AUDIT printk(KERN_INFO "%s: (change_protection_handler) The vm area is not mapped to a file\n", MODULE_NAME);
		goto handle_no_file_mapping;
	}

#ifdef EXCLUDE_SHARED_LIBRARIES
	if (strstr(vma->vm_file->f_path.dentry->d_name.name, ".so") != NULL)
	{
		AUDIT printk(KERN_CRIT "%s: (change_protection_handler) The file %s is skipped by the checks\n", MODULE_NAME, vma->vm_file->f_path.dentry->d_name.name);
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

	AUDIT printk(KERN_INFO "%s: (change_protection_handler) [%s] pid %d is executing change_protection in [%lx, %lx] with %08lx. The VMA is executable %d, is writable %d and was executable %d\n", MODULE_NAME, current->comm, current->tgid, start, end, prot, is_executable, is_writable, was_executable);

	/** The followings clear_bit are not necessary because the user software don't use or manipulate them ... */

	if (!IS_NOT_EXE(prot)) // if the pages are executable
	{

		/**
		 * 2 cases:
		 *	 1) The page was executable before:
					If the page was executable, now is executable but no write fault has occurred then the page should be not checked. Only if a write fault has occurred the page should be checked again.
					If the page should be not checked, the CHECK_DENY_BIT is set to 1.
		*	 2) The page was not executable before (ex. W -> X):
					If the page was not executable before, then the page should be checked in the following instruction fetch fault.

			When the page should be checked X_ORIG_EXE_BIT is set to 1 and CHECK_DENY_BIT is set to 0.
		*/

		set_bit(EXE_DENY_BIT, &prot); // The page should be checked in the following instruction fetch fault
		set_bit(ORIG_EXE_BIT, &prot); // The page is executable

	}
	else
	{ // if the page is not executable anymore

		AUDIT printk("%s: [%d] It's not EXE anymore\n", MODULE_NAME, current->tgid);
	}

	/**
	 * Setting the bit to indicate that pages were executable so a page restore is needed if a write will occur, now is again exe.
	 * If a write fault has occurred, in handle_mm_fault the bit CHECK_DENY_BIT has been setted to 0, so the page should be checked again.
	 */
	if (was_executable && is_writable)
	{
		/**
		 * If the page was exe and now is writable then a write should generate a write fault to be intercepted
		 * in order to restore the page (if an IF fault has happened since the page was exe) and set the bit to indicate that the page should be checked again
		 */
		clear_bit(WRITE_BIT, &prot);
		set_bit(ORIG_WRITE_BIT, &prot);
	}

	/* regs->cx = prot; */
	vma->vm_page_prot.pgprot = prot;

	return 0;
}
