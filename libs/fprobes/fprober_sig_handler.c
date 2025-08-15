/**
 * @file fprober_sig_handler.c
 * @author 
 * @brief 
 * @version 0.1
 * @date 2025-04-04
 * 
 * @copyright Copyright (c) 2025
 * 
 */

#include "fprobes_helper.h"
#include "fprobers.h"

#include "../utils.h"
#include "../kernel_checks.h"
#include "../my_mutexes.h"

int sig_handler(struct fprobe *fp, unsigned long entry_ip,unsigned long ret_ip, struct pt_regs *regs,void *dt)
{
	/**
	 * int force_sig_fault(int sig, int code, void __user *addr);
	 */
	int sig = (int)regs_get_kernel_argument(regs, 0);
	int code = (int)regs_get_kernel_argument(regs, 1);
	unsigned long address = (unsigned long)regs_get_kernel_argument(regs, 2);
	pid_t pid = current->tgid;
	unsigned long pte_val = 0;
	struct page_info *page_info = NULL;
	char *data = NULL;
	int ret = 0;
	int byte;

	int orig_exe_bit = -1;
	int orig_write_bit = -1;
	int pid_lock_idx = get_pid_bucket(pid, NUM_PID_BITS);
	unsigned long page_addr = address & PAGE_MASK;
	struct vm_area_struct *vma = NULL; // First page vmarea

#ifndef HOOKED_PROCESS_NAME
	unsigned char found = 0;
	struct hooked_pid_node* cur;
#endif

#ifdef ZONE_KERNEL_SYNC_CHECK

	struct vm_area_struct *curr_vma = NULL; // Next page vmarea
	int page_idx = 0;
	unsigned long start_offset = address & ~PAGE_MASK;
	unsigned long end_offset = PAGE_SIZE;
	struct open_zone *zone = NULL;
	struct stats stats = {0};
	unsigned long base_addr = address & PAGE_MASK;
	unsigned long start = 0;
	unsigned long end = 0;
	int num_pages = 0;
	int num_of_blocks = 0;
	int cross_flag = 0;
	int i = 0;
	int page_lock_idxs[MAX_PAGES] = {[0 ... MAX_PAGES - 1] = -1};
	bool is_shared = false;

#else

	int page_lock_idx = -1;

#endif

	if (address == 0)
		return 0;

	if (pid == 1)
	{
		AUDIT printk("%s: (sig_handler) process %d is excluded\n", MODULE_NAME, pid);
		return 0;
	}

	AUDIT printk(KERN_INFO "%s: sig_handler for [%s] pid %d (tid %d) at address %lx in the page %lx with sig %d and code %d\n", MODULE_NAME, current->comm, pid, current->pid, address, address & PAGE_MASK, sig, code);

	if (unlikely(sig == SIGSEGV && code == SEGV_MAPERR)) // Consistency check, it must be mapped.  SEGV_MAPERR: address not mapped to object
	{
		printk(KERN_ERR "%s: (sig_handler) page %lx (address %lx) not mapped for %d (%d)\n", MODULE_NAME, address & PAGE_MASK, address,pid, current->pid);;
		return 0;
	}

	if (likely(sig == SIGILL && (current->flags & INVALID_OP_HANDLED_FLAG))) // Fault caused by an illegal op-code and correctly handled.
	{
		/* Bypass handler */
		DEBUG_INFO printk(KERN_INFO "%s: (sig_handler) [%s] pid %d is bypassing handler SIGILL at address %lx\n", MODULE_NAME, current->comm, pid, address);
		current->flags &= ~INVALID_OP_HANDLED_FLAG; // Clear the flag

		regs->ip = ret_addr;
		return 1;
	}
	
	// check if its in hiicked list and take out last zone opened
	hash_for_each_possible(hooked_pids, cur, node, current->pid) {
		if (cur->pid == current->pid) {
			found = 1;
			break;
		}
	}
	if (!found)
		return 0;


	pte_val = get_page_table_entry(address & PAGE_MASK);
	// Consistency check, it must be mapped in the pte, this should never be false because if we are here this is not a SEGV_MAPERR error
	if (pte_val == (unsigned long)0) 
	{
		pte_val = get_page_table_entry_force(address & PAGE_MASK); // if we cant do it we try to force it by not checking the last level VALID bit
		if (pte_val == (unsigned long)0) {
			/* printk(KERN_ERR "%s: (sig_handler) page table entry not found for address %lx, page not mapped for pid %d (%d), pteval is %08lx\n", MODULE_NAME, address & PAGE_MASK, pid, current->pid, pte_val); */
			
			mmap_read_lock(current->mm);
			vma = find_vma(current->mm, address); // The vma of the next page. It's necessary in close_outer_zone if the page is not COW, shared and not writable. In that case get_user_pages will fail
			mmap_read_unlock(current->mm);
			/* printk(KERN_INFO "Trying to find vma %lx, prot \n", (unsigned long) vma); */
			/* if (vma) { */
			/* 	printk(KERN_INFO "vm_page_prot: %lx\n", (unsigned long) vma->vm_page_prot); */
			/* } */
			byte = 0x42;
			ret = copy_from_user(&byte, (void*)(address & PAGE_MASK), 1); // Forcing PTE lazy mapping
			if (ret != 0) 
				pte_val = get_page_table_entry_force(address & PAGE_MASK);
	

			DEBUG_INFO printk(KERN_INFO "Trying to force page map %x, new pte val %lx\n", byte, pte_val);

			//return 0;
			//goto allow_exe; // if we still cant do it we let it execute to receive another fault and come back here
		}
	}

	orig_exe_bit = test_bit(ORIG_EXE_BIT, &pte_val);
	orig_write_bit = test_bit(ORIG_WRITE_BIT, &pte_val);

	if (sig == SIGSEGV && orig_exe_bit) // Fault caused by an instruction fetch fault: code is SEGV_ACCERR
	{


		DELETE_ME printk("%s: (sig_handler) An IF fault has occured on page %lx at address %lx: (%d - %d) for [%s] pid %d (tid %d)\n", MODULE_NAME, address & PAGE_MASK, address, orig_exe_bit, orig_write_bit, current->comm, pid, current->pid);

		/**----------------------------------------------------------------- Finding the VMA ---------------------------------------------------------------------------------*/
		mmap_read_lock(current->mm);
		vma = find_vma(current->mm, page_addr); // The vma of the next page
		mmap_read_unlock(current->mm);

		if (vma == NULL) // Consistency check, it must be mapped in the pte
		{
			AUDIT printk(KERN_INFO "%s: (sig_handler) The page is not mapped\n", MODULE_NAME);
			goto exit;
		}

		if (is_bit_set(address & PAGE_MASK, CHECK_DENY_BIT) == true) // The page on which the fetch was generated must be checked or not
		{
			/**
			 * 1) X or WX -> IF fault -> WX -> NO WF and IF fault generated:
			 * If the page is WX then the page is checked on the instruction fault event that occurs at each write fault or at the first fetch of the page.
			 * If the page was checked when it was X, now becomes WX and generates the first IF without a write fault then it has already been checked.
			 * If a write fault occurs then the page should be checked again.
			 *
			 * 2) X or WX -> IF fault -> W -> NO WF -> X or WX -> IF fault:
			 * If the page was executable then writable and now is executable but no write fault (when it was W) has occurred then we_check_deny_bit is set to 1.
			 * Only if a write fault (we_check_deny_bit == 0) has occurred the page should be checked again.
			 */

			AUDIT printk(KERN_INFO "%s: (sig_handler) The page %lx has been already checked and no write fault has occurred at address %lx: (%d - %d) for [%s] pid %d (%d)\n", MODULE_NAME, address & PAGE_MASK, address, orig_exe_bit, orig_write_bit, current->comm, pid, current->pid);
#ifdef ZONE_KERNEL_SYNC_CHECK
			num_pages = 1;
#endif
			if (is_bit_set(address & PAGE_MASK, EXE_DENY_BIT) == false) // In a multi-threading environment, if the page has been checked we need to control the exe_deny_bit after acquiring the lock
				goto find_ret;
			else
				goto allow_exe;
		}

#ifndef ZONE_KERNEL_SYNC_CHECK
		LOCK
		{
			/**
			 * If the thread group is empty then the page is not shared between different processes and no other thread is accessing the page.
			 * So we don't need to acquire the lock for multi-threading and multi-process support.
			 */
			if (thread_group_empty(current))
				goto skip_lock_3;

			/**----------------------------------------------------------------- Locking the page (For multi-threading support)---------------------------------------------------------------------------------*/

			page_lock_idx = get_page_bucket(page_addr, NUM_PAGE_BITS);

			// printk(KERN_CRIT "%s: (sig_handler) The [%s] pid %d (%d) is locking (%d, %d) the page %lx\n", MODULE_NAME, current->comm, pid, current->pid, pid_lock_idx, page_lock_idxs[page_idx], address & PAGE_MASK);

			lock(pid_lock_idx, page_lock_idx, "sig_handler", page_addr);

			if (is_bit_set(address & PAGE_MASK, EXE_DENY_BIT) == false) // In a multi-threading environment, if the page has been checked we need to control the exe_deny_bit after acquiring the lock
				goto find_ret;

		skip_lock_3:
		}

		/**----------------------------------------------- Allocating memory for page content ------------------------------------------------------------------------*/
		data = kmalloc(PAGE_SIZE, GFP_ATOMIC);
		if (data == NULL)
		{
			printk(KERN_ERR "%s: (sig_handler) Error allocating page data\n", MODULE_NAME);
			goto allow_exe;
		}

		ret = copy_from_user(data, (void *)(address & PAGE_MASK), PAGE_SIZE);
		if (ret != 0)
		{
			printk(KERN_ERR "%s: (sig_handler) Error copying from user\n", MODULE_NAME);
			goto allow_exe;
		}

		/**----------------------------------------------- Checking page content  ------------------------------------------------------------------------*/

		page_checked++;

#ifdef SYNC_CHECK
		if (!run_kernel_check(data, address & PAGE_MASK, (address & PAGE_MASK) + PAGE_SIZE))
		{
			// check failed
			goto exit; // if we return here the program will seg fault
		}
#endif
#ifdef DOS_PROTECTION
		if (check_page_limit(current->real_cred->uid))
		{
			// over the limit - dont transfer
			goto exit;
		}
#endif

		page_info = register_page(data, address); // For the asynchronous checks
		if (page_info == NULL)
		{
			printk(KERN_ERR "%s: (sig_handler) Error registering page %lx\n", MODULE_NAME, address & PAGE_MASK);
		}

		goto allow_exe;

#else
		curr_vma = vma;

		/**
		 * SHARED PAGE: --> A child process has been created and the page searched is shared. Only a master-copy is registered in the hash table.
		 */
		if (curr_vma && curr_vma->vm_flags & VM_SHARED)
		{
			AUDIT printk(KERN_INFO "%s: (sig_handler) The page %lx is a shared mapping\n", MODULE_NAME, page_addr);

			/**
			 * Acquiring the same lock for different processes accessing the same shared page
			 */
			pid_lock_idx = get_shared_page_bucket(NUM_PID_BITS); // 2 different processes should lock the same page

			is_shared = true;
		}

		LOCK
		{

			/**
			 * If the VMA is not shared and the thread group is empty then the page is not shared between different processes and no other thread is accessing the page.
			 * So we don't need to acquire the lock for multi-threading and multi-process support.
			 */
			if (!is_shared && thread_group_empty(current))
				goto skip_lock_1;
			/**----------------------------------------------------------------- Acquiring the lock for multi-threading and multi-process support ---------------------------------------------------------------------------------*/

			// printk(KERN_CRIT "%s: (sig_handler) The [%s] pid %d (%d) is locking (%d, %d) the page %lx\n", MODULE_NAME, current->comm, pid, current->pid, pid_lock_idx, page_lock_idxs[page_idx], address & PAGE_MASK);

			page_lock_idxs[page_idx] = get_page_bucket(address & PAGE_MASK, NUM_PAGE_BITS);

			lock(pid_lock_idx, page_lock_idxs[page_idx], "sig_handler", page_addr);

			if (is_bit_set(page_addr, EXE_DENY_BIT) == false) // In a multi-threading environment, if the page has been checked in the meantime we need to control the exe_deny_bit after acquiring the lock
				goto find_ret;

			if (is_shared && page_shared_not_registered_yet(address & PAGE_MASK) != NULL) // In a multi-process environment, if the shared page has been checked in the meantime it's been registered in the hash table
			{
				num_pages = 1;
				goto allow_exe;
			}

		skip_lock_1:
		}

		/**----------------------------------------------- Allocating memory for MAX_PAGES page content ------------------------------------------------------------------------*/

		data = kmalloc(PAGE_SIZE * MAX_PAGES, GFP_ATOMIC);
		if (data == NULL)
		{
			printk(KERN_ERR "%s: (sig_handler) Error allocating page data\n", MODULE_NAME);
			goto exit;
		}

		/**----------------------------------------------- Opening a zone  ------------------------------------------------------------------------*/

		while (++num_pages <= MAX_PAGES) // To avoid infinite loop
		{
			page_idx = num_pages - 1;

			if (num_pages > 1) // The first page has been already opened, trying to open the following ones
			{
				LOCK
				{
					/**
					 * If the page comes from another VMA then we need to check if the following page is shared or not.
					 */
					if (curr_vma && (curr_vma->vm_flags & VM_SHARED))
					{
						pid_lock_idx = get_shared_page_bucket(NUM_PID_BITS); // 2 different processes should lock the same page
						is_shared = true;
					}
					else
						is_shared = false;
					/**
					 * If the VMA is not shared and the thread group is empty then the page is not shared between different processes and no other thread is accessing the page.
					 * So we don't need to acquire the lock for multi-threading and multi-process support.
					 * No contention on the same page is possible.
					 */
					if (!is_shared && thread_group_empty(current))
						goto skip_lock_2;

					page_lock_idxs[page_idx] = get_page_bucket(page_addr, NUM_PAGE_BITS);

					for (i = 0; i < page_idx; i++)
					{
						if (page_lock_idxs[i] == -1)
							continue;
						if (page_lock_idxs[i] == page_lock_idxs[page_idx]) // To avoid reacquiring the lock for pages that hashes to the same bucket
							goto lock_already_acquired;
					}

					lock(pid_lock_idx, page_lock_idxs[page_idx], "sig_handler", page_addr);

				lock_already_acquired:

					if (is_shared && page_shared_not_registered_yet(page_addr) != NULL) // In a multi-process environment, if the shared page has been checked in the meantime it's been registered in the hash table
					{
						num_pages--;
						break;
					}

				skip_lock_2:
				}

				/**
				 * The following page P' is X:
				 * 1) an IF fault on P' has already happened and the page has been checked --> then it contains illegal bytes and we don't continue the search. WE_CHECK_DENY_BIT is set to 1.
				 * 2) an IF fault on P' has not happened yet --> then we continue the search. WE_CHECK_DENY_BIT is set to 0.
				 * 3) an IF fault on P' has already happened and the page has been check by another thread, in concurrency.
				 */

				if (is_bit_set(page_addr, EXE_DENY_BIT) == false)
				{
					num_pages--;
					break;
				}

				// Updating the offsets
				start_offset = end_offset;
				end_offset = PAGE_ALIGN_UP(start_offset) + PAGE_SIZE;

				printk(KERN_INFO "%s: (sig_handler) Continuing the search in the next page %lx from [%lx, %lx]\n", MODULE_NAME, page_addr, base_addr + start_offset, base_addr + end_offset);
			}

			/**----------------------------------------------- Copying page bytes in the kernel ------------------------------------------------------------------------*/
			ret = copy_from_user(data + page_idx * PAGE_SIZE, (void *)page_addr, PAGE_SIZE);
			if (ret != 0)
			{
				printk(KERN_ERR "%s: (sig_handler) Error copying from user\n", MODULE_NAME);
				goto exit;
			}

		find_another_block:

			start = (unsigned long)data + start_offset;
			end = (unsigned long)data + end_offset;
			/**----------------------------------------------- Searching for JMP/Jcc/CALL/RET instructions ------------------------------------------------------------------------*/

			ret = disassemble_code(start, &end, &stats);

			end_offset = end - (unsigned long)data;

			if (ret == DISASSEMBLE_ERROR)
			{
				printk(KERN_ERR "%s: (sig_handler) An error has occurred in searching JMP/Jcc/CALL/RET instructions in [%lx, %lx]\n", MODULE_NAME, base_addr + start_offset, base_addr + end_offset);

				goto disassembler_error; // if disassembler fails the sync check occurs on the whole page
			}
			else if (ret == DISASSEMBLE_CONTINUE)
			{
				AUDIT printk(KERN_INFO "%s: (sig_handler) JMP/Jcc/CALL/RET not found in [%lx, %lx]\n", MODULE_NAME, base_addr + start_offset, base_addr + end_offset);

				/**
				 * We register the pages that contain cross-page instructions.
				 */
				if (!(PAGE_ALIGNED(base_addr + end_offset))) // If the end of the page is not reached then it contains a cross-page instruction
				{
					// printk(KERN_INFO "%s: (sig_handler) Pages %lx - %lx contains a cross-page instruction\n", MODULE_NAME, page_addr, page_addr + PAGE_SIZE);
					register_page_cross_pages_integrity(page_addr, PARTIALLY_OPENED_END);
					register_page_cross_pages_integrity(page_addr + PAGE_SIZE, PARTIALLY_OPENED_START);
				}

				if (num_pages >= MAX_PAGES)
				{
					AUDIT printk(KERN_INFO "%s: (sig_handler) Avoiding infinite loop\n", MODULE_NAME);
					break;
				}

				/**-------------------------------------------------------------------- Continuing the search in the next page -----------------------------------------------------------------------------*/

				page_addr += PAGE_SIZE; // The start of the next page

				if (curr_vma && page_addr >= curr_vma->vm_start && page_addr < curr_vma->vm_end)
				{
					AUDIT printk(KERN_INFO "%s: (sig_handler) The following page is in the same VMA\n", MODULE_NAME);
				}
				else // It could happen that the next page to dissasemble is not in the same VMA
				{
					mmap_read_lock(current->mm);
					curr_vma = find_vma(current->mm, page_addr);
					mmap_read_unlock(current->mm);
				}

				if (curr_vma == NULL)
				{
					AUDIT printk(KERN_INFO "%s: (sig_handler) The following page is not mapped\n", MODULE_NAME);
					break;
				}

				if ((curr_vma->vm_flags & VM_EXEC) && !(curr_vma->vm_flags & VM_WRITE)) // Only if the following page is only EXE we continue to disassemble
				{
					AUDIT printk(KERN_INFO "%s: (sig_handler) The following page is only EXE\n", MODULE_NAME);
				}
				else // Consistency check, it must be executable if the following page is in the same VMA
				{
					AUDIT printk(KERN_INFO "%s: (sig_handler) The following page is WX\n", MODULE_NAME);
					break;
				}

				AUDIT printk(KERN_INFO "%s: (sig_handler) Trying to continue the search in the next only X page %lx\n", MODULE_NAME, page_addr);
			}

			else if (ret & DISASSEMBLE_SUCCESS)
			{
				num_of_blocks++;
				AUDIT printk(KERN_INFO "%s: (sig_handler) JMP/Jcc/CALL/RET found in [%lx, %lx] and num_of_contiguous_block = %d\n", MODULE_NAME, base_addr + start_offset, base_addr + end_offset, num_of_blocks);

				if (num_pages >= MAX_PAGES) // Over the limit of the number of pages
				{
					AUDIT printk(KERN_INFO "%s: (sig_handler) Avoiding infinite loop\n", MODULE_NAME);
					break;
				}

				if (num_of_blocks == num_of_contiguous_block) // The disassembler found the required number of contiguous blocks
				{
					AUDIT printk(KERN_INFO "%s: (sig_handler) The disassembler found the required number of contiguous blocks\n", MODULE_NAME);
					break;
				}

				if ((ret & JMP_SUCCESS) || (ret & RET_SUCCESS)) // The disassembler found a JMP or RET instruction
				{
					AUDIT printk(KERN_INFO "%s: (sig_handler) The disassembler found a JMP or RET instruction\n", MODULE_NAME);
					//break;
				}

				// Updating the offsets
				start_offset = end_offset;
				end_offset = PAGE_SIZE;
				goto find_another_block;
			}
		}

		start = address;
		end = base_addr + end_offset; // user space end address

		if (end < start)
		{
			printk(KERN_ERR "%s: (sig_handler) end < start\n", MODULE_NAME);
			goto disassembler_error;
		}

		/**
		 * If a write occurs, the page could be modified and it may no longer contain cross-page instructions:
		 *
		 * If start is page aligned then there is no cross-page instruction that starts in the previous page and ends in the current page.
		 * If end is page aligned then there is no cross-page instruction that starts in the current page and ends in the next page.
		 */

		if (PAGE_ALIGNED(start)) // First page to open doesn't contain a cross-page instruction that starts in the previous page and ends in the current page
			unregister_page_cross_pages_integrity((start & PAGE_MASK));
		if (PAGE_ALIGNED(end)) // Last page to close doesn't contain a cross-page instruction that starts in the current page and ends in the next page
			unregister_page_cross_pages_integrity((start & PAGE_MASK) + (num_pages - 1) * PAGE_SIZE);

		/**
		 * The disassembler started (immediatly) from a cross-page instruction and the IF fault (following page) has not happened yet since
		 * the processor has not fetched the first byte of the cross-page instruction.
		 */
		if (end == start)
		{
			printk(KERN_INFO "%s: (sig_handler) end == start\n", MODULE_NAME);
			end = PAGE_ALIGN_UP(end);
		}

		/**
		 *
		 * Let's consider the following scenario: In this way is correctly handled.
		 *
		 * 1) A, B are two contiguous page. B follows A. A contains a cross-page instruction that starts in A and ends in B.
		 * 2) Both A, B are opened correctly.
		 * 3) B is written, then it's been completely restored and generates an IF fault. A is opened until the end of the page. A not generates a write fault and a following IF fault.
		 * 4) During the IF on B, the bytes from the start of the page to address should be not modified since a cross-page instruction could have been cut.
		 * So A is opened until the end of the page, B is completely restored and generates an IF fault. If B is closed (during the IF fault) from the start of the page to address then the cross-page instruction is broken.
		 */
		cross_flag = find_page_cross_pages_integrity((start & PAGE_MASK) - PAGE_SIZE); // If the previous page is in the hash table then it's not been modified. Don't substitute the bytes before the start to avoid breaking the instructions.
		if (cross_flag & PARTIALLY_OPENED_END)
			start = address & PAGE_MASK; // user space start address

		for (i = 0; i < num_pages; i++)
		{
			/**----------------------------------------------- Registering page in the kernel ------------------------------------------------------------------------*/

			AUDIT printk(KERN_INFO "%s: (sig_handler) Registering page %lx", MODULE_NAME, (address & PAGE_MASK) + i * PAGE_SIZE);

			if (is_shared)
				page_info = register_shared_page(data + i * PAGE_SIZE, (address & PAGE_MASK) + i * PAGE_SIZE); // To restore the page
			else
				page_info = register_page(data + i * PAGE_SIZE, (address & PAGE_MASK) + i * PAGE_SIZE); // To restore the page

			if (page_info == NULL)
			{
				printk(KERN_ERR "%s: (sig_handler) Error registering page %lx\n", MODULE_NAME, (address & PAGE_MASK) + i * PAGE_SIZE);
				goto page_check;
			}
		}

		/**----------------------------------------------- Checking page content  ------------------------------------------------------------------------*/
		page_checked += num_pages;
		zone_checked++;

#ifdef SYNC_CHECK
		if (!run_kernel_check(data + (start & ~PAGE_MASK), start, end))
		{
			printk(KERN_ERR "%s: (sig_handler) failed sync check\n", MODULE_NAME);
			goto exit; // if we return here the program will seg fault
		}
#endif
#ifdef DOS_PROTECTION
		/**----------------------------------------------- Checking bytes limit ------------------------------------------------------------------------*/
		if (check_bytes_limit(current->real_cred->uid, end - start))
		{
			// over the limit - dont transfer
			printk(KERN_ERR "%s: (sig_handler) over the limit - dont transfer\n", MODULE_NAME);
			goto exit;
		}
#endif

		/**----------------------------------------------- Transferring zone for asynchronous checks ------------------------------------------------------------------------*/
		zone = transfer_zone(data + (start & ~PAGE_MASK), start, end, &stats); // For asynchronous checks
		if (zone == NULL)
		{
			printk(KERN_ERR "%s: (sig_handler) Error transferring zone to user\n", MODULE_NAME);
		}
	
		/**------------------------------------------------ closing old zone ------------------------------------------------------- */

#if(ONE_OPEN_ZONE == 1)

		if (cur->open_start != cur->open_end) {
			ret = close_inner_zone(cur->open_start, cur->open_end, num_pages);
			if (ret < 0) {

				printk(KERN_ERR "%s: (invalid_op_handler) Error closgin previous zone bytes with error_code %d\n", MODULE_NAME, ret);

			}
		}
#endif
		/**------------------------------------------------ Closing parts of the page that are outside the zone ------------------------------------------------------- */

		DEBUG_INFO printk(KERN_INFO "%s: (sig_handler) Closing the bytes outside the zone [%lx, %lx) from page %lx\n", MODULE_NAME, start, end, start & PAGE_MASK);

		ret = close_outer_zone(data, start, end, num_pages, vma);
		if (ret < 0)
		{
			printk(KERN_ERR "%s: (sig_handler) Error closing the bytes outside the zone\n", MODULE_NAME);
			page_checked -= num_pages;
			zone_checked--;
			goto page_check;
		}

#if(ONE_OPEN_ZONE == 1)
		cur->open_start = start;
		cur->open_end = end;
#endif

#endif

	allow_exe:

		/**----------------------------------------------- Allowing execution for the first page------------------------------------------------------------------------*/

		/**
		 * CHECK_DENY_BIT is a way to mark that an X or WX page has already been checked across mprotect on the VMA and change_protection.
		 */

		if (vma && vma->vm_flags & VM_WRITE) // The first page is WX, the remaining if exists are only X
		{
			// allow exe for now
			SHARED_DEBUG printk(KERN_INFO "%s: Allowing exe for the WX page %lx\n", MODULE_NAME, (address & PAGE_MASK));

			flip_bit((address & PAGE_MASK), EXE_DENY_BIT, 0);
			flip_bit((address & PAGE_MASK), WRITE_BIT, 0);
			flip_bit((address & PAGE_MASK), ORIG_WRITE_BIT, 1);

			// now do it for the shared (if they exist)
			shared_flip_bit(vma, (address & PAGE_MASK), EXE_DENY_BIT, 0); 
			shared_flip_bit(vma, (address & PAGE_MASK), WRITE_BIT, 0);

			/**
			 * If the page will be write-only from exe-only we mark the page as checked. The page may have already been checked before it enters the was_only_executable state
			 * and begins toggling between exe-only and write-only
			 */
			flip_bit((address & PAGE_MASK), CHECK_DENY_BIT, 1);

			/**
			 * If we have concurrency we have to guarantee that changes are visible to all CPUs.
			 */

			on_each_cpu((smp_call_func_t)__flush_tlb_one_user, (void *)((address & PAGE_MASK)), false);
		}

		else
		{
			// allow exe for now
			AUDIT printk(KERN_INFO "%s: Allowing exe for the X page %lx\n", MODULE_NAME, (address & PAGE_MASK));

			flip_bit((address & PAGE_MASK), EXE_DENY_BIT, 0);
			shared_flip_bit(vma, (address & PAGE_MASK), EXE_DENY_BIT, 0);
			/**
			 * The page has been checked because it was X at least once
			 *
			 * If it's WX (then became only X) and the IF fault has already happened then the page has been checked. So, we set WE_CHECK_DENY_BIT to 1.
			 * If the page in the only X state will generate an IF fault then the page will not be checked again.
			 */
			flip_bit((address & PAGE_MASK), CHECK_DENY_BIT, 1);

			/**
			 * If we have concurrency we have to guarantee that changes are visible to all CPUs.
			 */

			on_each_cpu((smp_call_func_t)__flush_tlb_one_user, (void *)((address & PAGE_MASK)), false);
		}

#ifdef ZONE_KERNEL_SYNC_CHECK
		/**----------------------------------------------- Allowing execution for the remaining pages------------------------------------------------------------------------*/
		for (i = 1; i < num_pages; i++) // The remaining pages are only X
		{
			// allow exe for now
			AUDIT printk(KERN_INFO "%s: Allowing exe for the X page %lx\n", MODULE_NAME, (address & PAGE_MASK) + i * PAGE_SIZE);

			flip_bit((address & PAGE_MASK) + i * PAGE_SIZE, EXE_DENY_BIT, 0);
			shared_flip_bit(vma, (address & PAGE_MASK) + i * PAGE_SIZE, EXE_DENY_BIT, 0);
			/**
			 * If the page will be write-only from exe-only we mark the page as checked. The page may have already been checked before it enters the was_only_executable state
			 * and begins toggling between exe-only and write-only.
			 *
			 */
			flip_bit((address & PAGE_MASK) + i * PAGE_SIZE, CHECK_DENY_BIT, 1);

			/**
			 * If we have concurrency we have to guarantee that changes are visible to all CPUs.
			 */
			on_each_cpu((smp_call_func_t)__flush_tlb_one_user, (void *)((address & PAGE_MASK) + i * PAGE_SIZE), false);
		}
#endif

		// #ifdef ZONE_KERNEL_SYNC_CHECK
		// 		flush_tlb_mm_range_func(current->mm, (address & PAGE_MASK), (address & PAGE_MASK) + num_pages * PAGE_SIZE, PAGE_SHIFT, false);
		// #else
		// 		flush_tlb_mm_range_func(current->mm, (address & PAGE_MASK), (address & PAGE_MASK) + PAGE_SIZE, PAGE_SHIFT, false);
		// #endif

	find_ret:

		AUDIT printk(KERN_INFO "%s: (sig_handler) bypassing handler for SIGSEGV\n", MODULE_NAME);

		regs->ip = ret_addr;

		LOCK
		{
#ifdef ZONE_KERNEL_SYNC_CHECK

			for (i = MAX_PAGES - 1; i >= 0; i--)
			{
				unlock(pid_lock_idx, page_lock_idxs[i], "sig_handler", base_addr + i * PAGE_SIZE);
			}

#else

			unlock(pid_lock_idx, page_lock_idx, "sig_handler", page_addr);

#endif // ZONE_KERNEL_SYNC_CHECK
		}

		if (data != NULL)
			kfree(data);

		return 1;
	}

	else
	{
		if (sig == SIGTRAP && code == TRAP_TRACE) // Trap trace
		{
			AUDIT printk(KERN_INFO "%s: sig_handler: A debugger is executing, a trap trace has been generated at %lx (%d - %d)\n", MODULE_NAME, address, orig_exe_bit, orig_write_bit);
		}
		else
		{
			printk(KERN_ERR "%s: Process [%s] %d (%d) invoked sig_handler (sig %d, code %d) at %lx with (%d - %d): pteval is %08lx\n", MODULE_NAME, current->comm, pid, current->pid, sig, code, address, orig_exe_bit, orig_write_bit, pte_val);
		}

		return 0;
	}

exit:
	LOCK
	{
#ifdef ZONE_KERNEL_SYNC_CHECK
		{
			for (i = MAX_PAGES - 1; i >= 0; i--)
			{
				unlock(pid_lock_idx, page_lock_idxs[i], "sig_handler", base_addr + i * PAGE_SIZE);
			}
		}
#else

		unlock(pid_lock_idx, page_lock_idx, "sig_handler", page_addr);

#endif // ZONE_KERNEL_SYNC_CHECK
	}

	if (data != NULL)
		kfree(data);

	return 0;

#ifdef ZONE_KERNEL_SYNC_CHECK

disassembler_error:
	/**
	 * If the disassembler fails then we don't know if the page contains cross-page instructions.
	 */

	/**----------------------------------------------- Registering page not opened in the kernel ------------------------------------------------------------------------*/

	ret = register_page_cross_pages_integrity((address & PAGE_MASK), PARTIALLY_OPENED_START | PARTIALLY_OPENED_END);
	if (ret < 0)
	{
		printk(KERN_INFO "%s: (sig_handler) Error registering page that needs cross-page integrity %lx\n", MODULE_NAME, base_addr);
	}

	goto page_already_registered;

page_check:

	/**
	 * The disassembler worked correctly but you can't tell if the page contains cross-page instructions or not because it completed before reaching the end of the page.
	 *
	 * If start is page aligned then there is no cross-page instruction that starts in the previous page and ends in the current page.
	 * If end is page aligned then there is no cross-page instruction that starts in the current page and ends in the next page.
	 */
	if (!PAGE_ALIGNED(start))
		register_page_cross_pages_integrity((start & PAGE_MASK), PARTIALLY_OPENED_START);
	if (!PAGE_ALIGNED(end))
		register_page_cross_pages_integrity((start & PAGE_MASK) + (num_pages - 1) * PAGE_SIZE, PARTIALLY_OPENED_END);

page_already_registered:

	num_pages = 1;

	start = (address & PAGE_MASK);
	end = (address & PAGE_MASK) + PAGE_SIZE;

	printk(KERN_ERR "%s: (sig_handler) Checking whole page %lx\n", MODULE_NAME, start);

	page_checked++;

#ifdef SYNC_CHECK
	if (!run_kernel_check(data, start, end))
	{
		printk(KERN_ERR "%s: (sig_handler) failed sync check\n", MODULE_NAME);
		goto exit; // if we return here the program will seg fault
	}
#endif
#ifdef DOS_PROTECTION
	/**----------------------------------------------- Checking bytes limit ------------------------------------------------------------------------*/
	if (check_bytes_limit(current->real_cred->uid, PAGE_SIZE))
	{
		// over the limit - dont transfer
		printk(KERN_ERR "%s: (sig_handler) over the limit - dont transfer\n", MODULE_NAME);
		goto exit;
	}
#endif

	/**----------------------------------------------- Transferring zone for asynchronous checks ------------------------------------------------------------------------*/
	zone = transfer_zone(data, start, end, NULL); // For asynchronous checks
	if (zone == NULL)
	{
		printk(KERN_ERR "%s: (sig_handler) Error transferring zone to user\n", MODULE_NAME);
	}

	goto allow_exe;

#endif
}

int sig_handler_2(struct fprobe *fp, unsigned long entry_ip,unsigned long ret_ip, struct pt_regs *regs,void *data)
{
	/**
	 *void force_sig(int sig)
	 */

	int sig = (int)regs_get_kernel_argument(regs, 0);
	unsigned long address = 0;
	unsigned long *bp = NULL;
	unsigned long pte_val = 0;
	int exe_deny_bit = 0;
	int orig_exe_bit = 0;
	int orig_write_bit = 0;
	int we_check_deny_bit = 0;
#ifndef HOOKED_PROCESS_NAME
	unsigned char found = 0;
	struct hooked_pid_node* cur;
#endif

#ifdef HOOKED_PROCESS_NAME
	if (strstr(current->comm, HOOKED_PROCESS_NAME) == NULL)
	{
		// AUDIT printk("%s: (sig_handler_2) process [%s] %d is excluded from the analysis\n", MODULE_NAME, current->comm, current->tgid);
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

	bp = ((unsigned long *)regs->bp);
	address = *(bp + 18); // The address of the instruction that caused the fault: see DEFINE_IDTENTRY_ERRORCODE(exc_general_protection)

	pte_val = get_page_table_entry(address & PAGE_MASK);
	if (pte_val == (unsigned long)0) // Consistency check, it must be mapped in the pte
	{
		AUDIT printk(KERN_INFO "%s: (sig_handler_2) page table entry not found for address %lx, page not mapped\n", MODULE_NAME, address);
		return 0;
	}

	exe_deny_bit = test_bit(EXE_DENY_BIT, &pte_val);
	orig_exe_bit = test_bit(ORIG_EXE_BIT, &pte_val);
	orig_write_bit = test_bit(ORIG_WRITE_BIT, &pte_val);
	we_check_deny_bit = test_bit(CHECK_DENY_BIT, &pte_val);

	printk(KERN_INFO "%s: (sig_handler_2) The process [%s] %d (tid %d) invoked force_sig with sig %d at %lx (%d - %d - %d)\n", MODULE_NAME, current->comm, current->tgid, current->pid, sig, address,
		   orig_exe_bit, orig_write_bit, we_check_deny_bit);

	if (sig == SIGSEGV && (exe_deny_bit == false))
	{ // It means that the page for an unknown reason has not been checked yet and it's executable.

		if ((orig_exe_bit))
			return 0;

		if (we_check_deny_bit == false)
		{
			printk(KERN_INFO "%s: (sig_handler_2) The page %lx has not been checked yet\n", MODULE_NAME, address & PAGE_MASK);

			flip_bit(address & PAGE_MASK, EXE_DENY_BIT, 1);
			flip_bit(address & PAGE_MASK, ORIG_EXE_BIT, 1);
			flip_bit(address & PAGE_MASK, CHECK_DENY_BIT, 0);

			//shared_flip_bit(vma, address & PAGE_MASK, EXE_DENY_BIT, 1);
			on_each_cpu((smp_call_func_t)__flush_tlb_one_user, (void *)(address & PAGE_MASK), 0);

			regs->ip = ret_addr;
			return 1;
		}
	}

	return 0;
}
