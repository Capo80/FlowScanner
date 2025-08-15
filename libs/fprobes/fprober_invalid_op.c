/**
 * @file fprober_invalid_op.c
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
#include "../instruction.h"
#include "../utils.h"
#include "../kernel_checks.h"
#include "../my_mutexes.h"


// TODO: below function in other file??
#define PAGE_NOT_EXE -1
/**
 * The function finds the first instruction in the next page.
 *
 * @param next_page_data The next page content.
 * @param prev_page_data The previous page content.
 * @param start_instr_byte_offset The offset of the last instruction byte in the previous page.
 * @param last_instr_byte_offset The offset of the first instruction byte in the next page.
 * @param stats The stats struct.
 *
 * @return 1 on success, 0 on failure.
 */
static int handle_cross_page(uint8_t *next_page_data, uint8_t *prev_page_data, unsigned long start_instr_byte_offset, unsigned long *last_instr_byte_offset, struct stats *stats)
{
	uint8_t *buff = NULL;
	unsigned long end = 0;
	int ret = 0;
	int bytes_to_copy = PAGE_SIZE - start_instr_byte_offset;

	if (bytes_to_copy < 0)
	{
		// if bytes to copy is 0, it means that there is no cross page. The instruction is completely in the previous page
		printk(KERN_INFO "%s: (handle_cross_page) Error: bytes_to_copy is %d\n", MODULE_NAME, bytes_to_copy);
		return 0;
	}

	// Allocating the cross_page_data buffer
	buff = kmalloc(sizeof(uint8_t) * MAX_INSTRUCTION_SIZE, GFP_ATOMIC);
	if (buff == NULL)
	{
		printk(KERN_ERR "%s: (handle_cross_page) Error allocating cross page data buffer\n", MODULE_NAME);
		return 0;
	}

	// Copying the last bytes of the current page and the first bytes of the next page in the buff buffer
	memcpy(buff, (void *)prev_page_data + start_instr_byte_offset, bytes_to_copy);
	memcpy(buff + bytes_to_copy, (void *)next_page_data, MAX_INSTRUCTION_SIZE - bytes_to_copy);

	end = (unsigned long)buff + MAX_INSTRUCTION_SIZE;
	// Finding the first instruction in the next page
	ret = disassemble_code((unsigned long)buff, &end, stats);

	if (ret == DISASSEMBLE_ERROR)
	{
		printk(KERN_ERR "%s: (handle_cross_page) Error finding an aligned instruction in the next page, disassembler failed\n", MODULE_NAME);
		return 0;
	}

	if (end <= (unsigned long)buff)
	{
		printk(KERN_ERR "%s: (handle_cross_page) Error finding an aligned instruction in the next page, end <= buff\n", MODULE_NAME);
		return 0;
	}

	*last_instr_byte_offset = end - (unsigned long)buff - bytes_to_copy; // Computing the offset of the first instruction byte in the next page
	DEBUG_INFO printk(KERN_INFO "%s: (handle_cross_page) An aligned instruction in the next page is at offset %lx\n", MODULE_NAME, *last_instr_byte_offset);

	kfree(buff);
	return 1;
}

/**
 *
 * Registering a page fetched before the fork of a new process. The page has been fetched by the parent process and it has been inherited by the child process.
 * No fetch fault has been generated in the child process because the page has been already fetched by the parent process and EXE_DENY_BIT is equal to 0.
 *
 * @param address The address of the page.
 * @param vma The vma of the page.
 *
 * @return struct page_info* - pointer to the page info struct
 */
static struct page_info *register_page_fetched_before_fork(unsigned long address, struct vm_area_struct *vma)
{
	pid_t parent_pid = current->real_parent->tgid;
	unsigned long page_addr = address & PAGE_MASK;
	struct page_hash_node *curr = NULL;

	/**
	 * Let's assume that the page is private --> A child process has been created and the page searched is private.
	 * It's been ereditated from the parent. A kernel write (that follows an istruction fetch), in order to open the page, has happened before the fork().
	 * So the page has been already fetched for the first time and it contains invalid bytes. So it has generated an invalid opcode trap instead of a normal instruction fetch.
	 *
	 **/

	AUDIT printk(KERN_INFO "%s: (register_page_fetched_before_fork) Register the master copy for page %lx for the child process [%s] %d\n", MODULE_NAME, address & PAGE_MASK, current->comm, current->tgid);

	hash_for_each_possible(page_hash_table, curr, node, parent_pid)
	{
		if (curr->info != NULL && curr->pid == parent_pid && curr->address == page_addr) // COW pages have the same logical address in both address spaces
		{
			AUDIT printk(KERN_INFO "%s: (register_page_fetched_before_fork) found page %lx in the hash table for parent pid %d\n", MODULE_NAME, page_addr, parent_pid);

			if (vma && (vma->vm_flags & VM_SHARED))
				return register_shared_page(curr->info->data, page_addr);
			else
				return register_private_page(curr->info->data, page_addr);
		}
	}

	/**
	 * If the master copy is not found in the hash table it means that the page has not been fetched yet (see page_not_fetched_yet).
	 */
	printk(KERN_INFO "%s: (register_page_fetched_before_fork) Error finding page_info: page is %lx, ppid is %d and comm is %s\n", MODULE_NAME, address & PAGE_MASK, parent_pid, current->comm);
	return NULL;
}

/**
 * The function solves the problem of the cross-page instructions.
 *
 * @param address The address of the instruction.
 * @param page_info The page_info of the page.
 */
 static struct page_info *page_not_fetched_yet(unsigned long address, struct vm_area_struct *vma)
 {
 
     struct page_info *page_info = NULL;
     uint8_t *page_data = NULL;
     int ret = 0;
 
     int orig_exe_bit = -1;
     int exe_deny_bit = -1;
     unsigned long pte_val = 0;
 
     /**
      * Page could be not already fetched for the following reason:
      *
      * INSTRCUTION FETCH NOT HAPPENED YET: --> An invalid opcode trap, instead of a normal instruction fetch has occurred since the cross-page instruction is partially invalid.
      * For example, the cross-page instruction is 48 00 00. 48, that is a prefix, is at 0x.....fff (last byte of the previous page) and 0x00s are in the following page at 0x.....000.
      * The following page is not fetched yet. If the restore of the cross-page instruction is completed correctly, then the processor fetches the prefix and the first 0x00 and then it generates a normal instruction fetch.
      * To avoid to control again the same page, in this case, no istruction fetch fault is needed. The page has been already opened and checked in the invalid_op_handler.
      * In our case, at 0x.....fff there is an invalid opcode (0x0E) and the processor generates an invalid opcode trap. At 0x.....000 there are the remaining valid bytes (0x00s).
      *
      */
 
     AUDIT printk(KERN_INFO "%s: (page_not_fetched_yet) Register the master copy (INV_OP_CODE fault instead IF fault) for page %lx for the process [%s] %d\n", MODULE_NAME, address & PAGE_MASK, current->comm, current->tgid);
 
     page_data = kmalloc(PAGE_SIZE, GFP_ATOMIC);
     if (page_data == NULL)
     {
         printk(KERN_ERR "%s: (page_not_fetched_yet) Error allocating page data\n", MODULE_NAME);
         return NULL;
     }
 
     /**------------------------------------------------------- Page materialization ---------------------------------------------------------------------*/
 
     ret = copy_from_user(page_data, (void *)(address & PAGE_MASK), PAGE_SIZE); // Page materialized by the kernel
     if (ret != 0)
     {
         printk(KERN_INFO "%s: (page_not_fetched_yet) Error copying from user\n", MODULE_NAME);
         return NULL;
     }
 
     /**-------------------------------------------------------- The page is executable ? ---------------------------------------------------------------------------*/
 
     pte_val = get_page_table_entry(address & PAGE_MASK); // The page has been materialized, then pte_val should be != 0
     if (pte_val == (unsigned long)0)
     {
         printk(KERN_ERR "%s: (page_not_fetched_yet) Error getting pte_val\n", MODULE_NAME);
         return NULL;
     }
 
     orig_exe_bit = test_bit(ORIG_EXE_BIT, &pte_val);
     exe_deny_bit = test_bit(EXE_DENY_BIT, &pte_val);
 
     /**
      * Here exe_deny_bit should be equal to 1. The page has not been fetched yet. The processor has generated an invalid opcode trap instead of a normal instruction fetch.
      * If exe_deny_bit is equal to 0 (might be impossible), then the page has been already opened and checked in the force_sig_fault krpober.
      * However, the page for an unkown reason has not been registered in the hash table
      */
     if (exe_deny_bit == false || (exe_deny_bit && orig_exe_bit))
     {
 
         AUDIT printk(KERN_INFO "%s: (page_not_fetched_yet) The page %lx is X\n", MODULE_NAME, address & PAGE_MASK);
 
         if (vma && (vma->vm_flags & VM_SHARED))
             page_info = register_shared_page(page_data, address & PAGE_MASK);
         else
             page_info = register_private_page(page_data, address & PAGE_MASK); // Since we skip page check, and registration in handle_mm_fault kprober (if the fault has been generated by the kernel or not), we register the page here
 
         if (page_info == NULL)
         {
             printk(KERN_ERR "%s: (page_not_fetched_yet) Error registering page %lx\n", MODULE_NAME, address & PAGE_MASK);
             return NULL;
         }
 
         // printk(KERN_INFO "%s:  (page_not_fetched_yet) Closing the bytes outside the zone [%lx, %lx)\n", MODULE_NAME, address & PAGE_MASK, (address & PAGE_MASK) + PAGE_SIZE);
 
         ret = close_outer_zone(page_data, address & PAGE_MASK, (address & PAGE_MASK) + PAGE_SIZE, 1, vma); // Closing the whole page
         if (ret < 0)
         {
             printk(KERN_ERR "%s: (page_not_fetched_yet) Error closing the bytes outside the zone\n", MODULE_NAME);
         }
     }
     else
         return ERR_PTR(PAGE_NOT_EXE);
 
     AUDIT printk(KERN_INFO "%s: (page_not_fetched_yet) The page %lx will generate an IF fault but in the meantime it has already been opened and checked in the invalid_op_handler \n", MODULE_NAME, address & PAGE_MASK);
     return page_info;
 }
 
 /**
  * The function finds the first byte different from 0x0e in the page.
  *
  * @param start The start address.
  * @param page The page.
  *
  * @return the address of the first byte different from 0x0e, -1 otherwise.
  */
 static int find_first_invalid_opcode_byte(unsigned long __user start)
 {
 
     unsigned long start_offset = start & ~PAGE_MASK;
     unsigned long length = PAGE_SIZE - start_offset;
     int i = 0;
     char *k_page;
 
     k_page = kmalloc(length, GFP_ATOMIC);
     if (!k_page)
     {
         printk(KERN_ERR "%s: (find_first_invalid_opcpde_byte) Error: kmalloc failed\n", MODULE_NAME);
         return PAGE_END;
     }
 
     if (copy_from_user(k_page, (void *)start, length))
     {
         printk(KERN_ERR "%s: (find_first_invalid_opcpde_byte) Error: copy_from_user failed\n", MODULE_NAME);
         kfree(k_page);
         return PAGE_END;
     }
 
     for (i = 0; i < length; i++)
     {
         if (k_page[i] != INVALID_ONE_BYTE_OPCODE)
         {
             kfree(k_page);
             if (i == 0)
                 return PAGE_END;
             else
                 return start_offset + i;
         }
     }
 
     kfree(k_page);
     return PAGE_END; // Not found
 }

// ----------------------------------------------------------------------------------
#ifdef ZONE_KERNEL_SYNC_CHECK

int invalid_op_handler(struct fprobe *fp, unsigned long entry_ip,unsigned long ret_ip, struct pt_regs *regs,void *dt)
{
	/**
	 * static void do_error_trap(struct pt_regs *regs, long error_code, char *str, unsigned long trapnr, int signr, int sicode, void __user *addr)
	 */

	unsigned long trapnr = (unsigned long)regs_get_kernel_argument(regs, 3);
	unsigned long address = (unsigned long)regs_get_kernel_argument(regs, 6);
	int signr = (int)regs_get_kernel_argument(regs, 4);
	pid_t pid = current->tgid;

	unsigned long page_addr = address & PAGE_MASK;
	unsigned long base_addr = page_addr;
	unsigned long start_offset = address & ~PAGE_MASK;
	unsigned long end_offset = 0;
	unsigned long zone_size = 0;
	unsigned long off = 0;
	unsigned long start = address;
	unsigned long end = 0;
	unsigned long curr_open_end;

	struct open_zone *op_zone = NULL;
	struct page_info *page_info = NULL; // latest found page
	struct stats stats = {0};
	struct vm_area_struct *vma = NULL;
	spinlock_t* pte_lock;

	char *pages_data[MAX_PAGES] = {NULL}; // page data
	char *data = NULL;					  // Contiguous memory for at most MAX_PAGES pages

	int ret = 0;
	int next_zone_offset = 0;
	int num_pages = 0;
	int i = 0;
	int page_idx = 0;
	int num_of_blocks = 0;
	int pid_lock_idx = get_pid_bucket(pid, NUM_PID_BITS);
	int page_lock_idxs[MAX_PAGES] = {[0 ... MAX_PAGES - 1] = -1};
	unsigned long pages_not_fetched[MAX_PAGES] = {[0 ... MAX_PAGES - 1] = 0}; // Surely the first page has been fetched
#ifndef HOOKED_PROCESS_NAME
	unsigned char found = 0;
	struct hooked_pid_node* cur;
#endif
	
	if (address == 0)
	{
		AUDIT printk(KERN_INFO "%s: address is 0\n", MODULE_NAME);
		return 0;
	}

	/** --------------------------------------------------- Checking if trapnr is X86_TRAP_UD------------------------------------------------------------*/

	if (trapnr != X86_TRAP_UD) // 6 is the trap number for invalid opcode
	{
		AUDIT printk(KERN_INFO "%s: trapnr != X86_TRAP_UD\n", MODULE_NAME);

		if (signr == SIGILL) // 4 is the signal number for illegal opcode
		{
			printk(KERN_INFO "%s: signr == SIGILL\n", MODULE_NAME);
			goto handle;
		}

		return 0;
	}

	/** --------------------------------------------------- Opening a zone ------------------------------------------------------------*/

handle:

	// check if its in hiicked list and take out last zone opened
	hash_for_each_possible(hooked_pids, cur, node, current->pid) {
		if (cur->pid == current->pid) {
			found = 1;
			break;
		}
	}
	if (!found)
		return 0;

	DEBUG_INFO printk(KERN_INFO "%s: (invalid_op_handler) Opening a new zone in the page %lx from %lx for %d (%s)\n", MODULE_NAME, address & PAGE_MASK, address, pid, current->comm);

	while (++num_pages <= MAX_PAGES) // To avoid infinite loop
	{
		page_idx = num_pages - 1;

		page_info = find_current_page(page_addr); // Indexing based on the process pid

		if (page_info == NULL)
		{
			DEBUG_INFO printk(KERN_INFO "%s: (invalid_op_handler) Error finding page_info: page is %lx, pid is %d and comm is %s\n", MODULE_NAME, page_addr, pid, current->comm);

			/**------------------------------------------------------- The page is mapped in the address space of the process ? ---------------------------------------------------------------------*/

			mmap_read_lock(current->mm);
			vma = find_vma(current->mm, page_addr); // The vma of the next page. It's necessary in close_outer_zone if the page is not COW, shared and not writable. In that case get_user_pages will fail
			mmap_read_unlock(current->mm);

			if (!vma)
			{
				AUDIT printk(KERN_INFO "%s: (invalid_op_handler) page not mapped %lx\n", MODULE_NAME, address & PAGE_MASK);
				goto error_exit;
			}

			/**
			 * For the current process the PTE is stale: It could be that the XD_BIT is 1 because the page has been already opened by another process in force_sig_fault kprober.
			 * It should happen only for the shared pages.
			 * If the inherited page is private, then the invalid op-code fault is caused if and only if the current process has had an instruction fetch fault.
			 * For this reason, PTE cannot be stale.
			 */
			pages_not_fetched[page_idx] = page_addr;
			pid_lock_idx = get_pid_bucket(pid, NUM_PID_BITS); // If the page is private

			/**
			 * There are two cases:
			 * 
			 * 1) The instruction fetch fault has been already generated in the force_sig_fault kprober by another process. The page has been already registered in the hash table, for example in the parent process bucket
			 * 2) The page has not been fetched yet.
			 */

			/**------------------------------------------------------ The page is shared and current sharing process has not registered yet the page ----------------------------------------------*/
			if (vma->vm_flags & VM_SHARED)
			{
				page_info = page_shared_not_registered_yet(page_addr);

				if (page_info)
					goto page_found;

				pid_lock_idx = get_shared_page_bucket(NUM_PID_BITS);
			}

			/**-------------------------------------------------------- The page has been fetched before the fork (for example main pages could be already opened) -------------------------------------------*/

			/**
			 * Searching in the parent process PID bucket. The page has been already fetched by the parent process and it has been inherited by the child process.
			 */

#ifdef HOOKED_PROCESS_NAME
			if (strstr(current->real_parent->comm, HOOKED_PROCESS_NAME) != NULL)
			{
				page_info = register_page_fetched_before_fork(page_addr, vma);
				if (page_info)
					goto page_found;
			}
#else
			hash_for_each_possible(hooked_pids, cur, node, current->pid) {
				if (cur->pid == current->pid) {
					found = 1;
					break;
				}
			}
			if (found) {
				page_info = register_page_fetched_before_fork(page_addr, vma);
				if (page_info)
					goto page_found;
			}
#endif
			
			
			/**-------------------------------------------------------- Brute search on the whole page hash table -------------------------------------------*/
			/**
			 * This case if for consistency reasons. It should never happen.
			 * If a child process inherits a page from the parent process, then the PTE of the page should be the same in both address spaces.
			 * -) If the page inherited is private, then the current process should have already opened a zone in that page in the force_sig_fault kprober.
			 * -) If the page inherited is shared and an invalid opcode trap is generated instead of a normal instruction fetch then the page has been found in page_shared_not_registered_yet.
			 */

			// page_info = brute_search_and_register(page_addr, vma);
			// if (page_info)
			// 	goto page_found;

			/**-------------------------------------------------------- The following page has not been fetched yet, locking the page ---------------------------------------------------------------------------------------*/
			LOCK
			{
				if (!(vma->vm_flags & VM_SHARED) && thread_group_empty(current))
					goto skip_lock_2;

				page_lock_idxs[page_idx] = get_page_bucket(page_addr, NUM_PAGE_BITS);

				for (i = 0; i < page_idx; i++)
				{
					if (page_lock_idxs[i] == -1)
						continue;
					if (page_lock_idxs[i] == page_lock_idxs[page_idx]) // To avoid reacquiring the lock for pages that hashes to the same bucket
						goto skip_lock_2;
				}

				// printk(KERN_CRIT "%s: (invalid_op_handler) The [%s] pid %d (%d) is locking (%d, %d) on the page (not fetched) %lx\n", MODULE_NAME, current->comm, pid, current->pid, pid_lock_idx, page_lock_idxs[page_idx], page_addr);

				lock(pid_lock_idx, page_lock_idxs[page_idx], "invalid_op_handler", page_addr);

			skip_lock_2:
			}

			// cross-page
			page_info = page_not_fetched_yet(page_addr, vma); // Surely the first page has been fetched, the others could be not already fetched

			if (!IS_ERR_OR_NULL(page_info))
			{
				page_checked++;

				goto found_page_already_locked;
			}

			else
			{
				if (IS_ERR(page_info)) {
					AUDIT printk(KERN_INFO "%s: (invalid_op_handler) The page %lx is not X or WX\n", MODULE_NAME, page_addr);
				} else {
					AUDIT printk(KERN_ERR "%s: (invalid_op_handler) Error handling page not fetched yet: page is %lx, pid is %d and comm is %s\n", MODULE_NAME, page_addr, pid, current->comm);
				}	
			}

			if (num_pages > 1)
			{
				num_pages--;
				break;
			}
			else
				goto error_exit;
		}

	page_found:

		LOCK
		{
			/**
			 * If the VMA is not shared and the thread group is empty then the page is not shared between different processes and no other thread is accessing the page.
			 * So we don't need to acquire the lock for multi-threading and multi-process support.
			 */
			if (!page_info->is_shared && thread_group_empty(current))
				goto skip_lock_1;
			/**---------------------------------------------------- Locking the found page --------------------------------------------------------------------------*/
			if (page_info->is_shared)
				pid_lock_idx = get_shared_page_bucket(NUM_PID_BITS);

			page_lock_idxs[page_idx] = get_page_bucket(page_addr, NUM_PAGE_BITS);

			// printk(KERN_CRIT "%s: (invalid_op_handler) The [%s] pid %d (%d) is locking (%d, %d) the page %lx\n", MODULE_NAME, current->comm, pid, current->pid, pid_lock_idx, page_lock_idxs[page_idx], page_addr);

			lock(pid_lock_idx, page_lock_idxs[page_idx], "invalid_op_handler", page_addr);

		skip_lock_1:
		}

	found_page_already_locked:
		// if (page_info->address != page_addr) // Consistency check
		// {
		// 	printk(KERN_ERR "%s: (invalid_op_handler) page_info->address != page_addr\n", MODULE_NAME);
		// 	goto error_exit;
		// }

		if (page_info->data == NULL) // Consistency check
		{
			printk(KERN_ERR "%s: (invalid_op_handler) page_info->data is NULL\n", MODULE_NAME);
			goto error_exit;
		}

		pages_data[num_pages - 1] = page_info->data;

		if (num_pages > 1)
		{
			if (!handle_cross_page(pages_data[num_pages - 1], pages_data[num_pages - 2], end_offset, &start_offset, &stats))
			// Computes the starting instruction aligned offset in the following page
			{
				printk(KERN_ERR "%s: (invalid_op_handler) Error handling cross page\n", MODULE_NAME);
				num_pages--;
				break;
			}
		}

		// Computing end_offset in the current page to avoid reopening a previously opened zone
		next_zone_offset = find_first_invalid_opcode_byte(page_addr + start_offset);

	find_another_block:

		start = (unsigned long)page_info->data + start_offset;
		end = (unsigned long)page_info->data + ((next_zone_offset == PAGE_END) ? PAGE_SIZE : next_zone_offset);

		ret = disassemble_code(start, &end, &stats); // Fast disassembly

		if (end == start)
		{
			DEBUG_INFO printk(KERN_INFO "%s: (invalid_op_handler) the disassembler started (immediatly) from a cross-page instruction\n", MODULE_NAME);
		}

		end_offset = end - (unsigned long)page_info->data;

		if (ret == DISASSEMBLE_ERROR)
		{
			/**
			 * if disassembler fails the sync check should occur on the whole page. If I restore the entire page there is the risk of cutting the cross-page instruction
			if the next page has been opened in a zone and the inserted invalid op-codes (0x0E) are considered by the processor as operands.*/

			printk(KERN_ERR "%s: (invalid_op_handler) An error has occurred in searching JMP/Jcc/CALL/RET instructions\n", MODULE_NAME);
			goto restore_page;
		}

		else if (ret == DISASSEMBLE_CONTINUE)
		{
			AUDIT printk(KERN_INFO "%s: (invalid_op_handler) JMP/Jcc/CALL/RET not found in [%lx, %lx]\n", MODULE_NAME, page_addr + start_offset, page_addr + end_offset);

			if (next_zone_offset != PAGE_END) // next_zone_offset == PAGE_END means that the page should be disassembled until the end. No zone previously opened until the end of the page
			{
				if (next_zone_offset == end_offset)
				{
					DEBUG_INFO printk(KERN_INFO "%s: (invalid_op_handler) Correctly joined areas\n", MODULE_NAME);
				}
				else
				{ // Consistency check if the disassembler fails
					printk(KERN_ERR "%s: (invalid_op_handler) Incorrectly joined areas\n", MODULE_NAME);
					end = (unsigned long)page_info->data + next_zone_offset;
				}

				break;
			}

			if (!(PAGE_ALIGNED(page_addr + end_offset))) // If the end of the page is not reached then it contains a cross-page instruction
			{
				// printk(KERN_INFO "%s: (invalid_op_handler) Pages %lx - %lx contains a cross-page instruction\n", MODULE_NAME, page_addr, page_addr + PAGE_SIZE);
				//  page_addr is the current page
				register_page_cross_pages_integrity(page_addr, PARTIALLY_OPENED_END);
				register_page_cross_pages_integrity(page_addr + PAGE_SIZE, PARTIALLY_OPENED_START);
			}

			if (num_pages >= MAX_PAGES)
			{
				AUDIT printk(KERN_INFO "%s: (invalid_op_handler) Avoiding infinite loop\n", MODULE_NAME);
				break;
			}

			/**-------------------------------------------------------------------- Continuing the search in the next page -----------------------------------------------------------------------------*/

			page_addr += PAGE_SIZE; // The start of the next page

			DEBUG_INFO printk(KERN_INFO "%s: (invalid_op_handler) Continuing the search in the next page %lx\n", MODULE_NAME, page_addr);
		}

		else if (ret & DISASSEMBLE_SUCCESS)
		{
			num_of_blocks++;
			AUDIT printk(KERN_INFO "%s: (invalid_op_handler) JMP/Jcc/CALL/RET found in [%lx, %lx] and num_of_contiguous_block = %d\n", MODULE_NAME, page_addr + start_offset, page_addr + end_offset, num_of_blocks);

			if (num_pages >= MAX_PAGES) // Over the limit of the number of pages
			{
				AUDIT printk(KERN_INFO "%s: (invalid_op_handler) Avoiding infinite loop\n", MODULE_NAME);
				break;
			}

			if (num_of_blocks == num_of_contiguous_block)
			{
				AUDIT printk(KERN_INFO "%s: (invalid_op_handler) num_of_blocks == num_of_contiguous_block\n", MODULE_NAME);
				break;
			}

			if ((ret & JMP_SUCCESS) || (ret & RET_SUCCESS)) // The disassembler found a JMP or RET instruction
			{
				AUDIT printk(KERN_INFO "%s: (invalid_op_handler) The disassembler found a JMP or RET instruction\n", MODULE_NAME);
				//break;
			}

			if (end_offset == PAGE_SIZE) // Sono arrivato alla fine della pagina
			{
				// printk(KERN_INFO "%s: (invalid_op_handler) There aren't enough zones until the end of the page, continuing in the next page\n", MODULE_NAME);
				page_addr += PAGE_SIZE; // The start of the next page
				continue;				// Continue the search in the next page
			}

			if (next_zone_offset != PAGE_END && next_zone_offset == end_offset) // Sono arrivato al ricongiungimento delle aree
			{
				// printk(KERN_INFO "%s: (invalid_op_handler) There aren't enough zones until the next one starts\n", MODULE_NAME);
				end = (unsigned long)page_info->data + next_zone_offset;
				break;
			}

			// Updating the offsets
			start_offset = end_offset;
			goto find_another_block;
		}
	}

	// Re-computing variables

	start_offset = address & ~PAGE_MASK;
	end_offset = end - (unsigned long)pages_data[num_pages - 1];

	start = address;											// user space start address
	end = base_addr + (num_pages - 1) * PAGE_SIZE + end_offset; // user space end address
	zone_size = end - start;

	/** --------------------------------------------------- Restore zone bytes in the user pages ------------------------------------------------------------*/

	if (end < start) // Consistency check
	{
		printk(KERN_ERR "%s: (invalid_op_handler) end < start\n", MODULE_NAME);
		goto error_exit;
	}

	if (end == start)
	{
		/**
		 * The disassembler started (immediatly) from a cross-page instruction and the IF fault has not already happened in that page since
		 * the processor has not fetched the first byte of the cross-page instruction.
		 */
		printk(KERN_ERR "%s: (invalid_op_handler) end == start\n", MODULE_NAME);
		end = PAGE_ALIGN_UP(end);
	}

	/** --------------------------------------------------- Allocating contiguos memory for the zone content ------------------------------------------------------------*/

	if (num_pages == 1) // The zone is whitin a page
		data = pages_data[0] + start_offset;

	else // num_pages > 1
	{
		data = kmalloc(zone_size, GFP_ATOMIC); // Working on contiguous memory
		if (data == NULL)
		{
			printk(KERN_ERR "%s: (invalid_op_handler) Error allocating page data\n", MODULE_NAME);
			goto error_exit;
		}

		memcpy(data, pages_data[0] + start_offset, PAGE_SIZE - start_offset);
		off = PAGE_SIZE - start_offset;

		for (i = 1; i < num_pages - 1; i++) // Copying the zone in contiguos memory
		{
			memcpy(data + off + (i - 1) * PAGE_SIZE, pages_data[i], PAGE_SIZE);
			off += PAGE_SIZE;
		}

		memcpy(data + off, pages_data[i], end_offset);
	}

	/** --------------------------------------------------- Sync check ------------------------------------------------------------*/

	zone_checked++;
#ifdef SYNC_CHECK
	if (!run_kernel_check(data, start, end))
	{
		printk(KERN_ERR "%s: (invalid_op_handler) failed sync check\n", MODULE_NAME);
		goto error_exit;
	}
#endif
	/** --------------------------------------------------- Checking bytes limit------------------------------------------------------------*/
	if (check_bytes_limit(current->real_cred->uid, zone_size))
	{
		printk(KERN_ERR "%s: (invalid_op_handler) over the limit - dont transfer\n", MODULE_NAME);
		goto error_exit;
	}

	/** ----------------------------------------------------- Close old zone ------------------------------------ **/
	
#if(ONE_OPEN_ZONE == 1)

	if (cur->open_start != cur->open_end) {
		ret = close_inner_zone(cur->open_start, cur->open_end, num_pages);
		if (ret < 0) {

			printk(KERN_ERR "%s: (invalid_op_handler) Error closgin previous zone bytes with error_code %d\n", MODULE_NAME, ret);

		}
	}
#endif

	/** ----------------------------------------------------- Restore new zone ------------------------------------ **/

	op_zone = create_zone(data, start, end, num_pages, true, &stats); // For asynchronous checks
	if (op_zone == NULL)
	{
		printk(KERN_ERR "%s: (invalid_op_handler) Error transferring zone to user\n", MODULE_NAME);
	}

	ret = restore_zone_bytes(data, start, end, num_pages);
	if (ret < 0)
	{
		printk(KERN_ERR "%s: (invalid_op_handler) Error restoring zone bytes with error_code %d\n", MODULE_NAME, ret);

		if (ret == ALL_INVALID_ONE_BYTE_OPCODE)
			goto error_exit;
		else
			goto restore_page;
	}
	//page_info->opened += end - start; // update opened bytes
	//AUDIT printk(KERN_INFO "%s: (invalid_op_handler) page_info: %lx\n", page_info);

#if(ONE_OPEN_ZONE == 1)
	cur->open_start = start;
	cur->open_end = end;
#endif

exit:

	for (i = 0; i < num_pages; i++)
	{
		if (pages_not_fetched[i] != 0)
		{

			AUDIT printk(KERN_INFO "%s: (invalid_op_handler) The page %lx has been already opened and checked in the invalid_op_handler, the first fetch fault is not needed\n", MODULE_NAME, pages_not_fetched[i]);
			/**
			 * The following only X or WX page will generate a SIGSEGV when the zone will be restored but the page has been already opened in a zone, closed and checked.
			 * Then we don't need to check it again.
			 */

			pte_lock = get_pte_lock(current->mm, pages_not_fetched[i]);

			spin_lock(pte_lock);

			flip_bit(pages_not_fetched[i], EXE_DENY_BIT, 0);
			shared_flip_bit(vma, pages_not_fetched[i], EXE_DENY_BIT, 0);

			if (vma && vma->vm_flags & VM_WRITE) // The page fetched is WX
			{
				flip_bit(pages_not_fetched[i], WRITE_BIT, 0);
				flip_bit(pages_not_fetched[i], ORIG_WRITE_BIT, 1);

				shared_flip_bit(vma, pages_not_fetched[i], WRITE_BIT, 0);
			}

			flip_bit(pages_not_fetched[i], CHECK_DENY_BIT, 1); // The page is marked as WE_CHECK_DENY_BIT to avoid the check in the force_sig_fault krpober

			spin_unlock(pte_lock);

			if (!thread_group_empty(current))
				on_each_cpu((smp_call_func_t)__flush_tlb_one_user, (void *)(pages_not_fetched[i]), true);
			else
				on_each_cpu((smp_call_func_t)__flush_tlb_one_user, (void *)(pages_not_fetched[i]), false);
			
		}
	}

	LOCK
	{
		for (i = MAX_PAGES - 1; i >= 0; i--)
		{
			unlock(pid_lock_idx, page_lock_idxs[i], "invalid_op_handler", base_addr + i * PAGE_SIZE);
		}
	}

	current->flags |= INVALID_OP_HANDLED_FLAG;

	if (data != NULL && num_pages > 1)
		kfree(data);

	return 0;

error_exit:

	printk(KERN_ERR "%s: invalid op-code handled unsuccessfully\n", MODULE_NAME);

	LOCK
	{
		for (i = MAX_PAGES - 1; i >= 0; i--)
		{
			unlock(pid_lock_idx, page_lock_idxs[i], "invalid_op_handler", base_addr + i * PAGE_SIZE);
		}
	}

	if (data != NULL && num_pages > 1)
		kfree(data);


	return 0; // So that the program will fault. handler not skipped in sig_handler

restore_page:

	unsigned char compare_value[QWORD_SIZE + 1] = {[0 ... QWORD_SIZE] = INVALID_ONE_BYTE_OPCODE}; // Max operand size is 8 bytes

	start = address & PAGE_MASK;
	end = (address & PAGE_MASK) + PAGE_SIZE;

	printk(KERN_ERR "%s: (invalid_op_handler) Restoring the whole page %lx\n", MODULE_NAME, start);

	if (memcmp(pages_data[0] + start_offset, compare_value, QWORD_SIZE + 1) == 0)
	{
		printk(KERN_ERR "%s: (invalid_op_handler) Trying to restore page %lx that contains 0x0E\n", MODULE_NAME, page_addr);
		goto error_exit;
	}

/** --------------------------------------------------- Restoring whole page ------------------------------------------------------------*/
#ifdef SYNC_CHECK
	if (!run_kernel_check(pages_data[0], start, end))
	{
		printk(KERN_ERR "%s: (invalid_op_handler) failed sync check\n", MODULE_NAME);
		goto error_exit; // if we return here the program will seg fault
	}
#endif
	/** --------------------------------------------------- Checking bytes limit------------------------------------------------------------*/
	if (check_bytes_limit(current->real_cred->uid, PAGE_SIZE))
	{
		printk(KERN_ERR "%s: (invalid_op_handler) over the limit - dont transfer\n", MODULE_NAME);
		goto error_exit; // if we return here the program will seg fault
	}

	op_zone = create_zone(pages_data[0], start, end, 1, false, NULL); // For asynchronous checks
	if (op_zone == NULL)
	{
		printk(KERN_ERR "%s: (invalid_op_handler) Error transferring zone to user\n", MODULE_NAME);
	}

	ret = restore_page(start);

	if (ret < 0)
	{
		printk(KERN_ERR "%s: (invalid_op_handler) Error restoring page\n", MODULE_NAME);
		goto error_exit;
	}

	register_page_cross_pages_integrity(start, PARTIALLY_OPENED_START | PARTIALLY_OPENED_END); // Page completely restored

	// AUDIT printk(KERN_INFO "(invalid_op_code) Allowind exe on copmletely resotered page\n");
	// pages_not_fetched[0] = start;

	goto exit;
}
#endif
