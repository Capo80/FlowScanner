#include "utils.h"

void return_function(void)
{
    return;
}

void print_registers(struct pt_regs *regs)
{
    printk(KERN_INFO "Registers dump:\n");
    printk(KERN_INFO "%s: ax: %lx, bx: %lx, cx: %lx, dx: %lx\n", MODULE_NAME, regs->ax, regs->bx, regs->cx, regs->dx);
    printk(KERN_INFO "%s: si: %lx, di: %lx, bp: %lx, sp: %lx\n", MODULE_NAME, regs->si, regs->di, regs->bp, regs->sp);
    printk(KERN_INFO "%s: r8: %lx, r9: %lx, r10: %lx, r11: %lx\n", MODULE_NAME, regs->r8, regs->r9, regs->r10, regs->r11);
    printk(KERN_INFO "%s: r12: %lx, r13: %lx, r14: %lx, r15: %lx\n", MODULE_NAME, regs->r12, regs->r13, regs->r14, regs->r15);
    printk(KERN_INFO "%s: ip: %lx, flags: %lx\n", MODULE_NAME, regs->ip, regs->flags);
}

/**
 * The function gets the current process name.
 * @param path The path of the process.
 * @return The process name.
 */
char *get_basename(const char *path)
{
    char *base = strrchr(path, '/');
    return base ? base + 1 : (char *)path;
}

/**
 * The function converts a string of hexadecimal characters to a byte array.
 *
 * @param str The string to convert.
 * @param bytes The byte array.
 * @param num_bytes The number of bytes of the string.
 *
 * @return void
 */

void hex_string_to_bytes(const char *str, uint8_t *bytes, size_t num_bytes)
{
    size_t i;
    for (i = 0; i < num_bytes; ++i)
    {
        sscanf(str + 2 * i, "%2hhx", &bytes[i]);
    }
}

/**
 * The function converts a byte array to a string of hexadecimal characters.
 *
 * @param bytes The byte array.
 * @param num_bytes The number of bytes of the string.
 * @param hex_str The string to convert.
 *
 * @return void
 */
void bytes_to_hex_string(const uint8_t *bytes, size_t num_bytes, char *hex_str)
{
    size_t i;
    for (i = 0; i < num_bytes; ++i)
    {
        sprintf(hex_str + 2 * i, "%02x", bytes[i]);
    }
}

/**
 * @brief Do a bit flip on all shared mappings bit to flip is put in AND with current bit
 * 
 * @param vma vm area of the page to flip bit from
 * @param vaddr addr to flip the bit
 * @param bit_position bit to flip
 * @param set bit value
 */
void shared_flip_bit(struct vm_area_struct* vma, unsigned long vaddr, unsigned char bit_position, unsigned char set) {

    struct shared_map_hash_node* curr = NULL;
    struct list_head* pt_pos = NULL;
    struct page_table_node* pt_node = NULL;

#ifndef SHARED_DEFENCE
    return;
#endif
    //SHARED_DEBUG printk("(shared_flip_bit) searching for vma=%lx, vm_start=%lx\n", vma, vma->vm_start);
    hash_for_each_possible(shared_map_hash, curr, node, (unsigned long) vma) {
        //SHARED_DEBUG printk("(shared_flip_bit) found shared to flip\n");


        list_for_each(pt_pos, &curr->page_tables) {

            pt_node = list_entry(pt_pos, struct page_table_node, node);

            //SHARED_DEBUG printk("(shared_flip_bit) found page table %lx\n", pt_node->pgd);

            if (pt_node->pgd != vma->vm_mm->pgd) {
                if (set == 0 || (bit_position == EXE_DENY_BIT && set == 1)) {
                    SHARED_DEBUG printk("(shared_flip_bit) flipping page table %lx to 0 (or exe to 1)\n", (unsigned long) pt_node->pgd);
                
                    flip_bit_on_other(pt_node->pgd, vaddr, bit_position, set);
                } else {
                    if (is_bit_set_on_other(pt_node->pgd, vaddr, bit_position) || (bit_position == EXE_DENY_BIT && !is_bit_set_on_other(pt_node->pgd, vaddr, bit_position))) {

                        SHARED_DEBUG printk("(shared_flip_bit) flipping page table %lx to 1\n", (unsigned long) pt_node->pgd);
                
                        flip_bit_on_other(pt_node->pgd, vaddr, bit_position, set);
                    }
                }
            }
        }
    }
                    

}


/**
 * The function writes a page content on a not writable user page.
 *
 * @param user_vaddr The user virtual address.
 * @param data The page data to write.
 * @param num_pages The number of pages to write.
 * @param mmap_locked If the mmap_sem is locked or not.
 *
 * @return 0 on success, a negative value otherwise.
 */
int write_pages_on_not_writable_user_pages(unsigned long user_vaddr, char *data, int num_pages, struct vm_area_struct *vma)
{

    unsigned long kaddr[MAX_PAGES] = {0};
    unsigned long page_addr = user_vaddr & PAGE_MASK;
    unsigned int gup_flags = FOLL_FORCE | FOLL_WRITE | FOLL_GET;
    struct page *pages[MAX_PAGES] = {NULL};
    int ret = 0;
    int ref_counter = 0;
    int i = 0;
    int j = 0;

    AUDIT printk(KERN_INFO "%s: (write_pages_on_not_writable_user_pages) Writing %d pages on starting user virtual address %lx\n", MODULE_NAME, num_pages, user_vaddr);

    if (vma)
    {
        AUDIT
        {
            printk(KERN_INFO "%s: (write_pages_on_not_writable_user_pages) VMA flags for page %lx: %lx\n", MODULE_NAME, page_addr, vma->vm_flags);

            if (vma->vm_file != NULL)
            {
                printk(KERN_INFO "%s: (write_pages_on_not_writable_user_pages) vm_area is mapped to file %s\n", MODULE_NAME, vma->vm_file->f_path.dentry->d_iname); // For php is /dev/zero
            }
        }

        if (!(vma->vm_flags & VM_WRITE) && !is_cow_mapping(vma->vm_flags))
        {
            AUDIT printk(KERN_INFO "%s: (write_pages_on_not_writable_user_pages) The vma is not COW because the page is shared. The page is not writable too then get_user_pages return -EFAULT\n", MODULE_NAME);

            /**
             * PHP CASE:
             * The vma is not COW because the page is shared and not writable.
             *
             * FILE: mm/gup.c, FUNCTION: check_vma_flags, LINE: 10023:
             *
             * if (write) { //write = (gup_flags & FOLL_WRITE);
             *   if (!(vm_flags & VM_WRITE)) {
             *      if (!(gup_flags & FOLL_FORCE))
             *          return -EFAULT;
             *      if (!is_cow_mapping(vm_flags)) <-- HERE return -EFAULT; (php case)
             *           return -EFAULT;
             *    }
             * }*/

            gup_flags &= ~FOLL_WRITE; // The page is not writable
        }
    }

    ret = get_user_pages_fast(page_addr, num_pages, gup_flags, pages);

    /**
     * In the documentation: We used to let the write, force case do COW in VM_MAYWRITE VM_SHARED !VM_WRITE vma
     *
     * If the page is Copy-On-Write (COW) and the FOLL_FORCE and FOLL_WRITE flags are passed, the page is indeed duplicated.
     * This is done to maintain isolation between processes, so that one process cannot accidentally modify another process's data.
     * If a page it's shared, the COW mechanism is not triggered and the page is not duplicated.
     *
     * Internally, if it's a faulting page (FILE: mm/gup.c, FUNCTION: __get_user_pages, LINE: 1197 --> faultin_page ()), handle_mm_fault is called by faultin_page().
     * In handle_pte_fault() called by __handle_mm_fault (), if a WRITE_FAULT is detected, and the pte is not writable, the COW mechanism is triggered (do_wp_page ())
     *
     *
     * ret = get_user_pages(page_addr, NR_PAGES, FOLL_FORCE | FOLL_WRITE, pages, &vma):
     *
     * If a page is originally COW, thanks to get_user_pages with FOLL_FORCE and FOLL_WRITE, the page is duplicated and not shared anymore in the address space of the processes.
     * So, from now on the page is as if it were private*/

    if (ret == num_pages)
    {

        for (i = 0; i < num_pages; i++)

        {
            if (!pages[i]) // Consistency check
            {
                printk(KERN_ERR "%s: (write_pages_on_not_writable_user_pages) Error: page %d is NULL\n", MODULE_NAME, i);
                goto error;
            }

            ref_counter = page_mapcount(pages[i]); // The number of page-table that refer to the page

            if (ref_counter - 1 > 1) // Number of processes sharing the page
            {
                AUDIT printk(KERN_INFO "%s: (write_pages_on_not_writable_user_pages) Page at virtual address %lx is shared with %d references\n", MODULE_NAME, page_addr + i * PAGE_SIZE, ref_counter);
            }

            /**
             * kmap_local_page_prot è simile a kmap, ma restituisce una mappatura locale che è valida solo per il contesto del chiamante
             * e deve essere rilasciata con kunmap_local non appena possibile.
             * Questa funzione è utile per le operazioni che richiedono una mappatura temporanea e che possono liberare la mappatura immediatamente dopo l'uso.
             * Inoltre, kmap_local_page_prot consente di specificare le protezioni per la pagina mappata.
             */

            kaddr[i] = (unsigned long)kmap_local_page(pages[i]);
            if (!kaddr[i])
            {
                printk("%s: (write_pages_on_not_writable_user_pages) kmap failed\n", MODULE_NAME);
                goto error;
            }
        }

        for (i = 0; i < num_pages; i++)
        {

            //flip_bit(kaddr[i], WRITE_BIT, 1);

            AUDIT printk(KERN_INFO "%s: (write_pages_on_not_writable_user_pages) page\n", MODULE_NAME);
            //print_hex_dump(KERN_INFO, "Restoring: ", DUMP_PREFIX_NONE, 16, 1, data + i*PAGE_SIZE, PAGE_SIZE, false);
                    
            // Copy the data
            memcpy((void *)kaddr[i], data + i * PAGE_SIZE, PAGE_SIZE);
            flush_dcache_page(pages[i]);

            kunmap_local((void *)kaddr[i]);

            put_page(pages[i]);
        }

        flush_icache_user_range(page_addr, page_addr + num_pages * PAGE_SIZE);
    }

    else
    {
        printk(KERN_ERR "%s: (write_pages_on_not_writable_user_pages) get_user_pages for addr %lx failed with error %d\n", MODULE_NAME, user_vaddr, ret);
        return -EFAULT;
    }

    AUDIT printk(KERN_INFO "%s: (write_pages_on_not_writable_user_pages) %d pages successfully written\n", MODULE_NAME, num_pages);
    return 0;

error:
    for (j = 0; j < i; j++)
    {
        if (kaddr[j])
            kunmap_local((void *)kaddr[j]);

        if (pages[j])
            put_page(pages[j]);
    }

    return -EFAULT;
}

/**
 * The function writes a zone content on a not writable user page.
 *
 * @param data The zone data to write.
 * @param start The start address of the zone.
 * @param end The end address of the zone.
 * @param num_pages The number of pages to write.
 * @param mmap_locked If the mmap_sem is locked or not.
 *
 * @return 0 on success, a negative value otherwise.
 */
int write_zone_on_not_writable_user_pages(char *data, unsigned long start, unsigned long end, int num_pages)
{

    unsigned long kaddr[MAX_PAGES] = {0};
    unsigned long page_addr = start & PAGE_MASK;
    unsigned long start_offset = start & ~PAGE_MASK;
    unsigned long end_offset = end & ~PAGE_MASK;
    unsigned long off = 0;
    unsigned long gup_flags = FOLL_FORCE | FOLL_GET;
    unsigned long zone_size = end - start;
    struct page *pages[MAX_PAGES] = {NULL};
    int ret = 0;
    int ref_counter = 0;
    int i = 0;
    int j = 0;
    int iter = 0;

    AUDIT printk(KERN_INFO "%s: (write_zone_on_not_writable_user_pages) pid %d (%d) is writing an opened zone of size 0x%lx on starting user virtual address %lx\n", MODULE_NAME, current->tgid, current->pid, zone_size, start);

    /**
     * Here all the COW pages are duplicated and not shared anymore in the address space of the processes. See write_pages_on_not_writable_user_pages for more details.
     */

retry:
    ret = get_user_pages_fast(page_addr, num_pages, gup_flags, pages); // If it's CoW the page has been duplicated and not shared anymore. So, the page is private and writable.

    if (ret == num_pages)
    {
        for (i = 0; i < num_pages; i++)
        {
            if (!pages[i]) // Consistency check
            {
                printk(KERN_ERR "%s: (write_zone_on_not_writable_user_pages) Error: page %d is NULL\n", MODULE_NAME, i);
                goto error;
            }

            ref_counter = page_mapcount(pages[i]); // The number of page-table that refer to the page

            if (ref_counter - 1 > 1) // Number of processes sharing the page
            {
                AUDIT printk(KERN_INFO "%s: (write_zone_on_not_writable_user_pages) Page at virtual address %lx is shared with %d references\n", MODULE_NAME, page_addr + i * PAGE_SIZE, ref_counter);
            }

            /**
             * kmap_local_page_prot è simile a kmap, ma restituisce una mappatura locale che è valida solo per il contesto del chiamante
             * e deve essere rilasciata con kunmap_local non appena possibile.
             * Questa funzione è utile per le operazioni che richiedono una mappatura temporanea e che possono liberare la mappatura immediatamente dopo l'uso.
             * Inoltre, kmap_local_page_prot consente di specificare le protezioni per la pagina mappata.
             */

            kaddr[i] = (unsigned long)kmap_local_page(pages[i]);
            if (!kaddr[i])
            {
                printk("%s: (write_zone_on_not_writable_user_pages) kmap failed\n", MODULE_NAME);
                goto error;
            }
        }

        // for (i = 0; i < num_pages; i++)
            // flip_bit(kaddr[i], WRITE_BIT, 1);

        if (num_pages == 1)
        {
            // Copy the data
            VM_BUG_ON(start_offset + zone_size > PAGE_SIZE);
            memcpy((void *)(kaddr[0] + start_offset), data, zone_size);
        }
        else // num_pages > 1
        {
            // Copy the data
            memcpy((void *)(kaddr[0] + start_offset), data, PAGE_SIZE - start_offset); // Copy the first page
            off = PAGE_SIZE - start_offset;

            for (j = 1; j < num_pages - 1; j++) // Copying the intermediate pages
            {
                memcpy((void *)kaddr[j], data + off + (j - 1) * PAGE_SIZE, PAGE_SIZE);
                off += PAGE_SIZE;
            }

            AUDIT printk(KERN_INFO "%s: (write_zone_on_not_writable_user_pages) last page copy user_addr=%lx size=%lx\n", MODULE_NAME, kaddr[j], end_offset);
            if (end_offset == 0) // we always have a page here, if offset is zero it means we have an entire page
                memcpy((void *)kaddr[j], data + off, PAGE_SIZE); // Copy the last page
            else
                memcpy((void *)kaddr[j], data + off, end_offset); // Copy the last page
         
        }

        for (i = 0; i < num_pages; i++)
        {
            flush_dcache_page(pages[i]);

            kunmap_local((void *)kaddr[i]);

            put_page(pages[i]);
        }

        flush_icache_user_range(page_addr, page_addr + num_pages * PAGE_SIZE);
    }

    else
    {
        printk(KERN_ERR "%s: (write_zone_on_not_writable_user_pages) get_user_pages for starting page %lx failed with error %d\n", MODULE_NAME, page_addr, ret);

        /**
         * EINTR:
         * if (fatal_signal_pending(current)) {	// The current process has a pending signal
         *      ret = -EINTR;
         *      goto out;
         * }

        * If we have a pending SIGKILL, don't keep faulting pages and
        * potentially allocating memory --> (FILE: mm/gup.c, FUNCTION: __get_user_pages, LINE: 1185)
        */

        if (ret == -EINTR)
        {
            gup_flags |= FOLL_NOFAULT;

            if (iter++ < 1)
                goto retry;
        }

        return -EFAULT;
    }

    AUDIT printk(KERN_INFO "%s: (write_zone_on_not_writable_user_pages) %d pages successfully written\n", MODULE_NAME, num_pages);
    return 0;

error:
    for (j = 0; j < i; j++)
    {
        if (kaddr[j])
            kunmap_local((void *)kaddr[j]);

        if (pages[j])
            put_page(pages[j]);
    }

    return -EFAULT;
}

/**
 * The function finds a ret instruction from start
 * @param start The start address of the function
 * @return the address of the ret instruction, -1 otherwise.

 */
// unsigned long find_ret(uint8_t *start)
unsigned long find_ret(void (*func_ptr)(void))
{
    uint8_t *start = (uint8_t *)func_ptr;
    uint8_t *cur = start;
    unsigned long num_prefixes = 0;
    unsigned long op_code_size = 1;
    int iter = 0;

    uint8_t modrm_byte = 0;
    uint8_t sib_byte = 0;
    uint8_t prefix_byte = 0;
    uint8_t m_mmmm_byte = 0;
    uint8_t *first_op = 0;
    uint8_t op = 0;

    bool rex_w_found = 0;
    bool evex_pref_found = 0;
    bool vex_pref_found = 0;
    bool multibyte = 0;
    bool has_modrm = 0;

    unsigned int ddef = DWORD_SIZE, mdef = DWORD_SIZE;
    unsigned int msize = 0, dsize = 0;
    unsigned long total_size = 0;
    int instruction_type = 0;

    DEBUG_INFO printk(KERN_INFO "%s: (find_ret) Searching ret instruction from %lx\n", MODULE_NAME, (unsigned long)start);

    if ((unsigned long)start == 0)
    {
        printk(KERN_ERR "%s: (find_ret) Error: start or end is 0\n", MODULE_NAME);
        return 0;
    }

    while (cur != NULL)
    {
        if (++iter > 1000)
        {
            printk(KERN_ERR "%s: (find_ret) Error: too many iterations\n", MODULE_NAME);
            goto error_exit;
        }

    found_prefixes:

        prefix_byte = *cur;

        if (CHECK_PREFIX(prefix_byte))
        {
            if (CHECK_EVEX(prefix_byte))
            {
                INSTRUCTION_INFO printk(KERN_INFO "%s: (find_ret) EVEX_PREFIX found\n", MODULE_NAME);
                num_prefixes += 4;
                evex_pref_found = 1;
                m_mmmm_byte = *(cur + 1);
                cur += 4;
                goto cont;
            }
            else if (CHECK_VEX_2(prefix_byte) || CHECK_VEX_3(prefix_byte))
            {
                INSTRUCTION_INFO printk(KERN_INFO "%s: (find_ret) VEX_PREFIX_%d found\n", MODULE_NAME, CHECK_VEX_2(prefix_byte) ? 2 : 3);
                num_prefixes += CHECK_VEX_2(prefix_byte) ? 2 : 3;
                vex_pref_found = 1;
                if (CHECK_VEX_3(prefix_byte))
                    m_mmmm_byte = *(cur + 1);
                cur += CHECK_VEX_2(prefix_byte) ? 2 : 3; // The VEX prefix is 2 or 3 bytes long.
                goto cont;
            }
            else if (CHECK_PREFIX_66(prefix_byte))
            {
                INSTRUCTION_INFO printk(KERN_INFO "%s: (find_ret) OPERAND_OVERRIDE_PREFIX found.\n", MODULE_NAME);
                ddef = WORD_SIZE;
                goto skip_byte;
            }
            else if (CHECK_PREFIX_67(prefix_byte))
            {
                INSTRUCTION_INFO printk(KERN_INFO "%s: (find_ret) ADDRESS_SIZE_OVERRIDE_PREFIX found.\n", MODULE_NAME);
                mdef = WORD_SIZE;
                goto skip_byte;
            }
        }

        else if (CHECK_REX(prefix_byte))
        {
            if (CHECK_REXW(prefix_byte))
                rex_w_found = 1;

            goto skip_byte;
        }

        else
            goto cont;

    skip_byte:

        ++cur;
        num_prefixes++;
        INSTRUCTION_INFO printk(KERN_INFO "%s: (find_ret) Found prefix %x\n", MODULE_NAME, prefix_byte);
        goto found_prefixes;

    cont:
        /**----------------------------------------------------- STARTING HERE -----------------------------------------------------------------------------*/

        op = *cur;      // The first byte of the op-code
        first_op = cur; // ptr to the first byte of the op-code

        /**--------------------------------------------------------------- VEX and EVEX --------------------------------------------------------------------------------------*/

        if (vex_pref_found) // 1 byte op-code
        {

            op_code_size = 1;

            INSTRUCTION_INFO printk(KERN_INFO "%s: (find_ret) Instruction is VEX\n", MODULE_NAME);

            if (CHECK_VEX_2(prefix_byte)) // The 2-byte VEX implies a leading 0Fh opcode byte), has no m_mmmm_byte
            {
                INSTRUCTION_INFO printk(KERN_INFO "%s: (find_ret) Instruction is 2 byte VEX\n", MODULE_NAME);

                if (VEX_NO_MODRM(op))
                    goto next;

                if (CHECK_VEX_0F_IMM8(op))
                {
                    INSTRUCTION_INFO printk(KERN_INFO "%s: (find_ret) Instruction is 2 byte VEX and has an imm8\n", MODULE_NAME);
                    dsize++; // For the imm8
                }

                goto check_mod_rm_byte;
            }
            // VEX with 3 byte prefix
            if (CHECK_m_mmmm_field(m_mmmm_byte) == _0F38)
            {
                if (CHECK_VEX_0F38(op))
                {
                    INSTRUCTION_INFO printk(KERN_INFO "%s: (find_ret) Instruction is 3 byte VEX and 0F38 n", MODULE_NAME);

                    if (CHECK_VEX_0F38_IMM8(op))
                    {
                        INSTRUCTION_INFO printk(KERN_INFO "%s: (find_ret) Instruction is 3 byte VEX and 0F38 and has an imm8\n", MODULE_NAME);
                        dsize++; // For the imm8
                    }
                }
                else
                {
                    PRINT_INSTR_ERROR
                    {
                        printk(KERN_INFO "%s: (find_ret) Instruction is 3 byte VEX and 0F38 but the op-code is not valid\n", MODULE_NAME);
                        print_hex_dump(KERN_INFO, "JIT: The op_code is (with prefix if exists): ", DUMP_PREFIX_NONE, 16, 1, cur - num_prefixes - (op_code_size - 1), num_prefixes + op_code_size, false);
                    }
                    goto error_exit;
                };
            }
            else if (CHECK_m_mmmm_field(m_mmmm_byte) == _0F3A)
            {
                if (CHECK_VEX_0F3A(op))
                {
                    INSTRUCTION_INFO printk(KERN_INFO "%s: (find_ret) Instruction is 3 byte VEX and 0F3A\n", MODULE_NAME);

                    if (!CHECK_VEX_0F3A_NO_IMM8(op))
                    {
                        INSTRUCTION_INFO printk(KERN_INFO "%s: (find_ret) Instruction is 3 byte VEX and 0F3A and has imm8\n", MODULE_NAME);
                        dsize++; // For the imm8
                    }
                }
                else
                {
                    PRINT_INSTR_ERROR
                    {
                        printk(KERN_INFO "%s: (find_ret) Instruction is 3 byte VEX and 0F3A but the op-code is not valid\n", MODULE_NAME);
                        print_hex_dump(KERN_INFO, "JIT: The op_code is (with prefix if exists): ", DUMP_PREFIX_NONE, 16, 1, cur - num_prefixes - (op_code_size - 1), num_prefixes + op_code_size, false);
                    }
                    goto error_exit;
                };
            }
            else if (CHECK_m_mmmm_field(m_mmmm_byte) == _0F)
            {

                if (CHECK_VEX_0F(op))
                {
                    INSTRUCTION_INFO printk(KERN_INFO "%s: (find_ret) Instruction is 3 byte VEX and 0F\n", MODULE_NAME);

                    if (VEX_NO_MODRM(op))
                        goto next;

                    if (CHECK_VEX_0F_IMM8(op))
                    {
                        INSTRUCTION_INFO printk(KERN_INFO "%s: (find_ret) Instruction is 3 byte VEX and 0F and has imm8\n", MODULE_NAME);
                        dsize++; // For the imm8
                    }
                }
                else
                {
                    PRINT_INSTR_ERROR
                    {
                        printk(KERN_INFO "%s: (find_ret) Instruction is 3 byte VEX and 0F but the op-code is not valid\n", MODULE_NAME);
                        print_hex_dump(KERN_INFO, "JIT: The op_code is (with prefix if exists): ", DUMP_PREFIX_NONE, 16, 1, cur - num_prefixes - (op_code_size - 1), num_prefixes + op_code_size, false);
                    }
                    goto error_exit;
                };
            }
            else
            {
                PRINT_INSTR_ERROR
                {
                    printk(KERN_INFO "%s: (find_ret) Instruction is 3 byte VEX but the m_mmmm_byte is not valid\n", MODULE_NAME);
                }
                goto error_exit;
            }

            goto check_mod_rm_byte;
        }

        else if (evex_pref_found) // 1 byte op-code
        {

            op_code_size = 1;

            INSTRUCTION_INFO printk(KERN_INFO "%s: (find_ret) Instruction is EVEX\n", MODULE_NAME);

            if (CHECK_mm_field(m_mmmm_byte) == _0F38)
            {

                if (CHECK_EVEX_0F38(op))
                {
                    INSTRUCTION_INFO printk(KERN_INFO "%s: (find_ret) Instruction is EVEX and 0F38\n", MODULE_NAME);
                }
                else
                {
                    PRINT_INSTR_ERROR
                    {
                        printk(KERN_INFO "%s: (find_ret) Instruction is EVEX and 0F38 but the op-code is not valid\n", MODULE_NAME);
                        print_hex_dump(KERN_INFO, "JIT: The op_code is (with prefix if exists): ", DUMP_PREFIX_NONE, 16, 1, cur - num_prefixes - (op_code_size - 1), num_prefixes + op_code_size, false);
                    }
                    goto error_exit;
                }
            }
            else if (CHECK_mm_field(m_mmmm_byte) == _0F)
            {
                if (CHECK_EVEX_0F(op))
                {
                    INSTRUCTION_INFO printk(KERN_INFO "%s: (find_ret) Instruction is EVEX and 0F\n", MODULE_NAME);
                    if (CHECK_EVEX_0F_IMM8(op))
                    {
                        INSTRUCTION_INFO printk(KERN_INFO "%s: (find_ret) Instruction is EVEX and 0F and has imm8\n", MODULE_NAME);
                        dsize++; // For the imm8
                    }
                }
                else
                {
                    PRINT_INSTR_ERROR
                    {
                        printk(KERN_INFO "%s: (find_ret) Instruction is EVEX and 0F but the op-code is not valid\n", MODULE_NAME);
                        print_hex_dump(KERN_INFO, "JIT: The op_code is (with prefix if exists): ", DUMP_PREFIX_NONE, 16, 1, cur - num_prefixes - (op_code_size - 1), num_prefixes + op_code_size, false);
                    }
                    goto error_exit;
                }
            }
            else if (CHECK_mm_field(m_mmmm_byte) == _0F3A)
            {
                if (CHECK_EVEX_0F3A(op))
                {
                    INSTRUCTION_INFO printk(KERN_INFO "%s: (find_ret) Instruction is EVEX and 0F3A\n", MODULE_NAME);
                    dsize++; // For the imm8
                }
                else
                {
                    PRINT_INSTR_ERROR
                    {
                        printk(KERN_INFO "%s: (find_ret) Instruction is EVEX and 0F3A but the op-code is not valid\n", MODULE_NAME);
                        print_hex_dump(KERN_INFO, "JIT: The op_code is (with prefix if exists): ", DUMP_PREFIX_NONE, 16, 1, cur - num_prefixes - (op_code_size - 1), num_prefixes + op_code_size, false);
                    }
                    goto error_exit;
                }
            }
            else
            {
                PRINT_INSTR_ERROR
                {
                    printk(KERN_INFO "%s: (find_ret) Instruction is EVEX but the m_mmmm_byte is not valid\n", MODULE_NAME);
                }
                goto error_exit;
            }

            goto check_mod_rm_byte;
        }

        /**--------------------------------------------------------------- GENERAL INSTRUCTION --------------------------------------------------------------------------------------*/
        if (CHECK_0F(op)) /* two and three byte opcode */
        {
            INSTRUCTION_INFO printk(KERN_INFO "%s: (find_ret) Instruction has a multibyte op-code\n", MODULE_NAME);

            op = *(++cur); // The second byte of the op-code

            multibyte = 1;

            if (CHECK_38(op))
            {
                op_code_size = 3;

                INSTRUCTION_INFO printk(KERN_INFO "%s: (find_ret) Instruction has a three byte 38 table op-code\n", MODULE_NAME);

                op = *(++cur); // The third byte of the op-code

                if (CHECK_THREE_BYTE_038_UD(op))
                {
                    PRINT_INSTR_ERROR
                    {
                        print_hex_dump(KERN_ERR, "JIT: (find_ret) The UD 3-byte (38) op-code is (with prefix if exists): ", DUMP_PREFIX_NONE, 16, 1, cur - num_prefixes - (op_code_size - 1), num_prefixes + op_code_size, false);
                        print_hex_dump(KERN_INFO, "", DUMP_PREFIX_NONE, 16, 1, start, cur - start + MAX_INSTRUCTION_SIZE, false); // To debug
                    }
                    goto error_exit;
                }
                if (CHECK_MODRM38(op))
                    has_modrm = 1;

                if (CHECK_THREE_BYTE_038_ARITHMETIC(op))
                    instruction_type = ARITHMETIC;
                else if (CHECK_THREE_BYTE_038_MEMORY(op))
                    instruction_type = MEMORY;
                else if (CHECK_THREE_BYTE_038_CONTROL(op))
                    instruction_type = CONTROL;
                else
                    instruction_type = OTHER;
            }
            else if (CHECK_3A(op)) /* Three-byte 3A table */
            {
                op_code_size = 3;

                INSTRUCTION_INFO printk(KERN_INFO "%s: (find_ret) Instruction has a three byte 3A table op-code\n", MODULE_NAME);

                op = *(++cur); // The third byte of the op-code

                if (CHECK_THREE_BYTE_03A_UD(op))
                {
                    PRINT_INSTR_ERROR
                    {
                        print_hex_dump(KERN_ERR, "JIT: (find_ret) The UD 3-byte (3A) op-code is (with prefix if exists): ", DUMP_PREFIX_NONE, 16, 1, cur - num_prefixes - (op_code_size - 1), num_prefixes + op_code_size, false);
                        print_hex_dump(KERN_INFO, "", DUMP_PREFIX_NONE, 16, 1, start, cur - start + MAX_INSTRUCTION_SIZE, false); // To debug
                    }
                    goto error_exit;
                }

                dsize++; // For the imm8, all the instructions in the 3A table have an imm8

                if (CHECK_MODRM3A(op))
                    has_modrm = 1;

                if (CHECK_THREE_BYTE_03A_ARITHMETIC(op))
                    instruction_type = ARITHMETIC;
                else if (CHECK_THREE_BYTE_03A_MEMORY(op))
                    instruction_type = MEMORY;
                else
                    instruction_type = OTHER;
            }

            /* Two-byte table */
            else
            {
                INSTRUCTION_INFO printk(KERN_INFO "%s: (find_ret) Instruction has a two byte op-code\n", MODULE_NAME);

                op_code_size = 2;

                if (CHECK_TWO_BYTE_UD(op))
                {
                    PRINT_INSTR_ERROR
                    {
                        print_hex_dump(KERN_ERR, "JIT: (find_ret) The UD 2 byte op-code is (with prefix if exists): ", DUMP_PREFIX_NONE, 16, 1, cur - num_prefixes - (op_code_size - 1), num_prefixes + op_code_size, false);
                        print_hex_dump(KERN_INFO, "", DUMP_PREFIX_NONE, 16, 1, start, cur - start + MAX_INSTRUCTION_SIZE, false); // To debug
                    }
                    instruction_type = NOT_VALID;
                    goto error_exit;
                }

                if (CHECK_MODRM2(op))
                    has_modrm = 1;
                if (CHECK_DATA1_2(op))
                    dsize++;
                if (CHECK_DATA66_2(op))
                    dsize += ddef;

                if (CHECK_TWO_BYTE_ARITHMETIC(op))
                    instruction_type = ARITHMETIC;
                else if (CHECK_TWO_BYTE_CONTROL(op))
                    instruction_type = CONTROL;
                else if (CHECK_TWO_BYTE_LOGICAL(op))
                    instruction_type = LOGICAL;
                else if (CHECK_TWO_BYTE_MEMORY(op))
                    instruction_type = MEMORY;
                else if (CHECK_TWO_BYTE_SYSTEM(op))
                    instruction_type = SYSTEM;
                else
                    instruction_type = OTHER;
            }
        }
        else /* one byte opcode */
        {
            INSTRUCTION_INFO printk(KERN_INFO "%s: (find_ret) Instruction has a one byte op-code\n", MODULE_NAME);

            op_code_size = 1;

            if (CHECK_ONE_BYTE_UD(op))
            {
                PRINT_INSTR_ERROR
                {
                    print_hex_dump(KERN_ERR, "JIT: (find_ret) The UD 1-byte op-code is (with prefix if exists): ", DUMP_PREFIX_NONE, 16, 1, cur - num_prefixes - (op_code_size - 1), num_prefixes + op_code_size, false);
                }
                goto error_exit;
            }

            if (CHECK_MODRM(op))
                has_modrm = 1;

            if (CHECK_TEST(op)) // 0xf6 e 0xf7 con OP-code-extension 0,1,2 ha un immediate rispettivamente a 8, 32 bit
            {
                INSTRUCTION_INFO printk(KERN_INFO "%s: (find_ret) Instruction is TEST\n", MODULE_NAME);
                modrm_byte = *(cur + 1); // The modrm byte

                if (MODRM_REG_OPCODE(modrm_byte) == OPCODE_EXTENSION_0)
                    dsize += (op & 1) ? ddef : 1;
            }
            if (CHECK_DATA1(op))
                dsize++;
            if (CHECK_DATA2(op))
                dsize += 2;
            if (CHECK_DATA66(op))
                dsize += ddef;
            if (CHECK_MEM67(op))
                msize += mdef;

            if (CHECK_ONE_BYTE_ARITH(op))
                instruction_type = ARITHMETIC;
            else if (CHECK_ONE_BYTE_CONTROL(op))
                instruction_type = CONTROL;
            else if (CHECK_ONE_BYTE_LOGICAL(op))
                instruction_type = LOGICAL;
            else if (CHECK_ONE_BYTE_MEMORY(op))
                instruction_type = MEMORY;
            else if (CHECK_ONE_BYTE_SYSTEM(op))
                instruction_type = SYSTEM;
            else if (CHECK_ONE_BYTE_JCC(op))
                instruction_type = JCC;
            else if (CHECK_ONE_BYTE_JMP(op))
                instruction_type = JMP;
            else if (CHECK_ONE_BYTE_CALL(op))
                instruction_type = CALL;
            else if (CHECK_ONE_BYTE_RET(op))
                instruction_type = RET;
            else
                instruction_type = OTHER;
        }

        /**------------------------------------------------------------------ MODRM BYTE -------------------------------------------------------------------------------------*/
        if (has_modrm)
        { // The instruction has a modrm byte.

        check_mod_rm_byte:

            modrm_byte = *(++cur); // The modrm byte

            INSTRUCTION_INFO printk(KERN_INFO "%s: (find_ret) The modrm byte is %x\n", MODULE_NAME, modrm_byte);

            if (!multibyte && CHECK_OP_CODE_EXT(op)) // Group 0x80, 0x81, 0x83, 0xf6, 0xf7, 0xff
            {
                if (MODRM_REG_OPCODE(modrm_byte) > OPCODE_EXTENSION_7) // Consistency check
                {
                    PRINT_INSTR_ERROR printk(KERN_ERR "%s: (find_ret) Error: MODRM_REG_OPCODE is not valid and the instruction should have an OP_CODE_EXTENSION\n", MODULE_NAME);
                    goto error_exit;
                }

                if (CHECK_80_81_83(op))
                {
                    // OR, AND, XOR
                    if (MODRM_REG_OPCODE(modrm_byte) == OPCODE_EXTENSION_1 || MODRM_REG_OPCODE(modrm_byte) == OPCODE_EXTENSION_4 || MODRM_REG_OPCODE(modrm_byte) == OPCODE_EXTENSION_6)
                        instruction_type = LOGICAL;
                    // CMP
                    else if (MODRM_REG_OPCODE(modrm_byte) == OPCODE_EXTENSION_7)
                        instruction_type = CONTROL;
                }
                else if (CHECK_F6_F7(op))
                {
                    // NOT, NEG
                    if (MODRM_REG_OPCODE(modrm_byte) == OPCODE_EXTENSION_2 || MODRM_REG_OPCODE(modrm_byte) == OPCODE_EXTENSION_3)
                        instruction_type = LOGICAL;
                    // MUL, IMUL, DIV, IDIV
                    else if (MODRM_REG_OPCODE(modrm_byte) == OPCODE_EXTENSION_4 || MODRM_REG_OPCODE(modrm_byte) == OPCODE_EXTENSION_5 || MODRM_REG_OPCODE(modrm_byte) == OPCODE_EXTENSION_6 || MODRM_REG_OPCODE(modrm_byte) == OPCODE_EXTENSION_7)
                        instruction_type = ARITHMETIC;
                }
                else if (CHECK_FF(op))
                {

                    // CALL
                    if (MODRM_REG_OPCODE(modrm_byte) == OPCODE_EXTENSION_2 || MODRM_REG_OPCODE(modrm_byte) == OPCODE_EXTENSION_3)
                        instruction_type = CALL;
                    // JMP
                    else if (MODRM_REG_OPCODE(modrm_byte) == OPCODE_EXTENSION_4 || MODRM_REG_OPCODE(modrm_byte) == OPCODE_EXTENSION_5)
                        instruction_type = JMP;
                    // PUSH
                    else if (MODRM_REG_OPCODE(modrm_byte) == OPCODE_EXTENSION_6)
                        instruction_type = MEMORY;
                }
            }

            // INSTRUCTION_INFO printk(KERN_INFO "%s: (find_ret) Checking ModRM_MOD\n", MODULE_NAME);

            if (MODRM_MOD(modrm_byte) == REGISTER)
            {
                INSTRUCTION_INFO printk(KERN_INFO "%s: (find_ret) ModRM_MOD is REGISTER\n", MODULE_NAME);
                goto no_sib;
            }

            else if (MODRM_MOD(modrm_byte) == INDIRECT)
            {
                INSTRUCTION_INFO printk(KERN_INFO "%s: (find_ret) ModRM_MOD is INDIRECT\n", MODULE_NAME);
                if (MODRM_R_M(modrm_byte) == EIP_DISP32)
                {
                    INSTRUCTION_INFO printk("%s: ModRM_R_M [EIP] + DISP32\n", MODULE_NAME);
                    if (mdef == 2) // operand_ovveride_prefix found
                        msize += WORD_SIZE;
                    else
                        msize += DWORD_SIZE;
                }
            }

            else if (MODRM_MOD(modrm_byte) == INDIRECT_DISP8)
            {
                INSTRUCTION_INFO printk(KERN_INFO "%s: (find_ret) ModRM_MOD is INDIRECT_DISP8\n", MODULE_NAME);
                msize += BYTE_SIZE;
            }

            else if (MODRM_MOD(modrm_byte) == INDIRECT_DISP32)
            {
                INSTRUCTION_INFO printk(KERN_INFO "%s: (find_ret) ModRM_MOD is INDIRECT_DISP32\n", MODULE_NAME);

                if (mdef == 2) // operand_ovveride_prefix found
                    msize += WORD_SIZE;
                else
                    msize += DWORD_SIZE;
            }

            else
            {
                PRINT_INSTR_ERROR
                {
                    printk(KERN_INFO "%s: (find_ret) ModRM_MOD is not valid\n", MODULE_NAME);
                }
                goto error_exit;
            }

            if (MODRM_R_M(modrm_byte) == SIB) // The instruction has a SIB byte.
            {

                sib_byte = *(++cur); // The SIB byte

                INSTRUCTION_INFO printk(KERN_INFO "%s: (find_ret) ModRM_R_M is SIB: sib byte is %x\n", MODULE_NAME, sib_byte);

                /**
                 *
                 *      SIB Note 1                                    SIB Note 2
                 *  Mod bits	base                           Mod bits	        base
                 *  00	        disp32                         00	            disp32
                 *  01	        RBP/EBP+disp8                  01	            R13/R13D+disp8 <-- Il displacement è già indicato dal MOD R/M byte
                 *  10	        RBP/EBP+disp32                 10	            R13/R13D+disp32 <-- Il displacement è già indicato dal MOD R/M byte
                 *
                 */

                if (SIB_BASE(sib_byte) == SIB_DISPLACEMENT && MODRM_MOD(modrm_byte) == INDIRECT)
                {

                    INSTRUCTION_INFO printk(KERN_INFO "%s: (find_ret) ModRM_MOD is 00 and SIB_BASE is 101\n", MODULE_NAME);
                    if (mdef == 2) // operand_ovveride_prefix found
                        msize += WORD_SIZE;
                    else
                        msize += DWORD_SIZE;
                }
            }
        no_sib:
        }

        /**--------------------------------------------------------------- NO MODRM BYTE -------------------------------------------------------------------------------*/
        else // NO MODR/M byte
        {
            INSTRUCTION_INFO printk(KERN_INFO "%s: (find_ret) Instruction has no modrm byte\n", MODULE_NAME);
        }

        /* REX.W causes 66h to be ignored */
        if (rex_w_found && !multibyte)
        {
            if (CHECK_IMM64(op))
                dsize = 8;
            if (CHECK_OFF64(op))
                msize = 8;
        }

    next:
        cur += msize + dsize + 1;

        total_size = cur - first_op;

        // PRINT_INSTRUCTION
        // {
        //     print_hex_dump(KERN_INFO, "JIT: (find_ret) The complete instruction is ", DUMP_PREFIX_NONE, 16, 1, cur - num_prefixes - total_size, total_size + num_prefixes, false);
        // }

        if (instruction_type == RET)
        {
            // We found a ret or iret instruction.
            DEBUG_INFO print_hex_dump(KERN_INFO, "JIT: (find_ret) RET is ", DUMP_PREFIX_NONE, 16, 1, cur - num_prefixes - total_size, total_size + num_prefixes, false);
            goto found_exit;
        }

        /**-------------------------------------------------------------------- RESET VARIABLES ---------------------------------------------------------------------------------------------*/

        evex_pref_found = 0;
        vex_pref_found = 0;
        rex_w_found = 0;
        multibyte = 0;
        has_modrm = 0;

        ddef = DWORD_SIZE;
        mdef = DWORD_SIZE;

        msize = 0;
        dsize = 0;
        total_size = 0;
        num_prefixes = 0;
        op_code_size = 1; // We need to reset the size of the current string. We found a matching instruction
        instruction_type = 0;
    }

error_exit:
    return 0;

found_exit:
    return (unsigned long)cur - num_prefixes - total_size;
}

#ifdef ZONE_KERNEL_SYNC_CHECK
/**
 * Finding a page in the cross pages integrity hash table
 *
 * @brief - Finding a page in the cross pages integrity hash table
 * @param address - The address of the page
 *
 * @return 1 if the page is in the hash table, 0 otherwise
 */

int find_page_cross_pages_integrity(unsigned long address)
{
    struct page_cross_pages_integrity_hash_node *curr = NULL;
    unsigned long page_addr = address & PAGE_MASK;
    pid_t pid = current->tgid;

    hash_for_each_possible(cross_pages_integrity_hash_table, curr, node, pid)
    {
        if (curr->address == page_addr && curr->pid == pid)
        {
            AUDIT printk(KERN_INFO "%s: (find_page_cross_pages_integrity) The page %lx is in the hash table with flags %08x\n", MODULE_NAME, page_addr, curr->flags);
            return curr->flags;
        }
    }

    return false;
}
#endif

/**
 * Find the page in the hash table with the given address.
 *
 * @param start_addr The start address of the page.
 * @return The page info on success, NULL on failure.
 */
struct page_info *find_current_page(unsigned long start_addr)
{
    unsigned long page = start_addr & PAGE_MASK;
    struct page_hash_node *curr = NULL;
    struct page_info *page_info = NULL;
    pid_t pid = current->tgid;

    int orig_exe_bit = -1;
    int orig_write_bit = -1;

    DEBUG_INFO
    {
        orig_exe_bit = is_bit_set(page, ORIG_EXE_BIT);
        orig_write_bit = is_bit_set(page, ORIG_WRITE_BIT);
    }

    hash_for_each_possible(page_hash_table, curr, node, pid)
    {

        if (curr->info != NULL && curr->pid == pid && curr->address == page)
        {
            DEBUG_INFO printk(KERN_INFO "%s: (find_current_page) Found page %lx for pid %d - (ORIG_EXE: %d - ORIG_WRITE: %d)\n", MODULE_NAME, curr->address, pid,
                              orig_exe_bit, orig_write_bit);
            page_info = curr->info;
            return page_info;
        }
    }

    if (page_info == NULL)
    {
        DEBUG_INFO printk(KERN_INFO "%s: (find_current_page) Failed to find the page %lx (address is %lx) for pid %d - (ORIG_EXE: %d - ORIG_WRITE: %d)\n", MODULE_NAME, page, start_addr, pid,
                          orig_exe_bit, orig_write_bit);
        return NULL;
    }

    return page_info;
}
