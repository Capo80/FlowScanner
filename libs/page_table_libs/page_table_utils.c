#include <asm/processor-flags.h>
#include "page_table_utils.h"

#define MSR_EFER 0xc0000080 /* extended feature register */
// #define _EFER_LME 8         /* Long mode enable */
// #define EFER_LME (1 << _EFER_LME)
// #define _EFER_LMA 10 /* Long mode active (read-only) */
// #define EFER_LMA (1 << _EFER_LMA)

static long my_read_cr0(void)
{
    unsigned long val;
    asm volatile("mov %%cr0, %0" : "=r"(val));
    return val;
}

static inline unsigned long read_efer(void)
{
    uint32_t lo, hi;
    asm volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(MSR_EFER));
    return ((unsigned long)hi << 32) | lo;
}

static long my_read_cr4(void)
{
    unsigned long val;
    asm volatile("mov %%cr4, %0" : "=r"(val));
    return val;
}

int check_mode(void)
{
    unsigned long cr0 = my_read_cr0();
    unsigned long cr4 = my_read_cr4();
    unsigned long efer = read_efer();

    if ((cr0 & X86_CR0_PE))
    {
        if ((cr4 & X86_CR4_PAE) && (efer & EFER_LMA))
        {
            printk(KERN_INFO "JIT: LONG_MODE\n");
            return LONG_MODE;
        }
        printk(KERN_INFO "JIT: PROTECTED_MODE\n");
        return PROTECTED_MODE;
    }
    else
    {
        printk(KERN_INFO "JIT: REAL_MODE\n");
        return REAL_MODE;
    }
}

inline uint64_t my_read_cr3(void)
{
    uint64_t ret = 0;

    asm volatile(
        "movq %%cr3, %0\n"
        : "=r"(ret));

    return ret;
}

inline void my_write_cr3(uint64_t val)
{
    asm volatile(
        "movq %0, %%cr3\n"
        :
        : "r"(val));
}

inline void manual_tlb_flush(void)
{
    my_write_cr3(my_read_cr3());
}
int is_mapped_addr(unsigned long vaddr)
{

    void *target_address;

    pud_t *pdp;
    pmd_t *pde;
    pte_t *pte;
    pgd_t *pml4;

    target_address = (void *)vaddr;
    /* fixing the address to use for page table access */

    pml4 = PAGE_TABLE_ADDRESS;

    if (!(((ulong)(pml4[PML4(target_address)].pgd)) & VALID))
        return NO_MAP;

    pdp = __va((ulong)(pml4[PML4(target_address)].pgd) & PT_ADDRESS_MASK);

    if (!((ulong)(pdp[PDP(target_address)].pud) & VALID))
        return NO_MAP;

    pde = __va((ulong)(pdp[PDP(target_address)].pud) & PT_ADDRESS_MASK);

    if (!((ulong)(pde[PDE(target_address)].pmd) & VALID))
        return NO_MAP;

    if ((ulong)pde[PDE(target_address)].pmd & LH_MAPPING)
        return MAP;

    pte = __va((ulong)(pde[PDE(target_address)].pmd) & PT_ADDRESS_MASK);

    if (!((ulong)(pte[PTE(target_address)].pte) & VALID))
        return NO_MAP;

    return MAP;
}

int print_flags(unsigned long vaddr)
{

    void *target_address;

    pud_t *pdp;
    pmd_t *pde;
    pte_t *pte;
    pgd_t *pml4;

    target_address = (void *)vaddr;
    /* fixing the address to use for page table access */

    pml4 = PAGE_TABLE_ADDRESS;

    if (!(((ulong)(pml4[PML4(target_address)].pgd)) & VALID))
        return NO_MAP;

    printk("level 1: %lu - %d\n", ((ulong)(pml4[PML4(target_address)].pgd) & P_WRITE), IS_NOT_EXE((ulong)(pml4[PML4(target_address)].pgd)));

    pdp = __va((ulong)(pml4[PML4(target_address)].pgd) & PT_ADDRESS_MASK);

    if (!((ulong)(pdp[PDP(target_address)].pud) & VALID))
        return NO_MAP;

    printk("level 2: %lu - %d\n", ((ulong)(pdp[PDP(target_address)].pud) & P_WRITE), IS_NOT_EXE((ulong)(pdp[PDP(target_address)].pud)));

    pde = __va((ulong)(pdp[PDP(target_address)].pud) & PT_ADDRESS_MASK);

    if (!((ulong)(pde[PDE(target_address)].pmd) & VALID))
        return NO_MAP;

    if ((ulong)pde[PDE(target_address)].pmd & LH_MAPPING)
        return MAP;

    printk("level 3: %lu - %d\n", ((ulong)pde[PDE(target_address)].pmd & P_WRITE), IS_NOT_EXE((ulong)pde[PDE(target_address)].pmd));

    pte = __va((ulong)(pde[PDE(target_address)].pmd) & PT_ADDRESS_MASK);

    if (!((ulong)(pte[PTE(target_address)].pte) & VALID))
        return NO_MAP;

    printk("level 4: %lu - %d\n", ((ulong)(pte[PTE(target_address)].pte) & P_WRITE), IS_NOT_EXE((ulong)(pte[PTE(target_address)].pte)));

    return MAP;
}

/**
 * flip the bit in the page table entry of the given address in the given bit position
 * @param pgd - page table address
 * @param vaddr - the address to flip the bit in
 * @param bit_position - the bit position to flip
 * @param set - 1 to set the bit, 0 to clear it
 *
 * @return - MAP if the address is mapped, NO_MAP otherwise
 */
int flip_bit_on_other(pgd_t* pgd, unsigned long vaddr, unsigned char bit_position, unsigned char set)
{

    void *target_address;

    pud_t *pdp;
    pmd_t *pde;
    pte_t *pte;
    pgd_t *pml4;

    target_address = (void *)vaddr;
    /* fixing the address to use for page table access */

    pml4 = pgd;

    if (!(((ulong)(pml4[PML4(target_address)].pgd)) & VALID))
        return NO_MAP;

    pdp = __va((ulong)(pml4[PML4(target_address)].pgd) & PT_ADDRESS_MASK);

    if (!((ulong)(pdp[PDP(target_address)].pud) & VALID))
        return NO_MAP;

    pde = __va((ulong)(pdp[PDP(target_address)].pud) & PT_ADDRESS_MASK);

    if (!((ulong)(pde[PDE(target_address)].pmd) & VALID))
        return NO_MAP;

    if ((ulong)pde[PDE(target_address)].pmd & LH_MAPPING)
    {
        if (set)
        {
            set_bit(bit_position, (unsigned long *)&(pde[PDE(target_address)].pmd));
            // pr_info("bit %u set!\n", bit_position);
        }
        else
        {
            clear_bit(bit_position, (unsigned long *)&(pde[PDE(target_address)].pmd));
            // pr_info("bit %u cleared!\n", bit_position);
        }
        return MAP;
    }

    pte = __va((ulong)(pde[PDE(target_address)].pmd) & PT_ADDRESS_MASK);

    if (!((ulong)(pte[PTE(target_address)].pte) & VALID))
        return NO_MAP;

    if (set)
    {
        set_bit(bit_position, (unsigned long *)&(pte[PTE(target_address)].pte));
        // pr_info("bit %u set!\n", bit_position);
    }
    else
    {
        clear_bit(bit_position, (unsigned long *)&(pte[PTE(target_address)].pte));
        // pr_info("bit %u cleared!\n", bit_position);
    }
    return MAP;
}


int flip_bit(unsigned long vaddr, unsigned char bit_position, unsigned char set) {

    return flip_bit_on_other(PAGE_TABLE_ADDRESS, vaddr, bit_position, set);
    
}

int is_bit_set_on_other(pgd_t* pgd, unsigned long vaddr, unsigned char bit_position)
{

    void *target_address;

    pud_t *pdp;
    pmd_t *pde;
    pte_t *pte;
    pgd_t *pml4;

    target_address = (void *)vaddr;
    /* fixing the address to use for page table access */

    pml4 = pgd;

    if (!(((ulong)(pml4[PML4(target_address)].pgd)) & VALID))
        return NO_MAP;

    pdp = __va((ulong)(pml4[PML4(target_address)].pgd) & PT_ADDRESS_MASK);

    if (!((ulong)(pdp[PDP(target_address)].pud) & VALID))
        return NO_MAP;

    pde = __va((ulong)(pdp[PDP(target_address)].pud) & PT_ADDRESS_MASK);

    if (!((ulong)(pde[PDE(target_address)].pmd) & VALID))
        return NO_MAP;

    if ((ulong)pde[PDE(target_address)].pmd & LH_MAPPING)
        return test_bit(bit_position, (unsigned long *)&(pde[PDE(target_address)].pmd));

    pte = __va((ulong)(pde[PDE(target_address)].pmd) & PT_ADDRESS_MASK);

    if (!((ulong)(pte[PTE(target_address)].pte) & VALID))
        return NO_MAP;

    return test_bit(bit_position, (unsigned long *)&(pte[PTE(target_address)].pte));
}


int is_bit_set(unsigned long vaddr, unsigned char bit_position)
{
    return is_bit_set_on_other(PAGE_TABLE_ADDRESS, vaddr, bit_position);
}

pgd_t *alloc_page_table(void)
{

    pgd_t *new_page_table;

    new_page_table = (pgd_t *)__get_free_pages((GFP_KERNEL | __GFP_ZERO), 0);
    if (new_page_table == NULL)
        return NULL;

    // just copy the whole thing - don't care
    memcpy(new_page_table, current->active_mm->pgd, sizeof(pgd_t) * PTRS_PER_PGD);

    return new_page_table;
}

void free_page_table(pgd_t *to_free)
{
    free_pages((unsigned long)to_free, 0);
}

void update_page_table(void)
{
    my_write_cr3(virt_to_phys(current->active_mm->pgd));
}

unsigned int get_free_pdg_offset(pgd_t *pgd, unsigned long kernel_addr)
{

    int i;
    unsigned long pgd_value;
    unsigned long pud_phys = ((ulong)(pgd[PML4(kernel_addr)].pgd) & PT_ADDRESS_MASK);
    ;

    for (i = 0; i < 0xff; i++)
    {
        pgd_value = (unsigned long)(pgd[i].pgd);
        if (pgd_value & VALID)
            if ((pgd_value & PT_ADDRESS_MASK) == pud_phys)
                return i;
    }

    for (i = 0; i < 0xff; i++)
    {
        if (!(((unsigned long)(pgd[i].pgd)) & VALID))
            break;
    }

    return i;
}

void *map_user_address(void *kernel_addr)
{

    pgd_t *page_table;
    unsigned long user_addr, pgd_offset;
    unsigned long cast_kernel_addr = (unsigned long)kernel_addr;

    page_table = (pgd_t *)phys_to_virt(my_read_cr3() & ADDRESS_MASK);

    pgd_offset = get_free_pdg_offset(page_table, (unsigned long)kernel_addr);

    page_table[pgd_offset] = page_table[PML4(cast_kernel_addr)];
    user_addr = (cast_kernel_addr & 0x7fffffffff) | (pgd_offset << 39);

    return (void *)user_addr;
}

void set_all_pages_non_executable(struct task_struct *task)
{
    struct mm_struct *mm = task->mm;
    struct vm_area_struct *vma;
    pud_t *pdp;
    pmd_t *pde;
    pte_t *pte;
    pgd_t *pml4;
    unsigned long address;
    VMA_ITERATOR(iter, mm, 0);

    pml4 = PAGE_TABLE_ADDRESS;

    mmap_read_lock(mm);

    for_each_vma(iter, vma)
    {
        if (vma->vm_flags & VM_EXEC)
        {
            for (address = vma->vm_start; address < vma->vm_end; address += PAGE_SIZE)
            {
                if (!(((ulong)(pml4[PML4(address)].pgd)) & VALID))
                    continue;

                pdp = __va((ulong)(pml4[PML4(address)].pgd) & PT_ADDRESS_MASK);

                if (!((ulong)(pdp[PDP(address)].pud) & VALID))
                    continue;

                pde = __va((ulong)(pdp[PDP(address)].pud) & PT_ADDRESS_MASK);

                if (!((ulong)(pde[PDE(address)].pmd) & VALID))
                    continue;

                if ((ulong)pde[PDE(address)].pmd & LH_MAPPING)
                {
                    if ((ulong)pde[PDE(address)].pmd & USER_BIT)
                    {
                        set_bit(EXE_DENY_BIT, (unsigned long *)&(pde[PDE(address)].pmd));
                        set_bit(ORIG_EXE_BIT, (unsigned long *)&(pde[PDE(address)].pmd));
                    }

                    continue;
                }

                pte = __va((ulong)(pde[PDE(address)].pmd) & PT_ADDRESS_MASK);

                if (!((ulong)(pte[PTE(address)].pte) & VALID))
                    continue;

                if ((ulong)pte[PTE(address)].pte & USER_BIT)
                {
                    set_bit(EXE_DENY_BIT, (unsigned long *)&(pte[PTE(address)].pte));
                    set_bit(ORIG_EXE_BIT, (unsigned long *)&(pte[PTE(address)].pte));
                }
            }
        }
    }

    mmap_read_unlock(mm);
    return;
}

void set_all_pages_non_writable(struct task_struct *task)
{
    struct mm_struct *mm = task->mm;
    struct vm_area_struct *vma;
    pud_t *pdp;
    pmd_t *pde;
    pte_t *pte;
    pgd_t *pml4;
    unsigned long address;
    VMA_ITERATOR(iter, mm, 0);

    pml4 = PAGE_TABLE_ADDRESS;

    mmap_read_lock(mm);

    for_each_vma(iter, vma)
    {
        if (vma->vm_flags & VM_WRITE)
        {
            for (address = vma->vm_start; address < vma->vm_end; address += PAGE_SIZE)
            {
                if (!(((ulong)(pml4[PML4(address)].pgd)) & VALID))
                    continue;

                pdp = __va((ulong)(pml4[PML4(address)].pgd) & PT_ADDRESS_MASK);

                if (!((ulong)(pdp[PDP(address)].pud) & VALID))
                    continue;

                pde = __va((ulong)(pdp[PDP(address)].pud) & PT_ADDRESS_MASK);

                if (!((ulong)(pde[PDE(address)].pmd) & VALID))
                    continue;

                if ((ulong)pde[PDE(address)].pmd & LH_MAPPING)
                {
                    if ((ulong)pde[PDE(address)].pmd & USER_BIT)
                    {
                        clear_bit(WRITE_BIT, (unsigned long *)&(pde[PDE(address)].pmd));
                        set_bit(ORIG_WRITE_BIT, (unsigned long *)&(pde[PDE(address)].pmd));
                    }

                    continue;
                }

                pte = __va((ulong)(pde[PDE(address)].pmd) & PT_ADDRESS_MASK);

                if (!((ulong)(pte[PTE(address)].pte) & VALID))
                    continue;

                if ((ulong)pte[PTE(address)].pte & USER_BIT)
                {
                    clear_bit(WRITE_BIT, (unsigned long *)&(pte[PTE(address)].pte));
                    set_bit(ORIG_WRITE_BIT, (unsigned long *)&(pte[PTE(address)].pte));
                }
            }
        }
    }

    mmap_read_unlock(mm);
    return;
}

void set_all_sh_pages_non_writable(struct task_struct *task)
{
    struct mm_struct *mm = task->mm;
    struct vm_area_struct *vma;
    pud_t *pdp;
    pmd_t *pde;
    pte_t *pte;
    pgd_t *pml4;
    unsigned long address;
    VMA_ITERATOR(iter, mm, 0);

    pml4 = PAGE_TABLE_ADDRESS;

    mmap_read_lock(mm);

    for_each_vma(iter, vma)
    {
        if (vma->vm_flags & VM_SHARED && vma->vm_flags & VM_WRITE && vma->vm_flags & VM_EXEC) // The inherited pages are WX and shared: The writes for each process should be intercepted
        {
            for (address = vma->vm_start; address < vma->vm_end; address += PAGE_SIZE)
            {
                if (!(((ulong)(pml4[PML4(address)].pgd)) & VALID))
                    continue;

                pdp = __va((ulong)(pml4[PML4(address)].pgd) & PT_ADDRESS_MASK);

                if (!((ulong)(pdp[PDP(address)].pud) & VALID))
                    continue;

                pde = __va((ulong)(pdp[PDP(address)].pud) & PT_ADDRESS_MASK);

                if (!((ulong)(pde[PDE(address)].pmd) & VALID))
                    continue;

                if ((ulong)pde[PDE(address)].pmd & LH_MAPPING)
                {
                    if ((ulong)pde[PDE(address)].pmd & USER_BIT)
                    {
                        clear_bit(WRITE_BIT, (unsigned long *)&(pde[PDE(address)].pmd));
                        set_bit(ORIG_WRITE_BIT, (unsigned long *)&(pde[PDE(address)].pmd));
                    }

                    continue;
                }

                pte = __va((ulong)(pde[PDE(address)].pmd) & PT_ADDRESS_MASK);

                if (!((ulong)(pte[PTE(address)].pte) & VALID))
                    continue;

                if ((ulong)pte[PTE(address)].pte & USER_BIT)
                {
                    clear_bit(WRITE_BIT, (unsigned long *)&(pte[PTE(address)].pte));
                    set_bit(ORIG_WRITE_BIT, (unsigned long *)&(pte[PTE(address)].pte));
                }
            }
        }
    }

    mmap_read_unlock(mm);
    return;
}

void manage_inherited_pages(struct task_struct *task)
{
    struct mm_struct *mm = task->mm;
    struct vm_area_struct *vma;
    pud_t *pdp;
    pmd_t *pde;
    pte_t *pte;
    pgd_t *pml4;
    unsigned long address;
    VMA_ITERATOR(iter, mm, 0);

    pml4 = PAGE_TABLE_ADDRESS;

    mmap_read_lock(mm);

    for_each_vma(iter, vma)
    {
        printk(KERN_INFO "vma start %lx, vm end %lx\n", vma->vm_start, vma->vm_end);

        if (vma->vm_flags & VM_SHARED && vma->vm_flags & VM_WRITE && vma->vm_flags & VM_EXEC) // The inherited pages are WX and shared: The writes for each process should be intercepted
        {
            for (address = vma->vm_start; address < vma->vm_end; address += PAGE_SIZE)
            {
                if (!(((ulong)(pml4[PML4(address)].pgd)) & VALID))
                    continue;

                pdp = __va((ulong)(pml4[PML4(address)].pgd) & PT_ADDRESS_MASK);

                if (!((ulong)(pdp[PDP(address)].pud) & VALID))
                    continue;

                pde = __va((ulong)(pdp[PDP(address)].pud) & PT_ADDRESS_MASK);

                if (!((ulong)(pde[PDE(address)].pmd) & VALID))
                    continue;

                if ((ulong)pde[PDE(address)].pmd & LH_MAPPING)
                {
                    if ((ulong)pde[PDE(address)].pmd & USER_BIT)
                    {
                        clear_bit(WRITE_BIT, (unsigned long *)&(pde[PDE(address)].pmd));
                        set_bit(ORIG_WRITE_BIT, (unsigned long *)&(pde[PDE(address)].pmd));
                    }

                    continue;
                }

                pte = __va((ulong)(pde[PDE(address)].pmd) & PT_ADDRESS_MASK);

                if (!((ulong)(pte[PTE(address)].pte) & VALID))
                    continue;

                if ((ulong)pte[PTE(address)].pte & USER_BIT)
                {
                    clear_bit(WRITE_BIT, (unsigned long *)&(pte[PTE(address)].pte));
                    set_bit(ORIG_WRITE_BIT, (unsigned long *)&(pte[PTE(address)].pte));
                }
            }
        }

        else if (!(vma->vm_flags & VM_SHARED) && (vma->vm_flags & VM_EXEC)) // The inherited pages are X or WX and private
        {   
            
            for (address = vma->vm_start; address < vma->vm_end; address += PAGE_SIZE)
            {

                if (!(((ulong)(pml4[PML4(address)].pgd)) & VALID))
                    continue;

                pdp = __va((ulong)(pml4[PML4(address)].pgd) & PT_ADDRESS_MASK);

                if (!((ulong)(pdp[PDP(address)].pud) & VALID))
                    continue;

                pde = __va((ulong)(pdp[PDP(address)].pud) & PT_ADDRESS_MASK);

                if (!((ulong)(pde[PDE(address)].pmd) & VALID))
                    continue;

                if ((ulong)pde[PDE(address)].pmd & LH_MAPPING)
                {
                    if ((ulong)pde[PDE(address)].pmd & USER_BIT)
                    {
                        set_bit(EXE_DENY_BIT, (unsigned long *)&(pde[PDE(address)].pmd));
                        set_bit(ORIG_EXE_BIT, (unsigned long *)&(pde[PDE(address)].pmd));
                    }

                    continue;
                }

                pte = __va((ulong)(pde[PDE(address)].pmd) & PT_ADDRESS_MASK);

                if (!((ulong)(pte[PTE(address)].pte) & VALID))
                    continue;

                if ((ulong)pte[PTE(address)].pte & USER_BIT)
                {
                    set_bit(EXE_DENY_BIT, (unsigned long *)&(pte[PTE(address)].pte));
                    set_bit(ORIG_EXE_BIT, (unsigned long *)&(pte[PTE(address)].pte));
                }
            }
        }
    }
    
    mmap_read_unlock(mm);
    return;
}


unsigned long get_page_table_entry(unsigned long vaddr)
{

    void *target_address;

    pud_t *pdp;
    pmd_t *pde;
    pte_t *pte;
    pgd_t *pml4;

    target_address = (void *)vaddr;
    /* fixing the address to use for page table access */

    pml4 = PAGE_TABLE_ADDRESS;

    if (!(((ulong)(pml4[PML4(target_address)].pgd)) & VALID))
        return 0;

    pdp = __va((ulong)(pml4[PML4(target_address)].pgd) & PT_ADDRESS_MASK);

    if (!((ulong)(pdp[PDP(target_address)].pud) & VALID))
        return 0;

    pde = __va((ulong)(pdp[PDP(target_address)].pud) & PT_ADDRESS_MASK);

    if (!((ulong)(pde[PDE(target_address)].pmd) & VALID))
        return 0;

    if ((ulong)pde[PDE(target_address)].pmd & LH_MAPPING)
        return (ulong)pde[PDE(target_address)].pmd;

    pte = __va((ulong)(pde[PDE(target_address)].pmd) & PT_ADDRESS_MASK);

    if (!((ulong)(pte[PTE(target_address)].pte) & VALID))
        return 0;

    return (ulong)pte[PTE(target_address)].pte;
}

unsigned long get_page_table_entry_force(unsigned long vaddr)
{

    void *target_address;

    pud_t *pdp;
    pmd_t *pde;
    pte_t *pte;
    pgd_t *pml4;

    target_address = (void *)vaddr;
    /* fixing the address to use for page table access */

    pml4 = PAGE_TABLE_ADDRESS;

    if (!(((ulong)(pml4[PML4(target_address)].pgd)) & VALID)){
        pr_err("miss pgd");
        return 0;
    }
    pdp = __va((ulong)(pml4[PML4(target_address)].pgd) & PT_ADDRESS_MASK);

    if (!((ulong)(pdp[PDP(target_address)].pud) & VALID)){
        pr_err("miss pud");
        return 0;
    }

    pde = __va((ulong)(pdp[PDP(target_address)].pud) & PT_ADDRESS_MASK);

    if (!((ulong)(pde[PDE(target_address)].pmd) & VALID)){
        pr_err("miss pmd");
        return 0;
    }
    if ((ulong)pde[PDE(target_address)].pmd & LH_MAPPING)
        return (ulong)pde[PDE(target_address)].pmd;

    pte = __va((ulong)(pde[PDE(target_address)].pmd) & PT_ADDRESS_MASK);

    if (!((ulong)(pte[PTE(target_address)].pte) & VALID)){
        pr_err("miss pte");
        //return 0;
    }
    return (ulong)pte[PTE(target_address)].pte;
}

spinlock_t* get_pte_lock(struct mm_struct* mm, unsigned long vaddr)
{

    void *target_address;

    pud_t *pdp;
    pmd_t *pde;
    pgd_t *pml4;

    target_address = (void *)vaddr;
    /* fixing the address to use for page table access */

    pml4 = PAGE_TABLE_ADDRESS;

    if (!(((ulong)(pml4[PML4(target_address)].pgd)) & VALID))
        return 0;

    pdp = __va((ulong)(pml4[PML4(target_address)].pgd) & PT_ADDRESS_MASK);

    if (!((ulong)(pdp[PDP(target_address)].pud) & VALID))
        return 0;

    pde = __va((ulong)(pdp[PDP(target_address)].pud) & PT_ADDRESS_MASK);

    if (!((ulong)(pde[PDE(target_address)].pmd) & VALID))
        return 0;

    return pte_lockptr(mm, pde);
    
}
