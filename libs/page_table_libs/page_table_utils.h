#ifndef PAGE_UTILS_H
#define PAGE_UTILS_H

#include <linux/io.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <asm/pgtable.h>

// stuff for actual service operations
#define ADDRESS_MASK 0xfffffffffffff000
#define PAGE_TABLE_ADDRESS phys_to_virt(my_read_cr3() & ADDRESS_MASK)
#define PT_ADDRESS_MASK 0x7ffffffffffff000
#define VALID 0x1
#define P_WRITE 0x2
#define MODE 0x100
#define LH_MAPPING 0x80
#define IS_USER 0x4

//#include <asm/pgtable_types.h>
#define EXE_DENY_BIT 63

/**
 * The bit is setted to 1 when a write fault occurs in a page that was executable or when an instruction fetch fault occurs in a page.
 * It's a way to mark that an X or WX page has already been checked. If it's checked and it change_protection in X from WX or WX from X then it will not be checked again.
 * 
 * It's a way to remember that an IF fault has occurred in a page that was executable across the time. 
 * change_protection resets this bit to 0, so we need to remember that a check has already been done.
*/
#define CHECK_DENY_BIT 10 // bit 11 is not changed in pte_modify

#define ORIG_EXE_BIT 56
#define ORIG_WRITE_BIT 57 
//#define WX_ORIG_EXE_BIT 55

#define USER_BIT 2
#define WRITE_BIT 1
#define PRESENT_BIT 0
#define DIRTY_BIT 6

#define PML4(addr) (unsigned int)(((long long)(addr) >> 39) & 0x1ff)
#define PDP(addr) (unsigned int)(((long long)(addr) >> 30) & 0x1ff)
#define PDE(addr) (unsigned int)(((long long)(addr) >> 21) & 0x1ff)
#define PTE(addr) (unsigned int)(((long long)(addr) >> 12) & 0x1ff)
#define IS_NOT_EXE(addr) (unsigned int)(((long long)(addr) >> EXE_DENY_BIT) & 0x1)
#define IS_WRITE(addr) (unsigned int)(((long long)(addr) >> WRITE_BIT) & 0x1)

#define _PAGE_CHECK_DENY	(_AT(pteval_t, 1) << CHECK_DENY_BIT)

//#define NO_MAP (-1) // this is a baseline with no linkage to classical error code numbers
#define NO_MAP (-EFAULT)
#define MAP 1

enum execution_mode
{
	REAL_MODE = 0,
	PROTECTED_MODE = 1,
	LONG_MODE = 2
};

uint64_t my_read_cr3(void);
void my_write_cr3(uint64_t val);
void manual_tlb_flush(void);
int check_mode(void);

int is_mapped_addr(unsigned long vaddr);

pgd_t *alloc_page_table(void);
void free_page_table(pgd_t *to_free);

void update_page_table(void);
void *map_user_address(void *kernel_addr);
int print_flags(unsigned long vaddr);
int flip_bit(unsigned long vaddr, unsigned char bit_position, unsigned char set);
int flip_bit_on_other(pgd_t* pgd, unsigned long vaddr, unsigned char bit_position, unsigned char set);
int is_bit_set(unsigned long vaddr, unsigned char bit_position);
int is_bit_set_on_other(pgd_t* pgd, unsigned long vaddr, unsigned char bit_position);
void set_all_pages_non_executable(struct task_struct *task);
void set_all_pages_non_writable(struct task_struct *task);
void set_all_sh_pages_non_writable(struct task_struct *task);
void manage_inherited_pages(struct task_struct *task);
unsigned long get_page_table_entry(unsigned long vaddr);
unsigned long get_page_table_entry_force(unsigned long vaddr);
spinlock_t* get_pte_lock(struct mm_struct* mm, unsigned long vaddr);

#endif /* PAGE_UTILS_H */
