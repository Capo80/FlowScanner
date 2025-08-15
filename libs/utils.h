#ifndef UTILS_H
#define UTILS_H

#include <asm/tlbflush.h>
#include <linux/pfn_t.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/dcache.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/time64.h>
#include <linux/timex.h>
#include <linux/limits.h>
#include <linux/uaccess.h>
#include <linux/mm_types.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <asm/pgtable.h>
#include <linux/hashtable.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <asm/uaccess.h>
#include <linux/delay.h>    
#include <linux/highmem-internal.h>

#include "fprobes/fprobes_helper.h"
#include "page_table_libs/page_table_utils.h"
#include "instruction.h"
#include "ld.h"
#include "zone.h"
#include "../mod.h"


#define INSTR_BUCKET_NUM 8
#define NR_PAGES 1
#define PAGE_END -1
#define WRITE_BIT 1

/* to align the pointer to the (next) page boundary */
#define PAGE_ALIGN_UP(addr) ALIGN(addr, PAGE_SIZE)
/* to align the pointer to the (prev) page boundary */
#define ALIGN(x, a) __ALIGN_KERNEL((x), (a))

#define PAGE_ALIGN_DOWN(addr) ALIGN_DOWN(addr, PAGE_SIZE)
// #define ALIGN_DOWN(x, a) __ALIGN_KERNEL((x) - ((a)-1), (a))

#define ROUND_UP(addr, end)                                                 \
    {                                                                       \
        if (PAGE_ALIGNED(addr))                                             \
            end = addr + PAGE_SIZE;                                         \
        else if (((unsigned long)addr & ~PAGE_MASK) >= (PAGE_SIZE * 3) / 4) \
            end = PAGE_ALIGN_UP((unsigned long)addr) + PAGE_SIZE;           \
        else                                                                \
            end = PAGE_ALIGN_DOWN((unsigned long)addr) + PAGE_SIZE;         \
    }

#define COMPUTE_END_ADDR(start, end)                   \
    {                                                  \
        if (PAGE_ALIGNED(start))                       \
            end = (unsigned long)start + PAGE_SIZE;    \
        else                                           \
            end = PAGE_ALIGN_UP((unsigned long)start); \
    }

extern unsigned long find_ret(void (*func_ptr)(void));
extern int write_pages_on_not_writable_user_pages(unsigned long user_vaddr, char *data, int num_pages, struct vm_area_struct *vma);
extern int write_zone_on_not_writable_user_pages(char *data, unsigned long start, unsigned long end, int num_pages);
extern int find_page_cross_pages_integrity(unsigned long address);
extern struct page_info *find_current_page(unsigned long start_addr);
extern char *get_basename(const char *path);  
extern void return_function(void);
extern void set_all_pages_non_exec(struct task_struct *task);
extern void print_registers(struct pt_regs *regs);

void shared_flip_bit(struct vm_area_struct* vma, unsigned long vaddr, unsigned char bit_position, unsigned char set);

extern DECLARE_HASHTABLE(instruction_hash_table, INSTR_BUCKET_NUM);
extern spinlock_t instruction_hash_spinlocks[INSTR_BUCKET_NUM];

#endif