#ifndef KERNEL_ZONE_H
#define KERNEL_ZONE_H

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
#include <linux/hashtable.h>

#define BUCKET_BITS 16

#define DISASSEMBLE_ERROR -1
#define DISASSEMBLE_SUCCESS 0x1
#define DISASSEMBLE_CONTINUE 0x0

#define CALL_SUCCESS 0x2
#define JMP_SUCCESS 0x4
#define RET_SUCCESS 0x8
#define JCC_SUCCESS 0x10

#define PAGE_NOT_FOUND -1
#define PAGE_FOUND 0
#define WRITE_ERROR -2

#define ALL_INVALID_ONE_BYTE_OPCODE -2

struct stats
{
    uint8_t num_of_control_instructions;       // The number of control instructions in the zone.
    uint8_t num_of_arithmetic_instructions;    // The number of arithmetic instructions in the zone.
    uint8_t num_of_logical_instructions;       // The number of logical instructions in the zone.
    uint8_t num_of_data_transfer_instructions; // The number of data transfer instructions in the zone.
    uint8_t num_of_system_instructions;        // The number of system instructions in the zone.
    uint8_t num_of_miscellaneous_instructions; // The number of miscellaneous instructions in the zone.
    uint8_t num_of_vex_or_evex_instructions;   // The number of VEX or EVEX instructions in the zone.
};

struct open_zone
{
    char *data;           // The data of the zone.
    kuid_t uid;           // The UID of the process that owns the zone.
    pid_t ptid;           // The PTID of the process that owns the zone.
    pid_t tid;            // The TID of the process that owns the zone.
    unsigned long start;  // The start address of the zone.
    unsigned long end;    // The end address of the zone.
    struct stats stats;   // The statistics of the zone.
    struct timespec64 ts; // The timestamp of the zone.
};

struct zone_hash_node
{
    pid_t pid;              // The PID of the process that owns the zone.
    struct open_zone *zone; // The zone.
    struct hlist_node node; // The node for the hash table.
};

#define CHECK_CROSS_PAGE(cur, end, string)                                         \
    if ((unsigned long)(cur) >= (unsigned long)end)                                \
    {                                                                              \
        AUDIT printk(KERN_INFO "%s: The %s is cross-page\n", MODULE_NAME, string); \
        goto cross_page_exit;                                                      \
    }

extern int disassemble_code(unsigned long start, unsigned long *end, struct stats *stats);
extern int close_outer_zone(char *data, unsigned long start, unsigned long end, int num_pages, struct vm_area_struct *vma);
extern int close_inner_zone(unsigned long start, unsigned long end, int num_pages);
extern struct open_zone *transfer_zone(char *data, unsigned long start, unsigned long end, struct stats *stats);
extern struct open_zone *create_zone(char *data, unsigned long start, unsigned long end, int num_pages, bool is_zone, struct stats *stats);
extern int restore_page(unsigned long addr);
extern int restore_sh_page(unsigned long addr);
extern int restore_zone_bytes(char *data, unsigned long start, unsigned long end, int num_pages);

extern DECLARE_HASHTABLE(zone_hash_table, BUCKET_BITS); // The hash table for the zones
extern spinlock_t zone_spinlocks[1 << BUCKET_BITS];

#endif // KERNEL_ZONE_H
