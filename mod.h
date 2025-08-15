#ifndef GENERAL_H
#define GENERAL_H

#define PRINT_INSTR_ERROR if (0)
#define PRINT_INSTRUCTION if (0)
#define INSTRUCTION_INFO if(0)
#define DEBUG_INFO if (0)
#define SHARED_DEBUG if (0) // Debugging of the shared memory implementation
#define DCE_DEBUG if (0) // Debugging of the dinamic check engine
#define AUDIT if (0) // For debugging purposes switch to 1 to print audit messages
#define DRIVER_PRINT if (0)
#define DELETE_ME if (1)

#define LOCK if (1) // To enable locking mechanism

#define INVALID_ONE_BYTE_OPCODE 0x0E

//#define DOS_PROTECTION
#define SYNC_CHECK
//#define DEBUG_PROBES
/* #define ZONE_KERNEL_SYNC_CHECK */


/* #define SHARED_DEFENCE */

#define PAGE_MOP 0.85       // Mostly Opened Percentage: how many bytes need to be opened before clean up
#define DCE_CHECK_MODE 0        // 0 = AT_LEAST_ONE, 1 = MAJORITY, 2 = ALL OR NOTHING 
#define NUM_CONT_BLOCK 1
#define NUM_SYNC_CHECKS 8


// ! Commenting this does not work !! Make it zero if you want it disabled!!
// This makes it so only ever one block is open per-thread, meaning we are tracing every single basic-block
#define ONE_OPEN_ZONE 0


// #define C_TEST
// #define PYTHON_TEST   
// #define PHP_TEST
// #define LUAJIT_TEST
// #define RUBY_TEST

#define EXCLUDE_SHARED_LIBRARIES
/* #define EXCLUDE_SCRIPT_INTERPRETERS */

#ifdef EXCLUDE_SCRIPT_INTERPRETERS
#define TOTAL_INTERPRETERS	4
extern char* interpreters[TOTAL_INTERPRETERS];
#endif

#define MODULE_NAME "FlowScanner"

#ifndef HOOKED_PROCESS_NAME
#define TOTAL_HOOKED 17
extern char *hooked_list[TOTAL_HOOKED];
struct hooked_pid_node
{
	pid_t pid;		// PID to check.
	unsigned long open_start;
	unsigned long open_end;
	struct hlist_node node; // The node for the hash table.
};
extern DECLARE_HASHTABLE(hooked_pids, 8);
#endif

extern bool started;
extern bool finished;

extern int num_of_sync_checks;
extern int num_of_contiguous_block;

extern unsigned long num_of_cow_pages;
extern unsigned long tot_num_of_pages;
extern unsigned long total_zones_size;
extern unsigned long tot_num_of_zones;

extern unsigned long ret_addr;
extern int page_checked;
extern int zone_checked;
extern struct file *file;
extern void (*flush_tlb_mm_range_func)(struct mm_struct *, unsigned long, unsigned long, unsigned int, bool);
#endif
