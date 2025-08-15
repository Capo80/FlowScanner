#include "fprobes_helper.h"
#include "fprobers.h"



//static inline bool should_fault_around(struct vm_fault *vmf)
void should_fault_around_handler_f(struct fprobe *fp, unsigned long entry_ip,unsigned long ret_ip, struct pt_regs *regs,void *data) 
{

	DELETE_ME printk("(should_fault_around_handler) prevented fault around\n");
#ifndef HOOKED_PROCESS_NAME
	unsigned char found = 0;
	struct hooked_pid_node* cur;

	hash_for_each_possible(hooked_pids, cur, node, current->pid) {
		if (cur->pid == current->pid) {
			found = 1;
			break;
		}
	}
	if (!found)
		return;
#endif

	// we don't want memory optimizations like you in this town
	regs->ax = 0;

	return;

}

// vm_fault_t filemap_map_pages(struct vm_fault *vmf,
//  pgoff_t start_pgoff, pgoff_t end_pgoff)
int filemap_handler(struct fprobe *fp, unsigned long entry_ip,unsigned long ret_ip, struct pt_regs *regs,void *data) 
{

	struct vm_fault *vmf = (struct vm_fault*)regs_get_kernel_argument(regs, 0);
	pgoff_t start = (pgoff_t)regs_get_kernel_argument(regs, 1);
	pgoff_t end = (pgoff_t)regs_get_kernel_argument(regs, 2);
#ifndef HOOKED_PROCESS_NAME
	unsigned char found = 0;
	struct hooked_pid_node* cur;
#endif


	DELETE_ME printk("(filemap_handler) pgoff - start - end: %lu - %lu - %lu\n", vmf->pgoff, start, end);
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


	// we don't want memory optimizations like you in this town
	regs->si = vmf->pgoff;
	regs->dx = vmf->pgoff;

	AUDIT printk("(filemap_handler) changed start and end\n");
	return 0;

}